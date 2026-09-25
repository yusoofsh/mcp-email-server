# Deploy the private Email MCP

Repository: https://github.com/yusoofsh/mcp-email-server

Image: `ghcr.io/yusoofsh/mcp-email-server:latest`

The repository's root `Dockerfile` builds the single supported OAuth image.
`deploy/compose.yaml` is the canonical deployment, and `latest` is the only
published tag. Both `linux/amd64` and `linux/arm64` images are tested natively.
Pin the recorded registry digest when an exact artifact is required; `latest`
is intentionally mutable and is not a version or an immutability guarantee.

## What you need

Docker Compose, an HTTPS reverse proxy/domain, a local login password, and an
IMAP/SMTP account. No GitHub OAuth App, Google OAuth App or external identity
provider is needed. Login is local; ChatGPT receives OAuth bearer/refresh tokens.

This is a **single-operator** deployment, not a multi-tenant service. An authorized
client can use all configured mailboxes subject to upstream email policies.

## 1. Configure and create the password hash

```bash
git clone https://github.com/yusoofsh/mcp-email-server.git
cd mcp-email-server
cp deploy/.env.example deploy/.env
# Edit deploy/.env: public HTTPS origin, username, and callback registration policy.
bash deploy/init-secrets.sh
```

The script asks for a password twice and creates an Argon2id hash inside the
owner-only `deploy/secrets/` directory. It does not save the plaintext password.
Do not commit `.env`, `secrets/`, `/data`, mailbox credentials or authentication databases.

For ChatGPT, create a custom MCP app using `https://YOUR_HOST/mcp` with **OAuth**.
Leave client ID/secret blank for dynamic client registration. To let multiple MCP
clients register themselves without manually copying callback URLs, set
`MCP_AUTH_REDIRECT_URIS=*`. The server still records each client's callbacks during
registration and matches them during authorization. Each client can register up to
16 callbacks; the server keeps up to 128 client registrations. Registration is public,
but each new authorization requires your login password and explicit consent.

Open DCR accepts HTTPS callbacks, HTTP callbacks on the local loopback interface,
and reverse-domain native-app URI schemes. Loopback callbacks may change only their
port between registration and authorization. Callbacks cannot contain wildcards,
embedded credentials, fragments, or unsafe schemes such as `javascript:` and `file:`.
If you prefer an operator allowlist, use the exact callback URL(s) as a comma-separated
list instead. ChatGPT's callback URL can vary by installation; do not use a placeholder.

## 2. Initialize email configuration

The same container includes the original upstream CLI at `/opt/email/bin/mcp-email-server`.
Use it to initialize the private data volume **before** starting the remote service:

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml run --rm \
  --entrypoint /opt/email/bin/mcp-email-server email-mcp \
  config init --database /data/mail/catalog.sqlite3

docker compose --env-file deploy/.env -f deploy/compose.yaml run --rm \
  --entrypoint /opt/email/bin/mcp-email-server email-mcp \
  account add personal \
  --email YOUR_EMAIL_ADDRESS \
  --full-name 'YOUR NAME' \
  --imap-host YOUR_IMAP_HOST --imap-user YOUR_IMAP_USERNAME \
  --smtp-host YOUR_SMTP_HOST --smtp-port 587 --smtp-user YOUR_SMTP_USERNAME \
  --no-smtp-ssl --smtp-starttls
```

The CLI asks for IMAP and SMTP credentials without placing them in command arguments.
Use the provider's recommended TLS/STARTTLS settings; inspect `account add --help`
for explicit SSL/STARTTLS options. For iCloud, use the full iCloud address, an Apple
app-specific password, IMAP `imap.mail.me.com:993` with TLS and SMTP
`smtp.mail.me.com:587` with STARTTLS. These mailbox credentials are **different**
from your MCP login password and are stored by the upstream engine.

Inspect and update sending/attachment policy deliberately:

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml run --rm \
  --entrypoint /opt/email/bin/mcp-email-server email-mcp config policy

docker compose --env-file deploy/.env -f deploy/compose.yaml run --rm \
  --entrypoint /opt/email/bin/mcp-email-server email-mcp config update-policy --help
```

An empty recipient allowlist disables sending/forwarding/draft saves. Use exact
addresses or a domain allowlist; `'*'` explicitly permits all recipients. Every
policy change needs the current revision from `config policy`. Enable
`enable_attachment_content` to return attachment bytes through MCP; the local
`download_attachment` path alone is not a remote ChatGPT download. Upstream size
limits and client support still apply; binary resources do not guarantee a file
widget in every MCP client.

## 3. Start and expose HTTPS

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d
docker compose --env-file deploy/.env -f deploy/compose.yaml ps
curl --fail http://127.0.0.1:9557/healthz
```

By default the container binds only host loopback. Point an HTTPS reverse proxy
at `127.0.0.1:9557`, preserving the **public Host** header and every path including
`/.well-known/*`, `/authorize`, `/register`, `/token`, `/revoke`, `/login`, and `/mcp`.
Do not prepend a URL path. Disable response buffering and permit appropriate
request durations for email operations. When the proxy is itself in Docker,
place it and this service on a private network; proxy to `email-mcp:9557`, preserve
the public Host header, and remove the host port mapping.

Example Caddy (installed on the same host; replace the domain):

```caddyfile
mail-mcp.example.com {
    reverse_proxy 127.0.0.1:9557
}
```

The application rejects other Host/Origin headers. Do not expose the original
unauthenticated upstream HTTP transport. The app does not trust forwarded IP
headers; behind a proxy login limits apply collectively to that proxy.

```bash
curl --fail https://YOUR_HOST/.well-known/oauth-authorization-server
curl -i -X POST https://YOUR_HOST/mcp -H 'Content-Type: application/json' -d '{}'
# Expected: HTTP 401 with WWW-Authenticate resource metadata, not a login redirect.
```

Connect ChatGPT, enter your local username/password on the login page, read the
consent screen, and authorize. Test list/search/attachment retrieval first. Send a
message to yourself only after you explicitly authorize that live test.
The consent page shows the client name and callback. Approve only a connection you
started in a client you recognize. Denying a connection stays on the server page;
the server does not redirect an unauthenticated browser to the registered callback.

## Updating, revocation and backups

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml pull
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d
```

Keep the named `email_data` volume: it contains email configuration, credentials,
OAuth registrations and token hashes. Back it up encrypted and restrict access.
A new token or code never contains mailbox credentials. OAuth access lasts
15 minutes; refresh grants expire after 30 days, requiring a new login.

To revoke every client, stop the service and run:

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml stop
docker compose --env-file deploy/.env -f deploy/compose.yaml run --rm email-mcp reset-auth --confirm RESET
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d
```

To rotate the login password, stop the service, move the existing hash aside,
rerun `init-secrets.sh`, and restart. The changed hash invalidates existing grants.
Do not restore old auth databases to recover revoked sessions. API clients may
also revoke their own access via `/revoke`.

The login screen is the normal path. Basic credentials can be supplied to its
POST endpoint only alongside its browser cookie, CSRF token and explicit consent;
**Basic is never accepted as MCP authorization**.

The server rejects a supplied `Origin` that differs from the configured public
origin. Some embedded browsers omit `Origin` on form submissions; those login
requests still require both the ticket-bound CSRF token and the secure,
same-site browser cookie. A missing `Origin` does not bypass either check.

## CI and image access

[Main CI and GHCR](https://github.com/yusoofsh/mcp-email-server/actions/workflows/main.yml)
runs the full email, OAuth, packaging, browser, Windows and documentation checks.
Each native architecture candidate is built once and exercised by digest using
canonical Compose, HTTP OAuth, the complete tool catalog, restart persistence,
refresh and revocation. The random test port is rediscovered after a restart.

A single serialized publication step checks that the source is still current
`main`, then promotes only the two verified digests to `latest` without rebuilding.
Failed or stale runs leave `latest` unchanged. Pull requests do not publish.
Publishing uses the repository's `GITHUB_TOKEN` with `packages:write` only where
needed; no custom PAT is required by Actions. Old deployment variants are not
published. Existing mailbox volumes are never removed by this release workflow.

A newly created GHCR package may initially be private even when its repository is
public. Set the package visibility to public for anonymous pulls, or authenticate
Docker using an account permitted to read it. Verify package visibility after the
first publication. No PAT belongs in Compose or the container image.

For source builds:

```bash
docker build -t email-mcp:local .
docker run --rm email-mcp:local smoke-engine
```

See [the design and threat model](remote-design.md) for security boundaries and
[upstream configuration](configuration.md) for complete mailbox options.
