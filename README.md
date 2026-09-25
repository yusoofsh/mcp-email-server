# Private Email MCP

One self-hosted email MCP deployment: the original Python IMAP/SMTP engine behind
FastMCP OAuth, with a local username/password stored as an Argon2id hash.
No external identity provider is required.

```text
ChatGPT / MCP client -> HTTPS proxy -> OAuth MCP -> private stdio -> IMAP / SMTP
```

**Image:** `ghcr.io/yusoofsh/mcp-email-server:latest`, for Linux AMD64 and ARM64.
The root `Dockerfile` and `deploy/compose.yaml` are the only deployment definitions.
`latest` is intentionally mutable; CI records its exact digest for audit/rollback.

## Deploy

```bash
git clone https://github.com/yusoofsh/mcp-email-server.git
cd mcp-email-server
cp deploy/.env.example deploy/.env
# Edit the public HTTPS origin, login username and exact OAuth callback.
bash deploy/init-secrets.sh
```

Follow [the setup guide](docs/remote-oauth.md) to configure the mailbox and policies,
then start the service:

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml pull
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d
```

The app binds only host loopback on port 9557. Terminate HTTPS at your reverse proxy
and preserve the public Host header and OAuth endpoint paths. Do not add a static
Bearer gate in front of OAuth discovery/login. `/mcp` itself requires OAuth tokens.

The login password and mail-provider credentials are separate. Configure mailboxes
interactively using the included engine CLI; never send credentials through chat.
The upstream mail tools, sender/recipient policies and attachment controls remain
intact. This is a single-operator service, not multi-tenant mailbox isolation.

## Validation and maintenance

[Main CI](https://github.com/yusoofsh/mcp-email-server/actions/workflows/main.yml)
is the sole workflow. It retains Python, Windows, browser, packaging and mail E2E
checks, plus OAuth tests and native AMD64/ARM64 tests of the exact candidate images.
Only the current `main` commit can promote both tested digests to `latest`; the
publication step never rebuilds the images. Failed or stale runs leave `latest`
unchanged. Pull requests never publish images.

- [Deployment and migration](docs/remote-oauth.md)
- [Security design](docs/remote-design.md)
- [Mail tool contract](docs/tools.md)
- [Contributing and local engine development](CONTRIBUTING.md)

The engine and OAuth adapter use isolated dependency environments in one non-root
container; this is not a second deployment. Local engine CLI/UI and stdio remain
available for setup and development. No cloud-hosted runtime or unauthenticated
container variant is published by this fork.

Based on [Wh1isper/mcp-email-server](https://github.com/Wh1isper/mcp-email-server).
Original authorship and the [BSD-3-Clause license](LICENSE) are preserved.
