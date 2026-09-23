# Private Email MCP on Cloudflare Workers

A native TypeScript edition of this email MCP, using **Workers, KV, D1 and outbound
TCP/TLS**. No VPS, container subscription, external identity provider, R2, Workers
AI, Vectorize or Durable Objects is required. The original Python/FastMCP Docker
edition and its GHCR workflow remain available and unchanged.

The architecture is inspired by
[second-brain-cloudflare](https://github.com/rahilp/second-brain-cloudflare).
This is a runtime port, not Python/FastMCP executing inside Workers.

```text
ChatGPT -- OAuth + PKCE --> Worker -- TLS 993 ------> existing IMAP mailbox
                             |   -- TLS/STARTTLS --> existing SMTP submission
                             +-- KV: OAuth state
                             +-- D1: login nonces and rate limits
```

## Deploy

Prerequisites: **Bun 1.4.2**, **Node.js 22+** (24 recommended for Wrangler), a
Cloudflare account and an existing mailbox. Stay on Workers Free; this repository
does not upgrade your plan. This is not a new mail-hosting service.

```bash
git clone https://github.com/yusoofsh/mcp-email-server.git
cd mcp-email-server/workers
bun install --frozen-lockfile
bunx wrangler login
# Set CLOUDFLARE_ACCOUNT_ID when you have multiple Cloudflare accounts.

bun run credentials --public-url=https://email-mcp.YOUR_SUBDOMAIN.workers.dev \
  --redirect-uri=https://chatgpt.com/connector/oauth/YOUR_ACTUAL_CALLBACK_ID \
  --username=operator

cp mail-accounts.example.json .secrets/mail-accounts.json
chmod 600 .secrets/mail-accounts.json
# Edit the private file with your real mailbox credentials and folder names.
bun run setup
```

The generator saves a **256-bit random password** to `.secrets/login.txt` and only
its SHA-256 hash to `.secrets/worker.json`. Put the login in your password manager.
Never commit `.secrets/`, `.dev.vars`, or mailbox/API credentials. Fast hashing is
appropriate here because the secret has 256 bits of random entropy.
**Human-chosen passwords and existing Argon2 hashes are not supported by this
edition.** Do not substitute a memorable password.

Wrangler automatically creates this Worker's KV namespace and D1 database. Setup
applies the database migration and uploads application secrets. The initial Worker
fails closed until configured. Resource IDs added to `wrangler.jsonc` are not
secrets, but other accounts must use their own resources.

In ChatGPT, create a custom remote MCP app for `https://YOUR_HOST/mcp` using OAuth.
Copy the **exact callback supplied for that installation** into `--redirect-uri`.
Never use the literal example placeholder or a wildcard. DCR is supported, so
leave client ID/secret blank unless your client requires pre-registration.
Sign in with the generated username/password and approve the consent screen.
No GitHub or Google OAuth app is required. Basic credentials work only at the
login POST with its CSRF cookie and consent; `/mcp` requires a bearer token.

For an existing Docker deployment, preserve its configuration as a backup, create
new Worker login credentials, configure the mailbox separately and reconnect
ChatGPT. The Docker edition's Argon2 hash and OAuth sessions do not transfer.

## Mailbox configuration

The example uses iCloud's app-specific password with IMAP TLS 993 and SMTP
STARTTLS 587. Verify the special folder names with `list_mailboxes`; providers
may localize them. Other providers must support IMAP and authenticated SMTP using
a password or app-specific password. This edition does not add provider OAuth.

If the provider already saves sent mail automatically, use `save_sent: false` to
avoid duplicate Sent copies. Otherwise set `folders.sent` explicitly. SMTP
acceptance and Sent-folder append are separate outcomes. If SMTP accepted mail
but the Sent append failed, **do not resend**. A lost response after DATA yields
`delivery_unknown`: check independently before retrying.

## Enable writes and attachments deliberately

Writes and attachment-byte retrieval default to **disabled**. After verifying
reads, add these string-valued settings to `.secrets/worker.json`, keeping the
existing generated fields, and rerun setup:

```json
{
  "MAIL_WRITES_ENABLED": "true",
  "MAIL_ALLOWED_RECIPIENTS": "[\"you@example.com\",\"*@your-company.example\"]",
  "ALLOW_ATTACHMENT_CONTENT": "true"
}
```

An empty recipient list allows nobody; `"*"` explicitly allows every recipient.
Sending, forwarding and draft saves enforce this policy. Every write tool also
requires `confirm: true`. Keep client-side confirmation enabled for consequential
actions. Instructions found inside email or attachments are untrusted content,
not authorization to send, delete or disclose anything.

## Tools

```text
Accounts and folders:  list_accounts, list_mailboxes
History and search:    list_emails_metadata (bounded UID-window pagination)
Message bodies:        get_emails_content (one message, without marking read)
Large-message access:  get_message_structure, get_message_part
Attachment bytes:      get_attachment_content (embedded MCP binary resource)
Sending:               send_email, reply_email, forward_email
Drafts:                save_draft (IMAP APPEND)
Flags:                 set_email_flag (Seen/Flagged)
Moves:                 move_email, archive_email, trash_email (UID MOVE)
```

This is **not identical tool-schema parity** with the Python edition. It does not
provide IMAP IDLE/webhooks, an offline mailbox archive, arbitrary IMAP keywords,
reply-all, permanent EXPUNGE, large uploads, PDF extraction or new Gmail/Microsoft
OAuth. Servers without UID MOVE are refused instead of using an unsafe
mailbox-wide EXPUNGE fallback.

## Limits and pagination

These are conservative application limits, not silent truncation:

```text
Metadata:                   10 results per call, default 5
Search:                     At most 500 UID values scanned per window
Complete MIME parsing:      128 KiB
MIME-part chunks:           32 KiB wire bytes per call
Inline decoded attachment: At most 64 KiB encoded wire part
Outbound MIME:              192 KiB total
Outgoing attachments:      Combined 128 KiB, maximum 5 files
Accounts:                   At most 5; configuration must fit a 5 KiB secret
```

Continue `next_before_uid` while `has_more` is true **even on an empty page**.
An empty range is not proof the entire mailbox search is empty. Carry
`uidvalidity` across pages and known-message operations to avoid stale UID reuse.
History means mail still retained by the server, not recovery of deleted mail.

For larger attachments, decode each `content_base64` chunk, concatenate wire
bytes in offset order, and **only then** decode `transfer_encoding`
(base64/quoted-printable). Do not decode transfer encoding separately per chunk.
MCP clients differ in binary-resource support; an embedded resource does not
guarantee a ChatGPT download widget.

## Workers Free constraints

Cloudflare documents Workers Free with 100,000 requests/day, **10 ms CPU per
request**, 128 MB memory, 50 subrequests and six simultaneous outgoing connections.
Network waiting does not count as CPU, but parsing, composing, OAuth and SDK
execution do. KV has a tighter daily write quota, consumed by registrations,
consents and token refreshes. Your other Workers share account-level quotas.

This implementation needs no paid-only bindings, but that does not guarantee
arbitrary workloads fit Free. Complex messages can exceed CPU limits even within
the byte bounds. Monitor actual production CPU and error 1102 before relying on
this for business-critical mail. Local tests do not prove production CPU usage.

Workers blocks outbound port 25. This edition uses authenticated SMTP submission
on TLS 465 or mandatory STARTTLS 587. Providers can reject Cloudflare egress IPs;
real provider connectivity still needs a deployment test.

## Security and maintenance

The maintained Cloudflare OAuth library handles discovery, DCR/CIMD, S256 PKCE,
token protection and refresh/revocation. The application handles local login,
consent, callback allowlists, scope/credential-epoch validation and D1 nonces/rates.
Only one operator is supported; this is not multi-tenant mailbox authorization.

The login cookie is Secure, HttpOnly and SameSite=Strict. D1 consumes browser-bound
CSRF nonces atomically. Changing username or login hash invalidates access through
the credential epoch. Access tokens last 15 minutes; refresh credentials and DCR
registrations expire after 30 days. KV is eventually consistent: revocation is not
globally instantaneous, and the library permits a bounded previous-refresh retry
window. Do not claim stronger guarantees than its storage/protocol provide.

Logs are disabled by default. Never log authentication URLs, headers, email bodies
or secrets. Mailbox passwords must remain recoverable Worker secrets for IMAP/SMTP;
only the MCP login credential is one-way hashed. No independent security audit is
claimed.

Rotate using `bun run credentials ... --rotate` and rerun setup. Mailbox secrets
remain in their separate private file. Use the library's advertised revocation
endpoint with `token` and `client_id` and without `grant_type` to revoke a grant.
Keep this application's KV and D1 separate from your other services.

## CI and deployment automation

```bash
bun install --frozen-lockfile
bun run typecheck
bun test tests
bun run build
node node_modules/wrangler/bin/wrangler.js deploy --dry-run --outdir .wrangler/dry-run
BUNDLE_PATH=.wrangler/dry-run/index.js bun run test:runtime
```

The real workerd smoke test verifies KV/D1, OAuth S256, discovery, tool access and
revocation using generated test credentials and no real mailbox. Protocol tests
use fake TCP sockets. Neither test replaces a live mailbox/ChatGPT smoke test.
The browser bundle has a 1 MiB gzip **project budget**, not a platform-limit claim.

[Workers Free CI](https://github.com/yusoofsh/mcp-email-server/actions/workflows/workers-ci.yml)
tests pull requests without deployment. A main-branch manual run with `deploy`
enabled deploys only after validation, using repository secrets
`CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`. Use a scoped Workers/KV/D1 token,
not a global API key. Application secrets stay in Cloudflare; tests require none.
The Docker/GHCR workflow remains separate.

## Primary references

- [Reference architecture](https://github.com/rahilp/second-brain-cloudflare)
- [Cloudflare OAuth provider](https://github.com/cloudflare/workers-oauth-provider)
- [Workers TCP sockets](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/)
- [Workers limits](https://developers.cloudflare.com/workers/platform/limits/)
- [KV limits](https://developers.cloudflare.com/kv/platform/limits/)
- [D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/)
- [Automatic resource provisioning](https://developers.cloudflare.com/changelog/2025-10-24-automatic-resource-provisioning/)
