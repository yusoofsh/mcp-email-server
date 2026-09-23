# Remote OAuth design and review

## Boundary

`HTTPS proxy -> FastMCP 4 + PasswordOAuthProvider -> private stdio -> Wh1isper engine -> IMAP/SMTP`

One Docker container; two isolated virtual environments; one public port. The original
email package, handlers, schemas and SDK-v1 bounded stdio implementation remain unchanged.
FastMCP's supported `create_proxy` API forwards tool metadata and result content, including
embedded attachment resources. This is a front-end addition, not an untested global SDK migration.

## Authentication is not mailbox authentication

The operator's web login uses Argon2id. Email providers still use their own credentials
stored by the upstream engine. Mail credentials must be recoverable to authenticate to
IMAP/SMTP; they cannot be replaced with one-way password hashes. Protect and encrypt the
host/volume/backups accordingly. Only the MCP login password is stored as a one-way hash.

OAuth uses public-client DCR, authorization code + PKCE S256, protected-resource metadata,
short-lived opaque bearer tokens and rotating refresh tokens. DCR is implemented; CIMD is
not advertised. The single scope `email:access` permits all exposed email operations
subject to upstream policies. OAuth does not turn this single-operator service into a
multi-user mailbox authorization system.

FastMCP/SDK supply OAuth routing and PKCE validation. Application code owns local login,
consent, storage, token issuance and revocation through the documented `OAuthProvider`
interface. This is custom security-sensitive code, not a claim of a third-party audit.
Two pinned SDK interoperability gaps are covered by tests: resource indicators are checked
at the HTTP boundary, and public-client revocation replaces the SDK handler that requires
`client_secret` even when the registered client uses `none`.

## Protections

- No unauthenticated engine HTTP listener; `/mcp` rejects Basic credentials.
- Optional HTTP Basic at POST `/login` still requires a browser-bound CSRF token and explicit consent.
- Exact operator-configured HTTPS callback allowlist, fixed public issuer/resource; no wildcard redirects.
- Explicit consent naming the client, exact callback and capabilities. HTML escapes client input.
- Secure, HttpOnly, SameSite=Strict `__Host-` cookie plus a separate hidden CSRF token.
- Argon2id password verification in a bounded worker pool; generic failed-login messages.
- Rate limits backed by SQLite; request/query size and body-read time limits.
- SHA-256 indexes for random 256-bit opaque credentials; raw tokens/passwords are not persisted.
- Atomic authorization-code consumption and refresh-token rotation; detected refresh replay revokes the grant family.
- Expiry, resource, issuer, subject and revocation checks on every bearer request.
- Password hash/username/issuer changes invalidate grants at restart. Explicit reset also removes DCR clients.
- Non-root UID 10001, no Linux capabilities, read-only container filesystem, private persistent state.
- Access logs disabled to avoid recording authorization codes/tickets in URLs.

## Operational constraints

Use one replica and one worker, a private local SQLite volume, HTTPS termination and
an operator-controlled host. The service does not trust forwarded client-IP headers:
behind a proxy, per-IP limits apply collectively to that proxy. Additional edge limits
may improve abuse resistance. Public registration is bounded (128 clients); repeated
registrations can exhaust it. Reset registration state explicitly when needed.

Access tokens last 15 minutes; refresh grants have an absolute 30-day lifetime. After
that, reconnect interactively. Revocation/password changes invalidate grants; copied
old backups must not be restored as a way to recover revoked sessions.

Protect `/data`, the hash file and backups. Never mount the Docker socket or user home.
Scope exposed mailboxes and recipient allowlists carefully. Email bodies and attachments
are untrusted content: do not treat instructions inside mail as authorization to send,
delete or disclose data. Keep ChatGPT confirmation enabled for consequential mail actions.

No IMAP IDLE/webhook worker, offline lifetime archive, or new provider OAuth is added.
No real email is sent in CI. Native ChatGPT login and real mailbox delivery still require
a deployment smoke test by the operator.
