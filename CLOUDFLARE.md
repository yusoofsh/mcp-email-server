# Cloudflare Workers deployment

The native Workers edition is in **[workers/](workers/README.md)**.
It uses Workers, KV, D1 and direct TLS IMAP/SMTP, with no hidden VPS backend.

Start with the [setup guide](workers/README.md#deploy). The original
Python/FastMCP Docker edition and GHCR image remain supported separately.

[Workers CI](https://github.com/yusoofsh/mcp-email-server/actions/workflows/workers-ci.yml)
validates the OAuth and mail tests plus a real workerd smoke test before optional
manual deployment. [Issue #2](https://github.com/yusoofsh/mcp-email-server/issues/2)
tracks migration and live deployment acceptance.

Workers login uses a generated high-entropy credential, not the Docker edition's
Argon2 password hash. Read the migration and Free-plan limitations before switching.
