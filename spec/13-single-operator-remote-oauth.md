# Single-Operator Remote OAuth

## Scope and Boundary

This spec covers the optional hosted front end under `remote/`. It is a separate
deployment profile for one operator and the configured mailboxes. It does not add
a multi-user account model or change the local authority and management boundaries
in specs 01-12. The front end exposes the existing email tool surface through
HTTPS OAuth; mailbox credentials remain owned by the email engine.

An approved OAuth grant can perform every operation exposed by the configured
email engine and can reach every mailbox it manages. Consent is therefore an
operator decision for the full service, not a per-mailbox authorization.

## Client Registration and Redirects

`MCP_AUTH_REDIRECT_URIS` selects one of two policies:

- A comma-separated list permits only those exact callback values.
- The single value `*` enables public dynamic client registration for any client
  that supplies valid callback metadata.

Open registration does not relax client-specific redirect matching. A registration
stores at most 16 callback URIs; authorization must use a callback stored for that
client. HTTPS callbacks are supported. HTTP is permitted only on loopback and must
specify a nonzero port. Native private-use callbacks use reverse-domain schemes.
Native loopback authorization may vary the port while retaining the registered
loopback host, path, and query. Wildcards, credentials, fragments, unsafe browser
schemes, and non-loopback HTTP callbacks are rejected.

The service rate-limits registration and retains no more than 128 client
registrations. Reaching that cap fails closed and requires an operator reset.

## Authorization and Trust

Every client uses the public-client authorization-code flow with PKCE S256 and the
single `email:access` scope. The user must enter the local operator password and
explicitly approve each authorization. The consent page names the client and shows
its callback and full-service permission. Client metadata is untrusted display data.

The authorization server does not send an unauthenticated browser to a registered
callback. Authorization errors remain on the server, and declining consent renders
a local completion page. A successful redirect occurs only after password
verification and explicit approval. Authorization codes, access tokens, and refresh
tokens remain bound to the registered client; code exchange also verifies PKCE,
resource, and one-time use.

## Acceptance Criteria

1. Static exact callback allowlists continue to work, and `*` enables DCR without
   requiring callback enumeration by the operator.
2. Registration rejects invalid schemes, wildcards, credentials, fragments,
   non-loopback HTTP destinations, and registrations over 16 callbacks.
3. Authorization uses only that client's registered callback, allowing only the
   RFC 8252 loopback-port exception, and never redirects invalid authorization
   errors to an untrusted client.
4. Password verification and explicit consent precede successful callback
   redirects; denying consent stays on the authorization server.
5. Registration limits, single-operator/full-mailbox permission, callback rules,
   and operational reset guidance are documented and covered by CI checks.
6. Cross-origin navigation may open the ticketed login page only with the
   configured Host and a valid ticket. Login POST rejects a supplied foreign
   Origin; when Origin is absent, both the ticket-bound CSRF token and secure
   browser cookie are required.
