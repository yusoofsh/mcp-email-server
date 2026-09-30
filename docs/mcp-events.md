# MCP Events

The remote FastMCP front end advertises `events/list`, `events/subscribe`, `events/unsubscribe`, and `capabilities.events`. The `email.received` event requires string `account_name` for an account with `can_receive=true`. Payloads contain only `account_name` and `email_id`; existing read tools retrieve content. Metadata polling does not mark mail read or send messages.

Every 60 seconds, subscribed accounts are checked using provider INTERNALDATE windows with a fixed upper boundary while paginating. Event timestamps record observation time. Encrypted subscriptions, queues and watermarks share the private OAuth SQLite database. Restart resumes these records. OAuth-family revocation and account receive capability are rechecked before delivery. Changing the operator/hash/issuer invalidates grants and event records through the existing store binding.

Callbacks require public HTTPS on port 443, a signed fresh challenge, and a 2xx echoed receipt. DNS is resolved afresh and checked; TLS connects to the checked address while verifying the original hostname. Redirects are not followed. Standard Webhooks HMAC-SHA256 signatures cover the exact body bytes, fresh timestamp and stable event ID. Key rotation uses a short dual-signature window. Bodies are limited to 256 KiB, callback receipts to 16 KiB. Transient failures have bounded exponential retries; 410 unsubscribes and 413 stops retrying. Receivers must deduplicate event IDs.

Maximum lease: 24 hours, subject to OAuth-family validity. `cursor:null`: no historical replay. Only the remote front end exposes this capability; the private legacy stdio engine is unchanged. No additional production dependency or environment variable is required.

Local tests verify the authenticated modern wire methods, callback receipts, reference-only payloads, encrypted state, revocation, and the existing OAuth/tool suite. Live ChatGPT discovery, subscription receipt and restart recovery still need deployment validation. Rescan the plugin after deployment and test refresh, unsubscribe and revocation against its callback.

Reference: https://developers.openai.com/plugins/build/mcp-events
