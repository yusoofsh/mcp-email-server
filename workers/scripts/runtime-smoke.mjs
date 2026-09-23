// Real workerd/KV/D1 smoke. Uses generated test credentials, never a real mailbox.
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { readFile } from "node:fs/promises";
import { randomBytes, createHash } from "node:crypto";
import assert from "node:assert/strict";

const origin = "https://mail.example.com";
const callback = "https://client.example.com/callback";
const password = randomBytes(32).toString("base64url");
// Miniflare is supplied by the pinned Wrangler dependency/lockfile.
const mf = new Miniflare(convertV4MiniflareOptions({
  name: "email-mcp",
  modulesRoot: process.cwd(),
  modules: [
    { type: "ESModule", path: "runtime-entry.mjs", contents: `import app from './runtime-worker.mjs';
export default {fetch(request,env,ctx){
  // Simulator RPC can leak its loopback Host and rejects foreign Origin headers.
  // Rehydrate browser context only in this test entrypoint, never in production.
  const headers=new Headers(request.headers);
  headers.set('host',new URL(request.url).host);
  if(headers.has('x-smoke-origin')){headers.set('origin',headers.get('x-smoke-origin'));headers.delete('x-smoke-origin');}
  return app.fetch(new Request(request,{headers}),env,ctx);
}};` },
    { type: "ESModule", path: "runtime-worker.mjs", contents: await readFile(process.env.BUNDLE_PATH || "dist/index.js", "utf8") },
  ],
  compatibilityDate: "2026-09-23",
  compatibilityFlags: ["nodejs_compat", "global_fetch_strictly_public"],
  kvNamespaces: ["OAUTH_KV"], d1Databases: ["AUTH_DB"],
  bindings: {
    PUBLIC_URL: origin, AUTH_USERNAME: "test",
    AUTH_PASSWORD_HASH: "sha256:" + createHash("sha256").update(password).digest("hex"),
    AUTH_REDIRECT_URIS: callback,
  },
}));
const check = (response, code, context) => assert.equal(response.status, code, context);
try {
  const db = await mf.getD1Database("AUTH_DB");
  for (const statement of (await readFile("migrations/0001_auth.sql", "utf8")).split(";")) {
    if (statement.trim()) await db.prepare(statement).run();
  }
  const fetcher = await mf.getWorker("email-mcp");
  const call = (path, init = {}) => {
    const headers = new Headers(init.headers);
    if (headers.has("origin")) { headers.set("x-smoke-origin", headers.get("origin")); headers.delete("origin"); }
    // Never follow a test OAuth callback to an external website.
    return fetcher.fetch(origin + path, { ...init, headers, redirect: "manual" });
  };
  check(await call("/healthz"), 200, "health");
  const missing = await call("/mcp", { method: "POST" });
  check(missing, 401, "unauthenticated MCP");
  assert.match(missing.headers.get("WWW-Authenticate"), /resource_metadata/);
  const metadata = await (await call("/.well-known/oauth-authorization-server")).json();
  assert.deepEqual(metadata.code_challenge_methods_supported, ["S256"]);
  assert.equal(metadata.client_id_metadata_document_supported, true);
  const registration = await call("/oauth/register", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "Runtime smoke", redirect_uris: [callback], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], scope: "email:access offline_access" }),
  });
  check(registration, 201, "registration");
  const { client_id } = await registration.json();
  const verifier = randomBytes(48).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const url = "/authorize?" + new URLSearchParams({ client_id, redirect_uri: callback, response_type: "code", scope: "email:access offline_access", code_challenge: challenge, code_challenge_method: "S256", state: "runtime", resource: origin + "/mcp" });
  const login = await call(url); check(login, 200, "login page");
  const csrf = /name="csrf" value="([^"]+)"/.exec(await login.text())?.[1];
  assert.ok(csrf, "CSRF value");
  const cookie = login.headers.get("set-cookie").split(";")[0];
  const consent = await call(url, {
    method: "POST", headers: { origin, cookie, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ csrf, username: "test", password, decision: "approve" }).toString(),
  });
  check(consent, 303, "consent");
  const code = new URL(consent.headers.get("location")).searchParams.get("code");
  const token = await call("/oauth/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", client_id, code, code_verifier: verifier, redirect_uri: callback, resource: origin + "/mcp" }).toString(),
  });
  check(token, 200, "token exchange");
  const pair = await token.json();
  const headers = { authorization: "Bearer " + pair.access_token, "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2025-11-25" };
  const listing = await call("/mcp", { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
  check(listing, 200, "tools/list");
  assert.equal((await listing.json()).result.tools.length, 15);
  const account = await call("/mcp", { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "list_accounts", arguments: {} } }) });
  check(account, 200, "list_accounts");
  assert.equal((await account.json()).result.isError, undefined);
  const revocation = await call("/oauth/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id, token: pair.refresh_token, token_type_hint: "refresh_token" }).toString(),
  });
  check(revocation, 200, "revocation");
  check(await call("/mcp", { method: "POST", headers, body: "{}" }), 401, "revoked token");
  console.log("PASS: real workerd, KV, D1, OAuth S256, MCP 15 tools, account discovery and revocation");
} finally { await mf.dispose(); }
