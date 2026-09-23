import { test, expect, mock } from "bun:test";
import { Database } from "bun:sqlite";
mock.module("cloudflare:workers", () => ({ WorkerEntrypoint: class { constructor(public ctx: any, public env: any) {} } }));
mock.module("cloudflare:sockets", () => ({ connect: () => { throw new Error("Real sockets forbidden in tests"); } }));
const { default: worker } = await import("../src/index");
const { sha256, random, base64, utf8 } = await import("../src/bytes");
const BASE = "https://mail.example.com", CALLBACK = "https://chatgpt.com/connector/oauth/test";
class KV {
  map = new Map<string, { value: string; expires: number }>();
  async get(key: string, options: any) { const r = this.map.get(key); if (!r || r.expires < Date.now() / 1000) return null; return (typeof options === "string" ? options : options?.type) === "json" ? JSON.parse(r.value) : r.value; }
  async put(key: string, value: string, options: any = {}) { this.map.set(key, { value, expires: options.expiration || (options.expirationTtl ? Date.now() / 1000 + options.expirationTtl : Infinity) }); }
  async delete(key: string) { this.map.delete(key); }
  async list(options: any = {}) { const keys = [...this.map.keys()].filter(x => x.startsWith(options.prefix || "")).sort(); return { keys: keys.map(name => ({ name })), list_complete: true, cursor: "" }; }
}
class D1 {
  db = new Database(":memory:");
  constructor() { this.db.exec("CREATE TABLE login_nonce(id TEXT PRIMARY KEY,binding TEXT NOT NULL,expires INTEGER NOT NULL);CREATE TABLE auth_rate(id TEXT PRIMARY KEY,n INTEGER NOT NULL,expires INTEGER NOT NULL);"); }
  prepare(sql: string) {
    const db = this.db; let args: any[] = [];
    const item = { bind(...x: any[]) { args = x; return item; }, async first() { return db.query(sql).get(...args); }, async run() { const r = db.query(sql).run(...args); return { success: true, meta: { changes: r.changes } }; }, async all() { return { results: db.query(sql).all(...args), success: true }; } };
    return item;
  }
  async batch(items: any[]) { return Promise.all(items.map(i => i.run())); }
}
async function setup() {
  const password = random(), env: any = { PUBLIC_URL: BASE, AUTH_USERNAME: "operator", AUTH_PASSWORD_HASH: "sha256:" + await sha256(password), AUTH_REDIRECT_URIS: CALLBACK, OAUTH_KV: new KV(), AUTH_DB: new D1() };
  return { password, env, async call(path: string, init: RequestInit = {}) { const ctx: any = { waitUntil: () => {}, passThroughOnException: () => {} }; return worker.fetch(new Request(BASE + path, init), env, ctx); } };
}
async function register(s: Awaited<ReturnType<typeof setup>>) {
  const r = await s.call("/oauth/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Test client", redirect_uris: [CALLBACK], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], scope: "email:access offline_access" }) });
  const j: any = await r.json(); expect(r.status).toBe(201); return j.client_id as string;
}
const verifier = "a".repeat(64), challenge = base64(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(verifier)))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function form(s: Awaited<ReturnType<typeof setup>>, cid: string) {
  const q = new URLSearchParams({ client_id: cid, redirect_uri: CALLBACK, response_type: "code", scope: "email:access offline_access", code_challenge: challenge, code_challenge_method: "S256", state: "test-state", resource: BASE + "/mcp" });
  const path = "/authorize?" + q.toString(), r = await s.call(path), text = await r.text(); expect(r.status).toBe(200);
  return { path, cookie: r.headers.get("set-cookie")!.split(";")[0], csrf: /name="csrf" value="([^"]+)"/.exec(text)![1] };
}
async function issue(s: Awaited<ReturnType<typeof setup>>, cid: string) {
  const f = await form(s, cid), r = await s.call(f.path, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: BASE, cookie: f.cookie }, body: new URLSearchParams({ csrf: f.csrf, decision: "approve", username: "operator", password: s.password }) });
  expect(r.status).toBe(303); const u = new URL(r.headers.get("location")!); expect(u.searchParams.get("state")).toBe("test-state"); expect(u.searchParams.get("iss")).toBe(BASE); return u.searchParams.get("code")!;
}
async function redeem(s: Awaited<ReturnType<typeof setup>>, cid: string, code: string, extra: any = {}) {
  return s.call("/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", client_id: cid, code, redirect_uri: CALLBACK, code_verifier: verifier, resource: BASE + "/mcp", ...extra }) });
}
async function tokens(s: Awaited<ReturnType<typeof setup>>) { const cid = await register(s), code = await issue(s, cid), r = await redeem(s, cid, code), pair: any = await r.json(); expect(r.status).toBe(200); return { cid, pair }; }
function rpc(token: string) { return { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer " + token, "mcp-protocol-version": "2025-11-25" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) }; }

test("unconfigured Worker fails closed", async () => { const s = await setup(); delete s.env.AUTH_PASSWORD_HASH; expect((await s.call("/mcp")).status).toBe(503); expect((await (await s.call("/healthz")).json() as any).status).toBe("setup_required"); });
test("discovery and unauthenticated 401", async () => { const s = await setup(), r = await s.call("/mcp", { method: "POST" }); expect(r.status).toBe(401); expect(r.headers.get("www-authenticate")).toContain("resource_metadata"); const m: any = await (await s.call("/.well-known/oauth-authorization-server")).json(); expect(m.code_challenge_methods_supported).toEqual(["S256"]); const p: any = await (await s.call("/.well-known/oauth-protected-resource/mcp")).json(); expect(p.resource).toBe(BASE + "/mcp"); });
test("full OAuth to native MCP roundtrip", async () => { const s = await setup(), { pair } = await tokens(s), r = await s.call("/mcp", rpc(pair.access_token)); expect(r.status).toBe(200); expect((await r.json() as any).result.tools).toHaveLength(15); expect(JSON.stringify([...s.env.OAUTH_KV.map.values()])).not.toContain(s.password); });
test("wrong password, missing cookie/origin, replay denied", async () => {
  const s = await setup(), cid = await register(s), f = await form(s, cid), data = { csrf: f.csrf, decision: "approve", username: "operator", password: s.password };
  const send = (headers: any, change: any = {}) => s.call(f.path, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...headers }, body: new URLSearchParams({ ...data, ...change }) });
  expect((await send({ origin: BASE })).status).toBe(403); expect((await send({ cookie: f.cookie })).status).toBe(403); expect((await send({ origin: BASE, cookie: f.cookie }, { password: "x".repeat(43) })).status).toBe(401); expect((await send({ origin: BASE, cookie: f.cookie })).status).toBe(303); expect((await send({ origin: BASE, cookie: f.cookie })).status).toBe(403);
});
test("PKCE and authorization-code replay", async () => { const s = await setup(), cid = await register(s), code = await issue(s, cid); expect((await redeem(s, cid, code, { code_verifier: "wrong" })).status).toBe(400); const fresh = await issue(s, cid); expect((await redeem(s, cid, fresh)).status).toBe(200); expect((await redeem(s, cid, fresh)).status).toBe(400); });
test("DCR callback and resource substitution rejected", async () => { const s = await setup(), r = await s.call("/oauth/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["https://evil.example/callback"], token_endpoint_auth_method: "none" }) }); expect(r.status).toBe(400); const cid = await register(s), code = await issue(s, cid); expect((await redeem(s, cid, code, { resource: "https://evil.example/mcp" })).status).toBe(400); });
test("refresh rotates; changed credential invalidates access", async () => { const s = await setup(), { cid, pair } = await tokens(s), r = await s.call("/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", client_id: cid, refresh_token: pair.refresh_token, resource: BASE + "/mcp" }) }); expect(r.status).toBe(200); const next: any = await r.json(); expect(next.refresh_token).not.toBe(pair.refresh_token); s.env.AUTH_PASSWORD_HASH = "sha256:" + await sha256(random()); expect((await s.call("/mcp", rpc(next.access_token))).status).toBe(401); });
test("refresh revocation invalidates grant", async () => { const s = await setup(), { cid, pair } = await tokens(s), r = await s.call("/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: cid, token: pair.refresh_token, token_type_hint: "refresh_token" }) }); expect(r.status).toBe(200); expect((await s.call("/mcp", rpc(pair.access_token))).status).toBe(401); });
test("Basic rejected on MCP", async () => { const s = await setup(); expect((await s.call("/mcp", { method: "POST", headers: { authorization: "Basic " + btoa("operator:" + s.password) } })).status).toBe(401); });
test("request bounds and foreign origin", async () => { const s = await setup(); expect((await s.call("/oauth/token", { method: "POST", body: "x".repeat(17000) })).status).toBe(413); expect((await s.call("/mcp", { headers: { origin: "https://evil.example" } })).status).toBe(403); });
