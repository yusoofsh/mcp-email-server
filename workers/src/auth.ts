import { OAuthError, OAuthProvider, type AuthRequest } from "@cloudflare/workers-oauth-provider";
import { Env, origin, redirects } from "./config";
import { equal, random, sha256 } from "./bytes";

export const SCOPE = "email:access";
export const COOKIE = "__Host-email-mcp-login";
const headers = { "Cache-Control": "no-store", Pragma: "no-cache", "Referrer-Policy": "no-referrer" };
const esc = (s: string) => s.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

export function configured(env: Env): boolean {
  try {
    origin(env); redirects(env);
    return /^[a-zA-Z0-9_.-]{1,64}$/.test(env.AUTH_USERNAME || "") && /^sha256:[a-f0-9]{64}$/.test(env.AUTH_PASSWORD_HASH || "") && !!env.OAUTH_KV && !!env.AUTH_DB;
  } catch { return false; }
}
export const epoch = (env: Env) => sha256(env.AUTH_USERNAME + "\0" + env.AUTH_PASSWORD_HASH);

export async function rate(env: Env, key: string, limit: number, window: number): Promise<boolean> {
  const now = Math.floor(Date.now() / 1000), bucket = Math.floor(now / window), id = await sha256(key + ":" + bucket);
  // Atomic counter: denied attempts do not continuously increase/write the row.
  const row = await env.AUTH_DB.prepare("INSERT INTO auth_rate(id,n,expires) VALUES(?,1,?) ON CONFLICT(id) DO UPDATE SET n=n+1 WHERE n<? RETURNING n").bind(id, (bucket + 1) * window, limit).first<{ n: number }>();
  return !!row && row.n <= limit;
}
async function cleanup(env: Env) {
  const now = Math.floor(Date.now() / 1000);
  await env.AUTH_DB.batch([
    env.AUTH_DB.prepare("DELETE FROM login_nonce WHERE id IN (SELECT id FROM login_nonce WHERE expires<? LIMIT 100)").bind(now),
    env.AUTH_DB.prepare("DELETE FROM auth_rate WHERE id IN (SELECT id FROM auth_rate WHERE expires<? LIMIT 100)").bind(now),
  ]);
}
function cookie(request: Request): string {
  const entries = (request.headers.get("cookie") || "").split(";").map(x => x.trim()).filter(x => x.startsWith(COOKIE + "="));
  return entries.length === 1 ? entries[0].slice(COOKIE.length + 1) : "";
}
function page(req: AuthRequest, nonce: string, error = ""): Response {
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Email MCP authorization</title>
<style>body{font:16px system-ui;max-width:36rem;margin:6vh auto;padding:1.5rem;line-height:1.5}label{display:block;margin-top:1rem}input{box-sizing:border-box;width:100%;padding:.7rem}button{padding:.7rem;margin:1rem .5rem 0 0}code{overflow-wrap:anywhere}.error{color:#a00}</style>
<h1>Connect your email</h1><p>Client: <code>${esc(req.clientId)}</code></p><p>Callback: <code>${esc(req.redirectUri)}</code></p>
<p>This grants access to every configured mailbox, including sending, modifying messages and retrieving attachments, subject to server policies. Approve only the connection you started.</p>
<p>Your generated login password is not passed to the MCP client.</p><p role="alert" class="error">${esc(error)}</p>
<form method="post"><input type="hidden" name="csrf" value="${esc(nonce)}"><label for="username">Username</label><input id="username" name="username" autocomplete="username" required maxlength="64">
<label for="password">Generated password</label><input id="password" name="password" type="password" autocomplete="current-password" required maxlength="43">
<button name="decision" value="approve">Sign in and authorize</button><button name="decision" value="deny" formnovalidate>Deny</button></form></html>`, { headers: { ...headers, "Content-Type": "text/html;charset=utf-8" } });
}

export async function authorize(request: Request, env: Env): Promise<Response> {
  // Authorization parameters remain in the validated URL across GET and form POST.
  let req: AuthRequest;
  try { req = await env.OAUTH_PROVIDER.parseAuthRequest(new Request(request.url, { method: "GET" })); }
  catch { return Response.json({ error: "invalid_authorization_request" }, { status: 400, headers }); }
  if (!redirects(env).includes(req.redirectUri) || req.responseType !== "code" || req.codeChallengeMethod !== "S256" || !req.codeChallenge || !/^[A-Za-z0-9_-]{43}$/.test(req.codeChallenge)) {
    return Response.json({ error: "invalid_request", message: "Exact allowed callback and PKCE S256 are required" }, { status: 400, headers });
  }
  const scopes = req.scope.length ? req.scope : [SCOPE];
  if (!scopes.includes(SCOPE) || scopes.some(s => ![SCOPE, "offline_access"].includes(s))) return Response.json({ error: "invalid_scope" }, { status: 400, headers });
  if (request.method === "GET") {
    await cleanup(env);
    const nonce = random(), browser = random(), expires = Math.floor(Date.now() / 1000) + 300;
    await env.AUTH_DB.prepare("INSERT INTO login_nonce(id,binding,expires) VALUES(?,?,?)").bind(await sha256(nonce), await sha256(browser + "\0" + request.url), expires).run();
    const response = page(req, nonce);
    response.headers.set("Set-Cookie", `${COOKIE}=${browser}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=300`);
    return response;
  }
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers });
  if (request.headers.get("origin") !== origin(env)) return Response.json({ error: "invalid_origin" }, { status: 403, headers });
  const form = await request.formData(), nonce = String(form.get("csrf") || ""), browser = cookie(request);
  if (!/^[A-Za-z0-9_-]{43}$/.test(nonce) || !/^[A-Za-z0-9_-]{43}$/.test(browser)) return Response.json({ error: "invalid_csrf" }, { status: 403, headers });
  const nonceId = await sha256(nonce), binding = await sha256(browser + "\0" + request.url), now = Math.floor(Date.now() / 1000);
  const stored = await env.AUTH_DB.prepare("SELECT binding FROM login_nonce WHERE id=? AND expires>=?").bind(nonceId, now).first<{ binding: string }>();
  if (!stored || !equal(stored.binding, binding)) return Response.json({ error: "invalid_csrf" }, { status: 403, headers });
  const decision = form.get("decision");
  if (decision !== "approve" && decision !== "deny") return Response.json({ error: "consent_required" }, { status: 400, headers });
  if (decision === "approve") {
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    if (!await rate(env, "password:" + ip, 5, 300) || !await rate(env, "password:global", 30, 300)) return Response.json({ error: "rate_limited" }, { status: 429, headers: { ...headers, "Retry-After": "300" } });
    let username = String(form.get("username") || ""), password = String(form.get("password") || "");
    const auth = request.headers.get("authorization");
    if (auth?.toLowerCase().startsWith("basic ")) {
      try {
        const decoded = atob(auth.slice(6)), at = decoded.indexOf(":");
        if (at < 0) throw new Error();
        username = decoded.slice(0, at); password = decoded.slice(at + 1);
      } catch { username = ""; password = ""; }
    }
    // ONLY for a generated 256-bit random secret. Human passwords are unsupported.
    const validFormat = /^[A-Za-z0-9_-]{43}$/.test(password);
    const candidate = "sha256:" + await sha256(validFormat ? password : "invalid");
    if (!validFormat || !equal(username, env.AUTH_USERNAME) || !equal(candidate, env.AUTH_PASSWORD_HASH)) {
      const r = page(req, nonce, "Invalid username or generated password.");
      return new Response(r.body, { status: 401, headers: r.headers });
    }
  }
  const consumed = await env.AUTH_DB.prepare("DELETE FROM login_nonce WHERE id=? AND binding=? AND expires>=? RETURNING id").bind(nonceId, binding, now).first();
  if (!consumed) return Response.json({ error: "authorization_already_used" }, { status: 400, headers });
  let redirectTo: string;
  if (decision === "deny") {
    const u = new URL(req.redirectUri);
    u.searchParams.set("error", "access_denied"); u.searchParams.set("state", req.state); u.searchParams.set("iss", origin(env));
    redirectTo = u.toString();
  } else {
    ({ redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({ request: req, userId: "operator", scope: scopes, metadata: { clientId: req.clientId }, props: { epoch: await epoch(env), scopes } }));
  }
  return new Response(null, { status: 303, headers: { ...headers, Location: redirectTo, "Set-Cookie": `${COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0` } });
}

export async function provider(env: Env, apiHandler: Required<Pick<ExportedHandler<Env>, "fetch">>): Promise<OAuthProvider<Env>> {
  const currentEpoch = await epoch(env), base = origin(env), allowed = redirects(env);
  return new OAuthProvider<Env>({
    apiRoute: "/mcp", apiHandler, defaultHandler: { fetch: (r, e) => authorize(r, e) },
    authorizeEndpoint: "/authorize", tokenEndpoint: "/oauth/token", clientRegistrationEndpoint: "/oauth/register",
    accessTokenTTL: 900, refreshTokenTTL: 2592000, clientRegistrationTTL: 2592000,
    allowPlainPKCE: false, allowImplicitFlow: false, allowTokenExchangeGrant: false,
    clientIdMetadataDocumentEnabled: true, scopesSupported: [SCOPE, "offline_access"],
    resourceMetadata: { resource: base + "/mcp", authorization_servers: [base], scopes_supported: [SCOPE], resource_name: "Private Email MCP" },
    clientRegistrationCallback: ({ clientMetadata: m }) => {
      if (!Array.isArray(m.redirect_uris) || !m.redirect_uris.length || m.redirect_uris.length > 10 || m.redirect_uris.some(u => typeof u !== "string" || !allowed.includes(u)) || m.software_statement) return { code: "invalid_client_metadata", description: "Register only exact operator-allowed callbacks" };
      if (typeof m.scope === "string" && m.scope.split(" ").filter(Boolean).some(s => ![SCOPE, "offline_access"].includes(s))) return { code: "invalid_scope", description: "Unsupported scope" };
    },
    tokenExchangeCallback: ({ props, requestedScope }) => {
      if (props?.epoch !== currentEpoch) throw new OAuthError("invalid_grant", { description: "Operator credentials changed. Reconnect." });
      return { accessTokenProps: { epoch: currentEpoch, scopes: requestedScope } };
    },
    onError: () => undefined,
  });
}
export async function enforceProps(env: Env, props: unknown): Promise<boolean> {
  const p = props as { epoch?: string; scopes?: string[] } | undefined;
  return !!p && p.epoch === await epoch(env) && Array.isArray(p.scopes) && p.scopes.includes(SCOPE);
}
