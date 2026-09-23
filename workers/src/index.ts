import { Env, LIMITS } from "./config";
import { configured, enforceProps, provider, rate } from "./auth";
import { handleMcp } from "./tools";
import { connector } from "./socket";

const securityHeaders = {
  "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
};
const publicPaths = new Set(["/authorize", "/oauth/token", "/oauth/register", "/mcp", "/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]);

export async function boundedRequest(request: Request, limit: number): Promise<Request> {
  if (!request.body) return request;
  const reader = request.body.getReader(), parts: Uint8Array[] = [];
  let size = 0, timer: ReturnType<typeof setTimeout>;
  try {
    const body = await Promise.race([
      (async () => {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.length;
          if (size > limit) throw new Error("too_large");
          parts.push(value);
        }
        const result = new Uint8Array(size);
        let at = 0;
        for (const p of parts) { result.set(p, at); at += p.length; }
        return result;
      })(),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("timeout")), 10000); }),
    ]);
    return new Request(request.url, { method: request.method, headers: request.headers, body, redirect: request.redirect });
  } finally { clearTimeout(timer!); void reader.cancel().catch(() => {}); }
}

export const apiHandler = {
  async fetch(request, env, ctx) {
    if (!await enforceProps(env, (ctx as ExecutionContext & { props: unknown }).props)) return Response.json({ error: "invalid_token" }, { status: 401 });
    return handleMcp(request, env, connector);
  },
} satisfies ExportedHandler<Env>;

export default {
  async fetch(original: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(original.url);
    if (url.pathname === "/healthz") return Response.json({ status: configured(env) ? "ready" : "setup_required", mail_configured: !!env.MAIL_ACCOUNTS }, { headers: securityHeaders });
    if (!configured(env)) return Response.json({ error: "setup_required", message: "Configure Worker secrets, exact callbacks and database migrations." }, { status: 503, headers: securityHeaders });
    if (url.origin !== env.PUBLIC_URL || (original.headers.get("host") && original.headers.get("host") !== url.host)) return new Response("Invalid host", { status: 400, headers: securityHeaders });
    if (original.headers.has("origin") && original.headers.get("origin") !== env.PUBLIC_URL) return new Response("Invalid origin", { status: 403, headers: securityHeaders });
    if (!publicPaths.has(url.pathname)) return new Response("Not found", { status: 404, headers: securityHeaders });
    if (!["GET", "POST", "DELETE", "OPTIONS"].includes(original.method)) return new Response("Method not allowed", { status: 405, headers: securityHeaders });
    if (url.search.length > 8192) return new Response("Request too large", { status: 413, headers: securityHeaders });
    try {
      const request = await boundedRequest(original, url.pathname === "/mcp" ? LIMITS.request : 16384);
      if (url.pathname !== "/mcp" && !url.pathname.startsWith("/.well-known/")) {
        const ip = request.headers.get("CF-Connecting-IP") || "unknown";
        if (!await rate(env, "auth:" + ip, 60, 60) || !await rate(env, "auth:global", 150, 60)) return Response.json({ error: "rate_limited" }, { status: 429, headers: { ...securityHeaders, "Retry-After": "60" } });
      }
      const oauth = await provider(env, apiHandler), response = await oauth.fetch(request, env, ctx);
      const secured = new Response(response.body, response);
      for (const [k, v] of Object.entries(securityHeaders)) secured.headers.set(k, v);
      return secured;
    } catch (error) {
      const reason = error instanceof Error ? error.message : "";
      return Response.json({ error: reason === "too_large" ? "request_too_large" : reason === "timeout" ? "request_timeout" : "request_failed" }, { status: reason === "too_large" ? 413 : reason === "timeout" ? 408 : 503, headers: securityHeaders });
    }
  },
} satisfies ExportedHandler<Env>;
