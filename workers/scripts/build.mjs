import { mkdir, writeFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";

const result = await Bun.build({
  entrypoints: ["src/index.ts"],
  target: "browser",
  format: "esm",
  minify: true,
  external: ["cloudflare:*", "node:*"],
});
if (!result.success) {
  for (const log of result.logs) console.error(log);
  process.exit(1);
}
await mkdir("dist", { recursive: true });
const bytes = new Uint8Array(await result.outputs[0].arrayBuffer());
const gzip = gzipSync(bytes);
// A project budget, not a claim about the platform's current maximum.
if (gzip.length > 1024 * 1024) throw new Error("Worker exceeds the 1 MiB compressed project budget");
await writeFile("dist/index.js", bytes);
await writeFile("dist/build.json", JSON.stringify({ bytes: bytes.length, gzip_bytes: gzip.length, runtime: "Cloudflare Workers", external_services: ["KV", "D1", "configured IMAP/SMTP"] }, null, 2) + "\n");
console.log(`Worker bundle: ${bytes.length} bytes; ${gzip.length} bytes gzip`);
