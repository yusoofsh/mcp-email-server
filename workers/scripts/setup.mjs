import { readFile, writeFile, unlink, chmod } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { accounts, origin, redirects } from "../src/config.ts";

const config = JSON.parse(await readFile(".secrets/worker.json", "utf8"));
origin(config); redirects(config);
if (!/^sha256:[a-f0-9]{64}$/.test(config.AUTH_PASSWORD_HASH || "")) throw new Error("Generate credentials first");
const mail = JSON.parse(await readFile(".secrets/mail-accounts.json", "utf8"));
const secrets = {
  ...config,
  MAIL_ACCOUNTS: JSON.stringify(mail),
  MAIL_WRITES_ENABLED: config.MAIL_WRITES_ENABLED || "false",
  MAIL_ALLOWED_RECIPIENTS: config.MAIL_ALLOWED_RECIPIENTS || "[]",
  ALLOW_ATTACHMENT_CONTENT: config.ALLOW_ATTACHMENT_CONTENT || "false",
};
accounts(secrets);
for (const [name, value] of Object.entries(secrets)) {
  if (typeof value !== "string" || Buffer.byteLength(value) > 5120) throw new Error(`${name} exceeds the 5 KiB secret limit or is not a string`);
}
const run = (...args) => {
  const p = spawnSync("node", ["node_modules/wrangler/bin/wrangler.js", ...args], { stdio: "inherit" });
  if (p.error) throw p.error;
  if (p.status !== 0) throw new Error(`Wrangler failed (${p.status}); inspect the command output before retrying`);
};
// Initial deployment remains fail-closed until secrets exist. Only KV and D1 are provisioned.
run("deploy");
run("d1", "migrations", "apply", "AUTH_DB", "--remote");
const file = ".secrets/upload.json";
try {
  await writeFile(file, JSON.stringify(secrets), { mode: 0o600 });
  await chmod(file, 0o600);
  run("secret", "bulk", file);
} finally { await unlink(file).catch(() => {}); }
console.log(`Configured ${config.PUBLIC_URL}/mcp. Complete OAuth login and verify reads before authorizing any live send.`);
