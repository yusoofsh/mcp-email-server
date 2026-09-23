import { randomBytes, createHash } from "node:crypto";
import { mkdir, writeFile, access, chmod } from "node:fs/promises";
import { parseArgs } from "node:util";
import { origin, redirects } from "../src/config.ts";

const { values } = parseArgs({ options: {
  "public-url": { type: "string" },
  "redirect-uri": { type: "string", multiple: true },
  username: { type: "string", default: "operator" },
  rotate: { type: "boolean", default: false },
} });
const config = {
  PUBLIC_URL: values["public-url"] || "",
  AUTH_REDIRECT_URIS: (values["redirect-uri"] || []).join(","),
  AUTH_USERNAME: values.username,
};
try { origin(config); redirects(config); }
catch { throw new Error("Supply --public-url=https://YOUR_WORKER_HOST and the exact --redirect-uri=https://CLIENT_CALLBACK"); }
if (!/^[a-zA-Z0-9_.-]{1,64}$/.test(config.AUTH_USERNAME)) throw new Error("Use a simple username of 1-64 characters");
try {
  await access(".secrets/worker.json");
  if (!values.rotate) throw new Error("Existing credentials found. Use --rotate explicitly; existing sessions will become invalid.");
} catch (e) { if (e.code !== "ENOENT") throw e; }
await mkdir(".secrets", { recursive: true, mode: 0o700 });
await chmod(".secrets", 0o700);
const password = randomBytes(32).toString("base64url");
config.AUTH_PASSWORD_HASH = "sha256:" + createHash("sha256").update(password).digest("hex");
// Private files only. Never print passwords, hashes, mailbox secrets or API tokens to CI.
await writeFile(".secrets/login.txt", `Username: ${config.AUTH_USERNAME}\nPassword: ${password}\n`, { mode: 0o600 });
await writeFile(".secrets/worker.json", JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
await chmod(".secrets/login.txt", 0o600);
await chmod(".secrets/worker.json", 0o600);
console.log("Created .secrets/login.txt and .secrets/worker.json. Store login.txt in your password manager. Do not commit either file.");
