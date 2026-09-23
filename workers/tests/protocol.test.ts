import { describe, test, expect } from "bun:test";
import PostalMime from "postal-mime";
import { Imap, quote, mailboxName, decodeMailbox, parseList, bodyParts } from "../src/imap";
import { Smtp, compose } from "../src/smtp";
import { Wire, type SocketLike, type Connector } from "../src/wire";
import { accounts, confirmed, allowedRecipients, LIMITS, type Account, type Env } from "../src/config";
import { base64, unbase64, utf8, decodeTransfer } from "../src/bytes";
import { handleMcp } from "../src/tools";

const a: Account = { id: "test", email: "me@example.com", imap: { host: "imap.example.com", port: 993, username: "me", password: "test-password" }, smtp: { host: "smtp.example.com", port: 587, security: "starttls", username: "me", password: "test-password" } };
const env = { MAIL_ACCOUNTS: JSON.stringify([a]), MAIL_WRITES_ENABLED: "true", MAIL_ALLOWED_RECIPIENTS: '["*@example.com"]', ALLOW_ATTACHMENT_CONTENT: "true" } as Env;
class FakeSocket implements SocketLike {
  writes: string[] = []; secure = false; didClose = false;
  controller!: ReadableStreamDefaultController<Uint8Array>;
  readable = new ReadableStream<Uint8Array>({ start: c => { this.controller = c; } });
  writable = new WritableStream<Uint8Array>({ write: b => { const t = new TextDecoder().decode(b); this.writes.push(t); this.answer(t, this); } });
  opened = Promise.resolve({}); closed = new Promise<void>(() => {});
  constructor(private answer: (t: string, s: FakeSocket) => void, greeting = "") { if (greeting) this.push(greeting); }
  push(s: string | Uint8Array) { const b = typeof s === "string" ? utf8.encode(s) : s; for (let i = 0; i < b.length; i += 7) this.controller.enqueue(b.slice(i, i + 7)); }
  async close() { this.didClose = true; try { this.controller.close(); } catch {} }
  startTls(): SocketLike { this.secure = true; return this; }
}
function imapSocket(search = "990 998 995") {
  return new FakeSocket((t, s) => {
    const tag = t.split(" ")[0];
    if (t.includes(" LOGIN ")) s.push(`${tag} OK login\r\n`);
    else if (t.includes(" CAPABILITY")) s.push(`* CAPABILITY IMAP4rev1 MOVE\r\n${tag} OK caps\r\n`);
    else if (t.includes(" EXAMINE ") || t.includes(" SELECT ")) s.push(`* 9 EXISTS\r\n* OK [UIDVALIDITY 42] ids\r\n* OK [UIDNEXT 1001] next\r\n${tag} OK selected\r\n`);
    else if (t.includes(" UID SEARCH ")) s.push(`* SEARCH ${search}\r\n${tag} OK searched\r\n`);
    else if (t.includes("BODY.PEEK[1]")) s.push(`* 1 FETCH (UID 7 BODY[1]<0> {8}\r\nYWJjZA==)\r\n${tag} OK fetched\r\n`);
    else s.push(`${tag} OK command\r\n`);
  }, "* OK imap ready\r\n");
}

describe("input and MIME safety", () => {
  test("public TLS mail hosts only", () => {
    expect(accounts(env)).toHaveLength(1);
    for (const host of ["127.0.0.1", "localhost", "internal.local"]) expect(() => accounts({ MAIL_ACCOUNTS: JSON.stringify([{ ...a, imap: { ...a.imap, host } }]) })).toThrow();
    expect(() => accounts({ MAIL_ACCOUNTS: JSON.stringify([{ ...a, smtp: { ...a.smtp, port: 25 } }]) })).toThrow();
  });
  test("writes and recipients deny by default", () => {
    expect(() => confirmed({} as Env, true)).toThrow(); expect(() => confirmed(env, false)).toThrow();
    expect(() => allowedRecipients({} as Env, ["me@example.com"])).toThrow(); expect(() => allowedRecipients(env, ["x@evil.com"])).toThrow(); allowedRecipients(env, ["x@example.com"]);
  });
  for (const bad of ["bad\r\nLOGOUT", "bad\0name"]) test("reject controls " + JSON.stringify(bad), () => expect(() => quote(bad)).toThrow());
  for (const name of ["INBOX", "A&B", "日本語/收件箱", "Folder 😀"]) test("UTF7 roundtrip " + name, () => expect(decodeMailbox(mailboxName(name))).toBe(name));
  test("strict base64 and quoted printable", () => {
    expect(new TextDecoder().decode(decodeTransfer(utf8.encode("YWJjZA=="), "BASE64"))).toBe("abcd");
    expect(new TextDecoder().decode(decodeTransfer(utf8.encode("a=20b=\r\nc"), "QUOTED-PRINTABLE"))).toBe("a bc"); expect(() => unbase64("not?base64")).toThrow();
  });
  test("Unicode MIME and Bcc isolation", async () => {
    const m = compose(env, a, { to: ["to@example.com"], bcc: ["hidden@example.com"], subject: "Unicode سلام", text: "Hello 😄", attachments: [{ filename: "file.txt", mime_type: "text/plain", content_base64: base64(utf8.encode("secret bytes")) }] });
    expect(m.raw).not.toContain("hidden@example.com"); expect(m.sentRaw).toContain("Bcc: hidden@example.com"); expect(m.recipients).toContain("hidden@example.com");
    const p = await PostalMime.parse(m.raw); expect(p.text?.trim()).toBe("Hello 😄"); expect(p.subject).toBe("Unicode سلام"); expect(p.attachments).toHaveLength(1);
  });
  test("header and filename injection", () => {
    for (const input of [{ subject: "x\r\nBcc: evil@evil.com" }, { attachments: [{ filename: 'evil";file', mime_type: "text/plain", content_base64: "eA==" }] }]) expect(() => compose(env, a, { to: ["x@example.com"], subject: "ok", text: "hi", ...input })).toThrow();
  });
  test("outgoing size limit", () => expect(() => compose(env, a, { to: ["x@example.com"], subject: "s", text: "x".repeat(65537) })).toThrow());
  test("bounded MIME structure parser", () => {
    const p = bodyParts(parseList('(("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "7BIT" 10 1 NIL NIL)("APPLICATION" "PDF" ("NAME" "invoice.pdf") NIL NIL "BASE64" 80 NIL ("ATTACHMENT" ("FILENAME" "invoice.pdf"))) "MIXED")'));
    expect(p.map(x => x.part_id)).toEqual(["1", "2"]); expect(p[1].filename).toBe("invoice.pdf"); expect(() => parseList("(".repeat(40) + "NIL" + ")".repeat(40))).toThrow(); expect(() => parseList("(unterminated")).toThrow();
  });
});
describe("IMAP", () => {
  test("EXAMINE and stale UIDVALIDITY", async () => {
    const s = imapSocket(), c = await Imap.open(a, () => s); await c.select("INBOX", false, 42); expect(s.writes.some(s => s.includes("EXAMINE"))).toBeTrue(); await expect(c.select("INBOX", true, 41)).rejects.toMatchObject({ code: "stale_uid" }); await c.close(); expect(s.didClose).toBeTrue();
  });
  test("empty windows retain continuation", async () => { const c = await Imap.open(a, () => imapSocket("")); await c.select("INBOX"); const p = await c.search({}); expect(p.uids).toEqual([]); expect(p.next_before_uid).toBe(500); expect(p.has_more).toBeTrue(); await c.close(); });
  test("bounded UID pagination", async () => { const c = await Imap.open(a, () => imapSocket()); await c.select("INBOX"); const p = await c.search({ limit: 2 }); expect(p.uids).toEqual([998, 995]); expect(p.next_before_uid).toBe(994); await c.close(); });
  test("split literal bytes and BODY.PEEK", async () => { const s = imapSocket(), c = await Imap.open(a, () => s); expect(new TextDecoder().decode(await c.part(7, "1", 0, 8))).toBe("YWJjZA=="); expect(s.writes.at(-1)).toContain("BODY.PEEK[1]<0.8>"); await c.close(); });
  test("server cannot ignore partial bound", async () => { const c = await Imap.open(a, () => imapSocket()); await expect(c.part(7, "1", 0, 4)).rejects.toMatchObject({ code: "invalid_part" }); await c.close(); });
  test("no EXPUNGE fallback", async () => { const s = imapSocket(), c = await Imap.open(a, () => s); c.capabilities.delete("MOVE"); await expect(c.move(7, "Trash")).rejects.toMatchObject({ code: "move_unsupported" }); expect(s.writes.join("")).not.toContain("EXPUNGE"); await c.close(); });
  test("literal cap", async () => { const w = new Wire(new FakeSocket(() => {})); await expect(w.bytes(LIMITS.protocol + 1)).rejects.toThrow(); await w.close(); });
});
function smtpSocket(opts: { starttls?: boolean; rejectRecipient?: boolean; dropAfterData?: boolean } = {}) {
  return new FakeSocket((t, s) => {
    if (t.startsWith("EHLO")) s.push(`250-mail\r\n${!s.secure && opts.starttls !== false ? "250-STARTTLS\r\n" : ""}250 AUTH PLAIN\r\n`);
    else if (t === "STARTTLS\r\n") s.push("220 go TLS\r\n");
    else if (t.startsWith("AUTH")) { if (!s.secure) throw new Error("Credentials before TLS"); s.push("235 authenticated\r\n"); }
    else if (t.startsWith("MAIL")) s.push("250 sender\r\n");
    else if (t.startsWith("RCPT")) s.push(opts.rejectRecipient ? "550 denied\r\n" : "250 recipient\r\n");
    else if (t === "DATA\r\n") s.push("354 send data\r\n");
    else if (t.endsWith("\r\n.\r\n")) { if (opts.dropAfterData) void s.close(); else s.push("250 accepted\r\n"); }
  }, "220 SMTP ready\r\n");
}
describe("SMTP", () => {
  const mail = compose(env, a, { to: ["to@example.com"], subject: "Test", text: "Hello" });
  test("TLS before credentials; explicit acceptance", async () => { const s = smtpSocket(), r = await Smtp.send(a, mail, () => s); expect(r.delivery).toBe("accepted"); expect(s.writes.findIndex(x => x.startsWith("AUTH"))).toBeGreaterThan(s.writes.indexOf("STARTTLS\r\n")); expect(s.didClose).toBeTrue(); });
  test("mandatory STARTTLS", async () => { const s = smtpSocket({ starttls: false }); await expect(Smtp.send(a, mail, () => s)).rejects.toMatchObject({ code: "starttls_required" }); expect(s.writes.join("")).not.toContain("AUTH PLAIN "); });
  test("recipient rejection stops before DATA", async () => { const s = smtpSocket({ rejectRecipient: true }); await expect(Smtp.send(a, mail, () => s)).rejects.toMatchObject({ code: "smtp_rejected" }); expect(s.writes).not.toContain("DATA\r\n"); });
  test("disconnect after DATA means unknown outcome", async () => { await expect(Smtp.send(a, mail, () => smtpSocket({ dropAfterData: true }))).rejects.toMatchObject({ code: "delivery_unknown" }); });
});
describe("MCP", () => {
  const req = (method: string, params?: unknown) => new Request("https://mail.example.com/mcp", { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2025-11-25" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, ...(params ? { params } : {}) }) });
  const noConnect: Connector = () => { throw new Error("Unexpected network"); };
  test("tool schema and write annotations", async () => { const r = await handleMcp(req("tools/list"), env, noConnect); expect(r.status).toBe(200); const j = await r.json() as any; expect(j.result.tools).toHaveLength(15); const send = j.result.tools.find((x: any) => x.name === "send_email"); expect(send.annotations.readOnlyHint).toBeFalse(); expect(send.inputSchema.required).toContain("confirm"); });
  test("account list hides credentials", async () => { const r = await handleMcp(req("tools/call", { name: "list_accounts", arguments: {} }), env, noConnect); const body = await r.text(); expect(body).toContain("me@example.com"); expect(body).not.toContain("test-password"); });
  test("disabled writes before network", async () => { const r = await handleMcp(req("tools/call", { name: "send_email", arguments: { to: ["to@example.com"], subject: "s", text: "x", confirm: true } }), { ...env, MAIL_WRITES_ENABLED: "false" }, noConnect); expect(await r.text()).toContain("writes_disabled"); });
});
