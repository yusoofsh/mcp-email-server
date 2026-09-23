import { createMimeMessage } from "mimetext/browser";
import { Account, Env, LIMITS, MailError, address, allowedRecipients, safeText } from "./config";
import { base64, unbase64, utf8 } from "./bytes";
import { Connector, Wire } from "./wire";

export interface ComposeInput {
  to: string[]; cc?: string[]; bcc?: string[]; subject: string; text: string; html?: string;
  attachments?: { filename: string; mime_type: string; content_base64: string }[];
  in_reply_to?: string; references?: string;
}
export function compose(env: Env, a: Account, input: ComposeInput) {
  const recipients = [...new Set([...input.to, ...(input.cc || []), ...(input.bcc || [])].map(address))];
  if (!recipients.length || recipients.length > 10) throw new MailError("recipient_limit", "Use one to ten recipients");
  allowedRecipients(env, recipients);
  safeText(input.subject, 200);
  if (utf8.encode(input.text).length > 65536 || (input.html && utf8.encode(input.html).length > 65536)) throw new MailError("body_too_large", "Message body exceeds 64 KiB");
  const m = createMimeMessage();
  m.setSender({ addr: a.email, name: a.name || "" });
  m.setTo(input.to.map(address));
  if (input.cc?.length) m.setCc(input.cc.map(address));
  // Bcc belongs only in the SMTP envelope, not delivered MIME headers.
  m.setSubject(input.subject);
  const messageId = `<${crypto.randomUUID()}@${a.email.split("@")[1]}>`;
  m.setHeader("Message-ID", messageId);
  for (const [k, v] of [["In-Reply-To", input.in_reply_to], ["References", input.references]]) if (v) {
    safeText(v, 2000);
    if (!/^(?:<[^<>\s]+>\s*)+$/.test(v)) throw new MailError("invalid_thread", "Invalid threading header");
    m.setHeader(k!, v);
  }
  const fold = (s: string) => s.match(/.{1,76}/g)?.join("\r\n") || "";
  m.addMessage({ contentType: "text/plain", encoding: "base64", data: fold(base64(utf8.encode(input.text))) });
  if (input.html) m.addMessage({ contentType: "text/html", encoding: "base64", data: fold(base64(utf8.encode(input.html))) });
  if ((input.attachments || []).length > 5) throw new MailError("attachment_limit", "Use at most five attachments");
  let bytes = 0;
  for (const at of input.attachments || []) {
    if (!/^[\x20-\x21\x23-\x3a\x3c-\x5b\x5d-\x7e]{1,128}$/.test(at.filename)) throw new MailError("invalid_filename", "Use a safe ASCII filename");
    if (!/^[a-zA-Z0-9!#$&^_.+-]+\/[a-zA-Z0-9!#$&^_.+-]+$/.test(at.mime_type)) throw new MailError("invalid_mime", "Invalid MIME type");
    const content = unbase64(at.content_base64);
    bytes += content.length;
    if (bytes > 131072) throw new MailError("attachment_limit", "Combined attachments exceed 128 KiB");
    m.addAttachment({ filename: at.filename, contentType: at.mime_type, encoding: "base64", data: fold(base64(content)) });
  }
  m.boundaries = { mixed: crypto.randomUUID(), alt: crypto.randomUUID(), related: crypto.randomUUID() };
  const raw = m.asRaw().replace(/\r?\n/g, "\r\n") + "\r\n";
  if (utf8.encode(raw).length > LIMITS.outgoing) throw new MailError("message_too_large", "Outgoing MIME exceeds 192 KiB");
  const sentRaw = input.bcc?.length ? "Bcc: " + input.bcc.map(address).join(", ") + "\r\n" + raw : raw;
  return { raw, sentRaw, recipients, messageId };
}

export class Smtp {
  constructor(private wire: Wire) {}
  async reply(): Promise<{ code: number; lines: string[] }> {
    const lines: string[] = [];
    let expected = 0;
    for (let i = 0; i < 100; i++) {
      const m = /^(\d{3})([ -])(.*)$/.exec(await this.wire.line());
      if (!m) throw new MailError("smtp_protocol", "Malformed SMTP response");
      const code = Number(m[1]);
      if (expected && code !== expected) throw new MailError("smtp_protocol", "Inconsistent SMTP response");
      expected = code; lines.push(m[3]);
      if (m[2] === " ") return { code, lines };
    }
    throw new MailError("smtp_protocol", "SMTP response too long");
  }
  async command(cmd: string, allowed: number[]) {
    this.wire.resetBudget();
    await this.wire.write(cmd + "\r\n");
    const r = await this.reply();
    if (!allowed.includes(r.code)) throw new MailError("smtp_rejected", "SMTP rejected command before delivery");
    return r;
  }
  static async send(a: Account, mail: ReturnType<typeof compose>, connect: Connector) {
    const c = a.smtp;
    if (!c) throw new MailError("smtp_unconfigured", "SMTP not configured");
    const s = new Smtp(new Wire(connect(c.host, c.port, c.security === "tls" ? "on" : "starttls")));
    let dataStarted = false;
    try {
      await s.wire.opened();
      if ((await s.reply()).code !== 220) throw new MailError("smtp_greeting", "Unexpected SMTP greeting");
      let ehlo = await s.command("EHLO email-mcp.invalid", [250]);
      if (c.security === "starttls") {
        if (!ehlo.lines.some(l => /^STARTTLS(?: |$)/i.test(l))) throw new MailError("starttls_required", "STARTTLS unavailable; credentials were not sent");
        await s.command("STARTTLS", [220]); await s.wire.tls();
        ehlo = await s.command("EHLO email-mcp.invalid", [250]);
      }
      const auth = ehlo.lines.find(l => /^AUTH(?: |=)/i.test(l)) || "";
      if (/\bPLAIN\b/i.test(auth)) await s.command("AUTH PLAIN " + base64(utf8.encode(`\0${c.username}\0${c.password}`)), [235]);
      else if (/\bLOGIN\b/i.test(auth)) {
        await s.command("AUTH LOGIN", [334]);
        await s.command(base64(utf8.encode(c.username)), [334]);
        await s.command(base64(utf8.encode(c.password)), [235]);
      } else throw new MailError("smtp_auth_unsupported", "Use app-password AUTH PLAIN or LOGIN over TLS");
      await s.command(`MAIL FROM:<${a.email}>`, [250]);
      for (const r of mail.recipients) await s.command(`RCPT TO:<${r}>`, [250, 251]);
      await s.command("DATA", [354]);
      dataStarted = true;
      await s.wire.write(mail.raw.replace(/(^|\r\n)\./g, "$1..") + ".\r\n");
      if ((await s.reply()).code !== 250) throw new MailError("delivery_rejected", "SMTP explicitly rejected message data");
      return { delivery: "accepted" as const, message_id: mail.messageId };
    } catch (e) {
      if (dataStarted && !(e instanceof MailError && e.code === "delivery_rejected")) throw new MailError("delivery_unknown", "SMTP outcome unknown. Check Sent/recipient before retrying; duplicates are possible.");
      throw e;
    } finally { await s.wire.close(); }
  }
}
