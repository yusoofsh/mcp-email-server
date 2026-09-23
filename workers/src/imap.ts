import { Account, LIMITS, MailError, safeText } from "./config";
import { base64, unbase64 } from "./bytes";
import { Connector, Wire } from "./wire";

export function quote(s: string): string {
  return '"' + safeText(s, 1024).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
}

/** RFC 3501 modified UTF-7, not ordinary UTF-7 or UTF-8. */
export function mailboxName(s: string): string {
  safeText(s, 256);
  let out = "", run = "";
  const flush = () => {
    if (!run) return;
    const b = new Uint8Array(run.length * 2);
    for (let i = 0; i < run.length; i++) {
      b[i * 2] = run.charCodeAt(i) >> 8;
      b[i * 2 + 1] = run.charCodeAt(i) & 255;
    }
    out += "&" + base64(b).replace(/\//g, ",").replace(/=+$/, "") + "-";
    run = "";
  };
  for (const c of s) {
    if (c >= " " && c <= "~") { flush(); out += c === "&" ? "&-" : c; }
    else run += c;
  }
  flush();
  return out;
}

export function decodeMailbox(s: string): string {
  return s.replace(/&([A-Za-z0-9+,]*)-/g, (_, v: string) => {
    if (!v) return "&";
    v = v.replace(/,/g, "/");
    v += "=".repeat((4 - v.length % 4) % 4);
    const b = unbase64(v);
    if (b.length % 2) throw new MailError("invalid_mailbox", "Invalid modified UTF-7");
    let result = "";
    for (let i = 0; i < b.length; i += 2) result += String.fromCharCode((b[i] << 8) | b[i + 1]);
    return result;
  });
}

export interface RecordLine { line: string; literals: Uint8Array[]; }
export type ImapValue = string | number | null | ImapValue[];

export function parseList(text: string): ImapValue[] {
  let i = 0, n = 0;
  function value(depth = 0): ImapValue {
    if (++n > 2048 || depth > 30) throw new MailError("structure_too_deep", "MIME structure is too complex");
    while (text[i] === " ") i++;
    if (text[i] === "(") {
      i++;
      const a: ImapValue[] = [];
      while (true) {
        while (text[i] === " ") i++;
        if (text[i] === ")") { i++; return a; }
        if (i >= text.length) throw new MailError("invalid_structure", "Unclosed IMAP structure");
        a.push(value(depth + 1));
      }
    }
    if (text[i] === '"') {
      i++;
      let s = "";
      while (i < text.length) {
        const c = text[i++];
        if (c === '"') return s;
        if (c === "\\") { if (i >= text.length) break; s += text[i++]; }
        else s += c;
      }
      throw new MailError("invalid_structure", "Unclosed quoted value");
    }
    const begin = i;
    while (i < text.length && !/[ ()]/.test(text[i])) i++;
    if (begin === i) throw new MailError("invalid_structure", "Unexpected IMAP value");
    const s = text.slice(begin, i);
    return s === "NIL" ? null : /^\d+$/.test(s) ? Number(s) : s;
  }
  const result = value();
  if (!Array.isArray(result)) throw new MailError("invalid_structure", "Expected IMAP list");
  return result;
}

export interface Part {
  part_id: string; mime_type: string; encoding: string; encoded_size: number;
  filename: string | null; disposition: string | null;
}
function parameters(v: ImapValue): Record<string, string> {
  const out: Record<string, string> = {};
  if (Array.isArray(v)) for (let i = 0; i + 1 < v.length; i += 2) {
    if (typeof v[i] === "string" && typeof v[i + 1] === "string") out[(v[i] as string).toUpperCase()] = v[i + 1] as string;
  }
  return out;
}
export function bodyParts(node: ImapValue[], prefix = ""): Part[] {
  if (Array.isArray(node[0])) {
    const out: Part[] = [];
    let i = 0;
    while (Array.isArray(node[i])) {
      out.push(...bodyParts(node[i] as ImapValue[], prefix ? `${prefix}.${i + 1}` : String(i + 1)));
      i++;
    }
    return out;
  }
  const type = String(node[0] || "").toLowerCase(), subtype = String(node[1] || "").toLowerCase();
  if (!/^[a-z0-9!#$&^_.+-]+$/.test(type) || !/^[a-z0-9!#$&^_.+-]+$/.test(subtype) || !Number.isSafeInteger(node[6]) || Number(node[6]) < 0) {
    throw new MailError("invalid_structure", "Invalid MIME metadata");
  }
  const disposition = node[type === "text" ? 9 : type === "message" && subtype === "rfc822" ? 11 : 8];
  const dp = Array.isArray(disposition) ? parameters(disposition[1]) : {};
  const p = parameters(node[2]);
  return [{ part_id: prefix || "1", mime_type: `${type}/${subtype}`, encoding: String(node[5] || "7BIT"), encoded_size: Number(node[6]), filename: dp.FILENAME || p.NAME || null, disposition: Array.isArray(disposition) ? String(disposition[0]).toLowerCase() : null }];
}

export class Imap {
  private seq = 0;
  validity = 0; next = 0; count = 0; capabilities = new Set<string>();
  constructor(public wire: Wire) {}

  static async open(a: Account, connect: Connector): Promise<Imap> {
    const c = new Imap(new Wire(connect(a.imap.host, a.imap.port, "on")));
    try {
      await c.wire.opened();
      if (!/^\* OK\b/i.test(await c.wire.line())) throw new MailError("imap_greeting", "Unexpected IMAP greeting");
      await c.command(`LOGIN ${quote(a.imap.username)} ${quote(a.imap.password)}`);
      const caps = await c.command("CAPABILITY");
      for (const r of caps) if (/^\* CAPABILITY /i.test(r.line)) for (const v of r.line.split(" ").slice(2)) c.capabilities.add(v.toUpperCase());
      return c;
    } catch (e) { await c.close(); throw e; }
  }
  private async record(): Promise<RecordLine> {
    let line = await this.wire.line();
    const literals: Uint8Array[] = [];
    for (let i = 0; i < 32; i++) {
      const m = /\{(\d+)\}$/.exec(line);
      if (!m) return { line, literals };
      literals.push(await this.wire.bytes(Number(m[1])));
      line = line.slice(0, m.index) + `"LITERAL_${literals.length - 1}"` + await this.wire.line();
    }
    throw new MailError("response_too_complex", "Too many IMAP literals");
  }
  async command(command: string): Promise<RecordLine[]> {
    this.wire.resetBudget();
    const tag = "M" + (++this.seq);
    await this.wire.write(`${tag} ${command}\r\n`);
    const rows: RecordLine[] = [];
    for (let i = 0; i < 1024; i++) {
      const row = await this.record();
      if (row.line.startsWith(tag + " ")) {
        if (!new RegExp("^" + tag + " OK\\b", "i").test(row.line)) throw new MailError("imap_rejected", "IMAP command rejected; check mailbox, credentials or capabilities");
        return rows;
      }
      if (/^\* BYE\b/i.test(row.line)) throw new MailError("connection_closed", "IMAP session ended");
      rows.push(row);
    }
    throw new MailError("response_too_complex", "Too many IMAP response records");
  }
  async select(folder: string, writable = false, expected?: number) {
    const rows = await this.command(`${writable ? "SELECT" : "EXAMINE"} ${quote(mailboxName(folder))}`);
    this.validity = 0; this.next = 0; this.count = 0;
    for (const { line } of rows) {
      const v = /\[UIDVALIDITY (\d+)\]/i.exec(line), n = /\[UIDNEXT (\d+)\]/i.exec(line), e = /^\* (\d+) EXISTS/i.exec(line);
      if (v) this.validity = Number(v[1]);
      if (n) this.next = Number(n[1]);
      if (e) this.count = Number(e[1]);
    }
    if (!this.validity || !this.next) throw new MailError("missing_uid_state", "Provider did not supply UIDVALIDITY/UIDNEXT");
    if (expected !== undefined && expected !== this.validity) throw new MailError("stale_uid", "UIDVALIDITY changed; list messages again before acting");
  }
  async folders() {
    return (await this.command('LIST "" "*"')).filter(r => r.line.startsWith("* LIST ")).map(r => {
      const p = parseList("(" + r.line.slice(7) + ")");
      let name = String(p[2] || "");
      const m = /^LITERAL_(\d+)$/.exec(name);
      if (m) name = new TextDecoder().decode(r.literals[Number(m[1])]);
      return { name: decodeMailbox(name), flags: p[0], delimiter: p[1] };
    });
  }
  async search(opts: { before_uid?: number; limit?: number; from?: string; subject?: string; text?: string; since?: string; before?: string; unread?: boolean }) {
    const upper = Math.min(opts.before_uid ?? 4294967295, this.next - 1), lower = Math.max(1, upper - LIMITS.searchWindow + 1), limit = Math.min(opts.limit || LIMITS.page, LIMITS.page);
    if (upper < 1) return { uids: [], next_before_uid: null, has_more: false, scanned_uid_range: null };
    const criteria = [`UID ${lower}:${upper}`];
    for (const [field, key] of [["from", "FROM"], ["subject", "SUBJECT"], ["text", "TEXT"]] as const) if (opts[field]) criteria.push(`${key} ${quote(opts[field]!)}`);
    for (const [field, key] of [["since", "SINCE"], ["before", "BEFORE"]] as const) if (opts[field]) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(opts[field]!)) throw new MailError("invalid_date", "Use YYYY-MM-DD");
      const d = new Date(opts[field]! + "T00:00:00Z");
      if (!Number.isFinite(+d) || d.toISOString().slice(0, 10) !== opts[field]) throw new MailError("invalid_date", "Invalid date");
      criteria.push(`${key} ${d.getUTCDate()}-${["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][d.getUTCMonth()]}-${d.getUTCFullYear()}`);
    }
    if (opts.unread !== undefined) criteria.push(opts.unread ? "UNSEEN" : "SEEN");
    const nonAscii = criteria.some(x => /[^\x00-\x7f]/.test(x));
    const rows = await this.command(`UID SEARCH ${nonAscii ? "CHARSET UTF-8 " : ""}${criteria.join(" ")}`);
    const uids = rows.filter(r => /^\* SEARCH(?: |$)/i.test(r.line)).flatMap(r => r.line.slice(8).trim().split(/\s+/).filter(Boolean).map(Number));
    if (uids.some(u => !Number.isInteger(u) || u < lower || u > upper)) throw new MailError("invalid_search", "Provider returned out-of-range UIDs");
    const sorted = [...new Set(uids)].sort((a, b) => b - a), page = sorted.slice(0, limit), next = sorted.length > limit ? page[page.length - 1] - 1 : lower - 1;
    return { uids: page, next_before_uid: next > 0 ? next : null, has_more: next > 0, scanned_uid_range: [lower, upper] };
  }
  async metadata(uids: number[]) {
    if (!uids.length) return [];
    const rows = await this.command(`UID FETCH ${uids.join(",")} (UID FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS (DATE FROM TO CC SUBJECT MESSAGE-ID IN-REPLY-TO REFERENCES)])`);
    return rows.filter(r => / FETCH \(/i.test(r.line)).map(r => ({ uid: Number(/\bUID (\d+)/i.exec(r.line)?.[1]), size: Number(/RFC822\.SIZE (\d+)/i.exec(r.line)?.[1]), flags: /\bFLAGS \(([^)]*)\)/i.exec(r.line)?.[1].split(" ").filter(Boolean) || [], headers: r.literals[0] || new Uint8Array(0) })).filter(x => uids.includes(x.uid));
  }
  async raw(uid: number, max = LIMITS.message): Promise<Uint8Array> {
    const meta = await this.metadata([uid]);
    if (!meta.length) throw new MailError("not_found", "Message not found");
    if (!Number.isFinite(meta[0].size) || meta[0].size > max) throw new MailError("message_too_large", "Use get_message_structure and get_message_part");
    const rows = await this.command(`UID FETCH ${uid} (UID BODY.PEEK[]<0.${max + 1}>)`);
    const raw = rows.find(r => new RegExp("\\bUID " + uid + "\\b").test(r.line))?.literals[0];
    if (!raw) throw new MailError("not_found", "Message content not found");
    if (raw.length > max) throw new MailError("message_too_large", "Message exceeds parsing limit");
    return raw;
  }
  async structure(uid: number): Promise<Part[]> {
    const rows = await this.command(`UID FETCH ${uid} (UID BODYSTRUCTURE)`), row = rows.find(r => new RegExp("\\bUID " + uid + "\\b").test(r.line)), at = row?.line.indexOf("BODYSTRUCTURE ");
    if (!row || at === undefined || at < 0) throw new MailError("not_found", "Message structure not found");
    return bodyParts(parseList(row.line.slice(at + 14)));
  }
  async part(uid: number, section: string, offset: number, length: number): Promise<Uint8Array> {
    if (!/^[1-9]\d*(?:\.[1-9]\d*)*$/.test(section) || !Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) || length < 1 || length > LIMITS.attachment + 1) throw new MailError("invalid_part", "Invalid MIME part or range");
    const rows = await this.command(`UID FETCH ${uid} (UID BODY.PEEK[${section}]<${offset}.${length}>)`), row = rows.find(r => new RegExp("\\bUID " + uid + "\\b").test(r.line));
    if (!row) throw new MailError("not_found", "MIME part not found");
    const b = row.literals[0] || new Uint8Array(0);
    if (b.length > length) throw new MailError("invalid_part", "Provider ignored the partial-fetch bound");
    return b;
  }
  async flags(uid: number, flag: "\\Seen" | "\\Flagged", enabled: boolean) { await this.command(`UID STORE ${uid} ${enabled ? "+" : "-"}FLAGS.SILENT (${flag})`); }
  async move(uid: number, folder: string) {
    if (!this.capabilities.has("MOVE")) throw new MailError("move_unsupported", "UID MOVE unavailable; refusing unsafe mailbox-wide EXPUNGE");
    await this.command(`UID MOVE ${uid} ${quote(mailboxName(folder))}`);
  }
  async append(folder: string, raw: Uint8Array, flag = "\\Draft") {
    this.wire.resetBudget();
    const tag = "M" + (++this.seq);
    await this.wire.write(`${tag} APPEND ${quote(mailboxName(folder))} (${flag}) {${raw.length}}\r\n`);
    if (!(await this.wire.line()).startsWith("+")) throw new MailError("append_rejected", "Provider rejected APPEND before data");
    try {
      await this.wire.write(raw); await this.wire.write("\r\n");
      for (let i = 0; i < 100; i++) {
        const r = await this.record();
        if (r.line.startsWith(tag + " ")) {
          if (!r.line.startsWith(tag + " OK")) throw new MailError("append_rejected", "Provider rejected appended message");
          return;
        }
      }
      throw new Error("No completion");
    } catch (e) {
      if (e instanceof MailError && e.code === "append_rejected") throw e;
      throw new MailError("append_unknown", "Append outcome unknown; inspect mailbox before retrying");
    }
  }
  async close() { await this.wire.close(); }
}
