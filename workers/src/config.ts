import type { OAuthHelpers } from '@cloudflare/workers-oauth-provider';
export interface Env {
  OAUTH_KV: KVNamespace; AUTH_DB: D1Database; OAUTH_PROVIDER: OAuthHelpers;
  PUBLIC_URL: string; AUTH_USERNAME: string; AUTH_PASSWORD_HASH: string; AUTH_REDIRECT_URIS: string;
  MAIL_ACCOUNTS?: string; MAIL_ALLOWED_RECIPIENTS?: string; MAIL_WRITES_ENABLED?: string; ALLOW_ATTACHMENT_CONTENT?: string;
}
export interface Account {
  id: string; email: string; name?: string;
  imap: {host: string; port: number; username: string; password: string};
  smtp?: {host: string; port: number; username: string; password: string; security: 'tls' | 'starttls'};
  folders?: {sent?: string; drafts?: string; trash?: string; archive?: string}; save_sent?: boolean;
}
export class MailError extends Error {constructor(public code: string, message: string) {super(message);this.name='MailError';}}
export const LIMITS = {page:10,searchWindow:500,message:131072,part:32768,attachment:65536,outgoing:196608,protocol:393216,request:300000,line:16384};
export function safeText(value:unknown,max=256):string {
  if(typeof value!=='string'||value.length>max||/[\x00-\x1f\x7f]/.test(value))throw new MailError('invalid_input','Invalid text or control character');return value;
}
export function address(value:unknown):string {
  const s=safeText(value,254);
  if(!/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(s))throw new MailError('invalid_address','Use a bare ASCII email address');return s;
}
function host(value:unknown) {
  const s=safeText(value,253).toLowerCase();
  if(!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(s)||/\.(local|internal|localhost|invalid|test)$/.test(s))throw new MailError('invalid_config','Mail hosts must be public DNS names');
}
export function accounts(env:Pick<Env,'MAIL_ACCOUNTS'>):Account[] {
  let data:unknown;try{data=JSON.parse(env.MAIL_ACCOUNTS||'[]');}catch{throw new MailError('invalid_config','MAIL_ACCOUNTS must be JSON');}
  if(!Array.isArray(data)||data.length>5)throw new MailError('invalid_config','Configure at most five accounts');const ids=new Set<string>();
  return data.map((raw):Account=>{if(!raw||typeof raw!=='object')throw new MailError('invalid_config','Invalid account');const a=raw as Account;
    if(!/^[a-z0-9][a-z0-9_-]{0,31}$/.test(a.id)||ids.has(a.id))throw new MailError('invalid_config','Account IDs must be unique slugs');ids.add(a.id);address(a.email);if(a.name)safeText(a.name,128);
    if(!a.imap||a.imap.port!==993)throw new MailError('invalid_config','IMAP requires TLS port 993');host(a.imap.host);safeText(a.imap.username);safeText(a.imap.password,512);
    if(!a.imap.username||!a.imap.password)throw new MailError('invalid_config','Missing IMAP credentials');
    if(a.smtp){host(a.smtp.host);safeText(a.smtp.username);safeText(a.smtp.password,512);if(!a.smtp.username||!a.smtp.password||!((a.smtp.port===465&&a.smtp.security==='tls')||(a.smtp.port===587&&a.smtp.security==='starttls')))throw new MailError('invalid_config','SMTP requires TLS 465 or mandatory STARTTLS 587');}
    for(const f of Object.values(a.folders||{}))if(f)safeText(f);return a;});
}
export function getAccount(env:Env,id?:string):Account {const list=accounts(env);const a=id?list.find(a=>a.id===id):list.length===1?list[0]:undefined;if(!a)throw new MailError('account_required',list.length?'Select an account ID':'Configure MAIL_ACCOUNTS first');return a;}
export function confirmed(env:Env,value:unknown){if(env.MAIL_WRITES_ENABLED!=='true')throw new MailError('writes_disabled','Enable MAIL_WRITES_ENABLED explicitly');if(value!==true)throw new MailError('confirmation_required','Explicit confirm=true required');}
export function allowedRecipients(env:Env,recipients:string[]) {
  let allow:unknown;try{allow=JSON.parse(env.MAIL_ALLOWED_RECIPIENTS||'[]');}catch{throw new MailError('invalid_config','Invalid recipient allowlist');}
  if(!Array.isArray(allow)||allow.length>50)throw new MailError('invalid_config','Invalid recipient allowlist');
  for(const recipient of recipients){const lower=address(recipient).toLowerCase();if(!allow.some((p:unknown)=>typeof p==='string'&&(p==='*'||p.toLowerCase()===lower||(p.startsWith('*@')&&lower.split('@')[1]===p.slice(2).toLowerCase()))))throw new MailError('recipient_denied','A recipient is not allowed by server policy');}
}
export function origin(env:Env):string {const u=new URL(env.PUBLIC_URL);if(u.protocol!=='https:'||u.origin!==env.PUBLIC_URL||u.username||u.password)throw new MailError('invalid_config','PUBLIC_URL must be an exact HTTPS origin');return u.origin;}
export function redirects(env:Env):string[] {
  const list=(env.AUTH_REDIRECT_URIS||'').split(',').map(x=>x.trim()).filter(Boolean);if(!list.length||list.length>10)throw new MailError('invalid_config','Configure exact OAuth callback URLs');
  for(const s of list){const u=new URL(s);if(u.protocol!=='https:'||u.username||u.password||u.hash||u.search||s.includes('*')||u.pathname==='/')throw new MailError('invalid_config','OAuth callbacks require exact HTTPS paths');}return list;
}
