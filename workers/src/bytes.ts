import {MailError} from './config';
export const utf8=new TextEncoder();
export function base64(b:Uint8Array):string{let s='';for(let i=0;i<b.length;i+=8192)s+=String.fromCharCode(...b.subarray(i,i+8192));return btoa(s);}
export function unbase64(s:string):Uint8Array{s=s.replace(/[\r\n\t ]/g,'');if(s.length%4||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))throw new MailError('invalid_base64','Invalid base64');return Uint8Array.from(atob(s),c=>c.charCodeAt(0));}
export function concat(parts:Uint8Array[]):Uint8Array{const out=new Uint8Array(parts.reduce((n,b)=>n+b.length,0));let i=0;for(const p of parts){out.set(p,i);i+=p.length;}return out;}
export async function sha256(s:string):Promise<string>{const d=new Uint8Array(await crypto.subtle.digest('SHA-256',utf8.encode(s)));return [...d].map(x=>x.toString(16).padStart(2,'0')).join('');}
export function equal(a:string,b:string):boolean{let d=a.length^b.length;for(let i=0;i<Math.max(a.length,b.length);i++)d|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0);return d===0;}
export function random():string{return base64(crypto.getRandomValues(new Uint8Array(32))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
export function decodeTransfer(b:Uint8Array,encoding:string):Uint8Array{
  if(encoding.toUpperCase()==='BASE64')return unbase64(new TextDecoder().decode(b));
  if(encoding.toUpperCase()==='QUOTED-PRINTABLE'){const out:number[]=[];for(let i=0;i<b.length;i++){if(b[i]===61){if(b[i+1]===13&&b[i+2]===10){i+=2;continue;}const h=String.fromCharCode(b[i+1]||0,b[i+2]||0);if(/^[a-f0-9]{2}$/i.test(h)){out.push(parseInt(h,16));i+=2;continue;}}out.push(b[i]);}return Uint8Array.from(out);}return b;
}
