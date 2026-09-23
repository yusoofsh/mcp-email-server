import {LIMITS,MailError} from './config';
import {concat,utf8} from './bytes';
export interface SocketLike {readable:ReadableStream<Uint8Array>;writable:WritableStream<Uint8Array>;opened:Promise<unknown>;closed:Promise<void>;close():Promise<void>;startTls():SocketLike;}
export type Connector=(host:string,port:number,security:'on'|'starttls')=>SocketLike;
export class Wire {
  reader:ReadableStreamDefaultReader<Uint8Array>;writer:WritableStreamDefaultWriter<Uint8Array>;private buffer:Uint8Array=new Uint8Array(0);private total=0;
  constructor(public socket:SocketLike){this.reader=socket.readable.getReader();this.writer=socket.writable.getWriter();void socket.closed.catch(()=>{});}
  async timed<T>(p:Promise<T>):Promise<T>{let t:ReturnType<typeof setTimeout>;try{return await Promise.race([p,new Promise<never>((_,reject)=>{t=setTimeout(()=>{void this.close();reject(new MailError('network_timeout','Mail operation timed out; do not automatically retry writes'));},15000);})]);}finally{clearTimeout(t!);}}
  async opened(){await this.timed(this.socket.opened);}
  async write(data:string|Uint8Array){await this.timed(this.writer.write(typeof data==='string'?utf8.encode(data):data));}
  resetBudget(){this.total=this.buffer.length;}
  async fill(){const {value,done}=await this.timed(this.reader.read());if(done)throw new MailError('connection_closed','Mail server closed connection');this.total+=value.length;if(this.total>LIMITS.protocol)throw new MailError('response_too_large','Narrow the mail request');this.buffer=concat([this.buffer,value]);}
  async line():Promise<string>{for(;;){for(let i=0;i<this.buffer.length-1;i++)if(this.buffer[i]===13&&this.buffer[i+1]===10){if(i>LIMITS.line)throw new MailError('line_too_long','Protocol line exceeds limit');const out=new TextDecoder().decode(this.buffer.subarray(0,i));this.buffer=this.buffer.slice(i+2);return out;}if(this.buffer.length>LIMITS.line)throw new MailError('line_too_long','Protocol line exceeds limit');await this.fill();}}
  async bytes(n:number):Promise<Uint8Array>{if(!Number.isSafeInteger(n)||n<0||n>LIMITS.protocol)throw new MailError('literal_too_large','Fetch a smaller MIME part');while(this.buffer.length<n)await this.fill();const out=this.buffer.slice(0,n);this.buffer=this.buffer.slice(n);return out;}
  async tls(){if(this.buffer.length)throw new MailError('tls_boundary','Unexpected bytes at STARTTLS boundary');this.reader.releaseLock();this.writer.releaseLock();this.socket=this.socket.startTls();this.reader=this.socket.readable.getReader();this.writer=this.socket.writable.getWriter();void this.socket.closed.catch(()=>{});await this.opened();}
  async close(){try{await this.socket.close();}catch{/* Do not mask delivery results. */}}
}
