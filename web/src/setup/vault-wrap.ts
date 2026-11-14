export interface Wrapper {
 version: number
 kind: 'passkey' | 'recovery'
 vault_id: string
 credential_id: string
 kdf_salt: string
 iv: string
 ciphertext: string
 prf_input?: string
}
const text = new TextEncoder()
export const randomBytes = (n: number): Uint8Array<ArrayBuffer> => crypto.getRandomValues(new Uint8Array(n))
export function encode(b: BufferSource): string {
 const a=ArrayBuffer.isView(b)?new Uint8Array(b.buffer,b.byteOffset,b.byteLength):new Uint8Array(b)
 return btoa(String.fromCharCode(...a)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')
}
export function decode(s: string,n: number): Uint8Array<ArrayBuffer> {
 if(typeof s!=='string'|| !/^[A-Za-z0-9_-]*$/.test(s))throw Error('Invalid encoding')
 const b=Uint8Array.from(atob(s.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0))
 if(encode(b)!==s || (n>=0 && b.length!==n))throw Error('Invalid length/encoding')
 return b
}
export function aad(w: Wrapper): Uint8Array<ArrayBuffer> {
 const allowed=['version','kind','vault_id','credential_id','kdf_salt','iv','ciphertext','prf_input']
 if(Object.keys(w).some(key=>!allowed.includes(key)))throw Error('Unknown envelope field')
 if(w.version!==1 || !['passkey','recovery'].includes(w.kind))throw Error('Unsupported envelope')
 decode(w.vault_id,16)
 if(w.kind==='recovery'){if(w.credential_id!=='' || w.prf_input)throw Error('Wrong purpose')}
 else {const id=decode(w.credential_id,-1);if(!id.length||id.length>1024)throw Error('Invalid credential');decode(w.prf_input??'',32)}
 return text.encode(JSON.stringify(['warden',1,w.kind,w.vault_id,w.credential_id]))
}
async function baseKey(material: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
 if(material.length!==32)throw Error('Invalid key length')
 return crypto.subtle.importKey('raw',material,'HKDF',false,['deriveKey','deriveBits'])
}
async function kek(material: Uint8Array<ArrayBuffer>,salt: string,kind: string): Promise<CryptoKey> {
 return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:decode(salt,32),info:text.encode(`warden/v1/${kind}-wrap`)},await baseKey(material),{name:'AES-GCM',length:256},false,['encrypt','decrypt'])
}
export async function recoveryAuth(key: Uint8Array<ArrayBuffer>,salt: string): Promise<Uint8Array<ArrayBuffer>> {
 return new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:decode(salt,32),info:text.encode('warden/v1/recovery-auth')},await baseKey(key),256))
}
export async function wrap(material: Uint8Array<ArrayBuffer>,dek: Uint8Array<ArrayBuffer>,kind: Wrapper['kind'],vault: string,id: string,prfInput='',rng=randomBytes): Promise<Wrapper> {
 if(dek.length!==32 || material.length!==32)throw Error('Invalid key length')
 const w: Wrapper={version:1,kind,vault_id:vault,credential_id:id,kdf_salt:encode(rng(32)),iv:encode(rng(12)),ciphertext:''}
 if(kind==='passkey')w.prf_input=prfInput
 const data=aad(w);decode(w.kdf_salt,32);const iv=decode(w.iv,12)
 w.ciphertext=encode(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:data,tagLength:128},await kek(material,w.kdf_salt,kind),dek))
 return w
}
export async function unwrap(w: Wrapper,material: Uint8Array<ArrayBuffer>,kind: Wrapper['kind'],vault: string,id: string): Promise<Uint8Array<ArrayBuffer>> {
 if(w.kind!==kind||w.vault_id!==vault||w.credential_id!==id)throw Error('Wrong binding')
 const plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:decode(w.iv,12),additionalData:aad(w),tagLength:128},await kek(material,w.kdf_salt,kind),decode(w.ciphertext,48)))
 if(plain.length!==32){plain.fill(0);throw Error('Invalid DEK')}
 return plain
}
export function parseRecoveryKey(s: string): Uint8Array<ArrayBuffer> {
 const prefix='warden-recovery-v1:'
 if(!s.startsWith(prefix))throw Error('Enter the complete saved recovery key')
 return decode(s.slice(prefix.length),32)
}
