import { webcrypto } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { aad, decode, encode, wrap, unwrap, recoveryAuth, parseRecoveryKey } from './vault-wrap'
import type { Wrapper } from './vault-wrap'

beforeEach(() => vi.stubGlobal('crypto', webcrypto))
afterEach(() => vi.unstubAllGlobals())
const vector = JSON.parse(readFileSync('../internal/crypto/testdata/wrap-v1.json','utf8'))
test('shared Go/WebCrypto v1 bytes and non-extractable HKDF AES-GCM wrapping', async () => {
 const w = vector.wrapper as Wrapper
 expect(new TextDecoder().decode(aad(w))).toBe(vector.aad)
 expect(encode(await unwrap(w, decode(vector.material,32), 'passkey',w.vault_id,w.credential_id))).toBe(vector.dek)
 const made=await wrap(decode(vector.material,32),decode(vector.dek,32),'passkey',w.vault_id,w.credential_id,w.prf_input,n=>new Uint8Array(n).fill(4))
 expect(made).toEqual(w)
})
test('shared recovery envelope and independent authentication subkey/verifier bytes',async()=>{
 const v=JSON.parse(readFileSync('../internal/crypto/testdata/wrap-recovery-v1.json','utf8'))
 const w=v.wrapper as Wrapper,material=decode(v.material,32),dek=decode(v.dek,32)
 expect(new TextDecoder().decode(aad(w))).toBe(v.aad)
 expect(await wrap(material,dek,'recovery',w.vault_id,'','',n=>new Uint8Array(n).fill(4))).toEqual(w)
 expect(await unwrap(w,material,'recovery',w.vault_id,'')).toEqual(dek)
 const proof=await recoveryAuth(material,w.kdf_salt)
 expect(encode(proof)).toBe(v.recovery_auth)
 expect(encode(await crypto.subtle.digest('SHA-256',proof))).toBe(v.recovery_verifier)
 expect(v.recovery_auth).not.toBe(v.kek)
})

test('wrong material, salt, vault, credential, purpose, length, version and ciphertext never unwrap',async()=>{
 const w=vector.wrapper as Wrapper
 for (const patch of [{unexpected:true},{version:2},{kind:'other'},{vault_id:encode(new Uint8Array(16).fill(1))},{credential_id:encode(new Uint8Array([1]))},{kdf_salt:encode(new Uint8Array(32))},{ciphertext:w.ciphertext.slice(1)},{iv:'AA'},{prf_input:'bad'},{iv:w.iv+'='}]) {
  await expect(unwrap({...w,...patch} as Wrapper,decode(vector.material,32),'passkey',w.vault_id,w.credential_id)).rejects.toThrow()
 }
 const flipped=decode(w.ciphertext,48);flipped[47]^=1
 await expect(unwrap({...w,ciphertext:encode(flipped)},decode(vector.material,32),'passkey',w.vault_id,w.credential_id)).rejects.toThrow()
 await expect(unwrap(w,new Uint8Array(32),'passkey',w.vault_id,w.credential_id)).rejects.toThrow()
 await expect(wrap(new Uint8Array(31),new Uint8Array(32),'recovery',w.vault_id,'')).rejects.toThrow()
})
test('fresh IVs, RNG failure, recovery re-entry authenticates and unwraps',async()=>{
 const key=new Uint8Array(32).fill(7),dek=new Uint8Array(32).fill(8),vault=vector.wrapper.vault_id
 const a=await wrap(key,dek,'recovery',vault,''),b=await wrap(key,dek,'recovery',vault,'')
 expect(a.iv).not.toBe(b.iv)
 expect(await unwrap(a,key,'recovery',vault,'')).toEqual(dek)
 expect((await recoveryAuth(key,a.kdf_salt)).length).toBe(32)
 expect(parseRecoveryKey('warden-recovery-v1:'+encode(key))).toEqual(key)
 expect(()=>parseRecoveryKey('saved')).toThrow()
 await expect(wrap(key,dek,'recovery',vault,'','',()=>{throw Error('rng')})).rejects.toThrow('rng')
})
