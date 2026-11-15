import { decode, encode, parseRecoveryKey, randomBytes, recoveryAuth, unwrap, wrap } from './vault-wrap'
import type { Wrapper } from './vault-wrap'

type WireCreation = Omit<PublicKeyCredentialCreationOptions,'challenge'|'user'> & {challenge:string,user:Omit<PublicKeyCredentialUserEntity,'id'>&{id:string}}
type WireAssertion = Omit<PublicKeyCredentialRequestOptions,'challenge'|'allowCredentials'> & {challenge:string,allowCredentials?:{id:string,type:'public-key'}[]}
interface Registered {assertion:{publicKey:WireAssertion},vault_id:string,credential_id:string,prf_input:string}
type Credentials = Pick<CredentialsContainer,'create'|'get'>

// Serialize only signed ceremony fields. Never call credential.toJSON(): it
// includes client extension outputs, which may contain plaintext PRF material.
export function signedCredential(c: PublicKeyCredential,registration: boolean) {
 const common={id:encode(c.rawId),rawId:encode(c.rawId),type:'public-key',clientExtensionResults:{}}
 if(registration){const r=c.response as AuthenticatorAttestationResponse;return {...common,response:{clientDataJSON:encode(r.clientDataJSON),attestationObject:encode(r.attestationObject)}}}
 const r=c.response as AuthenticatorAssertionResponse
 return {...common,response:{clientDataJSON:encode(r.clientDataJSON),authenticatorData:encode(r.authenticatorData),signature:encode(r.signature),userHandle:r.userHandle?encode(r.userHandle):null}}
}
export class SetupClient {
 private csrf=''
 private controller=new AbortController()
 private generation=0
 private recovery?:Wrapper
 constructor(private fetcher:typeof fetch=(input,options)=>fetch(input,options),private credentials:Credentials=navigator.credentials){}
 private async post<T>(path:string,body:unknown):Promise<T>{
  const epoch=this.generation
  const response=await this.fetcher('/api/v1/setup/'+path,{method:'POST',cache:'no-store',credentials:'same-origin',headers:{'Content-Type':'application/json',...(this.csrf?{'X-CSRF-Token':this.csrf}:{})},body:JSON.stringify(body),signal:this.controller.signal})
  if(epoch!==this.generation)throw Error('Setup cancelled')
  if(!response.ok)throw Error(`Setup request rejected (${response.status}). Restart explicit init if setup expired or a ceremony failed.`)
  const value=await response.json() as T
  if(epoch!==this.generation)throw Error('Setup cancelled')
  return value
 }
 async authorize(password:string):Promise<void>{const r=await this.post<{csrf:string}>('password',{password});this.csrf=r.csrf}
 async register():Promise<string>{
  const epoch=this.generation
  let prf:Uint8Array<ArrayBuffer>|undefined,dek:Uint8Array<ArrayBuffer>|undefined,recovery:Uint8Array<ArrayBuffer>|undefined,proof:Uint8Array<ArrayBuffer>|undefined,roundtrip:Uint8Array<ArrayBuffer>|undefined
  try {
   const creation=await this.post<{publicKey:WireCreation}>('registration/begin',{})
   const options:PublicKeyCredentialCreationOptions={...creation.publicKey,challenge:decode(creation.publicKey.challenge,32),user:{...creation.publicKey.user,id:decode(creation.publicKey.user.id,32)},extensions:{prf:{}} as AuthenticationExtensionsClientInputs}
   const created=await this.credentials.create({publicKey:options,signal:this.controller.signal}) as PublicKeyCredential|null
   if(!created||epoch!==this.generation)throw Error('Passkey registration cancelled')
   const registered=await this.post<Registered>('registration/finish',signedCredential(created,true))
   const a=registered.assertion.publicKey
   const asserted=await this.credentials.get({publicKey:{...a,challenge:decode(a.challenge,32),allowCredentials:a.allowCredentials?.map(c=>({...c,id:decode(c.id,-1)})),extensions:{prf:{eval:{first:decode(registered.prf_input,32)}}} as AuthenticationExtensionsClientInputs},signal:this.controller.signal}) as PublicKeyCredential|null
   if(!asserted||epoch!==this.generation)throw Error('Passkey assertion cancelled')
   if(encode(asserted.rawId)!==registered.credential_id)throw Error('Wrong credential')
   const result=(asserted.getClientExtensionResults() as {prf?:{results?:{first?:ArrayBuffer}}}).prf?.results?.first
   if(!result||result.byteLength!==32)throw Error('This passkey did not return the required WebAuthn PRF output. Setup was not committed; use a standards PRF-capable authenticator.')
   prf=new Uint8Array(result)
   await this.post('assertion/finish',signedCredential(asserted,false))
   dek=randomBytes(32);recovery=randomBytes(32)
   const passkey=await wrap(prf,dek,'passkey',registered.vault_id,registered.credential_id,registered.prf_input)
   roundtrip=await unwrap(passkey,prf,'passkey',registered.vault_id,registered.credential_id)
   if(!roundtrip.every((v,i)=>v===dek![i]))throw Error('Passkey wrapper roundtrip failed')
   const wrapper=await wrap(recovery,dek,'recovery',registered.vault_id,'')
   proof=await recoveryAuth(recovery,wrapper.kdf_salt)
   const verifier=encode(await crypto.subtle.digest('SHA-256',proof))
   await this.post('prepare',{passkey_wrapper:passkey,recovery_wrapper:wrapper,recovery_verifier:verifier,dek:encode(roundtrip)})
   if(epoch!==this.generation)throw Error('Setup cancelled')
   this.recovery=wrapper
   return 'warden-recovery-v1:'+encode(recovery)
  } catch(error){this.recovery=undefined;throw error}
  finally{prf?.fill(0);dek?.fill(0);recovery?.fill(0);proof?.fill(0);roundtrip?.fill(0)}
 }
 async confirm(saved:string):Promise<void>{
  if(!this.recovery)throw Error('No prepared recovery wrapper')
  const wrapper=this.recovery
  let key:Uint8Array<ArrayBuffer>|undefined,dek:Uint8Array<ArrayBuffer>|undefined,proof:Uint8Array<ArrayBuffer>|undefined
  try {
   key=parseRecoveryKey(saved);dek=await unwrap(wrapper,key,'recovery',wrapper.vault_id,'');proof=await recoveryAuth(key,wrapper.kdf_salt)
   await this.post('finalize',{recovery_auth:encode(proof),dek:encode(dek)})
   this.cancel()
  } finally{key?.fill(0);dek?.fill(0);proof?.fill(0)}
 }
 cancel(){this.generation++;this.controller.abort();this.csrf='';this.recovery=undefined}
}
