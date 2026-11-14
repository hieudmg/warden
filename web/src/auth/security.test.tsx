import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { AuthClient } from './auth'
import { SecurityView } from './security-view'
import { encode, wrap, recoveryAuth } from '../setup/vault-wrap'

beforeEach(()=>vi.stubGlobal('crypto',webcrypto))
afterEach(()=>{cleanup();vi.unstubAllGlobals()})
const binary=(n:number,value=0)=>new Uint8Array(n).fill(value)
function credential(prf?:Uint8Array,id=7){return {rawId:binary(1,id).buffer,response:{clientDataJSON:binary(1).buffer,attestationObject:binary(1).buffer,authenticatorData:binary(1).buffer,signature:binary(1).buffer,userHandle:binary(32).buffer},getClientExtensionResults:()=>({prf:prf?{results:{first:prf.buffer}}:{enabled:true}})} as unknown as PublicKeyCredential}
async function harness(){
 const prf=binary(32,4),dek=binary(32,3),root=binary(32,5),input=encode(binary(32,6)),vault=encode(binary(16,2))
 const recovery=await wrap(root,dek,'recovery',vault,'')
 const sent:{path:string,body:Record<string,unknown>,headers:Record<string,string>}[]=[]
 const options={publicKey:{challenge:encode(binary(32)),user:{id:encode(binary(32)),name:'owner',displayName:'Owner'},rp:{id:'warden.example',name:'Warden'},pubKeyCredParams:[{alg:-7,type:'public-key'}],allowCredentials:[{id:'CQ',type:'public-key'}],userVerification:'required'}}
 const fetcher=vi.fn(async(path:RequestInfo|URL,init?:RequestInit)=>{
  const route=String(path);const body=init?.body?JSON.parse(String(init.body)):{};sent.push({path:route,body,headers:init?.headers as Record<string,string>})
  let data:unknown={}
  if(route.endsWith('/status'))data={authenticated:true,unlocked:true,csrf:'csrf',credential_id:'Bw'}
  else if(route.endsWith('/passkeys/list'))data={credentials:['Bw']}
  else if(route.endsWith('/recovery/begin'))data={id:'nonce',kdf_salt:recovery.kdf_salt}
  else if(route.endsWith('/recovery/proof'))data={csrf:'recovery-csrf',grant:'recovery-grant',wrapper:recovery}
  else if(route.endsWith('/begin'))data={id:'pending',options,credential_id:'Bw',prf_input:input}
  else if(route.endsWith('/fresh/finish'))data={grant:'bound-grant'}
  else if(route.endsWith('/registration'))data={options,credential_id:'CQ',prf_input:input,vault_id:vault}
  else if(route.endsWith('/key'))data={id:'rotation',dek:encode(dek),vault_id:vault,prf_input:input}
  return new Response(JSON.stringify(data),{status:200,headers:{'Content-Type':'application/json'}})
 })
 const credentials={create:vi.fn(async()=>credential(undefined,9)),get:vi.fn(async()=>credential(new Uint8Array(prf),9))}
 return {client:new AuthClient(fetcher,credentials),fetcher,credentials,sent,root,recovery,dek,prf}
}
test('fresh grant binds exact method path and SHA256 bytes and never sends PRF extension results',async()=>{
 const h=await harness();await h.client.status();const body='{"private_key":"synthetic"}'
 const grant=await h.client.grantFor('PUT','/api/v1/key-pairs/3',body)
 expect(grant).toBe('bound-grant')
 const begin=h.sent.find(x=>x.path.endsWith('/fresh/begin'))!
 expect(begin.body).toEqual({action:'key_mutation',credential_id:'Bw',method:'PUT',path:'/api/v1/key-pairs/3',digest:encode(await webcrypto.subtle.digest('SHA-256',new TextEncoder().encode(body)))})
 expect(JSON.stringify(h.sent)).not.toContain('results')
})
test('new passkey always performs independent get after creation, rewraps same DEK and locally roundtrips',async()=>{
 const h=await harness();await h.client.status();await h.client.addPasskey()
 expect(h.credentials.create).toHaveBeenCalledOnce()
 expect(h.credentials.get).toHaveBeenCalledTimes(3) // old-owner start, new PRF, bound old-owner delivery
 const commit=h.sent.find(x=>x.path.endsWith('/passkeys/commit'))!
 expect(commit.body).toMatchObject({id:'pending',dek:encode(h.dek),wrapper:{credential_id:'CQ',kind:'passkey'}})
 expect(JSON.stringify(h.sent)).not.toContain('results')
})
test('missing new PRF or canceled late credential cannot commit enrollment',async()=>{
 const h=await harness();await h.client.status();h.credentials.get.mockResolvedValue(credential(undefined,9))
 await expect(h.client.addPasskey()).rejects.toThrow(/PRF/)
 expect(h.sent.some(x=>x.path.endsWith('/passkeys/commit'))).toBe(false)
 const next=await harness();await next.client.status();let resolve!:(c:PublicKeyCredential)=>void
 next.credentials.create.mockImplementationOnce(()=>new Promise(r=>{resolve=r}))
 const pending=next.client.addPasskey();await vi.waitFor(()=>expect(resolve).toBeDefined());next.client.cancel();resolve(credential(undefined,9))
 await expect(pending).rejects.toThrow(/cancel/);expect(next.sent.some(x=>x.path.endsWith('/registration'))).toBe(false)
})
test('recovery derives proof before wrapper, unlocks restricted context, replaces then requires ordinary login',async()=>{
 const h=await harness();await h.client.recover('warden-recovery-v1:'+encode(h.root))
 const expected=await recoveryAuth(h.root,h.recovery.kdf_salt)
 expect(h.sent.find(x=>x.path.endsWith('/recovery/proof'))?.body).toMatchObject({proof:encode(expected)})
 expect(h.client.getSnapshot()).toMatchObject({recovering:true,authenticated:false})
 await h.client.addPasskey()
 expect(h.client.getSnapshot()).toMatchObject({recovering:false,authenticated:false,unlocked:false})
 expect(h.sent.filter(x=>x.path.endsWith('/fresh/begin'))).toHaveLength(0)
})
test('rotation requires saved reentry; wrong root cannot send commit',async()=>{
 const h=await harness();await h.client.status();const saved=await h.client.rotateRecovery()
 await expect(h.client.confirmRecoveryRotation('warden-recovery-v1:'+encode(binary(32,42)))).rejects.toThrow()
 expect(h.sent.some(x=>x.path.endsWith('/rotation/commit'))).toBe(false)
 await h.client.confirmRecoveryRotation(saved)
 expect(h.sent.find(x=>x.path.endsWith('/rotation/commit'))?.body).toMatchObject({id:'rotation',dek:encode(h.dek)})
})
test('late recovery wrapper after cancellation cannot deliver DEK or restore recovery',async()=>{
 const h=await harness();const original=h.fetcher.getMockImplementation()!
 let resolve!:(r:Response)=>void
 h.fetcher.mockImplementation(async(path,options)=>String(path).endsWith('/recovery/proof')?new Promise<Response>(r=>{resolve=r}):original(path,options))
 const pending=h.client.recover('warden-recovery-v1:'+encode(h.root))
 await vi.waitFor(()=>expect(resolve).toBeDefined());h.client.cancel()
 resolve(new Response(JSON.stringify({csrf:'csrf',grant:'grant',wrapper:h.recovery}),{status:200}))
 await expect(pending).rejects.toThrow(/cancel/)
 expect(h.sent.some(x=>x.path.endsWith('/recovery/unlock'))).toBe(false)
 expect(h.client.getSnapshot().recovering).not.toBe(true)
})
test('security UI lists credentials and offers add removal and recovery rotation while unlocked',async()=>{
 const h=await harness();await h.client.status();render(<SecurityView client={h.client}/>)
 expect(await screen.findByText('Bw')).toBeInTheDocument()
 expect(screen.getByRole('button',{name:'Add passkey'})).toBeInTheDocument()
 fireEvent.click(screen.getByRole('button',{name:'Rotate recovery key'}))
 expect(await screen.findByText(/warden-recovery-v1:/)).toBeInTheDocument()
 fireEvent.click(screen.getByRole('button',{name:'I saved it; hide key'}))
 expect(screen.getByLabelText('Re-enter saved recovery key')).toBeInTheDocument()
})
