import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { AuthClient } from './auth'
import { AuthGate } from './auth-gate'
import { securityEpoch } from './session'
import { encode, wrap } from '../setup/vault-wrap'

beforeEach(()=>vi.stubGlobal('crypto',webcrypto))
afterEach(()=>{cleanup();vi.unstubAllGlobals()})
function assertion(prf?:Uint8Array){return {rawId:new Uint8Array([7]).buffer,response:{clientDataJSON:new Uint8Array([1]).buffer,authenticatorData:new Uint8Array([2]).buffer,signature:new Uint8Array([3]).buffer,userHandle:new Uint8Array([4]).buffer},getClientExtensionResults:()=>({prf:prf?{results:{first:prf.buffer}}:undefined})} as unknown as PublicKeyCredential}
async function harness(prf=true){
 const material=new Uint8Array(32).fill(5),dek=new Uint8Array(32).fill(3),input=encode(new Uint8Array(32).fill(6))
 const wrapper=await wrap(material,dek,'passkey',encode(new Uint8Array(16)),'Bw',input)
 const sent:{path:string,body:Record<string,unknown>}[]=[]
 const fetcher=vi.fn(async(path:RequestInfo|URL,options?:RequestInit)=>{
  expect(options?.cache).toBe('no-store');expect(options?.credentials).toBe('same-origin')
  const route=String(path);sent.push({path:route,body:options?.body?JSON.parse(String(options.body)):{}})
  const data=route.endsWith('/status')?{}:route.endsWith('/begin')?{id:'challenge',credential_id:'Bw',prf_input:input,options:{publicKey:{challenge:encode(new Uint8Array(32)),userVerification:'required',allowCredentials:[{type:'public-key',id:'Bw'}]}}}:route.endsWith('/fresh/finish')?{grant:'one-use-grant',wrapper}:route.endsWith('/login/finish')?{authenticated:true,unlocked:false,csrf:'csrf',credential_id:'Bw'}:{}
  return new Response(JSON.stringify(data),{status:route.endsWith('/status')?401:200,headers:{'Content-Type':'application/json'}})
 })
 const credentials={get:vi.fn(async(_options:CredentialRequestOptions)=>assertion(prf?new Uint8Array(material):undefined))}
 return {client:new AuthClient(fetcher,credentials),sent,credentials,fetcher,dek}
}
test('login works locked without PRF; fresh signed get locally unwraps and delivers only DEK with grant',async()=>{
 const h=await harness();await h.client.status();await h.client.login()
 expect(h.client.getSnapshot()).toMatchObject({authenticated:true,unlocked:false})
 expect(h.credentials.get.mock.calls[0][0].publicKey?.extensions).toBeUndefined()
 await h.client.unlock();expect(h.client.getSnapshot().unlocked).toBe(true)
 expect(h.credentials.get.mock.calls[1][0].publicKey?.extensions).toMatchObject({prf:{eval:{first:new Uint8Array(32).fill(6)}}})
 expect(h.sent.find(x=>x.path.endsWith('/unlock'))?.body).toEqual({grant:'one-use-grant',dek:encode(h.dek)})
 for(const request of h.sent.filter(x=>x.path.endsWith('/finish')))expect(request.body.credential).toMatchObject({clientExtensionResults:{}})
 expect(JSON.stringify(h.sent)).not.toContain('results')
})
test('observing another browser lock invalidates outstanding managed promises',async()=>{
 const h=await harness();await h.client.login();await h.client.unlock();const epoch=securityEpoch()
 h.fetcher.mockResolvedValueOnce(new Response(JSON.stringify({authenticated:true,unlocked:false,csrf:'csrf',credential_id:'Bw'}),{status:200}))
 await h.client.status();expect(securityEpoch()).toBeGreaterThan(epoch);expect(h.client.getSnapshot().unlocked).toBe(false)
})
test('missing PRF permits login but fails unlock without DEK delivery',async()=>{
 const h=await harness(false);await h.client.login();await expect(h.client.unlock()).rejects.toThrow(/PRF/)
 expect(h.sent.some(x=>x.path.endsWith('/unlock'))).toBe(false)
})
test('late browser credential after lock/logout cannot finish or restore management',async()=>{
 const h=await harness();await h.client.login()
 let resolve!:(value:PublicKeyCredential)=>void
 h.credentials.get.mockImplementationOnce(()=>new Promise(r=>{resolve=r}))
 const pending=h.client.unlock();await vi.waitFor(()=>expect(resolve).toBeDefined())
 await h.client.lock();resolve(assertion(new Uint8Array(32).fill(5)))
 await expect(pending).rejects.toThrow(/cancelled/)
 expect(h.client.getSnapshot().unlocked).toBe(false)
 expect(h.sent.some(x=>x.path.endsWith('/fresh/finish'))).toBe(false)
 await h.client.logout();expect(h.client.getSnapshot().authenticated).toBe(false)
})
test('usable gate shows login, locked controls, management, and resets secret children on lock',async()=>{
 const h=await harness();render(<AuthGate client={h.client}><div>Managed secret forms</div></AuthGate>)
 fireEvent.click(await screen.findByRole('button',{name:'Log in with passkey'}))
 fireEvent.click(await screen.findByRole('button',{name:'Unlock with passkey PRF'}))
 expect(await screen.findByText('Managed secret forms')).toBeInTheDocument()
 fireEvent.click(screen.getByRole('button',{name:'Lock vault'}))
 expect(await screen.findByRole('heading',{name:'Vault locked'})).toBeInTheDocument()
 expect(screen.queryByText('Managed secret forms')).toBeNull()
})
