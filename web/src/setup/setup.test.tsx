import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { SetupClient } from './setup'
import { mountSetup } from './setup-view'
import { encode } from './vault-wrap'

beforeEach(()=>vi.stubGlobal('crypto',webcrypto))
afterEach(()=>vi.unstubAllGlobals())
function credential(registration: boolean, prf?: Uint8Array) {
 return {type:'public-key',rawId:new Uint8Array([7]).buffer,response:registration?{clientDataJSON:new Uint8Array([1]).buffer,attestationObject:new Uint8Array([2]).buffer}:{clientDataJSON:new Uint8Array([1]).buffer,authenticatorData:new Uint8Array([2]).buffer,signature:new Uint8Array([3]).buffer,userHandle:new Uint8Array([4]).buffer},getClientExtensionResults:()=>({prf:registration?{enabled:true}:prf?{results:{first:prf.buffer}}:{}})} as unknown as PublicKeyCredential
}
function harness(prf=true) {
 const sent: {path:string,body: Record<string,unknown>}[]=[]
 const fetcher=vi.fn(async(path:RequestInfo|URL,options?:RequestInit)=>{
  expect(options?.cache).toBe('no-store');expect(options?.credentials).toBe('same-origin')
  const route=String(path);sent.push({path:route,body:JSON.parse(String(options?.body))})
  const data=route.endsWith('/password')?{csrf:'csrf'}:route.endsWith('/registration/begin')?{publicKey:{challenge:encode(new Uint8Array(32)),user:{id:encode(new Uint8Array(32))},rp:{id:'warden.example'},pubKeyCredParams:[]}}:route.endsWith('/registration/finish')?{assertion:{publicKey:{challenge:encode(new Uint8Array(32)),allowCredentials:[{type:'public-key',id:'Bw'}]}},vault_id:encode(new Uint8Array(16)),credential_id:'Bw',prf_input:encode(new Uint8Array(32).fill(6))}:{}
  return new Response(JSON.stringify(data),{status:200,headers:{'Content-Type':'application/json'}})
 })
 const credentials={create:vi.fn(async()=>credential(true)),get:vi.fn(async(_options:CredentialRequestOptions)=>credential(false,prf?new Uint8Array(32).fill(5):undefined))}
 return {client:new SetupClient(fetcher,credentials),sent,credentials}
}
test('default browser fetch is not invoked with the SetupClient as receiver',async()=>{
 vi.stubGlobal('fetch', function(this:unknown){ if(this instanceof SetupClient) throw new TypeError('Illegal invocation'); return Promise.resolve(new Response('{"csrf":"csrf"}')) })
 const client=new SetupClient(undefined,{create:vi.fn(),get:vi.fn()})
 await expect(client.authorize('23456789')).resolves.toBeUndefined()
})
test('create enabled without PRF results uses independent authenticated get then wraps, saved re-entry finalizes',async()=>{
 const {client,sent,credentials}=harness();await client.authorize('23456789');const saved=await client.register()
 expect(credentials.get).toHaveBeenCalledOnce()
 const options=credentials.get.mock.calls[0][0] as CredentialRequestOptions
 expect((options.publicKey?.extensions as {prf:{eval:{first:Uint8Array}}}).prf.eval.first).toEqual(new Uint8Array(32).fill(6))
 expect(sent.map(x=>x.path.split('/').slice(-2).join('/'))).toContain('assertion/finish')
 for(const message of sent.filter(x=>/registration\/finish|assertion\/finish/.test(x.path)))expect(message.body.clientExtensionResults).toEqual({})
 expect(sent.some(x=>x.path.endsWith('/finalize'))).toBe(false)
 await expect(client.confirm('checkbox saved')).rejects.toThrow()
 expect(sent.some(x=>x.path.endsWith('/finalize'))).toBe(false)
 await expect(client.confirm('warden-recovery-v1:'+encode(new Uint8Array(32)))).rejects.toThrow()
 await client.confirm(saved)
 expect(sent.at(-1)?.path).toBe('/api/v1/setup/finalize')
 expect(JSON.stringify(sent)).not.toContain('warden-recovery-v1:')
})
test('no PRF results fails explicitly without prepare or commit',async()=>{
 const {client,sent}=harness(false);await client.authorize('23456789')
 await expect(client.register()).rejects.toThrow(/PRF/)
 expect(sent.some(x=>x.path.endsWith('/prepare')||x.path.endsWith('/finalize'))).toBe(false)
})
test('setup-only view hides saved key before manual re-entry and clears on exit',async()=>{
 const root=document.createElement('main');document.body.append(root)
 const actions={authorize:vi.fn(async()=>{}),register:vi.fn(async()=> 'warden-recovery-v1:saved'),confirm:vi.fn(async()=>{}),cancel:vi.fn()}
 mountSetup(root,actions)
 const submit=async()=>{root.querySelector('form')!.dispatchEvent(new Event('submit',{cancelable:true}));await new Promise(resolve=>setTimeout(resolve,0))}
 ;(root.querySelector('input') as HTMLInputElement).value='23456789';await submit()
 ;(root.querySelector('button') as HTMLButtonElement).click();await new Promise(resolve=>setTimeout(resolve,0))
 expect(root.textContent).toContain('warden-recovery-v1:saved')
 ;(root.querySelector('button') as HTMLButtonElement).click()
 expect(root.textContent).not.toContain('warden-recovery-v1:saved')
 ;(root.querySelector('input') as HTMLInputElement).value='saved reentry';await submit()
 expect(actions.confirm).toHaveBeenCalledWith('saved reentry')
 expect(root.textContent).toContain('initialized')
 expect(root.querySelector('input')).toBeNull();root.remove()
})

test('cancel clears pending recovery and rejects late results',async()=>{
 const {client}=harness();await client.authorize('23456789');await client.register();client.cancel()
 await expect(client.confirm('anything')).rejects.toThrow()
})
