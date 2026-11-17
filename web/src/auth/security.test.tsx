import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { AuthClient } from './auth'
import { SecurityView } from './security-view'
import { encode, wrap, recoveryAuth } from '../setup/vault-wrap'
import { invalidateSecurity } from './session'
import { act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

beforeEach(()=>vi.stubGlobal('crypto',webcrypto))
afterEach(()=>{cleanup();vi.unstubAllGlobals()})
const binary=(n:number,value=0)=>new Uint8Array(n).fill(value)
function credential(prf?:Uint8Array,id=7){return {rawId:binary(1,id).buffer,response:{clientDataJSON:binary(1).buffer,attestationObject:binary(1).buffer,authenticatorData:binary(1).buffer,signature:binary(1).buffer,userHandle:binary(32).buffer},getClientExtensionResults:()=>({prf:prf?{results:{first:prf.buffer}}:{enabled:true}})} as unknown as PublicKeyCredential}
async function harness(method: 'account' | 'passkey' = 'passkey'){
 const prf=binary(32,4),dek=binary(32,3),root=binary(32,5),input=encode(binary(32,6)),vault=encode(binary(16,2))
 const recovery=await wrap(root,dek,'recovery',vault,'')
 const sent:{path:string,body:Record<string,unknown>,headers:Record<string,string>}[]=[]
 const options={publicKey:{challenge:encode(binary(32)),user:{id:encode(binary(32)),name:'owner',displayName:'Owner'},rp:{id:'warden.example',name:'Warden'},pubKeyCredParams:[{alg:-7,type:'public-key'}],allowCredentials:[{id:'CQ',type:'public-key'}],userVerification:'required'}}
 const fetcher=vi.fn(async(path:RequestInfo|URL,init?:RequestInit)=>{
  const route=String(path);const body=init?.body?JSON.parse(String(init.body)):{};sent.push({path:route,body,headers:init?.headers as Record<string,string>})
  let data:unknown={}
  if(route.endsWith('/method'))data={auth_method:method}
  else if(route.endsWith('/status'))data={authenticated:true,unlocked:true,csrf:'csrf',credential_id:'Bw'}
  else if(route.endsWith('/passkeys/list'))data={credentials:['Bw']}
  else if(route.endsWith('/clients/list'))data={pending:[{id:'device-id',label:'fixture device',fingerprint:'public-fingerprint',status:'pending',expires:'2099-01-01T00:00:00Z'}],clients:[]}
  else if(route.endsWith('/recovery/begin'))data={id:'nonce',kdf_salt:recovery.kdf_salt}
  else if(route.endsWith('/recovery/proof'))data={csrf:'recovery-csrf',grant:'recovery-grant',wrapper:recovery}
  else if(route.endsWith('/begin'))data={id:'pending',options,credential_id:'Bw',prf_input:input}
  else if(route.endsWith('/fresh/finish'))data={grant:'bound-grant'}
  else if(route.endsWith('/registration'))data={options,credential_id:'CQ',prf_input:input,vault_id:vault}
  else if(route.endsWith('/key'))data={id:'rotation',dek:encode(dek),vault_id:vault,prf_input:input}
  return new Response(JSON.stringify(data),{status:200,headers:{'Content-Type':'application/json'}})
 })
 const credentials={create:vi.fn(async()=>credential(undefined,9)),get:vi.fn(async(_options:CredentialRequestOptions)=>credential(new Uint8Array(prf),9))}
 return {client:new AuthClient(fetcher,credentials),fetcher,credentials,sent,root,recovery,dek,prf}
}
test.each(['account', 'passkey'] as const)('%s security disclosure starts collapsed and supports keyboard expansion without canceling requests', async method => {
 const h = await harness(method); await h.client.status()
 const cancel = vi.spyOn(h.client, 'cancel')
 const user = userEvent.setup()
 render(<SecurityView client={h.client} />)
 const toggle = screen.getByRole('button', { name: method === 'account' ? 'Account and recovery' : 'Passkeys and recovery' })
 expect(toggle).toHaveAttribute('aria-expanded', 'false')
 expect(screen.queryByRole('button', { name: 'Rotate recovery key' })).not.toBeInTheDocument()
 const panel = document.getElementById(toggle.getAttribute('aria-controls')!)!
 expect(panel).not.toBeVisible()
 await user.tab(); expect(toggle).toHaveFocus()
 await user.keyboard('{Enter}')
 expect(toggle).toHaveAttribute('aria-expanded', 'true')
 expect(panel).toBeVisible()
 expect(screen.getByRole('button', { name: 'Rotate recovery key' })).toBeEnabled()
 await user.keyboard(' ')
 expect(toggle).toHaveAttribute('aria-expanded', 'false')
 await user.tab()
 expect(screen.queryByRole('button', { name: 'Refresh devices' })).not.toBeInTheDocument()
 expect(panel).not.toContainElement(document.activeElement as HTMLElement)
 expect(cancel).not.toHaveBeenCalled()
})
test.each(['account', 'passkey'] as const)('%s restricted recovery overrides a collapsed disclosure and cannot be hidden', async method => {
 const h = await harness(method); await h.client.status()
 render(<SecurityView client={h.client} />)
 await act(async () => { await h.client.recover('warden-recovery-v1:' + encode(h.root)) })
 const toggle = screen.getByRole('button', { name: method === 'account' ? 'Account and recovery' : 'Passkeys and recovery' })
 expect(toggle).toHaveAttribute('aria-expanded', 'true')
 expect(toggle).toBeDisabled()
 fireEvent.click(toggle)
 expect(screen.getByRole('button', { name: 'Abort recovery' })).toBeVisible()
 expect(screen.getByRole('button', { name: method === 'account' ? 'Replace account password' : 'Register replacement passkey' })).toBeVisible()
 expect(screen.getByText(/Restricted recovery: no management/)).toBeVisible()
})
test('global epoch cancels an authenticator promise without AuthClient.cancel',async()=>{
 const h=await harness();await h.client.status();let resolve!:(value:PublicKeyCredential)=>void
 h.credentials.get.mockImplementationOnce(()=>new Promise(r=>{resolve=r}))
 const pending=h.client.grantFor('GET','/api/v1/data/export','')
 await vi.waitFor(()=>expect(resolve).toBeDefined());invalidateSecurity()
 expect(h.credentials.get.mock.calls.at(-1)?.[0]?.signal?.aborted).toBe(true)
 resolve(credential())
 await expect(pending).rejects.toThrow(/cancel/i)
 expect(h.sent.some(x=>x.path.endsWith('/fresh/finish'))).toBe(false)
})
test.each(['cancel', 'epoch', 'unmount'])('late recovery rotation never restores offline key after %s', async reset => {
 const h=await harness(); await h.client.status()
 let resolve!:(value:string)=>void
 vi.spyOn(h.client,'rotateRecovery').mockImplementationOnce(()=>new Promise(r=>{resolve=r}))
 const view=render(<SecurityView client={h.client}/>)
 fireEvent.click(screen.getByRole('button', { name: 'Passkeys and recovery' }))
 fireEvent.click(screen.getByRole('button',{name:'Rotate recovery key'}))
 if(reset==='cancel')fireEvent.click(screen.getByRole('button',{name:'Cancel security operation'}))
 else if(reset==='epoch')act(()=>invalidateSecurity())
 else view.unmount()
 await act(async()=>resolve('warden-recovery-v1:synthetic-late-root'))
 if(reset==='unmount')render(<SecurityView client={h.client}/>)
 expect(screen.queryByText(/synthetic-late-root/)).not.toBeInTheDocument()
})
test('device approval UI compares fingerprint and requires a fresh exact request grant',async()=>{
 const h=await harness();await h.client.status();render(<SecurityView client={h.client}/>)
 fireEvent.click(screen.getByRole('button', { name: 'Passkeys and recovery' }))
 expect(await screen.findByText('fixture device')).toBeInTheDocument()
 expect(screen.getByText('public-fingerprint')).toBeInTheDocument()
 fireEvent.click(screen.getByRole('button',{name:'Approve fixture device'}))
 await vi.waitFor(()=>expect(h.sent.some(x=>x.path.endsWith('/clients/approve'))).toBe(true))
 const sent=h.sent.find(x=>x.path.endsWith('/clients/approve'))!
 expect(sent.body).toEqual({id:'device-id',commitment:'public-fingerprint'})
 expect(sent.headers['X-Warden-Action']).toBe('bound-grant')
 expect(h.sent.find(x=>x.path.endsWith('/fresh/begin'))?.body).toMatchObject({action:'client_approve',method:'POST',path:'/api/v1/auth/clients/approve'})
})
test('device status errors clear on repeated security epochs without stale UI restoration',async()=>{
 const h=await harness();await h.client.status();render(<SecurityView client={h.client}/>)
 fireEvent.click(screen.getByRole('button', { name: 'Passkeys and recovery' }))
 await screen.findByText('fixture device')
 fireEvent.click(screen.getByRole('button',{name:'Cancel security operation'}))
 h.fetcher.mockRejectedValue(new Error('synthetic device status failure'))
 fireEvent.click(screen.getByRole('button',{name:'Refresh devices'}))
 expect(await screen.findByText('synthetic device status failure')).toBeInTheDocument()
 fireEvent.click(screen.getByRole('button',{name:'Cancel security operation'}))
 expect(screen.queryByText('synthetic device status failure')).not.toBeInTheDocument()
})
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
test('a pending rotation cannot be reused after an external security epoch reset',async()=>{
 const h=await harness();await h.client.status();const saved=await h.client.rotateRecovery()
 invalidateSecurity()
 await expect(h.client.confirmRecoveryRotation(saved)).rejects.toThrow(/cancel|pending/i)
 expect(h.sent.some(x=>x.path.endsWith('/rotation/commit'))).toBe(false)
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
 fireEvent.click(screen.getByRole('button', { name: 'Passkeys and recovery' }))
 expect(await screen.findByText('Bw')).toBeInTheDocument()
 expect(screen.getByRole('button',{name:'Add passkey'})).toBeInTheDocument()
 fireEvent.click(screen.getByRole('button',{name:'Rotate recovery key'}))
 expect(await screen.findByText(/warden-recovery-v1:/)).toBeInTheDocument()
 fireEvent.click(screen.getByRole('button',{name:'I saved it; hide key'}))
 expect(screen.getByLabelText('Re-enter saved recovery key')).toBeInTheDocument()
})
