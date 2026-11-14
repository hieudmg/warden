import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import { authClient, type AuthClient } from './auth'
import { DevicesView } from './devices-view'

export function SecurityView({ client = authClient }: { client?: AuthClient }) {
 const state = useSyncExternalStore(client.subscribe, client.getSnapshot)
 const [ids, setIDs] = useState<string[]>([])
 const [error, setError] = useState('')
 const [notice, setNotice] = useState('')
 const [busy, setBusy] = useState(false)
 const [saved, setSaved] = useState('')
 const [confirm, setConfirm] = useState(false)
 const [reentry, setReentry] = useState('')
 const generation = useRef(0)
 useEffect(() => {
  const epoch = ++generation.current
  setSaved(''); setConfirm(false); setReentry(''); setBusy(false)
  if (state.authenticated && !state.recovering) void client.listPasskeys().then(x => { if (epoch === generation.current) setIDs(x) }).catch(() => {})
  return () => { generation.current++; client.cancel() }
 }, [client, state.authenticated, state.recovering, state.unlocked])
 const run = async (action: () => Promise<void>) => {
  const epoch = generation.current
  setBusy(true); setError(''); setNotice('')
  try { await action() } catch (e) { if (epoch === generation.current) setError(e instanceof Error ? e.message : 'Security operation failed') }
  finally { if (epoch === generation.current) setBusy(false) }
 }
 const cancel = () => { generation.current++; client.cancel(); setSaved(''); setConfirm(false); setReentry(''); setBusy(false); setError('') }
 return <section aria-label="Passkeys and recovery" className="p-4 border-b space-y-3">
  <h2>Passkeys and recovery</h2>
  <DevicesView client={client} />
  <p>Recovery replaces ALL old passkeys only after the new PRF passkey is verified. Old credentials remain intact on failure. Old backups and already retrieved secrets cannot be revoked.</p>
  {state.recovering ? <>
   <p>Restricted recovery: no management, read or export access. Register a new PRF-capable passkey to replace all previous passkeys, revoke sessions and client authorizations, and return to ordinary login.</p>
   {state.unlocked && <button disabled={busy} onClick={() => void run(() => client.addPasskey())}>Register replacement passkey</button>}
   <button onClick={() => { cancel(); void run(() => client.abortRecovery()) }}>Abort recovery</button>
  </> : <>
   <ul>{ids.map(id => <li key={id}><code>{id}</code> <button disabled={busy || !state.unlocked || ids.length <= 1} onClick={() => void run(async () => { await client.removePasskey(id); setIDs(await client.listPasskeys()) })}>Revoke passkey {id}</button></li>)}</ul>
   <button disabled={busy || !state.unlocked} onClick={() => void run(async () => { await client.addPasskey(); setIDs(await client.listPasskeys()) })}>Add passkey</button>
   <button disabled={busy || !state.unlocked || !!saved || confirm} onClick={() => void run(async () => { const key = await client.rotateRecovery(); setSaved(key) })}>Rotate recovery key</button>
   {state.unlocked && saved && <div><p>Save this offline secret privately. Current recovery remains valid until saved re-entry succeeds. Avoid shared/synchronized storage. Re-entry must finish within the 60-second authorization.</p><pre>{saved}</pre><button onClick={() => { setSaved(''); setConfirm(true) }}>I saved it; hide key</button></div>}
   {state.unlocked && confirm && <form onSubmit={e => { e.preventDefault(); const value = reentry; setReentry(''); void run(async () => { await client.confirmRecoveryRotation(value); setConfirm(false); setNotice('Recovery key rotated. Old key no longer authenticates against current state; old backups remain decryptable.') }) }}><label>Re-enter saved recovery key<input aria-label="Re-enter saved recovery key" type="password" autoComplete="off" value={reentry} onChange={e => setReentry(e.target.value)} /></label><button disabled={busy}>Confirm saved recovery key</button></form>}
   <button onClick={cancel}>Cancel security operation</button>
  </>}
  {error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}
 </section>
}
