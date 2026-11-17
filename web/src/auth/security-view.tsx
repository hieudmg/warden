import { useEffect, useId, useRef, useState, useSyncExternalStore } from 'react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { authClient, type AuthClient } from './auth'
import { DevicesView } from './devices-view'
import { securityEpoch, securitySignal, useSecurityEpoch } from './session'

export function SecurityView({ client = authClient }: { client?: AuthClient }) {
 const state = useSyncExternalStore(client.subscribe, client.getSnapshot)
 const [ids, setIDs] = useState<string[]>([])
 const [error, setError] = useState('')
 const [notice, setNotice] = useState('')
 const [busy, setBusy] = useState(false)
 const [saved, setSaved] = useState('')
 const [confirm, setConfirm] = useState(false)
 const [reentry, setReentry] = useState('')
 const [password, setPassword] = useState('')
 const [confirmation, setConfirmation] = useState('')
 const account = state.authMethod === 'account'
 const [expanded, setExpanded] = useState(false)
 const panelID = useId()
 const open = state.recovering || expanded
 const title = account ? 'Account and recovery' : 'Passkeys and recovery'
 const generation = useRef(0)
 const security = useSecurityEpoch()
 useEffect(() => {
  const clear = () => { generation.current++; setSaved(''); setReentry(''); setPassword(''); setConfirmation(''); setConfirm(false); setBusy(false); setError(''); setNotice('') }
  const signal = securitySignal()
  signal.addEventListener('abort', clear)
  return () => signal.removeEventListener('abort', clear)
 }, [security])
 useEffect(() => {
  const epoch = ++generation.current
  setSaved(''); setConfirm(false); setReentry(''); setPassword(''); setConfirmation(''); setBusy(false)
  if (!account && state.authenticated && !state.recovering) void client.listPasskeys().then(x => { if (epoch === generation.current) setIDs(x) }).catch(() => {})
  // This effect owns only its local results. AuthGate owns client lifetime;
  // canceling it here would abort lock/logout because their render runs cleanup.
  return () => { generation.current++ }
 }, [client, state.authenticated, state.recovering, state.unlocked, account])
 const run = async (action: (current: () => boolean) => Promise<void>) => {
  const epoch = generation.current, global = securityEpoch()
  const current = () => epoch === generation.current && global === securityEpoch()
  setBusy(true); setError(''); setNotice('')
  try { await action(current) } catch (e) { if (current()) setError(e instanceof Error ? e.message : 'Security operation failed') }
  finally { if (current()) setBusy(false) }
 }
 const cancel = () => { generation.current++; client.cancel(); setSaved(''); setConfirm(false); setReentry(''); setPassword(''); setConfirmation(''); setBusy(false); setError('') }
 return <section aria-label={title} className="security-settings border-b bg-muted/20 px-4 py-3 sm:px-6">
  <h2><Button variant="ghost" className="h-auto w-full justify-between gap-3 px-2 py-2 text-left disabled:opacity-100" aria-expanded={open} aria-controls={panelID} disabled={state.recovering} onClick={() => setExpanded(value => !value)}>
   <span>{title}</span><span aria-hidden="true" className="text-muted-foreground">{open ? '−' : '+'}</span>
  </Button></h2>
  {/* Keep mounted: hiding settings must not change security request ownership. */}
  <div id={panelID} hidden={!open} className="pt-3">
  <div className={state.recovering ? 'max-w-2xl' : 'grid items-start gap-4 lg:grid-cols-2'}>
  <DevicesView client={client} />
  <section aria-label="Recovery and credentials" className="security-card">
  <h3 className="font-medium text-foreground">{state.recovering ? 'Replace credentials' : 'Recovery and credentials'}</h3>
  <p>{account ? 'Recovery replaces your password while preserving the same encrypted vault.' : 'Recovery replaces ALL old passkeys only after the new PRF passkey is verified.'} Old credentials remain intact on failure. Old backups and already retrieved secrets cannot be revoked.</p>
  {state.recovering ? <>
   <p>Restricted recovery: no management, read or export access. {account ? 'Set a replacement password' : 'Register a new PRF-capable passkey'} to revoke all old sessions and client authorizations, then return to ordinary login.</p>
   {state.unlocked && (account ? <form onSubmit={e => { e.preventDefault(); const p = password, c = confirmation; setPassword(''); setConfirmation(''); void run(() => client.resetPassword(p, c)) }}><label>New password<Input type="password" autoComplete="new-password" required value={password} onChange={e => setPassword(e.target.value)} /></label><label>Confirm new password<Input type="password" autoComplete="new-password" required value={confirmation} onChange={e => setConfirmation(e.target.value)} /></label><p>Use 12–1024 UTF-8 bytes. Spaces are preserved exactly.</p><Button disabled={busy}>Replace account password</Button></form> : <Button disabled={busy} onClick={() => void run(() => client.addPasskey())}>Register replacement passkey</Button>)}
   <Button variant="outline" onClick={() => { cancel(); void run(() => client.abortRecovery()) }}>Abort recovery</Button>
  </> : <>
   {!account && <><ul>{ids.map(id => <li key={id}><code>{id}</code> <Button variant="destructive" disabled={busy || !state.unlocked || ids.length <= 1} onClick={() => void run(async current => { await client.removePasskey(id); if (!current()) return; const ids = await client.listPasskeys(); if (current()) setIDs(ids) })}>Revoke passkey {id}</Button></li>)}</ul>
   <Button variant="outline" disabled={busy || !state.unlocked} onClick={() => void run(async current => { await client.addPasskey(); if (!current()) return; const ids = await client.listPasskeys(); if (current()) setIDs(ids) })}>Add passkey</Button></>}
   <Button variant="outline" disabled={busy || !state.unlocked || !!saved || confirm} onClick={() => void run(async current => { const key = await client.rotateRecovery(); if (current()) setSaved(key) })}>Rotate recovery key</Button>
   {state.unlocked && saved && <div><p>Save this offline secret privately. Current recovery remains valid until saved re-entry succeeds. Avoid shared/synchronized storage. Re-entry must finish within the 60-second authorization.</p><pre>{saved}</pre><Button onClick={() => { setSaved(''); setConfirm(true) }}>I saved it; hide key</Button></div>}
   {state.unlocked && confirm && <form onSubmit={e => { e.preventDefault(); const value = reentry; setReentry(''); void run(async current => { await client.confirmRecoveryRotation(value); if (!current()) return; setConfirm(false); setNotice('Recovery key rotated. Old key no longer authenticates against current state; old backups remain decryptable.') }) }}><label>Re-enter saved recovery key<Input aria-label="Re-enter saved recovery key" type="password" autoComplete="off" value={reentry} onChange={e => setReentry(e.target.value)} /></label><Button disabled={busy}>Confirm saved recovery key</Button></form>}
   <Button variant="ghost" onClick={cancel}>Cancel security operation</Button>
  </>}
  {error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}
  </section>
  </div>
  </div>
 </section>
}
