import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import type { AuthClient, ClientDevices } from './auth'
import { securityEpoch, securitySignal } from './session'

export function DevicesView({ client }: { client: AuthClient }) {
 const state = useSyncExternalStore(client.subscribe, client.getSnapshot)
 const [devices, setDevices] = useState<ClientDevices>({ pending: [], clients: [] })
 const [error, setError] = useState('')
 const [busy, setBusy] = useState(false)
 const generation = useRef(0)
 const requested = new URLSearchParams(location.search).get('device')
 useEffect(() => {
  const epoch = ++generation.current
  setDevices({ pending: [], clients: [] }); setError(''); setBusy(false)
  let active = true
  let signal = securitySignal()
  const reset = () => {
   generation.current++; setDevices({ pending: [], clients: [] }); setError(''); setBusy(false)
   // invalidateSecurity replaces its controller after synchronous abort delivery.
   queueMicrotask(() => { if (active) { signal = securitySignal(); signal.addEventListener('abort', reset, { once: true }) } })
  }
  signal.addEventListener('abort', reset, { once: true })
  if (state.authenticated && !state.recovering) void client.listDevices().then(x => { if (generation.current === epoch) setDevices(x) }).catch(() => { if (generation.current === epoch) setError('Unable to load devices. Refresh after login or recovery.') })
  return () => { active = false; generation.current++; signal.removeEventListener('abort', reset) }
 }, [client, state.authenticated, state.recovering, state.unlocked])
 const run = async (action: () => Promise<unknown>) => {
  const epoch = generation.current, security = securityEpoch(); setBusy(true); setError('')
  const current = () => epoch === generation.current && security === securityEpoch()
  try { await action(); if (!current()) return; const next = await client.listDevices(); if (current()) setDevices(next) }
  catch (e) { if (current()) setError(e instanceof Error ? e.message : 'Device action failed') }
  finally { if (current()) setBusy(false) }
 }
 if (!state.authenticated || state.recovering) return null
 return <section aria-label="CLI devices" className="space-y-2">
  <h3>CLI devices</h3>
  <p>Compare the complete fingerprint with the CLI before {state.authMethod === 'account' ? 'fresh password verification' : 'fresh passkey approval'}. Approval cannot unlock the vault. Credentials remain in agent memory only; restart needs new approval. Revocation blocks future API retrieval, not already retrieved remote credentials or established sessions.</p>
  <button disabled={busy} onClick={() => void run(async () => {})}>Refresh devices</button>
  <ul>{devices.pending.map(d => <li key={d.id}>
   <strong>{d.label}</strong> {requested === d.id && <span>Requested device</span>}<p>Request: {d.id}</p><code>{d.fingerprint}</code><p>Expires: {d.expires}</p>
   <button disabled={busy} onClick={() => void run(() => client.approveDevice(d.id, d.fingerprint))}>Approve {d.label}</button>
   <button disabled={busy} onClick={() => void run(() => client.approveDevice(d.id, d.fingerprint, true))}>Deny {d.label}</button>
  </li>)}</ul>
  <ul>{devices.clients.map(d => <li key={d.id}>{d.label} <code>{d.fingerprint}</code> {d.revoked ? 'Revoked' : <button disabled={busy} onClick={() => void run(() => client.revokeDevice(d.id))}>Revoke device {d.label}</button>}</li>)}</ul>
  {error && <p role="alert">{error}</p>}
 </section>
}
