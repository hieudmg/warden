import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import type { ReactNode } from 'react'
import { authClient, AuthClient } from './auth'
import { SecurityView } from './security-view'
import { securityEpoch, securitySignal, useSecurityEpoch } from './session'

export function AuthGate({ children, client = authClient }: { children: ReactNode, client?: AuthClient }) {
  const state = useSyncExternalStore(client.subscribe, client.getSnapshot)
  const [error, setError] = useState('')
  const [pendingEpoch, setPendingEpoch] = useState<number | null>(null)
  const [recovery, setRecovery] = useState('')
  const epoch = useSecurityEpoch()
  const pending = pendingEpoch === epoch
  const generation = useRef(0)
  const resetSignal = securitySignal()
  useEffect(() => {
    setRecovery(''); setError('')
    setPendingEpoch(value => value === epoch ? value : null)
  }, [client, state.ready, state.authenticated, state.unlocked, state.recovering, epoch])
  useEffect(() => {
    const clearRecovery = () => { generation.current++; setRecovery(''); setError(''); setPendingEpoch(null) }
    resetSignal.addEventListener('abort', clearRecovery)
    return () => { resetSignal.removeEventListener('abort', clearRecovery) }
  }, [resetSignal])
  useEffect(() => {
    const unwatch = client.watch()
    void client.status().catch(() => {})
    // Poll security metadata only: another browser can globally lock this vault.
    const timer = setInterval(() => { void client.status().catch(() => {}) }, 15000)
    return () => { generation.current++; setRecovery(''); clearInterval(timer); unwatch(); client.cancel() }
  }, [client])
  const run = async (action: () => Promise<void>) => {
    // Drop unsubmitted recovery input before a competing flow can await.
    setRecovery(''); setError('')
    let id = ++generation.current, taskEpoch = securityEpoch()
    try {
      // Login/recovery cancel their previous epoch synchronously on entry.
      const task = action()
      id = ++generation.current
      taskEpoch = securityEpoch()
      setPendingEpoch(taskEpoch)
      await task
    } catch (e) { if (id === generation.current && taskEpoch === securityEpoch()) setError(e instanceof Error ? e.message : 'Authentication failed') }
    finally { if (id === generation.current && taskEpoch === securityEpoch()) setPendingEpoch(null) }
  }
  return <>
    <section aria-label="Warden security" className="flex flex-wrap items-center gap-3 p-4 border-b">
      <strong>Warden</strong>
      {!state.ready ? <p>Checking session…</p> : state.recovering ? <p>Restricted recovery</p> : !state.authenticated ?
        <button disabled={pending} onClick={() => void run(() => client.login())}>Log in with passkey</button> : <>
          <p>{state.unlocked ? 'Vault unlocked' : 'Vault locked'}</p>
          {!state.unlocked && <button disabled={pending} onClick={() => void run(() => client.unlock())}>Unlock with passkey PRF</button>}
          {state.unlocked && <button onClick={() => void run(() => client.lock())}>Lock vault</button>}
          <button onClick={() => void run(() => client.logout())}>Log out</button>
        </>}
      {state.authenticated && <p>Key reveal/mutation and export/import require a new passkey assertion for the exact request. Legacy management transport stays blocked.</p>}
      {state.ready && !state.authenticated && !state.recovering && <form onSubmit={e => { e.preventDefault(); const saved = recovery; setRecovery(''); void run(() => client.recover(saved)) }}><label>Offline recovery key<input type="password" autoComplete="off" aria-label="Offline recovery key" value={recovery} onChange={e => setRecovery(e.target.value)} /></label><button disabled={pending}>Recover and replace all passkeys</button></form>}
      {error && <p role="alert">{error}</p>}
    </section>
    {(state.authenticated || state.recovering) && <SecurityView client={client} />}
    {state.authenticated && state.unlocked && !state.recovering ? children : <main className="p-6">
      <h1>{state.authenticated ? 'Vault locked' : 'Passkey authentication required'}</h1>
      <p>Login does not require vault key material. Unlock requires a new verified passkey assertion and working PRF. Restart always starts locked.</p>
      <p>Lock closes global server key access. Logout ends only this browser session.</p>
      <p>Recovery grants only replacement-passkey enrollment, never normal management. Save offline recovery material privately; historical backups cannot be revoked.</p>
    </main>}
  </>
}
