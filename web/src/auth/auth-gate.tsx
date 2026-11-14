import { useEffect, useState, useSyncExternalStore } from 'react'
import type { ReactNode } from 'react'
import { authClient, AuthClient } from './auth'

export function AuthGate({ children, client = authClient }: { children: ReactNode, client?: AuthClient }) {
  const state = useSyncExternalStore(client.subscribe, client.getSnapshot)
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  useEffect(() => {
    const unwatch = client.watch()
    void client.status().catch(() => {})
    // Poll security metadata only: another browser can globally lock this vault.
    const timer = setInterval(() => { void client.status().catch(() => {}) }, 15000)
    return () => { clearInterval(timer); unwatch(); client.cancel() }
  }, [client])
  const run = async (action: () => Promise<void>) => {
    setError(''); setPending(true)
    try { await action() } catch (e) { setError(e instanceof Error ? e.message : 'Authentication failed') }
    finally { setPending(false) }
  }
  return <>
    <section aria-label="Warden security" className="flex flex-wrap items-center gap-3 p-4 border-b">
      <strong>Warden</strong>
      {!state.ready ? <p>Checking session…</p> : !state.authenticated ?
        <button disabled={pending} onClick={() => void run(() => client.login())}>Log in with passkey</button> : <>
          <p>{state.unlocked ? 'Vault unlocked' : 'Vault locked'}</p>
          {!state.unlocked && <button disabled={pending} onClick={() => void run(() => client.unlock())}>Unlock with passkey PRF</button>}
          {state.unlocked && <button onClick={() => void run(() => client.lock())}>Lock vault</button>}
          <button onClick={() => void run(() => client.logout())}>Log out</button>
        </>}
      {state.authenticated && <p>Key reveal/mutation, transport extraction and export/import are fail-closed until fresh sensitive-action support is delivered.</p>}
      {error && <p role="alert">{error}</p>}
    </section>
    {state.authenticated && state.unlocked ? children : <main className="p-6">
      <h1>{state.authenticated ? 'Vault locked' : 'Passkey authentication required'}</h1>
      <p>Login does not require vault key material. Unlock requires a new verified passkey assertion and working PRF. Restart always starts locked.</p>
      <p>Lock closes global server key access. Logout ends only this browser session.</p>
      <p>Passkey/recovery management, key-vault changes and data transfer are unavailable until the next security milestone.</p>
    </main>}
  </>
}
