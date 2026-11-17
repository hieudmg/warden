import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import type { ReactNode } from 'react'
import { authClient, AuthClient } from './auth'
import { SecurityView } from './security-view'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { securityEpoch, securitySignal, useSecurityEpoch } from './session'

export function AuthGate({ children, client = authClient }: { children: ReactNode, client?: AuthClient }) {
  const state = useSyncExternalStore(client.subscribe, client.getSnapshot)
  const [error, setError] = useState('')
  const [pendingEpoch, setPendingEpoch] = useState<number | null>(null)
  const [recovery, setRecovery] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [verification, setVerification] = useState(false)
  const [freshPassword, setFreshPassword] = useState('')
  const passwordWaiter = useRef<{ resolve: (password: string) => void, reject: (error: Error) => void } | null>(null)
  const verificationTrigger = useRef<HTMLElement | null>(null)
  const closeVerification = (value?: string) => {
    const waiter = passwordWaiter.current; passwordWaiter.current = null
    setFreshPassword(''); setVerification(false)
    if (value === undefined) waiter?.reject(Error('Password verification cancelled'))
    else waiter?.resolve(value)
  }
  const epoch = useSecurityEpoch()
  const pending = pendingEpoch === epoch || !!state.transition
  const generation = useRef(0)
  const resetSignal = securitySignal()
  useEffect(() => {
    client.setPasswordRequester(() => new Promise<string>((resolve, reject) => {
      passwordWaiter.current?.reject(Error('Password verification cancelled'))
      verificationTrigger.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
      passwordWaiter.current = { resolve, reject }; setFreshPassword(''); setVerification(true)
    }))
    return () => { client.setPasswordRequester(); closeVerification() }
  }, [client])
  useEffect(() => {
    setRecovery(''); setPassword(''); setError('')
    setPendingEpoch(value => value === epoch ? value : null)
  }, [client, state.ready, state.authenticated, state.unlocked, state.recovering, epoch])
  useEffect(() => {
    const clearRecovery = () => { generation.current++; setRecovery(''); setPassword(''); setError(''); setPendingEpoch(null); closeVerification() }
    resetSignal.addEventListener('abort', clearRecovery)
    return () => { resetSignal.removeEventListener('abort', clearRecovery) }
  }, [resetSignal])
  useEffect(() => {
    const unwatch = client.watch()
    void client.status().catch(() => {})
    const timer = setInterval(() => { void client.status().catch(() => {}) }, 15000)
    return () => { generation.current++; setRecovery(''); setPassword(''); clearInterval(timer); unwatch(); client.cancel() }
  }, [client])
  const run = async (action: () => Promise<void>) => {
    setRecovery(''); setPassword(''); setError('')
    let id = ++generation.current, taskEpoch = securityEpoch()
    try {
      const task = action()
      id = ++generation.current
      taskEpoch = securityEpoch()
      setPendingEpoch(taskEpoch)
      await task
    } catch (e) { if (id === generation.current && taskEpoch === securityEpoch()) setError(e instanceof Error ? e.message : 'Authentication failed') }
    finally { if (id === generation.current && taskEpoch === securityEpoch()) setPendingEpoch(null) }
  }
  const account = state.authMethod === 'account'
  const passwordField = <label>Password<Input type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} /></label>
  return <>
    <Dialog open={verification} onOpenChange={open => { if (!open) closeVerification() }}><DialogContent showCloseButton={false} onCloseAutoFocus={e => { e.preventDefault(); verificationTrigger.current?.focus() }}><DialogHeader><DialogTitle>Verify your password</DialogTitle><DialogDescription>Approve only the sensitive action you just requested. Your password is not saved for the next action.</DialogDescription></DialogHeader><form className="security-form space-y-4" onSubmit={e => { e.preventDefault(); const value = freshPassword; closeVerification(value) }}><label>Current password<Input autoFocus type="password" autoComplete="current-password" required value={freshPassword} onChange={e => setFreshPassword(e.target.value)} /></label><div className="flex flex-wrap justify-end gap-2"><Button type="button" variant="outline" onClick={() => closeVerification()}>Cancel verification</Button><Button type="submit">Verify password</Button></div></form></DialogContent></Dialog>
    <section aria-label="Warden security" className="vault-strip flex flex-wrap items-center gap-x-3 gap-y-2 border-b bg-card px-4 py-3 text-sm sm:px-6">
      <strong className="mr-1 text-sm tracking-tight">Warden <span className="font-normal text-muted-foreground">/ Vault</span></strong>
      {!state.ready ? <p>Checking session…</p> : state.recovering ? <p>Restricted recovery</p> : !state.authenticated ?
        account ? <form onSubmit={e => { e.preventDefault(); const value = password; setPassword(''); void run(() => client.login(username, value)) }}><label>Username<Input autoComplete="username" maxLength={64} required value={username} onChange={e => setUsername(e.target.value)} /></label>{passwordField}<Button disabled={pending}>Log in and unlock</Button></form> :
        <Button disabled={pending} onClick={() => void run(() => client.login())}>Log in with passkey</Button> : <>
          <p className={state.unlocked ? 'vault-state bg-primary/10 text-primary' : 'vault-state bg-muted text-muted-foreground'}><span aria-hidden="true" className="size-1.5 rounded-full bg-current" />{state.unlocked ? 'Vault unlocked' : 'Vault locked'}</p>
          {!state.unlocked && (account ? <form onSubmit={e => { e.preventDefault(); const value = password; setPassword(''); void run(() => client.unlock(value)) }}>{passwordField}<Button disabled={pending}>Unlock with password</Button></form> : <Button disabled={pending} onClick={() => void run(() => client.unlock())}>Unlock with passkey PRF</Button>)}
          {state.unlocked && <Button variant="outline" disabled={pending} onClick={() => void run(() => client.lock())}>Lock vault</Button>}
          <Button variant="ghost" disabled={pending} onClick={() => void run(() => client.logout())}>Log out</Button>
        </>}
      {state.authenticated && <p className="w-full text-xs leading-relaxed text-muted-foreground">Key reveal/mutation and export/import require {account ? 'fresh password verification' : 'a new passkey assertion'} for the exact request. Legacy management transport stays blocked.</p>}
      {state.ready && !state.authenticated && !state.recovering && <form onSubmit={e => { e.preventDefault(); const saved = recovery; setRecovery(''); void run(() => client.recover(saved)) }}><label>Offline recovery key<Input type="password" autoComplete="off" aria-label="Offline recovery key" value={recovery} onChange={e => setRecovery(e.target.value)} /></label><Button variant="outline" disabled={pending}>{account ? 'Recover and replace account password' : 'Recover and replace all passkeys'}</Button></form>}
      {state.transition && <p role="status">Confirming server {state.transition}…</p>}
      {state.transitionError && <p role="alert">{state.transitionError}</p>}
      {error && <p role="alert">{error}</p>}
    </section>
    {(state.authenticated || state.recovering) && <SecurityView client={client} />}
    {state.authenticated && state.unlocked && !state.recovering ? children : <main className="security-empty mx-auto my-8 max-w-2xl space-y-3 rounded-xl border bg-card p-6 shadow-sm max-sm:mx-4">
      <h1>{state.authenticated ? 'Vault locked' : account ? 'Account authentication required' : 'Passkey authentication required'}</h1>
      <p>{account ? 'Sign in with your username and password to unlock the encrypted vault. After global lock, re-enter your password. Restart always starts locked.' : 'Login does not require vault key material. Unlock requires a new verified passkey assertion and working PRF. Restart always starts locked.'}</p>
      <p>Lock closes global server key access. Logout ends only this browser session.</p>
      <p>Recovery grants only credential replacement, never normal management. Save offline recovery material privately; historical backups cannot be revoked.</p>
    </main>}
  </>
}
