import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { AuthClient } from './auth'
import { AuthGate } from './auth-gate'
import { csrfHeader, invalidateSecurity } from './session'

beforeEach(() => vi.stubGlobal('crypto', webcrypto))
afterEach(() => { cleanup(); vi.unstubAllGlobals() })
function deferredRequest() {
 let resolve!: (response: Response) => void, reject!: (error: Error) => void
 const promise = new Promise<Response>((yes, no) => { resolve = yes; reject = no })
 return { promise, resolve, reject, signal: undefined as AbortSignal | undefined, dispatched: false }
}
async function harness(mode: 'account' | 'passkey') {
 let authenticated = true, unlocked = true
 const held = new Map<string, ReturnType<typeof deferredRequest>>()
 const calls: string[] = []
 const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
  const path = String(input).replace('/api/v1/auth/', ''); calls.push(path)
  const pending = held.get(path)
  if (pending) {
   held.delete(path)
   pending.signal = init?.signal ?? undefined
   const abort = () => pending.reject(new DOMException('Dispatch canceled', 'AbortError'))
   if (pending.signal?.aborted) abort()
   else pending.signal?.addEventListener('abort', abort, { once: true })
   const response = await pending.promise
   if (pending.signal?.aborted) throw new DOMException('Dispatch canceled', 'AbortError')
   pending.dispatched = true
   if (response.ok && path === 'lock') unlocked = false
   if (response.ok && path === 'logout') authenticated = false
   return response
  }
  if (path === 'account/login') { authenticated = true; unlocked = true }
  const data = path === 'method' ? { auth_method: mode } : path === 'account/login' ? { authenticated, unlocked, csrf: 'replacement-csrf', credential_id: 'replacement' } : path === 'status' ? { authenticated, unlocked, csrf: 'csrf', credential_id: 'owner' } : path === 'passkeys/list' ? { credentials: ['owner'] } : { pending: [], clients: [] }
  return new Response(JSON.stringify(data), { status: path === 'status' && !authenticated ? 401 : 200 })
 })
 const client = new AuthClient(fetcher, { get: vi.fn(async () => { throw Error('Unexpected authenticator') }) })
 await client.status()
 const view = render(<AuthGate client={client}><p>Protected management</p></AuthGate>)
 await screen.findByText('Protected management')
 await act(async () => {})
 return { client, calls, view, hold(path: string) { const request = deferredRequest(); held.set(path, request); return request }, server: () => ({ authenticated, unlocked }) }
}
const cases = (['account', 'passkey'] as const).flatMap(mode => (['lock', 'logout'] as const).map(action => ({ mode, action })))
test.each(cases)('$mode $action survives its own render cleanup while immediately canceling old work', async ({ mode, action }) => {
 const h = await harness(mode), old = h.hold('clients/list'), authority = h.hold(action)
 const oldWork = h.client.listDevices().catch(error => error)
 fireEvent.click(screen.getByRole('button', { name: action === 'lock' ? 'Lock vault' : 'Log out' }))
 await act(async () => {})
 expect(old.signal?.aborted).toBe(true)
 expect(authority.signal).toBeDefined()
 expect(authority.signal?.aborted).toBe(false)
 expect(screen.queryByText('Protected management')).toBeNull()
 // A status poll or direct reauthentication cannot undo the local fence while
 // the authority-changing POST is waiting to dispatch.
 const beforeStatus = h.calls.filter(path => path === 'status').length
 await act(async () => { await h.client.status() })
 expect(h.calls.filter(path => path === 'status')).toHaveLength(beforeStatus)
 await expect(h.client.login('owner', 'password')).rejects.toThrow(/transition/i)
 await expect(h.client.unlock('password')).rejects.toThrow(/transition/i)
 await expect(h.client.recover('not-a-recovery-key')).rejects.toThrow(/transition/i)
 await expect(h.client.abortRecovery()).rejects.toThrow(/transition/i)
 expect(authority.signal?.aborted).toBe(false)
 await act(async () => authority.resolve(new Response('{}', { status: 200 })))
 expect(authority.dispatched).toBe(true)
 expect(h.server()).toEqual({ authenticated: action === 'lock', unlocked: action !== 'lock' })
 expect(h.client.getSnapshot()).toMatchObject({ authenticated: action === 'lock', unlocked: false })
 if (action === 'logout') expect(csrfHeader()).toBe('')
 expect(await oldWork).toMatchObject({ name: 'AbortError' })
})
test.each(cases)('$mode $action failure stays locally closed, visible, and cannot be reopened by polling', async ({ mode, action }) => {
 const h = await harness(mode), authority = h.hold(action)
 fireEvent.click(screen.getByRole('button', { name: action === 'lock' ? 'Lock vault' : 'Log out' }))
 await act(async () => authority.resolve(new Response('{}', { status: 503 })))
 expect(h.client.getSnapshot()).toMatchObject({ authenticated: action === 'lock', unlocked: false })
 expect(await screen.findByText(/Could not confirm server/)).toBeInTheDocument()
 await act(async () => { await h.client.status() })
 expect(screen.queryByText('Protected management')).toBeNull()
})
test.each(['cancel', 'unmount', 'epoch'] as const)('pending transition retains %s cancellation and late-response protection', async reset => {
 const h = await harness('account'), authority = h.hold('lock')
 fireEvent.click(screen.getByRole('button', { name: 'Lock vault' }))
 await act(async () => {})
 expect(authority.signal?.aborted).toBe(false)
 if (reset === 'cancel') fireEvent.click(screen.getByRole('button', { name: 'Cancel security operation' }))
 else if (reset === 'unmount') h.view.unmount()
 else act(() => invalidateSecurity())
 expect(authority.signal?.aborted).toBe(true)
 await act(async () => authority.resolve(new Response('{}', { status: 200 })))
 expect(authority.dispatched).toBe(false)
 expect(h.server().unlocked).toBe(true)
 expect(h.client.getSnapshot().unlocked).toBe(false)
 if (reset !== 'unmount') expect(await screen.findByText(/Could not confirm server/)).toBeInTheDocument()
})
test.each(cases)('$mode $action rejects a stale response body and serializes replacement authentication', async ({ mode, action }) => {
 const h = await harness(mode), authority = h.hold(action)
 let finishBody!: (value: object) => void
 const body = new Promise<object>(resolve => { finishBody = resolve })
 const response = new Response('{}')
 vi.spyOn(response, 'json').mockImplementation(() => body)
 fireEvent.click(screen.getByRole('button', { name: action === 'lock' ? 'Lock vault' : 'Log out' }))
 await act(async () => authority.resolve(response))
 act(() => h.client.cancel())
 await expect(h.client.login('replacement', 'password')).rejects.toThrow(/transition/i)
 await act(async () => finishBody({}))
 expect(h.client.getSnapshot()).toMatchObject({ unlocked: false })
 expect(await screen.findByText(/Could not confirm server/)).toBeInTheDocument()
 expect(screen.queryByText('Protected management')).toBeNull()
 if (action === 'logout') expect(csrfHeader()).toBe('')
})
test('an old logout finalizer cannot clear CSRF or publish errors into a replacement identity', async () => {
 const h = await harness('account')
 h.hold('recovery/abort')
 const authority = h.hold('logout')
 let finishBody!: (value: object) => void
 const response = new Response('{}')
 vi.spyOn(response, 'json').mockImplementation(() => new Promise(resolve => { finishBody = resolve }))
 let oldAbort!: Promise<unknown>, closing!: Promise<unknown>
 // A previously started recovery teardown has its own finally publication.
 // Canceling its fetch does not prevent that finally from replacing the view.
 act(() => {
  oldAbort = h.client.abortRecovery().catch(error => error)
  closing = h.client.logout().catch(error => error)
  authority.resolve(response)
 })
 await act(async () => { await oldAbort })
 await vi.waitFor(() => expect(finishBody).toBeDefined())
 await act(async () => { await h.client.login('replacement', 'new password') })
 expect(csrfHeader()).toBe('replacement-csrf')
 await act(async () => { finishBody({}); await closing })
 expect(h.client.getSnapshot()).toMatchObject({ authenticated: true, unlocked: true })
 expect(h.client.getSnapshot().transitionError).toBeUndefined()
 expect(csrfHeader()).toBe('replacement-csrf')
})
test.each(['lock', 'logout'] as const)('%s immediately rejects and clears an outstanding fresh-password modal', async action => {
 const h = await harness('account'), authority = h.hold(action)
 let grant!: Promise<string | undefined>, closing!: Promise<void>
 act(() => { grant = h.client.grantFor('GET', '/api/v1/data/export'); grant.catch(() => {}) })
 await screen.findByLabelText('Current password')
 fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'discard this fresh password' } })
 act(() => { closing = h.client[action](); closing.catch(() => {}) })
 await expect(grant).rejects.toThrow(/cancel/i)
 expect(screen.queryByLabelText('Current password')).toBeNull()
 expect(authority.signal?.aborted).toBe(false)
 await act(async () => { authority.resolve(new Response('{}')); await closing })
 expect(h.calls).not.toContain('account/fresh')
})
