import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { AuthClient } from './auth'
import { AuthGate } from './auth-gate'
import { encode, wrap } from '../setup/vault-wrap'

beforeEach(() => vi.stubGlobal('crypto', webcrypto))
afterEach(() => { cleanup(); vi.unstubAllGlobals() })
async function harness() {
 const root = new Uint8Array(32).fill(5), dek = new Uint8Array(32).fill(3)
 const recovery = await wrap(root, dek, 'recovery', encode(new Uint8Array(16)), '')
 const sent: { path: string, body: Record<string, unknown> }[] = []
 const credentials = { get: vi.fn(() => { throw Error('WebAuthn forbidden') }), create: vi.fn(() => { throw Error('WebAuthn forbidden') }) }
 const fetcher = vi.fn(async (path: RequestInfo | URL, options?: RequestInit) => {
  const route = String(path); sent.push({ path: route, body: options?.body ? JSON.parse(String(options.body)) : {} })
  const value = route.endsWith('/method') ? { auth_method: 'account' } : route.endsWith('/account/login') ? { authenticated: true, unlocked: true, csrf: 'csrf', credential_id: 'account-id' } : route.endsWith('/account/fresh') ? { grant: 'bound-grant' } : route.endsWith('/recovery/begin') ? { id: 'nonce', kdf_salt: recovery.kdf_salt } : route.endsWith('/recovery/proof') ? { csrf: 'recovery-csrf', grant: 'grant', wrapper: recovery } : {}
  return new Response(JSON.stringify(value), { status: route.endsWith('/status') ? 401 : 200 })
 })
 return { client: new AuthClient(fetcher, credentials), sent, credentials, root }
}
test('account login unlock fresh and recovery use exact password submissions, never WebAuthn', async () => {
 const h = await harness(); await h.client.status()
 await h.client.login('owner', ' exact account password ')
 expect(h.client.getSnapshot()).toMatchObject({ authMethod: 'account', authenticated: true, unlocked: true })
 await h.client.lock(); await h.client.unlock(' exact account password ')
 h.client.setPasswordRequester(async () => ' fresh account password ')
 expect(await h.client.grantFor('GET', '/api/v1/data/export')).toBe('bound-grant')
 expect(h.sent.find(x => x.path.endsWith('/account/fresh'))?.body).toMatchObject({ password: ' fresh account password ', action: 'export', method: 'GET', path: '/api/v1/data/export' })
 await h.client.recover('warden-recovery-v1:' + encode(h.root))
 await h.client.resetPassword(' replacement password ', ' replacement password ')
 expect(h.sent.find(x => x.path.endsWith('/account/reset'))?.body).toEqual({ password: ' replacement password ', password_confirmation: ' replacement password ' })
 expect(h.client.getSnapshot()).toMatchObject({ authenticated: false, unlocked: false, recovering: false })
 expect(h.credentials.get).not.toHaveBeenCalled(); expect(h.credentials.create).not.toHaveBeenCalled()
})
test('account forms clear passwords and fresh action requires a new accessible password form each time', async () => {
 const h = await harness(); render(<AuthGate client={h.client}><p>Managed account</p></AuthGate>)
 fireEvent.change(await screen.findByLabelText('Username'), { target: { value: 'owner' } })
 fireEvent.change(screen.getByLabelText('Password'), { target: { value: ' exact account password ' } })
 fireEvent.click(screen.getByRole('button', { name: 'Log in and unlock' }))
 expect(await screen.findByText('Managed account')).toBeInTheDocument()
 expect(screen.queryByLabelText('Password')).toBeNull()
 let pending!: Promise<string | undefined>
 act(() => { pending = h.client.grantFor('GET', '/api/v1/data/export') })
 const dialog = await screen.findByRole('dialog', { name: 'Verify your password' })
 expect(dialog).toBeInTheDocument()
 fireEvent.change(screen.getByLabelText('Current password'), { target: { value: ' fresh account password ' } })
 fireEvent.click(screen.getByRole('button', { name: 'Verify password' }))
 await act(async () => { expect(await pending).toBe('bound-grant') })
 expect(screen.queryByRole('dialog')).toBeNull()
 act(() => { pending = h.client.grantFor('GET', '/api/v1/data/export') })
 expect(await screen.findByLabelText('Current password')).toHaveValue('')
 fireEvent.click(screen.getByRole('button', { name: 'Cancel verification' }))
 await expect(pending).rejects.toThrow(/cancel/i)
 expect(h.sent.filter(x => x.path.endsWith('/account/fresh'))).toHaveLength(1)
 expect(h.credentials.get).not.toHaveBeenCalled()
})
