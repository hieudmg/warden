import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { SetupClient } from './setup'
import { encode } from './vault-wrap'
import { mountSetup } from './setup-view'
beforeEach(() => vi.stubGlobal('crypto', webcrypto))
afterEach(() => { vi.unstubAllGlobals(); document.body.replaceChildren() })
test('account setup uses temporary authorization and recovery reentry without WebAuthn', async () => {
 const sent: { path: string, body: Record<string, unknown> }[] = []
 const fetcher = vi.fn(async (path: RequestInfo | URL, options?: RequestInit) => {
  const route = String(path); sent.push({ path: route, body: JSON.parse(String(options?.body)) })
  return new Response(JSON.stringify(route.endsWith('/password') ? { csrf: 'csrf', auth_method: 'account' } : route.endsWith('/account/begin') ? { vault_id: encode(new Uint8Array(16)) } : {}), { status: 200 })
 })
 const credentials = { create: vi.fn(() => { throw Error('WebAuthn forbidden') }), get: vi.fn(() => { throw Error('WebAuthn forbidden') }) }
 const client = new SetupClient(fetcher, credentials)
 await client.authorize('23456789'); expect(client.authenticationMethod()).toBe('account')
 await expect(client.registerAccount('owner', ' exact account password ', 'wrong')).rejects.toThrow(/match/)
 expect(sent).toHaveLength(1)
 const saved = await client.registerAccount('owner', ' exact account password ', ' exact account password ')
 expect(saved).toMatch(/^warden-recovery-v1:/)
 expect(sent.find(x => x.path.endsWith('/account/prepare'))?.body).toMatchObject({ username: 'owner', password: ' exact account password ', password_confirmation: ' exact account password ', recovery_wrapper: { kind: 'recovery' } })
 expect(sent.some(x => x.path.endsWith('/finalize'))).toBe(false)
 await client.confirm(saved)
 expect(sent.at(-1)?.path).toMatch(/finalize$/)
 expect(credentials.create).not.toHaveBeenCalled(); expect(credentials.get).not.toHaveBeenCalled()
})
test('account setup page presents selected mode and accessible confirmed password fields', async () => {
 const root = document.createElement('main'); document.body.append(root)
 const client = { authorize: vi.fn(async () => {}), authenticationMethod: () => 'account' as const, register: vi.fn(), registerAccount: vi.fn(async () => 'warden-recovery-v1:fixture'), confirm: vi.fn(), cancel: vi.fn() }
 mountSetup(root, client)
 const input = root.querySelector('input')!; input.value = '23456789'; root.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
 await vi.waitFor(() => expect(root.textContent).toContain('Create your owner account'))
 expect(root.querySelector('input[name="username"]')).not.toBeNull()
 expect(root.querySelector('input[name="password_confirmation"]')).not.toBeNull()
 expect(root.textContent).not.toContain('Register and verify passkey')
})
