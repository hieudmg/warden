import { decode, encode, unwrap } from '../setup/vault-wrap'
import type { Wrapper } from '../setup/vault-wrap'
import { signedCredential } from '../setup/setup'
import { invalidateSecurity, onSecurityDenied, setCSRF } from './session'

type WireAssertion = Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & { challenge: string, allowCredentials?: { id: string, type: 'public-key' }[] }
interface Begin { id: string, options: { publicKey: WireAssertion }, credential_id: string, prf_input?: string }
interface State { ready: boolean, authenticated: boolean, unlocked: boolean }
interface Login { authenticated: boolean, unlocked: boolean, csrf: string, credential_id: string }

export class AuthClient {
  private csrf = ''
  private credential = ''
  private epoch = 0
  private controller = new AbortController()
  private state: State = { ready: false, authenticated: false, unlocked: false }
  private listeners = new Set<() => void>()
  constructor(private fetcher: typeof fetch = (input, options) => fetch(input, options), private credentials: Pick<CredentialsContainer, 'get'> = { get: options => navigator.credentials.get(options) }) {}
  getSnapshot = () => this.state
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener) } }
  private change(state: State) { this.state = state; for (const listener of this.listeners) listener() }
  private check(epoch: number) { if (epoch !== this.epoch) throw Error('Authentication operation cancelled') }
  cancel = () => { this.epoch++; this.controller.abort(); this.controller = new AbortController(); invalidateSecurity() }
  watch = () => onSecurityDenied(status => {
    this.cancel()
    if (status === 401) this.csrf = ''
    this.change({ ready: true, authenticated: status !== 401 && this.state.authenticated, unlocked: false })
  })
  private async request<T>(path: string, body?: unknown): Promise<T> {
    const epoch = this.epoch
    const response = await this.fetcher('/api/v1/auth/' + path, { method: body === undefined ? 'GET' : 'POST', cache: 'no-store', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', ...(this.csrf ? { 'X-CSRF-Token': this.csrf } : {}) }, body: body === undefined ? undefined : JSON.stringify(body), signal: this.controller.signal })
    this.check(epoch)
    if (!response.ok) throw Error(`Authentication request rejected (${response.status}). Log in again if the session expired.`)
    const data = await response.json() as T
    this.check(epoch)
    return data
  }
  async status() {
    const epoch = this.epoch
    try {
      const state = await this.request<Login>('status')
      if (this.state.unlocked && !state.unlocked || this.state.authenticated && !state.authenticated) this.cancel()
      this.csrf = state.csrf; setCSRF(this.csrf); this.credential = state.credential_id
      this.change({ ready: true, authenticated: state.authenticated, unlocked: state.unlocked })
    } catch {
      this.check(epoch)
      if (this.state.authenticated || this.state.unlocked) this.cancel()
      this.csrf = ''; setCSRF('')
      this.change({ ready: true, authenticated: false, unlocked: false })
    }
  }
  private options(b: Begin, prf: boolean): PublicKeyCredentialRequestOptions {
    const wire = b.options.publicKey
    return { ...wire, challenge: decode(wire.challenge, 32), allowCredentials: wire.allowCredentials?.map(c => ({ ...c, id: decode(c.id, -1) })), ...(prf ? { extensions: { prf: { eval: { first: decode(b.prf_input ?? '', 32) } } } as AuthenticationExtensionsClientInputs } : {}) }
  }
  async login() {
    this.cancel()
    const epoch = this.epoch
    const b = await this.request<Begin>('login/begin', {})
    const credential = await this.credentials.get({ publicKey: this.options(b, false), signal: this.controller.signal }) as PublicKeyCredential | null
    this.check(epoch)
    if (!credential) throw Error('Passkey login cancelled')
    const state = await this.request<Login>('login/finish', { id: b.id, credential: signedCredential(credential, false) })
    this.csrf = state.csrf; setCSRF(this.csrf); this.credential = state.credential_id
    this.change({ ready: true, authenticated: true, unlocked: state.unlocked })
  }
  async unlock() {
    const epoch = this.epoch
    let prf: Uint8Array<ArrayBuffer> | undefined, dek: Uint8Array<ArrayBuffer> | undefined
    try {
      // A NEW required-UV assertion, never an age flag or login's PRF result.
      // The server binds it to this session's credential before releasing wrapper.
      const b = await this.request<Begin>('fresh/begin', { action: 'unlock', credential_id: this.credential })
      const credential = await this.credentials.get({ publicKey: this.options(b, true), signal: this.controller.signal }) as PublicKeyCredential | null
      const result = credential && (credential.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } }).prf?.results?.first
      if (result) prf = new Uint8Array(result)
      this.check(epoch)
      if (!credential) throw Error('Passkey unlock cancelled')
      if (encode(credential.rawId) !== b.credential_id) throw Error('Wrong passkey credential')
      if (!prf || prf.byteLength !== 32) throw Error('This passkey did not return required WebAuthn PRF output. No plaintext-key fallback is available.')
      const verified = await this.request<{ grant: string, wrapper: Wrapper }>('fresh/finish', { id: b.id, credential: signedCredential(credential, false) })
      dek = await unwrap(verified.wrapper, prf, 'passkey', verified.wrapper.vault_id, b.credential_id)
      this.check(epoch)
      await this.request('unlock', { grant: verified.grant, dek: encode(dek) })
      this.check(epoch)
      this.change({ ready: true, authenticated: true, unlocked: true })
    } finally { prf?.fill(0); dek?.fill(0) }
  }
  async lock() {
    this.cancel()
    this.change({ ready: true, authenticated: this.state.authenticated, unlocked: false })
    await this.request('lock', {})
  }
  async logout() {
    this.cancel()
    this.change({ ready: true, authenticated: false, unlocked: false })
    try { await this.request('logout', {}) }
    finally { this.csrf = ''; setCSRF('') }
  }
}
export const authClient = new AuthClient()
