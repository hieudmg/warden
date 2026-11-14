import { decode, encode, unwrap, wrap, parseRecoveryKey, recoveryAuth, randomBytes } from '../setup/vault-wrap'
import { sensitiveAction } from './actions'
import type { Wrapper } from '../setup/vault-wrap'
import { signedCredential } from '../setup/setup'
import { invalidateSecurity, onSecurityDenied, setCSRF } from './session'

type WireAssertion = Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & { challenge: string, allowCredentials?: { id: string, type: 'public-key' }[] }
interface Begin { id: string, options: { publicKey: WireAssertion }, credential_id: string, prf_input?: string }
interface State { ready: boolean, authenticated: boolean, unlocked: boolean, recovering?: boolean }
type WireCreation = Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials'> & { challenge: string, user: Omit<PublicKeyCredentialUserEntity, 'id'> & { id: string }, excludeCredentials?: { id: string, type: 'public-key' }[] }
interface Login { authenticated: boolean, unlocked: boolean, csrf: string, credential_id: string }

export class AuthClient {
  private csrf = ''
  private credential = ''
  private epoch = 0
  private controller = new AbortController()
  private rotation?: { id: string, wrapper: Wrapper }
  private state: State = { ready: false, authenticated: false, unlocked: false }
  private listeners = new Set<() => void>()
  constructor(private fetcher: typeof fetch = (input, options) => fetch(input, options), private credentials: Pick<CredentialsContainer, 'get'> & Partial<Pick<CredentialsContainer, 'create'>> = { get: options => navigator.credentials.get(options), create: options => navigator.credentials.create(options) }) {}
  getSnapshot = () => this.state
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener) } }
  private change(state: State) { this.state = state; for (const listener of this.listeners) listener() }
  private check(epoch: number) { if (epoch !== this.epoch) throw Error('Authentication operation cancelled') }
  cancel = () => { this.epoch++; this.controller.abort(); this.controller = new AbortController(); this.rotation = undefined; invalidateSecurity() }
  watch = () => onSecurityDenied(status => {
    this.cancel()
    if (status === 401) this.csrf = ''
    this.change({ ready: true, authenticated: status !== 401 && this.state.authenticated, unlocked: false })
  })
  private async request<T>(path: string, body?: unknown, grant?: string): Promise<T> {
    const epoch = this.epoch
    const response = await this.fetcher('/api/v1/auth/' + path, { method: body === undefined ? 'GET' : 'POST', cache: 'no-store', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', ...(this.csrf ? { 'X-CSRF-Token': this.csrf } : {}), ...(grant ? { 'X-Warden-Action': grant } : {}) }, body: body === undefined ? undefined : JSON.stringify(body), signal: this.controller.signal })
    this.check(epoch)
    if (!response.ok) throw Error(`Authentication request rejected (${response.status}). Log in again if the session expired.`)
    const data = await response.json() as T
    this.check(epoch)
    return data
  }
  async status() {
    if (this.state.recovering) return
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
  async grantFor(method: string, path: string, body = ''): Promise<string | undefined> {
    const action = sensitiveAction(method, path)
    if (!action) return undefined
    if (!this.state.authenticated || !this.state.unlocked || this.state.recovering) throw Error('Log in and unlock before a sensitive action')
    const epoch = this.epoch
    const digest = encode(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)))
    this.check(epoch)
    const b = await this.request<Begin>('fresh/begin', { action, credential_id: this.credential, method, path, digest })
    const credential = await this.credentials.get({ publicKey: this.options(b, false), signal: this.controller.signal }) as PublicKeyCredential | null
    this.check(epoch)
    if (!credential) throw Error('Fresh passkey verification cancelled')
    return (await this.request<{ grant: string }>('fresh/finish', { id: b.id, credential: signedCredential(credential, false) })).grant
  }
  async listPasskeys(): Promise<string[]> { return (await this.request<{ credentials: string[] }>('passkeys/list')).credentials }
  async removePasskey(id: string) {
    const body = { credential_id: id }, epoch = this.epoch
    const grant = await this.grantFor('POST', '/api/v1/auth/passkeys/remove', JSON.stringify(body))
    this.check(epoch)
    await this.request('passkeys/remove', body, grant)
    if (id === this.credential) { this.cancel(); this.csrf = ''; setCSRF(''); this.change({ ready: true, authenticated: false, unlocked: false, recovering: false }) }
  }
  async addPasskey() {
    const epoch = this.epoch, recovering = !!this.state.recovering
    let prf: Uint8Array<ArrayBuffer> | undefined, dek: Uint8Array<ArrayBuffer> | undefined, round: Uint8Array<ArrayBuffer> | undefined
    try {
      const grant = recovering ? undefined : await this.grantFor('POST', '/api/v1/auth/passkeys/begin', '{}')
      const b = await this.request<{ id: string, options: { publicKey: WireCreation } }>('passkeys/begin', {}, grant)
      const c = b.options.publicKey
      const created = await this.credentials.create?.({ publicKey: { ...c, challenge: decode(c.challenge, 32), user: { ...c.user, id: decode(c.user.id, 32) }, excludeCredentials: c.excludeCredentials?.map(x => ({ ...x, id: decode(x.id, -1) })), extensions: { prf: {} } as AuthenticationExtensionsClientInputs }, signal: this.controller.signal }) as PublicKeyCredential | null
      this.check(epoch)
      if (!created) throw Error('Passkey registration cancelled')
      const registered = await this.request<Begin & { vault_id: string }>('passkeys/registration', { id: b.id, credential: signedCredential(created, true) })
      // Creation capability/results are never sufficient: independently signed get.
      const asserted = await this.credentials.get({ publicKey: this.options(registered, true), signal: this.controller.signal }) as PublicKeyCredential | null
      const result = asserted && (asserted.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } }).prf?.results?.first
      if (result) prf = new Uint8Array(result)
      this.check(epoch)
      if (!asserted || encode(asserted.rawId) !== registered.credential_id) throw Error('New passkey assertion cancelled or mismatched')
      if (!prf || prf.byteLength !== 32) throw Error('The new passkey must return working WebAuthn PRF output. Nothing was committed.')
      await this.request('passkeys/assertion', { id: b.id, credential: signedCredential(asserted, false) })
      const body = { id: b.id }
      const deliveryGrant = recovering ? undefined : await this.grantFor('POST', '/api/v1/auth/passkeys/key', JSON.stringify(body))
      const delivery = await this.request<{ dek: string, vault_id: string, prf_input: string }>('passkeys/key', body, deliveryGrant)
      dek = decode(delivery.dek, 32)
      const wrapper = await wrap(prf, dek, 'passkey', delivery.vault_id, registered.credential_id, registered.prf_input)
      round = await unwrap(wrapper, prf, 'passkey', delivery.vault_id, registered.credential_id)
      if (!round.every((v, i) => v === dek![i])) throw Error('New passkey wrapper round-trip failed')
      this.check(epoch)
      await this.request('passkeys/commit', { id: b.id, wrapper, dek: encode(round) })
      if (recovering) { this.cancel(); this.csrf = ''; setCSRF(''); this.change({ ready: true, authenticated: false, unlocked: false, recovering: false }) }
    } finally { prf?.fill(0); dek?.fill(0); round?.fill(0) }
  }
  async recover(saved: string) {
    this.cancel()
    const epoch = this.epoch
    let root: Uint8Array<ArrayBuffer> | undefined, proof: Uint8Array<ArrayBuffer> | undefined, dek: Uint8Array<ArrayBuffer> | undefined
    try {
      root = parseRecoveryKey(saved)
      const b = await this.request<{ id: string, kdf_salt: string }>('recovery/begin', {})
      proof = await recoveryAuth(root, b.kdf_salt)
      this.check(epoch)
      const verified = await this.request<{ csrf: string, grant: string, wrapper: Wrapper }>('recovery/proof', { id: b.id, proof: encode(proof) })
      this.csrf = verified.csrf; setCSRF(this.csrf)
      this.change({ ready: true, authenticated: false, unlocked: false, recovering: true })
      dek = await unwrap(verified.wrapper, root, 'recovery', verified.wrapper.vault_id, '')
      this.check(epoch)
      await this.request('recovery/unlock', { grant: verified.grant, dek: encode(dek) })
      this.change({ ready: true, authenticated: false, unlocked: true, recovering: true })
    } finally { root?.fill(0); proof?.fill(0); dek?.fill(0) }
  }
  async abortRecovery() {
    this.cancel()
    try { await this.request('recovery/abort', {}) }
    finally { this.csrf = ''; setCSRF(''); this.change({ ready: true, authenticated: false, unlocked: false, recovering: false }) }
  }
  async rotateRecovery(): Promise<string> {
    const epoch = this.epoch
    let dek: Uint8Array<ArrayBuffer> | undefined, root: Uint8Array<ArrayBuffer> | undefined, proof: Uint8Array<ArrayBuffer> | undefined, round: Uint8Array<ArrayBuffer> | undefined
    try {
      const grant = await this.grantFor('POST', '/api/v1/auth/recovery/rotation/key', '{}')
      const b = await this.request<{ id: string, dek: string, vault_id: string }>('recovery/rotation/key', {}, grant)
      dek = decode(b.dek, 32); root = randomBytes(32)
      const wrapper = await wrap(root, dek, 'recovery', b.vault_id, '')
      round = await unwrap(wrapper, root, 'recovery', b.vault_id, '')
      if (!round.every((v, i) => v === dek![i])) throw Error('Recovery round-trip failed')
      proof = await recoveryAuth(root, wrapper.kdf_salt)
      const verifier = encode(await crypto.subtle.digest('SHA-256', proof))
      this.check(epoch)
      await this.request('recovery/rotation/prepare', { id: b.id, wrapper, verifier })
      this.check(epoch)
      this.rotation = { id: b.id, wrapper }
      return 'warden-recovery-v1:' + encode(root)
    } finally { dek?.fill(0); root?.fill(0); proof?.fill(0); round?.fill(0) }
  }
  async confirmRecoveryRotation(saved: string) {
    if (!this.rotation) throw Error('No pending recovery rotation')
    const epoch = this.epoch, pending = this.rotation
    let root: Uint8Array<ArrayBuffer> | undefined, dek: Uint8Array<ArrayBuffer> | undefined, proof: Uint8Array<ArrayBuffer> | undefined
    try {
      root = parseRecoveryKey(saved); dek = await unwrap(pending.wrapper, root, 'recovery', pending.wrapper.vault_id, ''); proof = await recoveryAuth(root, pending.wrapper.kdf_salt)
      this.check(epoch)
      await this.request('recovery/rotation/commit', { id: pending.id, proof: encode(proof), dek: encode(dek) })
      this.rotation = undefined
    } finally { root?.fill(0); dek?.fill(0); proof?.fill(0) }
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
