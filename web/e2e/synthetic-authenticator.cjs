// TEST ONLY: synthetic signed WebAuthn + injected PRF support, NOT a genuine
// authenticator, hardware attestation, or proof of browser/provider PRF support.
// Loaded with Playwright addInitScript; never imported by either production entry.
module.exports = async function syntheticAuthenticator(seed) {
  if (!globalThis.crypto?.subtle) return // Initial about:blank is not the HTTPS fixture.
  const bytes = value => new Uint8Array(value)
  const join = (...values) => new Uint8Array(values.flatMap(value => Array.from(bytes(value))))
  const utf8 = value => new TextEncoder().encode(value)
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
  const encode = value => btoa(String.fromCharCode(...bytes(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  const hash = async value => new Uint8Array(await crypto.subtle.digest('SHA-256', value))
  const length = (major, value) => value < 24 ? bytes([major * 32 + value]) : value < 256 ? bytes([major * 32 + 24, value]) : bytes([major * 32 + 25, value >> 8, value & 255])
  const cbor = value => {
    if (typeof value === 'number') return value >= 0 ? length(0, value) : length(1, -1 - value)
    if (typeof value === 'string') { const text = utf8(value); return join(length(3, text.length), text) }
    if (value instanceof Uint8Array) return join(length(2, value.length), value)
    const entries = value instanceof Map ? [...value] : Object.entries(value)
    return join(length(5, entries.length), ...entries.flatMap(([key, item]) => [cbor(key), cbor(item)]))
  }
  const id = bytes([9, 8, 7, 6]), prf = bytes(Array(32).fill(42))
  let owner
  const counter = 0 // Signature counters are intentionally unsupported by this fixture.
  const key = crypto.subtle.importKey('jwk', seed, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
  const clientData = (type, challenge) => utf8(JSON.stringify({ type, challenge: encode(challenge), origin: location.origin, crossOrigin: false }))
  const der = signature => {
    const integer = part => { let offset = 0; while (offset < part.length - 1 && part[offset] === 0) offset++; part = part.slice(offset); if (part[0] & 128) part = join(bytes([0]), part); return join(bytes([2, part.length]), part) }
    const body = join(integer(signature.slice(0, 32)), integer(signature.slice(32)))
    return join(bytes([48, body.length]), body)
  }
  const common = response => ({ id: encode(id), rawId: id.slice().buffer, type: 'public-key', response, getClientExtensionResults: () => globalThis.__syntheticNoPRF ? {} : ({ prf: { enabled: true, results: { first: prf.slice().buffer } } }) })
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: {
    create: async ({ publicKey: options }) => {
      owner = bytes(options.user.id); globalThis.__syntheticOwner = Array.from(owner)
      const data = clientData('webauthn.create', options.challenge)
      const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, decode(seed.x)], [-3, decode(seed.y)]]))
      const authData = join(await hash(utf8(options.rp.id)), bytes([0x45, 0, 0, 0, 0]), bytes(Array(16).fill(0)), bytes([0, id.length]), id, cose)
      return common({ clientDataJSON: data.buffer, attestationObject: cbor({ fmt: 'none', attStmt: {}, authData }).buffer })
    },
    get: async ({ publicKey: options }) => {
      const data = clientData('webauthn.get', options.challenge)
      const authData = join(await hash(utf8(options.rpId)), bytes([5, counter >>> 24, counter >>> 16, counter >>> 8, counter]))
      const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, await key, join(authData, await hash(data))))
      return common({ clientDataJSON: data.buffer, authenticatorData: authData.buffer, signature: der(signature).buffer, userHandle: bytes(owner || globalThis.__syntheticOwner || []).buffer })
    },
  } })
}
