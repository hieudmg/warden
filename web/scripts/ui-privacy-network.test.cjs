const assert = require('node:assert/strict')
const test = require('node:test')
const { assertNetworkComplete } = require('../e2e/ui-privacy-network.cjs')

const origin = 'https://localhost:12345'
const imageOrigin = 'http://127.0.0.1:23456'
const assets = ['setup.js', 'shared.js', 'management.js', 'management.css', 'latin.woff2', 'latin-ext.woff2', 'cyrillic.woff2', 'cyrillic-ext.woff2', 'vietnamese.woff2'].map(name => `assets/${name}`)
const options = { origin, imageOrigin, assets }
const complete = url => ({ url, method: 'GET', status: 200, finished: true, failure: null })
const loaded = () => assets.map(name => complete(`${origin}/${name}`))

// These assertions exercise exactly the gate called before the browser writes PASS.
test('all nine assets require successful completed responses', () => {
  assert.doesNotThrow(() => assertNetworkComplete(loaded(), options))
})
test('a missing manifest asset is rejected', () => {
  assert.throws(() => assertNetworkComplete(loaded().slice(1), options), /asset/)
})
for (const [name, change] of [
  ['stylesheet HTTP 500 with completed body', { status: 500 }],
  ['stylesheet HTTP 200 headers without body completion', { finished: false }],
  ['stylesheet transfer failure after HTTP 200 headers', { finished: false, failure: 'net::ERR_CONTENT_LENGTH_MISMATCH' }],
  ['stylesheet caller cancellation', { finished: false, failure: 'net::ERR_ABORTED' }],
]) {
  test(`the production gate rejects ${name}`, () => {
    const network = loaded()
    Object.assign(network[3], change)
    assert.throws(() => assertNetworkComplete(network, options), /asset|response|request|complete|failed/i)
  })
}
for (const [name, change] of [
  ['HTTP 500', { status: 500 }],
  ['transport failure', { status: null, finished: false, failure: 'net::ERR_CONNECTION_RESET' }],
  ['unfinished HTTP 200', { finished: false }],
]) {
  test(`unexpected fixture API ${name} blocks PASS`, () => {
    const request = { ...complete(`${origin}/api/v1/projects`), ...change }
    assert.throws(() => assertNetworkComplete([...loaded(), request], options), /response|request|complete|failed/i)
  })
}
test('a later successful retry cannot hide a failed stylesheet response', () => {
  const failed = { ...complete(`${origin}/${assets[3]}`), status: 500 }
  assert.throws(() => assertNetworkComplete([failed, ...loaded()], options), /response|request|failed/i)
})
test('the intentional independent HTTP image response is recorded and accepted', () => {
  assert.doesNotThrow(() => assertNetworkComplete([...loaded(), complete(`${imageOrigin}/unique.svg`)], options))
})
test('the completed initial unauthenticated status probe is an explicit HTTP 401 exception', () => {
  const probe = { ...complete(`${origin}/api/v1/auth/status`), status: 401, phase: 'initial session probe' }
  assert.doesNotThrow(() => assertNetworkComplete([...loaded(), probe], options))
})
test('the initial HTTP 401 probe may discard its body with net::ERR_ABORTED only', () => {
  const probe = { ...complete(`${origin}/api/v1/auth/status`), status: 401, phase: 'initial session probe', finished: false, failure: 'net::ERR_ABORTED' }
  assert.doesNotThrow(() => assertNetworkComplete([...loaded(), probe], options))
  assert.throws(() => assertNetworkComplete([...loaded(), { ...probe, failure: 'net::ERR_CONNECTION_RESET' }], options), /request failed/)
})
test('HTTP 401 is not exempt outside the initial GET status probe', () => {
  for (const request of [
    { ...complete(`${origin}/api/v1/auth/status`), status: 401, phase: 'management' },
    { ...complete(`${origin}/api/v1/projects`), status: 401, phase: 'initial session probe' },
    { ...complete(`${origin}/api/v1/auth/status`), status: 401, phase: 'initial session probe', method: 'POST' },
  ]) assert.throws(() => assertNetworkComplete([...loaded(), request], options), /response/i)
})
test('only the first mount read cancellation with a later completed replacement is expected', () => {
  const url = `${origin}/api/v1/ssh-connections`
  const aborted = { ...complete(url), status: null, finished: false, failure: 'net::ERR_ABORTED', phase: 'management' }
  const replacement = { ...complete(url), phase: 'management' }
  assert.doesNotThrow(() => assertNetworkComplete([...loaded(), aborted, replacement], options))
  for (const network of [
    [...loaded(), aborted],
    [...loaded(), replacement, aborted],
    [...loaded(), { ...aborted, phase: 'logout' }, replacement],
    [...loaded(), { ...aborted, failure: 'net::ERR_CONNECTION_RESET' }, replacement],
    [...loaded(), { ...aborted, status: 500 }, replacement],
  ]) assert.throws(() => assertNetworkComplete(network, options), /request|response/i)
})
for (const [phase, key, status] of [['lock', 'locked', 200], ['logout', 'loggedOut', 401]]) {
  test(`${phase} cancellation is rejected even with an independently verified completed probe`, () => {
    const aborted = { ...complete(`${origin}/api/v1/auth/${phase}`), method: 'POST', phase, status: null, finished: false, failure: 'net::ERR_ABORTED' }
    const probe = { ...complete(`${origin}/api/v1/auth/status`), status, phase: `${phase} confirmation` }
    const network = [...loaded(), aborted, probe]
    const verified = { ...options, verifiedTransitions: { [key]: true } }
    assert.throws(() => assertNetworkComplete(network, verified), /request failed/)
    assert.throws(() => assertNetworkComplete([...loaded(), { ...aborted, status: 200 }, probe], verified), /request failed/)
    assert.throws(() => assertNetworkComplete([...loaded(), { ...aborted, failure: null, status: 200 }, probe], verified), /incomplete/)
    assert.throws(() => assertNetworkComplete(network, options), /request failed/)
    assert.throws(() => assertNetworkComplete([...loaded(), aborted], verified), /request failed/)
    assert.throws(() => assertNetworkComplete([...loaded(), { ...aborted, failure: 'net::ERR_CONNECTION_RESET' }, probe], verified), /request failed/)
  })
}
test('the completed unauthenticated logout confirmation is an explicit HTTP 401 exception', () => {
  const probe = { ...complete(`${origin}/api/v1/auth/status`), status: 401, phase: 'logout confirmation' }
  assert.doesNotThrow(() => assertNetworkComplete([...loaded(), probe], { ...options, verifiedTransitions: { loggedOut: true } }))
  assert.throws(() => assertNetworkComplete([...loaded(), probe], options), /response/i)
})
test('an independent image-host HTTP failure blocks PASS', () => {
  const failed = { ...complete(`${imageOrigin}/unique.svg`), status: 503 }
  assert.throws(() => assertNetworkComplete([...loaded(), failed], options), /response|request|failed/i)
})
