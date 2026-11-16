const assert = require('node:assert/strict')

const mountReadPaths = new Set(['/api/v1/ssh-connections', '/api/v1/db-connections', '/api/v1/groups', '/api/v1/projects', '/api/v1/key-pairs'])
const completed = request => request.status >= 200 && request.status < 300 && request.finished && !request.failure

/** Browser evidence gate shared by the production journey and deterministic tests. */
function assertNetworkComplete(network, { origin, imageOrigin, assets, verifiedTransitions = {} }) {
  const completedAssets = assets.map(name => {
    const request = network.find(request => request.url === `${origin}/${name}` && completed(request))
    assert(request, `production asset response not successfully completed: ${name}`)
    return { name, status: request.status, finished: request.finished }
  })
  const expectedFailures = []
  for (const [index, request] of network.entries()) {
    const url = new URL(request.url)
    if (!['http:', 'https:'].includes(url.protocol) || ![origin, imageOrigin].includes(url.origin)) continue
    const statusProbe = url.origin === origin && url.pathname === '/api/v1/auth/status' && request.method === 'GET'
    const initialProbe = statusProbe && request.phase === 'initial session probe' && request.status === 401
    const logoutProbe = statusProbe && request.phase === 'logout confirmation' && request.status === 401 && verifiedTransitions.loggedOut
    let expectedCancellation
    if (request.failure === 'net::ERR_ABORTED') {
      if (initialProbe) expectedCancellation = 'initial unauthenticated probe body discarded'
      // StrictMode/root invalidation cancels the first mount's list reads. Do
      // not exempt a missing replacement, a later failure, or any asset abort.
      const firstMountRead = url.origin === origin && request.method === 'GET' && request.phase === 'management' && mountReadPaths.has(url.pathname) && [null, 200].includes(request.status) && network.findIndex(candidate => candidate.url === request.url) === index
      if (firstMountRead && network.slice(index + 1).some(candidate => candidate.url === request.url && candidate.phase === 'management' && candidate.method === 'GET' && completed(candidate))) expectedCancellation = 'first mount read replaced by a completed response'
      // The UI cleanup also cancels transition requests. Only admit these when
      // separate normal-cookie HTTP probes prove the server changed state.
      const transition = url.origin === origin && request.method === 'POST' && [null, 200].includes(request.status) && ['lock', 'logout'].includes(request.phase) && url.pathname === `/api/v1/auth/${request.phase}`
      const verified = request.phase === 'lock' ? verifiedTransitions.locked : verifiedTransitions.loggedOut
      const probeStatus = request.phase === 'lock' ? 200 : 401
      if (transition && verified && network.slice(index + 1).some(candidate => candidate.url === `${origin}/api/v1/auth/status` && candidate.method === 'GET' && candidate.phase === `${request.phase} confirmation` && candidate.status === probeStatus && candidate.finished && !candidate.failure)) expectedCancellation = 'transition independently confirmed against server state'
    }
    if (expectedCancellation) {
      expectedFailures.push({ ...request, reason: expectedCancellation })
      continue
    }
    assert(!request.failure, `fixture request failed: ${request.url}: ${request.failure}`)
    assert(request.finished, `fixture request incomplete: ${request.url}`)
    assert(request.status >= 200 && request.status < 300 || initialProbe || logoutProbe, `fixture response unsuccessful: ${request.url}: ${request.status}`)
    if (initialProbe || logoutProbe) expectedFailures.push({ ...request, reason: 'expected unauthenticated status probe' })
  }
  return { completedAssets, expectedFailures }
}

module.exports = { assertNetworkComplete }
