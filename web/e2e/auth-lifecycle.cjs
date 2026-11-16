// Shared browser evidence for real HTTPS auth transitions. No response mocks.
const assert = require('node:assert/strict')
const https = require('node:https')

function trackRequests(context, phase) {
 const network = [], requests = new Map()
 context.on('request', request => {
  const record = { url:request.url(), method:request.method(), phase:phase(), status:null, finished:false, failure:null }
  requests.set(request,record); network.push(record)
 })
 context.on('response', response => { const record = requests.get(response.request()); if (record) record.status = response.status() })
 context.on('requestfinished', request => { const record = requests.get(request); if (record) record.finished = true })
 context.on('requestfailed', request => { const record = requests.get(request); if (record) record.failure = request.failure()?.errorText || 'Unknown request failure' })
 return network
}

// Register BEFORE the action: correlate one newly initiated request, not an old
// response or headers-only event. A failed request cannot satisfy the barrier.
function completedRequest(page, path, method = 'GET', timeout = 15000) {
 const promise = new Promise((resolve, reject) => {
  let selected
  const cleanup = () => { clearTimeout(timer); page.off('request', started); page.off('requestfinished', finished); page.off('requestfailed', failed); page.off('close', closed) }
  const stop = error => { cleanup(); reject(error) }
  const started = request => { if (!selected && new URL(request.url()).pathname === path && request.method() === method) selected = request }
  const finished = async request => {
   if (request !== selected) return
   cleanup()
   try { const response = await request.response(); assert(response && response.status() >= 200 && response.status() < 300, `unsuccessful ${method} ${path}`); resolve(request) } catch (error) { reject(error) }
  }
  const failed = request => { if (request === selected) stop(Error(`failed ${method} ${path}: ${request.failure()?.errorText}`)) }
  const closed = () => stop(Error(`page closed before ${method} ${path} completed`))
  const timer = setTimeout(() => stop(Error(`incomplete ${method} ${path}`)), timeout)
  timer.unref?.()
  page.on('request',started); page.on('requestfinished',finished); page.on('requestfailed',failed); page.on('close',closed)
 })
 // The click can fail before the caller reaches await; preserve its rejection
 // without creating an unhandled promise while the runner collects artifacts.
 promise.catch(() => {})
 return promise
}

// TEST ONLY: deliberately hold dispatch across the optimistic render/effect
// cleanup, obeying the caller's actual AbortSignal. Native fetch receives the
// unmodified request on release. No cookie, response or authentication bypass.
async function installTransitionHold(context) {
 await context.addInitScript(() => {
  const nativeFetch = window.fetch.bind(window)
  window.__authTransitionHold = { action:null, pending:false, aborted:false, release:null }
  window.fetch = async (input, init) => {
   const hold = window.__authTransitionHold
   if (hold.action && new URL(String(input), location.href).pathname === '/api/v1/auth/' + hold.action && init?.method === 'POST') {
    hold.action = null; hold.pending = true
    await new Promise((resolve,reject) => {
     const abort = () => { hold.aborted = true; reject(new DOMException('Held dispatch canceled','AbortError')) }
     if (init.signal?.aborted) { abort(); return }
     init.signal?.addEventListener('abort',abort,{once:true})
     hold.release = () => { init.signal?.removeEventListener('abort',abort); resolve() }
    })
   }
   return nativeFetch(input,init)
  }
 })
}
async function armTransition(page, action, held) {
 if (held) await page.evaluate(action => { Object.assign(window.__authTransitionHold,{action,pending:false,aborted:false,release:null}) }, action)
}
async function releaseTransition(page, held) {
 if (!held) return
 // Two rendering turns expose the state-change/unmount passive cleanup before
 // dispatch is released; unlike a sleep, this synchronizes browser scheduling.
 await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))))
 const observed = await page.evaluate(() => ({pending:window.__authTransitionHold.pending,aborted:window.__authTransitionHold.aborted}))
 assert.equal(observed.pending,true,'transition POST must reach the deliberate dispatch hold')
 assert.equal(observed.aborted,false,'transition POST was canceled by its own render cleanup')
 await page.evaluate(() => window.__authTransitionHold.release())
}

async function cookieHeader(page, origin) { return (await page.context().cookies(origin)).map(cookie => `${cookie.name}=${cookie.value}`).join('; ') }
// Existing fixture-only localhost certificate exception. These requests replay
// the PRE-transition cookie, so Set-Cookie deletion alone cannot fake revocation.
function oldCookieProbe(origin, path, cookie) {
 return new Promise((resolve,reject) => {
  const request = https.get(origin + path,{rejectUnauthorized:false,headers:{Cookie:cookie}},response => { response.resume(); response.on('end',() => resolve(response.statusCode)); response.on('error',reject) })
  request.on('error',reject); request.setTimeout(15000,() => request.destroy(Error('old-cookie probe timed out')))
 })
}
async function proveLocked(page, origin, cookie) {
 const state = await page.evaluate(async () => {
  const response = await fetch('/api/v1/auth/status',{cache:'no-store',credentials:'same-origin'})
  const state = await response.json(); return {status:response.status,authenticated:state.authenticated,unlocked:state.unlocked}
 })
 assert.deepEqual(state,{status:200,authenticated:true,unlocked:false},'server must be locked, not only the optimistic UI')
 const managementStatus = await oldCookieProbe(origin,'/api/v1/groups',cookie)
 assert.equal(managementStatus,423,'pre-existing session must lose protected management access after global lock')
 return { ...state, managementStatus }
}
async function proveLoggedOut(page, origin, cookie) {
 const status = await page.evaluate(async () => { const response = await fetch('/api/v1/auth/status',{cache:'no-store',credentials:'same-origin'}); await response.arrayBuffer(); return response.status })
 assert.equal(status,401,'browser must be unauthorized after logout')
 const oldSessionStatus = await oldCookieProbe(origin,'/api/v1/auth/status',cookie)
 assert.equal(oldSessionStatus,401,'server must revoke the pre-existing session, not merely delete its cookie')
 return { status, oldSessionStatus }
}
module.exports = {trackRequests,completedRequest,installTransitionHold,armTransition,releaseTransition,cookieHeader,proveLocked,proveLoggedOut}
