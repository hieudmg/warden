const assert = require('node:assert/strict')
const { test } = require('node:test')
const { EventEmitter } = require('node:events')
const { completedRequest, trackRequests } = require('../e2e/auth-lifecycle.cjs')
const { assertNetworkComplete } = require('../e2e/ui-privacy-network.cjs')
const origin = 'https://localhost:12345'
const options = {origin,imageOrigin:origin,assets:[],verifiedTransitions:{locked:true,loggedOut:true}}
const path = '/api/v1/auth/passkeys/list'
function request(status = 200) { return {url:() => origin + path,method:() => 'GET',response:async () => ({status:() => status}),failure:() => ({errorText:'net::ERR_ABORTED'})} }
test('post-lock list barrier awaits a newly started full body, not old completion or 200 headers', async () => {
 const page = new EventEmitter(), old = request(), current = request()
 const ready = completedRequest(page,path); let completed = false; ready.then(() => {completed = true})
 page.emit('requestfinished',old); page.emit('request',current); page.emit('response',{request:() => current,status:() => 200})
 await Promise.resolve(); assert.equal(completed,false)
 page.emit('requestfinished',current); assert.equal(await ready,current)
 assert.equal(page.listenerCount('requestfailed'),0)
})
test('post-lock list barrier rejects cancellation even after 200 headers', async () => {
 const page = new EventEmitter(), current = request()
 const ready = completedRequest(page,path)
 page.emit('request',current); page.emit('response',{request:() => current,status:() => 200}); page.emit('requestfailed',current)
 await assert.rejects(ready,/ERR_ABORTED/)
 assert.equal(page.listenerCount('requestfinished'),0)
})
test('request tracking records pre-response failure and incomplete 200 instead of losing them', () => {
 const context = new EventEmitter(), network = trackRequests(context,() => 'lock'), failed = request(), incomplete = request()
 context.emit('request',failed); context.emit('requestfailed',failed)
 context.emit('request',incomplete); context.emit('response',{request:() => incomplete,status:() => 200})
 assert.equal(network[0].failure,'net::ERR_ABORTED'); assert.equal(network[0].status,null)
 assert.equal(network[1].finished,false); assert.equal(network[1].status,200)
 for (const record of network) assert.throws(() => assertNetworkComplete([record],options),/failed|incomplete/)
})
for (const phase of ['lock','logout']) for (const status of [null,200]) {
 test(`${phase} metadata cancellation (${status}) cannot be waived by a later replacement or verified transitions`, () => {
  const failed = {url:origin+path,method:'GET',phase,status,finished:false,failure:'net::ERR_ABORTED'}
  const replacement = {...failed,status:200,finished:true,failure:null}
  assert.throws(() => assertNetworkComplete([failed,replacement],options),/failed/)
 })
}
