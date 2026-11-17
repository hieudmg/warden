#!/usr/bin/env node
// Isolated account browser lifecycle. Uses production assets and the same
// documented shared Chromium as ui-privacy.cjs, with NO WebAuthn substitution.
// Screenshots/traces/video contain disposable secrets: keep the output private.
const assert = require('node:assert/strict')
const fs = require('node:fs/promises')
const os = require('node:os')
const path = require('node:path')
const https = require('node:https')
const { spawn, spawnSync } = require('node:child_process')
const { assertNetworkComplete } = require('./ui-privacy-network.cjs')
const { trackRequests, completedRequest, installTransitionHold, armTransition, releaseTransition, cookieHeader, proveLocked, proveLoggedOut } = require('./auth-lifecycle.cjs')
const shared = require(path.join(os.homedir(), '.local/share/playwright-global/index.cjs'))
process.umask(0o077)
const repo = path.resolve(__dirname, '../..')
const project = process.env.PW_REFERENCE_PROJECT || '/var/www/code/php/dispatcher'
const output = path.resolve(process.env.WARDEN_ACCOUNT_ARTIFACTS || '/var/tmp/warden-account-browser-artifacts')
const delay = ms => new Promise(resolve => setTimeout(resolve, ms))
async function waitFor(action, message) {
 for (let n = 0; n < 400; n++) { try { const value = await action(); if (value) return value } catch {} await delay(50) }
 throw Error(message)
}
// Test-only self-signed loopback exception, never a production trust claim.
function ready(origin) { return new Promise(resolve => { const req = https.get(origin + '/', { rejectUnauthorized: false }, res => { res.resume(); resolve(res.statusCode === 200) }); req.on('error', () => resolve(false)); req.setTimeout(300, () => req.destroy()) }) }
async function main() {
 await fs.mkdir(output, { recursive: true, mode: 0o700 }); await fs.chmod(output, 0o700)
 const dir = await fs.mkdtemp(path.join('/var/tmp', 'warden-t9-browser-account-'))
 const children = [], errors = [], csp = [], videos = [], verifiedTransitions = {}, serverProofs = {}
 let network = [], phase = 'setup'
 let browser, context, page, runtime, sequence = 0, password = ' disposable account password '
 const fixture = kind => {
  const child = spawn('go', ['test', `./internal/server/${kind}`, '-run', `^TestUIBrowserAccount${kind === 'setup' ? 'Setup' : 'Runtime'}Fixture$`, '-count=1', '-v', '-timeout=200s'], { cwd: repo, env: { ...process.env, TMPDIR: '/var/tmp', WARDEN_UI_BROWSER_DIR: dir } })
  children.push(child); const chunks = [], number = ++sequence
  child.stdout.on('data', b => chunks.push(b)); child.stderr.on('data', b => chunks.push(b))
  child.completed = new Promise(resolve => child.on('exit', async code => { await fs.writeFile(path.join(output, `${number}-${kind}.log`), Buffer.concat(chunks), { mode: 0o600 }); resolve(code) }))
  return child
 }
 const visible = locator => locator.waitFor({ state: 'visible' })
 const screenshot = name => page.screenshot({ path: path.join(output, name + '.png'), fullPage: true })
 const responsiveScreenshots = async name => {
  for (const [size, viewport] of [['desktop', { width: 1440, height: 1000 }], ['mobile', { width: 375, height: 812 }]]) {
   await page.setViewportSize(viewport)
   for (const label of ['Warden security', 'Account and recovery']) {
    const region = page.getByRole('region', { name: label, exact: true })
    if (await region.count()) assert(await region.evaluate(el => el.scrollWidth <= el.clientWidth && el.getBoundingClientRect().right <= innerWidth), `${label} overflows at ${size}`)
   }
   await screenshot(`${name}-${size}`)
  }
  await page.setViewportSize({ width: 1440, height: 1000 })
 }
 try {
  assert.equal(spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem'), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' }).status, 0)
  const setup = fixture('setup')
  const cfg = await waitFor(async () => JSON.parse(await fs.readFile(path.join(dir, 'config.json'), 'utf8')), 'setup config unavailable')
  assert.equal(cfg.auth_method, 'account'); const origin = cfg.public_origin
  await waitFor(() => ready(origin), 'setup HTTPS unavailable')
  browser = await shared.connect({ project })
  context = await browser.newContext({ ignoreHTTPSErrors: true, recordVideo: { dir: path.join(output, 'video') }, acceptDownloads: true })
  await context.tracing.start({ screenshots: true, snapshots: true, sources: true })
  const heldDispatch = process.env.WARDEN_UI_HOLD_TRANSITIONS === '1'
  if (heldDispatch) await installTransitionHold(context)
  await context.addInitScript(() => {
   globalThis.__credentialCalls = 0; globalThis.__accountCSP = []
   Object.defineProperty(navigator, 'credentials', { configurable: true, get() { globalThis.__credentialCalls++; throw Error('Account mode must not access navigator.credentials') } })
   document.addEventListener('securitypolicyviolation', e => globalThis.__accountCSP.push({ directive: e.effectiveDirective, blocked: e.blockedURI }))
  })
  context.on('page', p => { if (p.video()) videos.push(p.video()); p.on('pageerror', e => errors.push(e.message)) })
  network = trackRequests(context, () => phase)
  page = await context.newPage(); page.setDefaultTimeout(15000)
  const check = async () => { assert.equal(await page.evaluate(() => globalThis.__credentialCalls), 0); csp.push(...await page.evaluate(() => globalThis.__accountCSP)); assert.equal(csp.length, 0); assert.equal(errors.length, 0) }
  await page.goto(origin); assert.equal(await page.evaluate(() => isSecureContext), true)
  await screenshot('01-setup-welcome')
  await page.getByLabel('Setup password', { exact: true }).fill('23456789'); await page.getByRole('button', { name: 'Continue', exact: true }).click()
  await visible(page.getByRole('heading', { name: 'Create your owner account' })); await screenshot('02-account-creation')
  await page.getByLabel('Username', { exact: true }).fill('owner'); await page.getByLabel('Password', { exact: true }).fill(password); await page.getByLabel('Confirm password', { exact: true }).fill(password)
  await page.getByRole('button', { name: 'Create account and recovery key' }).click()
  await visible(page.getByRole('heading', { name: 'Save your offline recovery key' }))
  let saved = await page.locator('pre').textContent(); await screenshot('03-offline-recovery-private')
  await page.getByRole('button', { name: 'I saved it — hide and re-enter' }).click(); await page.getByLabel('Saved recovery key', { exact: true }).fill(saved)
  await page.getByRole('button', { name: 'Continue', exact: true }).click(); await visible(page.getByRole('heading', { name: 'Warden initialized' })); await check()
  assert.equal(await setup.completed, 0)
  runtime = fixture('runtime'); await waitFor(() => ready(origin), 'runtime HTTPS unavailable')
  phase = 'initial session probe'
  await page.goto(origin)
  const login = async () => { phase = 'management'; await page.getByLabel('Username', { exact: true }).fill('owner'); await page.getByLabel('Password', { exact: true }).fill(password); await page.getByRole('button', { name: 'Log in and unlock' }).click(); await visible(page.getByRole('heading', { name: 'Warden Hub' })) }
  await visible(page.getByRole('button', { name: 'Log in and unlock' })); await screenshot('04-account-login'); await login()
  assert.equal(await page.getByRole('button', { name: 'Add passkey', exact: true }).count(), 0)
  const settings = page.getByRole('button', { name: 'Account and recovery', exact: true })
  assert.equal(await settings.getAttribute('aria-expanded'), 'false')
  assert.equal(await page.getByRole('button', { name: 'Rotate recovery key', exact: true }).count(), 0)
  await responsiveScreenshots('05-account-collapsed')
  await settings.focus(); await settings.press('Enter')
  assert.equal(await settings.getAttribute('aria-expanded'), 'true')
  await visible(page.getByRole('button', { name: 'Rotate recovery key', exact: true }))
  await responsiveScreenshots('05-account-expanded')
  await settings.press('Space')
  assert.equal(await settings.getAttribute('aria-expanded'), 'false')
  // Verify a new password modal inside the existing export dialog's focus scope.
  await page.getByRole('button', { name: 'Export data', exact: true }).click()
  const download = page.waitForEvent('download'); download.catch(() => {})
  await page.getByRole('button', { name: 'Export', exact: true }).click()
  await visible(page.getByRole('dialog', { name: 'Verify your password' })); await screenshot('06-fresh-password')
  await page.getByLabel('Current password', { exact: true }).fill(password); await page.getByRole('button', { name: 'Verify password', exact: true }).click()
  const exported = await download; assert.equal(exported.suggestedFilename(), 'warden-data.json'); await exported.delete()
  // Password fresh verification also protects recovery-key rotation and reentry.
  await settings.click()
  await page.getByRole('button', { name: 'Rotate recovery key', exact: true }).click()
  await visible(page.getByRole('dialog', { name: 'Verify your password' })); assert.equal(await page.getByLabel('Current password', { exact: true }).inputValue(), '')
  await page.getByLabel('Current password', { exact: true }).fill(password); await page.getByRole('button', { name: 'Verify password', exact: true }).click()
  await visible(page.locator('pre')); saved = await page.locator('pre').textContent()
  await page.getByRole('button', { name: 'I saved it; hide key', exact: true }).click(); await page.getByLabel('Re-enter saved recovery key', { exact: true }).fill(saved); await page.getByRole('button', { name: 'Confirm saved recovery key', exact: true }).click()
  await visible(page.getByText('Recovery key rotated.', { exact: false }))
  const previousCookie = await cookieHeader(page, origin)
  assert(previousCookie, 'a session cookie must predate lock/logout')
  await armTransition(page, 'lock', heldDispatch)
  const lockPost = completedRequest(page, '/api/v1/auth/lock', 'POST')
  const postLockDevices = completedRequest(page, '/api/v1/auth/clients/list')
  phase = 'lock'
  await page.getByRole('button', { name: 'Lock vault', exact: true }).click(); await visible(page.getByRole('button', { name: 'Unlock with password' }))
  await releaseTransition(page, heldDispatch)
  await Promise.all([lockPost, postLockDevices])
  phase = 'lock confirmation'
  serverProofs.locked = await proveLocked(page, origin, previousCookie); verifiedTransitions.locked = true
  await screenshot('07-locked')
  phase = 'management'
  await page.getByLabel('Password', { exact: true }).fill(password); await page.getByRole('button', { name: 'Unlock with password' }).click(); await visible(page.getByRole('heading', { name: 'Warden Hub' })); await check()
  await waitFor(() => network.every(request => request.finished || request.failure), 'requests did not settle before runtime restart')
  await fs.writeFile(path.join(dir, 'stop'), 'stop'); assert.equal(await runtime.completed, 0); runtime = undefined; await fs.unlink(path.join(dir, 'stop'))
  runtime = fixture('runtime'); await waitFor(() => ready(origin), 'restarted runtime unavailable'); await page.reload()
  await visible(page.getByRole('button', { name: 'Unlock with password' }))
  // The restart's locked-state metadata read must finish before unlock replaces it.
  await waitFor(() => network.every(request => request.finished || request.failure), 'restart requests did not settle')
  const postUnlockDevices = completedRequest(page, '/api/v1/auth/clients/list')
  const postUnlockManagement = ['/api/v1/ssh-connections', '/api/v1/db-connections', '/api/v1/groups', '/api/v1/projects', '/api/v1/key-pairs'].map(path => completedRequest(page, path))
  await page.getByLabel('Password', { exact: true }).fill(password); await page.getByRole('button', { name: 'Unlock with password' }).click(); await visible(page.getByRole('heading', { name: 'Warden Hub' }))
  await Promise.all([postUnlockDevices, ...postUnlockManagement])
  const logoutCookie = await cookieHeader(page, origin)
  assert(logoutCookie, 'a live session cookie must predate logout')
  await armTransition(page, 'logout', heldDispatch)
  const logoutPost = completedRequest(page, '/api/v1/auth/logout', 'POST')
  phase = 'logout'
  await page.getByRole('button', { name: 'Log out', exact: true }).click(); await visible(page.getByRole('button', { name: 'Log in and unlock' }))
  await releaseTransition(page, heldDispatch)
  await logoutPost
  phase = 'logout confirmation'
  serverProofs.loggedOut = await proveLoggedOut(page, origin, logoutCookie); verifiedTransitions.loggedOut = true
  phase = 'recovery'
  await page.getByLabel('Offline recovery key', { exact: true }).fill(saved); await page.getByRole('button', { name: 'Recover and replace account password' }).click()
  await visible(page.getByRole('button', { name: 'Replace account password' }))
  assert.equal(await settings.getAttribute('aria-expanded'), 'true')
  assert.equal(await settings.isDisabled(), true)
  await responsiveScreenshots('08-restricted-account-recovery')
  password = ' replacement disposable password '
  await page.getByLabel('New password', { exact: true }).fill(password); await page.getByLabel('Confirm new password', { exact: true }).fill(password); await page.getByRole('button', { name: 'Replace account password' }).click()
  await visible(page.getByRole('button', { name: 'Log in and unlock' })); await login(); await check(); await screenshot('09-recovered-management')
  assert(network.some(r => new URL(r.url).pathname === '/api/v1/auth/status' && r.status === 401))
  assert(!network.some(r => /\/passkeys\/|\/login\/(begin|finish)|\/fresh\/(begin|finish)/.test(new URL(r.url).pathname)))
  await waitFor(() => network.every(request => request.finished || request.failure), 'requests did not settle before network gate')
  const { expectedFailures } = assertNetworkComplete(network, { origin, imageOrigin: origin, assets: [], verifiedTransitions })
  await fs.writeFile(path.join(output, 'result.json'), JSON.stringify({ passed: true, heldDispatch, verifiedTransitions, serverProofs, expectedFailures, checks: ['setup+recovery confirmation', 'login+unlock', 'nested fresh export', 'fresh recovery rotation', 'global lock+re-unlock', 'locked restart', 'logout', 'restricted recovery+password replacement', 'no WebAuthn/PRF', 'CSP'], network, errors, csp }, null, 2))
  console.log('PASS account browser lifecycle; private artifacts: ' + output)
 } catch (e) {
  if (page) await screenshot('failure').catch(() => {})
  await fs.writeFile(path.join(output, 'failure.txt'), String(e.stack || e))
  await fs.writeFile(path.join(output, 'failure.json'), JSON.stringify({ network, verifiedTransitions, serverProofs, errors, csp }, null, 2))
  throw e
 } finally {
  if (context) {
   await context.tracing.stop({ path: path.join(output, 'trace.zip') }).catch(() => {})
   for (const page of context.pages()) await page.close()
   for (const [index, video] of videos.entries()) await video.saveAs(path.join(output, 'video', `page-${index}.webm`))
   await context.close()
  }
  if (browser) await browser.close()
  if (runtime) await fs.writeFile(path.join(dir, 'stop'), 'stop')
  for (const child of children) { if (child.exitCode === null) child.kill('SIGTERM'); await child.completed }
  await fs.rm(dir, { recursive: true, force: true })
 }
}
main().catch(e => { console.error(e.message); process.exitCode = 1 })
