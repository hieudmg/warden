#!/usr/bin/env node
// Production HTTPS/CSP/network acceptance via the documented shared Chromium.
// No project dependency install, browser launch fallback, token/CSRF bypass,
// API response mocking, production test route, or genuine PRF claim.
const assert = require('node:assert/strict')
const fs = require('node:fs/promises')
const path = require('node:path')
const os = require('node:os')
const https = require('node:https')
const http = require('node:http')
const { spawn, spawnSync } = require('node:child_process')
const { generateKeyPairSync } = require('node:crypto')
const syntheticAuthenticator = require('./synthetic-authenticator.cjs')
const { assertNetworkComplete } = require('./ui-privacy-network.cjs')
const { completedRequest, installTransitionHold, armTransition, releaseTransition, cookieHeader, proveLocked, proveLoggedOut } = require('./auth-lifecycle.cjs')
process.umask(0o077)
const shared = require(path.join(os.homedir(), '.local/share/playwright-global/index.cjs'))
const repo = path.resolve(__dirname, '../..')
// This read-only reference installation is explicitly documented by the machine
// service README. Override only with another inspected compatible installation.
const project = process.env.PW_REFERENCE_PROJECT || '/var/www/code/php/dispatcher'
const output = path.resolve(process.env.WARDEN_UI_ARTIFACTS || '/tmp/warden-t9-browser-artifacts')
const delay = ms => new Promise(resolve => setTimeout(resolve, ms))
async function waitFor(action, message) {
  for (let attempt = 0; attempt < 400; attempt++) { try { const value = await action(); if (value) return value } catch {} await delay(50) }
  throw Error(message)
}
// TEST-ONLY self-signed loopback certificate trust exception. This differs from
// production certificate trust and is not evidence of private-CA trust support.
// HTTPS secure contexts, real TLS, Origin/Host/cookie/CSRF/WebAuthn and browser CSP
// remain evaluated. No production transport setting is changed.
function ready(origin) { return new Promise(resolve => { const req = https.get(origin + '/', { rejectUnauthorized: false }, response => { response.resume(); resolve(response.statusCode === 200) }); req.on('error', () => resolve(false)); req.setTimeout(300, () => req.destroy()) }) }
async function main() {
  await fs.mkdir(output, { recursive: true, mode: 0o700 })
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'warden-t9-browser-'))
  const env = { ...process.env, WARDEN_UI_BROWSER_DIR: dir }
  const children = []
  const fixture = kind => {
    const child = spawn('go', ['test', `./internal/server/${kind}`, '-run', `^TestUIBrowser${kind === 'setup' ? 'Setup' : 'Runtime'}Fixture$`, '-count=1', '-v', '-timeout=200s'], { cwd: repo, env })
    children.push(child)
    const chunks = []
    child.stdout.on('data', chunk => chunks.push(chunk)); child.stderr.on('data', chunk => chunks.push(chunk))
    child.completed = new Promise(resolve => child.on('exit', async code => { await fs.writeFile(path.join(output, `${kind}.log`), Buffer.concat(chunks)); resolve(code) }))
    return child
  }
  let browser, context, imageServer
  const failures = [], violations = [], network = [], imageHits = [], videos = [], consoleErrors = []
  const verifiedTransitions = {}, serverProofs = {}
  const requests = new Map()
  let phase = 'setup'
  try {
    const cert = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem'), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' })
    assert.equal(cert.status, 0, 'create disposable test-only certificate')
    const setup = fixture('setup')
    const cfg = await waitFor(async () => JSON.parse(await fs.readFile(path.join(dir, 'config.json'), 'utf8')), 'setup config did not become ready')
    const origin = cfg.public_origin
    await waitFor(() => ready(origin), 'setup HTTPS did not become ready')
    // connect() starts/reuses only the documented compatible global service.
    browser = await shared.connect({ project })
    context = await browser.newContext({ ignoreHTTPSErrors: true, recordVideo: { dir: path.join(output, 'video') }, acceptDownloads: true })
    await context.tracing.start({ screenshots: true, snapshots: true, sources: true })
    const heldDispatch = process.env.WARDEN_UI_HOLD_TRANSITIONS === '1'
    if (heldDispatch) await installTransitionHold(context)
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    await context.addInitScript(syntheticAuthenticator, privateKey.export({ format: 'jwk' }))
    await context.addInitScript(() => { globalThis.__cspViolations = []; document.addEventListener('securitypolicyviolation', event => globalThis.__cspViolations.push({ directive: event.effectiveDirective, blocked: event.blockedURI })) })
    context.on('request', request => {
      const record = { url: request.url(), method: request.method(), phase, status: null, finished: false, failure: null }
      requests.set(request, record); network.push(record)
    })
    context.on('response', response => { requests.get(response.request()).status = response.status() })
    // requestfinished is emitted only after the response body downloads, not
    // merely when 200 headers arrive. HTTP 4xx/5xx also finish, so check both.
    context.on('requestfinished', request => { requests.get(request).finished = true })
    context.on('requestfailed', request => { requests.get(request).failure = request.failure()?.errorText || 'Unknown request failure' })
    context.on('page', page => {
      if (page.video()) videos.push(page.video())
      page.on('pageerror', error => failures.push(error.message))
      page.on('console', message => { if (message.type() === 'error') consoleErrors.push({ message: message.text(), url: message.location().url, phase }) })
    })
    const page = await context.newPage()
    page.setDefaultTimeout(15000)
    const expectVisible = async locator => { await locator.waitFor({ state: 'visible' }) }
    const checkHeaders = response => { const headers = response.headers(); assert.equal(headers['x-frame-options'], 'DENY'); assert.equal(headers['x-content-type-options'], 'nosniff'); assert.equal(headers['referrer-policy'], 'no-referrer'); assert.match(headers['content-security-policy'], /frame-ancestors 'none'/); assert.match(headers['content-security-policy'], /script-src 'self';/); assert.doesNotMatch(headers['content-security-policy'], /unsafe-eval/) }
    const checkCSP = async label => { const current = await page.evaluate(() => globalThis.__cspViolations); violations.push(...current.map(event => ({ ...event, label }))); assert.equal(current.length, 0, `${label} CSP violations`) }
    checkHeaders(await page.goto(origin))
    assert.equal(await page.evaluate(() => isSecureContext), true)
    await expectVisible(page.getByRole('heading', { name: 'Initialize Warden' }))
    await page.getByLabel('Setup password').fill('23456789')
    await page.getByRole('button', { name: 'Continue', exact: true }).click()
    await page.getByRole('button', { name: 'Register and verify passkey' }).click()
    await expectVisible(page.getByRole('heading', { name: 'Save your offline recovery key' }))
    const saved = await page.locator('pre').textContent()
    const owner = await page.evaluate(() => globalThis.__syntheticOwner)
    await page.addInitScript(value => { globalThis.__syntheticOwner = value }, owner)
    await page.screenshot({ path: path.join(output, 'setup.png'), fullPage: true })
    await checkCSP('setup')
    await page.getByRole('button', { name: 'I saved it — hide and re-enter' }).click()
    await page.getByLabel('Saved recovery key').fill(saved)
    await page.getByRole('button', { name: 'Continue', exact: true }).click()
    await expectVisible(page.getByRole('heading', { name: 'Warden initialized' }))
    assert.equal(await setup.completed, 0)
    const runtime = fixture('runtime')
    await waitFor(() => ready(origin), 'runtime HTTPS did not become ready')
    phase = 'initial session probe'
    checkHeaders(await page.goto(origin))
    await expectVisible(page.getByRole('button', { name: 'Log in with passkey' }))
    await waitFor(() => network.some(request => request.url === `${origin}/api/v1/auth/status` && request.status === 401), 'initial unauthenticated status probe did not return 401 headers')
    await page.screenshot({ path: path.join(output, 'login.png'), fullPage: true }); await checkCSP('login')
    phase = 'management'
    await page.getByRole('button', { name: 'Log in with passkey' }).click()
    await expectVisible(page.getByRole('button', { name: 'Unlock with passkey PRF' }))
    const unlocksBeforeUnsupportedPRF = network.filter(request => request.url === `${origin}/api/v1/auth/unlock`).length
    await page.evaluate(() => { globalThis.__syntheticNoPRF = true })
    await page.getByRole('button', { name: 'Unlock with passkey PRF' }).click()
    await expectVisible(page.getByRole('alert').filter({ hasText: 'No plaintext-key fallback' }))
    assert.equal(await page.getByRole('heading', { name: 'Warden Hub' }).count(), 0)
    assert.equal(network.filter(request => request.url === `${origin}/api/v1/auth/unlock`).length, unlocksBeforeUnsupportedPRF, 'unsupported PRF must not submit unlock; it needs no HTTP-failure exception')
    await page.evaluate(() => { globalThis.__syntheticNoPRF = false })
    await page.getByRole('button', { name: 'Unlock with passkey PRF' }).click()
    await expectVisible(page.getByRole('heading', { name: 'Warden Hub' }))
    const securitySettings = page.getByRole('button', { name: 'Passkeys and recovery', exact: true })
    assert.equal(await securitySettings.getAttribute('aria-expanded'), 'false')
    await securitySettings.focus(); await securitySettings.press('Enter')
    await expectVisible(page.getByRole('button', { name: 'Add passkey', exact: true }))
    await page.screenshot({ path: path.join(output, 'passkey-settings.png'), fullPage: true })
    await securitySettings.press('Space')
    assert.equal(await securitySettings.getAttribute('aria-expanded'), 'false')
    await page.getByRole('button', { name: 'New connection', exact: true }).click()
    const dialog = page.locator('[data-slot="dialog-content"]')
    await dialog.getByLabel('Name', { exact: true }).fill('synthetic-ssh')
    await dialog.getByLabel('Host', { exact: true }).fill('localhost')
    await dialog.getByLabel('Username', { exact: true }).fill('synthetic')
    await dialog.locator('#ssh-password').fill('synthetic-password')
    assert.equal(await dialog.locator('#ssh-password').getAttribute('type'), 'password')
    await dialog.getByRole('button', { name: 'Reveal password', exact: true }).click()
    assert.equal(await dialog.locator('#ssh-password').getAttribute('type'), 'text')
    await dialog.getByRole('combobox', { name: 'Group', exact: true }).click()
    await expectVisible(page.getByRole('option', { name: 'None', exact: true }))
    await page.screenshot({ path: path.join(output, 'dialog-popover.png'), fullPage: true }); await checkCSP('SSH dialog and Base UI combobox popup')
    // Record the actual runtime style-tag need, not an assumed Radix API.
    const styles = await page.locator('style').allTextContents(); assert(styles.some(text => text.includes('overflow') || text.includes('scroll')))
    await page.getByRole('option', { name: 'None', exact: true }).click()
    await dialog.getByRole('button', { name: 'Save', exact: true }).click()
    await dialog.waitFor({ state: 'hidden' })
    await page.getByRole('button', { name: 'Edit synthetic-ssh' }).click()
    assert.equal(await dialog.locator('#ssh-password').inputValue(), '')
    assert.equal(await dialog.locator('#ssh-password').getAttribute('type'), 'password')
    await dialog.getByRole('button', { name: 'Cancel', exact: true }).click()
    await page.getByRole('tab', { name: 'Databases', exact: true }).click()
    await page.getByRole('button', { name: 'New database', exact: true }).click()
    assert.equal(await dialog.locator('#db-password').getAttribute('type'), 'password')
    await dialog.getByRole('combobox', { name: 'SSH connection', exact: true }).click()
    await page.getByRole('option', { name: 'Direct', exact: true }).click()
    await checkCSP('DB dialog and popover'); await dialog.getByRole('button', { name: 'Cancel', exact: true }).click()
    await page.getByRole('tab', { name: 'Key Pairs', exact: true }).click()
    await page.getByRole('button', { name: 'New key pair', exact: true }).click()
    assert.equal(await dialog.getByLabel('Private key passphrase', { exact: true }).getAttribute('type'), 'password')
    await checkCSP('key pair dialog'); await dialog.getByRole('button', { name: 'Cancel', exact: true }).click()
    await page.getByRole('button', { name: 'Export data', exact: true }).click()
    await checkCSP('export dialog'); const download = page.waitForEvent('download'); download.catch(() => {})
    await dialog.getByRole('button', { name: 'Export', exact: true }).click()
    const exported = await download; assert.equal(exported.suggestedFilename(), 'warden-data.json'); await exported.delete()
    await page.getByRole('button', { name: 'Import data', exact: true }).click(); await checkCSP('import dialog'); await dialog.getByRole('button', { name: 'Cancel', exact: true }).click()
    await page.getByRole('tab', { name: 'Projects & Reports', exact: true }).click()
    await page.getByRole('button', { name: 'New project', exact: true }).click()
    await dialog.getByLabel('Name', { exact: true }).fill('synthetic-project'); await dialog.getByRole('button', { name: 'Create project', exact: true }).click()
    await dialog.waitFor({ state: 'hidden' })
    imageServer = http.createServer((request, response) => { imageHits.push({ url: request.url, referer: request.headers.referer }); response.writeHead(200, { 'Content-Type': 'image/svg+xml' }); response.end('<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"/>') })
    await new Promise(resolve => imageServer.listen(0, '127.0.0.1', resolve))
    const hostile = `http://127.0.0.1:${imageServer.address().port}/unique-hostile-${Date.now()}.svg`
    await page.getByRole('button', { name: 'synthetic-project', exact: true }).click()
    await page.getByRole('button', { name: 'Add report', exact: true }).click()
    await dialog.getByLabel('Title', { exact: true }).fill('hostile-network-fixture')
    await dialog.getByLabel('Agent model', { exact: true }).fill('synthetic')
    await dialog.getByLabel('Summary', { exact: true }).fill(`![tracking](${hostile})\n\n[unsafe](javascript:alert%281%29)\n\n[safe](https://example.invalid/)\n\n<img src="${hostile}?raw"><style>body{background:url(${hostile}?css)}</style>`)
    await checkCSP('project/report dialogs'); await dialog.getByRole('button', { name: 'Create report', exact: true }).click()
    await dialog.waitFor({ state: 'hidden' })
    const imageAction = page.getByRole('button', { name: /Open image.*tracking.*reveals your IP/i })
    await expectVisible(imageAction)
    await page.evaluate(() => document.fonts.ready)
    assert.equal(await page.locator('.markdown-body img, .markdown-body style').count(), 0)
    assert.equal(imageHits.length, 0, 'zero implicit image/CSS requests at the hostile server')
    assert.equal(network.filter(request => request.url.startsWith(hostile)).length, 0)
    await page.screenshot({ path: path.join(output, 'markdown-before.png'), fullPage: true }); await checkCSP('hostile Markdown')
    const observationStarted = Date.now()
    await delay(500)
    const imageObservationMs = Date.now() - observationStarted
    assert.equal(imageHits.length, 0, 'zero implicit requests throughout the pre-activation observation window')
    assert.equal(network.filter(request => request.url.startsWith(hostile)).length, 0)
    const imageBeforeActivation = imageHits.length
    const popupReady = context.waitForEvent('page')
    await imageAction.click(); const popup = await popupReady; await popup.waitForLoadState()
    await waitFor(() => imageHits.length > 0, 'explicit image activation did not reach the image host')
    assert.equal(imageHits.length, 1); assert.equal(imageHits[0].referer, undefined); assert.equal(await popup.evaluate(() => opener === null), true)
    await popup.screenshot({ path: path.join(output, 'markdown-explicit.png') }); await popup.close()
    const manifest = JSON.parse(await fs.readFile(path.join(repo, 'internal/web/dist/.vite/manifest.json'), 'utf8'))
    const assets = [...new Set(Object.values(manifest).flatMap(entry => [entry.file, ...(entry.css || []), ...(entry.assets || [])]))]
    // Ensure every emitted font actually goes through the font loader under CSP,
    // including unicode subsets not naturally needed by this English test page.
    await page.evaluate(async names => { for (const [index, name] of names.entries()) { const face = new FontFace(`fixture${index}`, `url(/${name})`); await face.load(); document.fonts.add(face) } }, assets.filter(name => name.endsWith('.woff2')))
    await checkCSP('all emitted assets/fonts')
    const previousCookie = await cookieHeader(page, origin)
    assert(previousCookie, 'an authenticated cookie must predate both transitions')
    await armTransition(page, 'lock', heldDispatch)
    // Register before the click and wait for full post-lock metadata bodies,
    // not only optimistic UI or the unrelated status response.
    const lockPost = completedRequest(page, '/api/v1/auth/lock', 'POST')
    const postLockList = completedRequest(page, '/api/v1/auth/passkeys/list')
    const postLockDevices = completedRequest(page, '/api/v1/auth/clients/list')
    phase = 'lock'
    await page.getByRole('button', { name: 'Lock vault', exact: true }).click(); await expectVisible(page.getByRole('heading', { name: 'Vault locked', exact: true }))
    await releaseTransition(page, heldDispatch)
    await Promise.all([lockPost, postLockList, postLockDevices])
    phase = 'lock confirmation'
    serverProofs.locked = await proveLocked(page, origin, previousCookie)
    verifiedTransitions.locked = true
    const logoutCookie = await cookieHeader(page, origin)
    assert(logoutCookie, 'a live session cookie must predate logout')
    await armTransition(page, 'logout', heldDispatch)
    const logoutPost = completedRequest(page, '/api/v1/auth/logout', 'POST')
    phase = 'logout'
    await page.getByRole('button', { name: 'Log out', exact: true }).click(); await expectVisible(page.getByRole('button', { name: 'Log in with passkey' }))
    await releaseTransition(page, heldDispatch)
    await logoutPost
    phase = 'logout confirmation'
    serverProofs.loggedOut = await proveLoggedOut(page, origin, logoutCookie)
    verifiedTransitions.loggedOut = true
    assert.equal(await page.locator('.markdown-body').count(), 0)
    const imageOrigin = new URL(hostile).origin
    await waitFor(() => network.every(request => ![origin, imageOrigin].includes(new URL(request.url).origin) || request.finished || request.failure), 'fixture requests did not complete')
    const { completedAssets, expectedFailures } = assertNetworkComplete(network, { origin, imageOrigin, assets, verifiedTransitions })
    const unexpectedConsoleErrors = consoleErrors.filter(error => !(error.message === 'Failed to load resource: the server responded with a status of 401 (Unauthorized)' && expectedFailures.some(request => request.url === error.url && request.status === 401)))
    failures.push(...unexpectedConsoleErrors.map(error => error.message))
    assert.deepEqual(failures, [])
    await fs.writeFile(path.join(output, 'result.json'), JSON.stringify({ status: 'PASS', tests: 1, browser: browser.version(), heldDispatch, syntheticAuthenticator: true, genuinePRF: false, testOnlyCertificateException: true, origin, imageBeforeActivation, imageObservationMs, imageAfterActivation: imageHits.length, imageHits, violations, failures, consoleErrors, expectedFailures, verifiedTransitions, serverProofs, loadedAssets: assets, completedAssets, network }, null, 2))
    await fs.writeFile(path.join(dir, 'stop'), '')
    assert.equal(await runtime.completed, 0)
    await fs.writeFile(path.join(output, 'index.html'), '<!doctype html><meta charset="utf-8"><title>T9 UI privacy artifacts</title><h1>T9 production HTTPS UI privacy — PASS</h1><p>One disposable synthetic signed WebAuthn/injected-PRF journey, including explicit unsupported-PRF refusal. Test-only self-signed certificate exception; not genuine PRF or production trust evidence.</p><ul>' + ['result.json', 'trace.zip', 'setup.png', 'login.png', 'dialog-popover.png', 'markdown-before.png', 'markdown-explicit.png', 'video/'].map(file => `<li><a href="${file}">${file}</a></li>`).join('') + '</ul>')
    console.log(`PASS production HTTPS UI privacy/CSP (synthetic signed WebAuthn + injected PRF, test-only certificate exception). Artifacts: ${output}`)
  } catch (error) {
    await fs.writeFile(path.join(output, 'failure.json'), JSON.stringify({ error: error.stack, violations, failures, consoleErrors, verifiedTransitions, serverProofs, network, imageHits }, null, 2))
    throw error
  } finally {
    if (context) {
      await context.tracing.stop({ path: path.join(output, 'trace.zip') })
      for (const page of context.pages()) await page.close()
      // Remote-library contexts require explicit artifact download; recordVideo
      // alone does not copy the service's files into this caller's directory.
      for (const [index, video] of videos.entries()) await video.saveAs(path.join(output, 'video', `page-${index}.webm`))
      await context.close()
    }
    if (browser) await browser.close() // Disconnect only; never stop the shared service.
    if (imageServer) await new Promise(resolve => imageServer.close(resolve))
    for (const child of children) if (child.exitCode === null) child.kill('SIGTERM')
    await Promise.all(children.map(child => child.completed))
    await fs.rm(dir, { recursive: true, force: true }) // Only this newly-created synthetic fixture.
  }
}
main().catch(error => { console.error(error); process.exitCode = 1 })
