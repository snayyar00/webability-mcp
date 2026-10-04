/**
 * Fresh machine: Chromium is not downloaded yet. Local runs install it once
 * (single-flight) and retry; remote runs never install; any failure ends in
 * one actionable line, never Playwright's raw banner. Launcher and installer
 * are injected: nothing here downloads a browser.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'

import { createLauncher, NOT_INSTALLED_MESSAGE, notInstalledMessage } from '../src/browser.ts'

// The Playwright this package actually resolves — read independently of src.
const PW_VERSION: string = JSON.parse(
  readFileSync(createRequire(new URL('../src/browser.ts', import.meta.url)).resolve('playwright/package.json'), 'utf8'),
).version

const RAW = "browserType.launch: Executable doesn't exist at /x/chromium-1234/chrome\n╔═══╗\n║ Looks like Playwright was just installed. Please run: npx playwright install ║\n╚═══╝"
const ACTIONABLE = `Chromium is not installed. Run: npx playwright@${PW_VERSION} install chromium (one-time, ~150 MB). Or use the hosted server https://mcp.webability.io/mcp — no install.`

/** A launcher that fails with the raw banner until `install()` has run. */
function fakeWorld(opts: { installFails?: boolean; stillMissingAfterInstall?: boolean } = {}) {
  const calls = { launch: 0, install: 0, logs: [] as string[] }
  let installed = false
  const browser = { id: 'b' }
  return {
    calls,
    deps: {
      launch: async () => {
        calls.launch++
        if (!installed) throw new Error(RAW)
        return browser
      },
      install: async () => {
        calls.install++
        await new Promise((r) => setTimeout(r, 20))
        if (opts.installFails) throw new Error('network down')
        installed = !opts.stillMissingAfterInstall
      },
      env: {} as NodeJS.ProcessEnv,
      log: (m: string) => void calls.logs.push(m),
    },
    browser,
  }
}

test('missing browser, local: installs once then retries the launch', async () => {
  const w = fakeWorld()
  const launch = createLauncher(w.deps)
  assert.equal(await launch({}), w.browser)
  assert.equal(w.calls.install, 1)
  assert.equal(w.calls.launch, 2)
})

test('three concurrent launches share ONE install', async () => {
  const w = fakeWorld()
  const launch = createLauncher(w.deps)
  const got = await Promise.all([launch({}), launch({}), launch({})])
  assert.deepEqual(got, [w.browser, w.browser, w.browser])
  assert.equal(w.calls.install, 1)
})

test('install failure gives the actionable line, not the raw banner', async () => {
  const w = fakeWorld({ installFails: true })
  const launch = createLauncher(w.deps)
  await assert.rejects(launch({}), (e: Error) => {
    assert.equal(e.message, ACTIONABLE)
    return true
  })
})

test('install that leaves the browser missing still ends in the actionable line', async () => {
  const w = fakeWorld({ stillMissingAfterInstall: true })
  const launch = createLauncher(w.deps)
  await assert.rejects(launch({}), (e: Error) => e.message === ACTIONABLE)
  assert.equal(w.calls.install, 1)
})

test('remote mode never installs', async () => {
  const w = fakeWorld()
  const launch = createLauncher(w.deps)
  await assert.rejects(launch({ remote: true }), (e: Error) => {
    assert.doesNotMatch(e.message, /Executable doesn't exist|╔/)
    return true
  })
  assert.equal(w.calls.install, 0)
  assert.equal(w.calls.launch, 1)
})

test('WEBABILITY_NO_AUTO_INSTALL=1 skips the install and gives the actionable line', async () => {
  const w = fakeWorld()
  w.deps.env = { WEBABILITY_NO_AUTO_INSTALL: '1' }
  const launch = createLauncher(w.deps)
  await assert.rejects(launch({}), (e: Error) => e.message === ACTIONABLE)
  assert.equal(w.calls.install, 0)
})

test('other launch errors pass through unchanged and never install', async () => {
  const calls = { install: 0 }
  const boom = new Error('Target page, context or browser has been closed')
  const launch = createLauncher({
    launch: async () => { throw boom },
    install: async () => { calls.install++ },
    env: {},
    log: () => {},
  })
  await assert.rejects(launch({}), (e: Error) => e === boom)
  assert.equal(calls.install, 0)
})

test('launch passes headless and extra args to the engine', async () => {
  const seen: any[] = []
  const launch = createLauncher({ launch: async (o) => { seen.push(o); return {} }, install: async () => {}, env: {}, log: () => {} })
  await launch({ args: ['--disable-http2'] })
  assert.deepEqual(seen, [{ headless: true, args: ['--disable-http2'] }])
})

test('install progress goes to the log callback (stderr), not stdout', async () => {
  const w = fakeWorld()
  await createLauncher(w.deps)({})
  assert.ok(w.calls.logs.some((l) => /Chromium/.test(l)), 'a progress line is logged')
})

test('the manual install command pins the Playwright version this package resolves', () => {
  assert.match(PW_VERSION, /^\d+\.\d+\.\d+/)
  assert.ok(NOT_INSTALLED_MESSAGE.includes(`npx playwright@${PW_VERSION} install chromium`), NOT_INSTALLED_MESSAGE)
})

test('the install command falls back to an unpinned one only when no version could be read', () => {
  assert.ok(notInstalledMessage('1.2.3').includes('npx playwright@1.2.3 install chromium'))
  assert.ok(notInstalledMessage(undefined).includes('npx playwright install chromium'))
})
