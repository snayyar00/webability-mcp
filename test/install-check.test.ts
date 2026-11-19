import assert from 'node:assert/strict'
import { test } from 'node:test'

import { checkInstall, type InstallObservation } from '../src/installCheck.ts'

const URL = 'https://site.example/'
const FINAL_URL = 'https://site.example/home'
const SCRIPT = 'https://enhancer.webability.io/widget.min.js'
const DOCUMENTED_SCRIPT = 'https://widget-v2.webability.io/widget.min.js'

function observation(overrides: Partial<InstallObservation>): InstallObservation {
  return {
    finalUrl: FINAL_URL,
    scriptElements: [],
    requests: [],
    policyViolations: [],
    runtimeErrors: [],
    observationDurationMs: 1000,
    ...overrides,
  }
}

function observer(fixture: InstallObservation) {
  return async (url: string) => {
    assert.equal(url, URL)
    return fixture
  }
}

// Assert the state and evidence produced from raw observations.
// These fixtures replace browser observation only; the classifier is never mocked.
test('check_install: present includes the successfully loaded script as evidence', async () => {
  const result = await checkInstall(URL, { observe: observer(observation({
    scriptElements: [{ src: SCRIPT }],
    requests: [{ url: SCRIPT, status: 200 }],
  })) })

  assert.equal(result.url, URL)
  assert.equal(result.finalUrl, FINAL_URL)
  assert.equal(result.state, 'present')
  assert.ok(result.evidence.length > 0)
  assert.deepEqual(result.evidence.find((e) => e.kind === 'script'), {
    kind: 'script', scriptUrl: SCRIPT, httpStatus: 200,
  })
})

test('check_install: blocked includes the enforced policy and blocked script as evidence', async () => {
  const policy = "default-src 'self'; script-src 'self'"
  const result = await checkInstall(URL, { observe: observer(observation({
    scriptElements: [{ src: DOCUMENTED_SCRIPT }],
    requests: [{ url: DOCUMENTED_SCRIPT, failure: 'net::ERR_BLOCKED_BY_CSP' }],
    policyViolations: [{ blockedUrl: DOCUMENTED_SCRIPT, directive: 'script-src-elem', policy, disposition: 'enforce' }],
  })) })

  assert.equal(result.url, URL)
  assert.equal(result.finalUrl, FINAL_URL)
  assert.equal(result.state, 'blocked')
  assert.ok(result.evidence.length > 0)
  assert.deepEqual(result.evidence.find((e) => e.kind === 'security_policy'), {
    kind: 'security_policy', blockedUrl: DOCUMENTED_SCRIPT, directive: 'script-src-elem', policy,
  })
})

test('check_install: error includes the attributable script exception as evidence', async () => {
  const message = 'Error: widget initialization failed'
  const result = await checkInstall(URL, { observe: observer(observation({
    scriptElements: [{ src: SCRIPT }],
    requests: [{ url: SCRIPT, status: 200 }],
    runtimeErrors: [{ scriptUrl: SCRIPT, message }],
  })) })

  assert.equal(result.url, URL)
  assert.equal(result.finalUrl, FINAL_URL)
  assert.equal(result.state, 'error')
  assert.ok(result.evidence.length > 0)
  assert.deepEqual(result.evidence.find((e) => e.kind === 'script_error'), {
    kind: 'script_error', scriptUrl: SCRIPT, message,
  })
})

test('check_install: not installed includes the completed observation scope as evidence', async () => {
  const unrelated = 'https://site.example/app.js'
  const result = await checkInstall(URL, { observe: observer(observation({
    scriptElements: [{ src: unrelated }],
    requests: [{ url: unrelated, status: 200 }],
  })) })

  assert.equal(result.url, URL)
  assert.equal(result.finalUrl, FINAL_URL)
  assert.equal(result.state, 'not_installed')
  assert.ok(result.evidence.length > 0)
  assert.deepEqual(result.evidence.find((e) => e.kind === 'absence'), {
    kind: 'absence', inspectedScriptUrls: [unrelated], observationDurationMs: 1000,
  })
})

test('check_install: failed downloads are errors with script_load evidence', async () => {
  for (const outcome of [{ status: 404 }, { failure: 'net::ERR_NAME_NOT_RESOLVED' }, { failure: 'net::ERR_CONNECTION_RESET' }, { failure: 'net::ERR_BLOCKED_BY_CLIENT' }]) {
    const result = await checkInstall(URL, { observe: observer(observation({
      scriptElements: [{ src: SCRIPT }], requests: [{ url: SCRIPT, ...outcome }],
    })) })
    assert.equal(result.state, 'error')
    assert.deepEqual(result.evidence, [{ kind: 'script_load', scriptUrl: SCRIPT,
      ...('status' in outcome ? { httpStatus: outcome.status } : { failure: outcome.failure }) }])
  }
})

test('check_install: consent-held tag without a request is blocked', async () => {
  const attributes = { 'data-cookieconsent': 'marketing' }
  const result = await checkInstall(URL, { observe: observer(observation({
    scriptElements: [{ src: SCRIPT, type: 'text/plain', attributes }],
  })) })
  assert.equal(result.state, 'blocked')
  assert.deepEqual(result.evidence, [{ kind: 'consent', scriptUrl: SCRIPT, type: 'text/plain', attributes }])
})

test('check_install: unknown load outcome and navigation failure are not absence', async () => {
  await assert.rejects(checkInstall(URL, { observe: observer(observation({ scriptElements: [{ src: SCRIPT }] })) }), /could not be established/)
  await assert.rejects(checkInstall(URL, { observe: async () => { throw new Error('Navigation failed') } }), /Navigation failed/)
})

test('check_install: exact identity, report-only CSP and unrelated errors', async () => {
  const script = `${SCRIPT}?v=2#embed`
  const result = await checkInstall(URL, { observe: observer(observation({
    requests: [{ url: script, status: 200 }],
    policyViolations: [{ blockedUrl: script, directive: 'script-src', policy: "script-src 'none'", disposition: 'report' }],
    runtimeErrors: [{ scriptUrl: 'https://site.example/app.js', message: 'unrelated' }],
  })) })
  assert.equal(result.state, 'present')
  for (const src of ['https://enhancer.webability.io.evil.test/widget.min.js', 'https://enhancer.webability.io/other.js', 'http://enhancer.webability.io/widget.min.js']) {
    assert.equal((await checkInstall(URL, { observe: observer(observation({ scriptElements: [{ src }], requests: [{ url: src, status: 200 }] })) })).state, 'not_installed')
  }
})

test('check_install: dashboard and legacy embed hosts are recognized', async () => {
  for (const src of ['https://widget.webability.io/widget.min.js', 'https://widget.access-widget.com/widget.min.js']) {
    const result = await checkInstall(URL, { observe: observer(observation({
      scriptElements: [{ src }],
      requests: [{ url: src, status: 200 }],
    })) })
    assert.equal(result.state, 'present', src)
    assert.deepEqual(result.evidence, [{ kind: 'script', scriptUrl: src, httpStatus: 200 }])
  }
  for (const src of ['https://widget.webability.io.evil.test/widget.min.js', 'https://widget.access-widget.com/other.js']) {
    assert.equal((await checkInstall(URL, { observe: observer(observation({ scriptElements: [{ src }], requests: [{ url: src, status: 200 }] })) })).state, 'not_installed', src)
  }
})
