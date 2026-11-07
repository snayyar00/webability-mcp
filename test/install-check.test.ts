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

// Intentionally red: assert the desired behavior, not the unimplemented error.
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
