/**
 * The hosted server's refusal must teach, not just deny.
 *
 * DEV-1049: the tool description promises "Works on any URL — deployed sites,
 * localhost, staging". True of the stdio binary; FALSE of the hosted server,
 * where the SSRF guard blocks loopback and RFC1918. So the single most obvious
 * first thing a developer tries — point it at their dev server — fails with
 * `Blocked URL: "localhost" resolves to blocked internal address ::1`, which
 * reads as a broken product. They uninstall rather than file a bug.
 *
 * The guard is correct and untouched. These pin the MESSAGE, and the one place
 * it must stay generic.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { blockedUrlMessage, isDeveloperLocalAddress, resolvedAddressFrom } from '../src/blockedUrlMessage.ts'

const LOCALHOST_DETAIL = '"localhost" resolves to blocked internal address ::1'

test('a developer pointing at localhost is told what to do instead', () => {
  const msg = blockedUrlMessage(LOCALHOST_DETAIL, '::1')
  assert.match(msg, /npx -y @webability\/mcp/, 'must name the server that DOES scan localhost')
  assert.match(msg, /claude mcp add/, 'must give a runnable command')
  assert.match(msg, /runs in our cloud/, 'must explain WHY, or it still reads as a fault')
})

test('the message keeps the original diagnostic', () => {
  // The hostname and resolved address are the useful detail when a PUBLIC
  // hostname unexpectedly resolves somewhere private.
  assert.match(blockedUrlMessage(LOCALHOST_DETAIL, '::1'), /resolves to blocked internal address ::1/)
})

test('it warns about the two traps that waste an hour', () => {
  const msg = blockedUrlMessage(LOCALHOST_DETAIL, '127.0.0.1')
  assert.match(msg, /-y/, 'npx without -y fails with "could not determine executable to run"')
  assert.match(msg, /allowedHosts/, 'Vite 403s a tunnel hostname until it is allowlisted')
})

test('CLOUD METADATA gets the generic message, never the guided one', () => {
  // 169.254.169.254 is not a dev server — it is what an SSRF attempt looks
  // like. A detailed explanation hands a prober a map, and naming the range
  // confirms which cloud we run on.
  const msg = blockedUrlMessage('"x.test" resolves to blocked internal address 169.254.169.254', '169.254.169.254')
  assert.doesNotMatch(msg, /npx/, 'must not coach an SSRF probe')
  assert.doesNotMatch(msg, /our cloud/)
  assert.equal(msg, 'Blocked URL: "x.test" resolves to blocked internal address 169.254.169.254')
})

test('CGNAT also stays generic', () => {
  assert.doesNotMatch(blockedUrlMessage('detail', '100.64.0.1'), /npx/)
})

test('developer-local classification covers the real dev-server addresses', () => {
  for (const a of ['::1', '::', '127.0.0.1', '0.0.0.0', '10.0.0.5', '172.16.0.1', '172.31.255.254', '192.168.1.81', '::ffff:127.0.0.1']) {
    assert.equal(isDeveloperLocalAddress(a), true, a)
  }
})

test('and excludes what is NOT a dev server', () => {
  for (const a of ['169.254.169.254', '100.64.0.1', '100.127.0.1', '8.8.8.8', '172.32.0.1', '172.15.0.1', '', 'not-an-ip']) {
    assert.equal(isDeveloperLocalAddress(a), false, a)
  }
})

test('a blocked URL with no resolved address stays generic', () => {
  // e.g. a scheme rejection, where there is no address to classify.
  assert.equal(blockedUrlMessage('scheme "file:" not allowed'), 'Blocked URL: scheme "file:" not allowed')
})

test('the resolved address is parsed out of the guard text', () => {
  assert.equal(resolvedAddressFrom(LOCALHOST_DETAIL), '::1')
  assert.equal(resolvedAddressFrom('"a.test" resolves to blocked internal address 192.168.1.5'), '192.168.1.5')
  assert.equal(resolvedAddressFrom('cannot resolve host "nope"'), undefined)
})
