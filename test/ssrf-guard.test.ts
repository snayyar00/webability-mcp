/**
 * assertSafeUrl's own address handling (hosted SSRF guard, server.ts).
 *
 * The guard asks `isIP(u.hostname)` to decide whether a URL names a literal
 * address or a hostname. WHATWG URL keeps the brackets on an IPv6 hostname
 * (`new URL('http://[::1]/').hostname === '[::1]'`), and `isIP('[::1]')` is 0.
 * So every IPv6 literal took the DNS branch: loopback refused for the wrong
 * reason ("cannot resolve host"), and a PUBLIC IPv6 site — which a hosted scan
 * must be able to reach — refused outright.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { assertSafeUrl } from '../src/server.ts'

test('a bracketed IPv6 literal is classified as an address, not a hostname', async () => {
  // BLOCKED, and for the right reason: the guard must say what it refused.
  await assert.rejects(() => assertSafeUrl('http://[::1]:8080/'), /resolves to blocked internal address ::1$/)
  await assert.rejects(() => assertSafeUrl('http://[::ffff:127.0.0.1]/'), /resolves to blocked internal address ::ffff:7f00:1$/)
  await assert.rejects(() => assertSafeUrl('http://[fe80::1]/'), /resolves to blocked internal address fe80::1$/)
  await assert.rejects(() => assertSafeUrl('http://[fd00::1]/'), /resolves to blocked internal address fd00::1$/)
})

test('a public IPv6 literal is allowed', async () => {
  // 2606:4700::1111 is Cloudflare's public resolver. The old code answered
  // `cannot resolve host "[2606:4700::1111]"` — a real site refused as if the
  // name were bogus. No DNS lookup: the literal is the address.
  await assertSafeUrl('http://[2606:4700::1111]/')
  await assertSafeUrl('https://[2606:4700::1111]:8443/x?y=1')
  await assertSafeUrl('http://[64:ff9b::808:808]/')
})

test('the error text names the bare address, not the bracket form', async () => {
  const err = await assertSafeUrl('http://[::1]/').then(() => null, (e: Error) => e)
  assert.ok(err)
  assert.doesNotMatch(err.message, /cannot resolve host/, 'a literal must never reach DNS')
  assert.doesNotMatch(err.message, /\[::1\].*blocked internal address/, 'the diagnostic must not re-bracket')
})

test('IPv4 and hostname paths are unchanged', async () => {
  await assert.rejects(() => assertSafeUrl('http://127.0.0.1/'), /resolves to blocked internal address 127\.0\.0\.1$/)
  await assert.rejects(() => assertSafeUrl('http://169.254.169.254/latest/meta-data/'), /blocked internal address 169\.254\.169\.254$/)
  await assert.rejects(() => assertSafeUrl('http://localhost/'), /resolves to blocked internal address (127\.0\.0\.1|::1)$/)
  await assertSafeUrl('http://8.8.8.8/')
})

test('scheme and syntax rejections keep their own messages', async () => {
  await assert.rejects(() => assertSafeUrl('file:///etc/passwd'), /scheme "file:" not allowed/)
  await assert.rejects(() => assertSafeUrl('ftp://example.test/'), /scheme "ftp:" not allowed/)
  await assert.rejects(() => assertSafeUrl('not a url'), /invalid URL/)
})
