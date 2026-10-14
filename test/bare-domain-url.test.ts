/**
 * A URL typed without a scheme ("webability.io") must be scanned, not refused.
 *
 * Zapier's "Page URL" field and most humans send bare domains. The hosted SSRF
 * guard used to run `new URL()` on the raw value, which throws on a bare domain,
 * so the call failed with `invalid URL` before the scan code (which already
 * added https://) ever ran. Normalising first must NOT open a hole: bare
 * localhost / loopback / metadata addresses are still refused.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer, normalizeUrlArg } from '../src/server.ts'

async function hostedClient() {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer({ remote: true, authToken: 'test-token' })
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return client
}

const textOf = (res: any) => res.content.map((c: any) => c.text).join('\n')

test('normalizeUrlArg adds https:// only when there is no scheme', () => {
  assert.equal(normalizeUrlArg('webability.io'), 'https://webability.io')
  assert.equal(normalizeUrlArg('  www.usa.gov/about  '), 'https://www.usa.gov/about')
  assert.equal(normalizeUrlArg('localhost:3000'), 'https://localhost:3000')
  assert.equal(normalizeUrlArg('https://webability.io'), 'https://webability.io')
  assert.equal(normalizeUrlArg('http://webability.io'), 'http://webability.io')
  assert.equal(normalizeUrlArg('HTTPS://webability.io'), 'HTTPS://webability.io')
  assert.equal(normalizeUrlArg('file:///etc/passwd'), 'file:///etc/passwd')
  assert.equal(normalizeUrlArg('ftp://host/x'), 'ftp://host/x')
  // A scheme without "//" is still a scheme: new URL() accepts http:example.com.
  assert.equal(normalizeUrlArg('http:example.com'), 'http:example.com')
  assert.equal(normalizeUrlArg('javascript:alert(1)'), 'javascript:alert(1)')
  // host:port is not a scheme.
  assert.equal(normalizeUrlArg('example.com:8080/x'), 'https://example.com:8080/x')
  // Blank stays blank so alias fallbacks (verify_fix url -> pageUrl) still work.
  assert.equal(normalizeUrlArg('   '), '')
})

test('hosted verify_fix: a blank url does not block the pageUrl alias', async () => {
  const client = await hostedClient()
  const text = textOf(await client.callTool({
    name: 'verify_fix',
    arguments: { url: ' ', pageUrl: 'http://127.0.0.1:3000/', context: 'Checking a blank canonical url falls through to the alias.' },
  }))
  // The alias (a loopback URL) is what the guard must judge, not "https://".
  assert.match(text, /Blocked URL/)
  assert.doesNotMatch(text, /invalid URL "https:\/\/"/)
})

for (const bare of ['localhost:3000', '127.0.0.1', '169.254.169.254/latest/meta-data']) {
  test(`hosted scan_page still refuses bare ${bare}, as a blocked address not a parse error`, async () => {
    const client = await hostedClient()
    const text = textOf(await client.callTool({
      name: 'scan_page',
      arguments: { url: bare, context: 'Checking bare internal addresses stay blocked after normalisation.' },
    }))
    assert.match(text, /Blocked URL/)
    assert.doesNotMatch(text, /invalid URL/, 'must reach the address check, not fail parsing')
  })
}

test('hosted flow_scan refuses a bare loopback address inside autoNavigate', async () => {
  const client = await hostedClient()
  const text = textOf(await client.callTool({
    name: 'flow_scan',
    arguments: {
      startUrl: 'https://www.usa.gov',
      autoNavigate: ['127.0.0.1:3000/admin'],
      context: 'Checking a bare loopback URL in a journey is still blocked.',
    },
  }))
  assert.match(text, /Blocked URL/)
  assert.doesNotMatch(text, /invalid URL/)
})

test('hosted file:// is still refused', async () => {
  const client = await hostedClient()
  const text = textOf(await client.callTool({
    name: 'scan_page',
    arguments: { url: 'file:///etc/passwd', context: 'Checking non-http schemes stay blocked.' },
  }))
  assert.match(text, /Blocked URL/)
})
