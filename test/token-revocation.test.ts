/**
 * #229: a token the platform validated was trusted for TOKEN_TTL_MS (5 min).
 * Revoking it in the dashboard left it working in MCP for the rest of that
 * window, because only the HTTP gate ever wrote to the cache and nothing a
 * *tool* call learned was fed back into it.
 *
 * Now any platform call made with the caller's own token that answers 401/403
 * evicts the token, so the next request re-validates against the platform.
 */
import assert from 'node:assert/strict'
import { afterEach, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'
import { TOKEN_TTL_MS, forgetValidatedToken, validatedTokens } from '../src/tokenCache.ts'
import { checkToken } from '../src/tokenCheck.ts'

const TOKEN = 'revoked-token'
const realFetch = globalThis.fetch

afterEach(() => {
  globalThis.fetch = realFetch
  forgetValidatedToken(TOKEN)
})

/** A cached token is trusted with no platform call. */
test('a cached token skips the platform call', async () => {
  let calls = 0
  globalThis.fetch = (async () => {
    calls++
    return new Response('{}', { status: 200 })
  }) as typeof fetch
  validatedTokens.set(TOKEN, Date.now() + TOKEN_TTL_MS)

  assert.deepEqual(await checkToken('https://api.test', validatedTokens, TOKEN), { state: 'valid' })
  assert.equal(calls, 0)
})

/** Evicting forces the next request to ask the platform again. */
test('an evicted token is re-validated against the platform', async () => {
  let calls = 0
  globalThis.fetch = (async () => {
    calls++
    return new Response('{}', { status: 200 })
  }) as typeof fetch
  validatedTokens.set(TOKEN, Date.now() + TOKEN_TTL_MS)

  await checkToken('https://api.test', validatedTokens, TOKEN)
  assert.equal(calls, 0, 'cached: no platform call')

  forgetValidatedToken(TOKEN)
  assert.deepEqual(await checkToken('https://api.test', validatedTokens, TOKEN), { state: 'valid' })
  assert.equal(calls, 1, 'after eviction: one platform call')
})

/** Drives the real createServer with fetch stubbed to answer `status` for the audit route. */
async function getAuditWithStatus(status: number) {
  globalThis.fetch = (async () => new Response('{}', { status })) as typeof fetch
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer({ remote: true, authToken: TOKEN })
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  const res: any = await client.callTool({ name: 'get_audit', arguments: { id: 1, context: 'revocation check', llm_model: 'test' } })
  return res.content.map((c: any) => c.text).join('\n') as string
}

for (const status of [401, 403]) {
  test(`get_audit answering ${status} evicts the caller's token`, async () => {
    validatedTokens.set(TOKEN, Date.now() + TOKEN_TTL_MS)
    const text = await getAuditWithStatus(status)
    assert.match(text, /could not authenticate/, text)
    assert.equal(validatedTokens.has(TOKEN), false, 'a refused token must not stay cached')
  })
}

/** A status that is not a verdict on the token must leave the cache alone. */
test('get_audit answering 429 keeps the token cached', async () => {
  validatedTokens.set(TOKEN, Date.now() + TOKEN_TTL_MS)
  await getAuditWithStatus(429)
  assert.equal(validatedTokens.has(TOKEN), true)
})
