/**
 * Body caps (#199) without spawning the hosted server: readBodyCapped stops
 * an oversized body (declared or chunked) and still returns a normal one.
 * The full-server check is body-limit.e2e.mjs.
 */
import assert from 'node:assert/strict'
import { createServer, request } from 'node:http'
import { AddressInfo } from 'node:net'
import { test } from 'node:test'

import { BodyTooLargeError, declaredTooLarge, MCP_MAX_BODY_BYTES, OAUTH_MAX_BODY_BYTES, readBodyCapped } from '../src/bodyLimit'

const LIMIT = 1024

/** Server that reads with the cap and answers 200 <bytes> or 413. */
async function withServer(fn: (port: number) => Promise<void>) {
  const server = createServer(async (req, res) => {
    try {
      const body = await readBodyCapped(req, LIMIT)
      res.end(`200 ${body.length}`)
    } catch (err) {
      res.setHeader('Connection', 'close')
      res.end(err instanceof BodyTooLargeError ? '413' : 'other')
    }
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()))
  try {
    await fn((server.address() as AddressInfo).port)
  } finally {
    server.close()
  }
}

function post(port: number, body: Buffer, chunked: boolean): Promise<string> {
  return new Promise((resolve) => {
    const req = request({ host: '127.0.0.1', port, method: 'POST', headers: chunked ? {} : { 'content-length': body.length } }, (res) => {
      let out = ''
      res.on('data', (c) => (out += c))
      res.on('end', () => resolve(out))
    })
    req.on('error', () => resolve('reset'))
    if (chunked) {
      for (let off = 0; off < body.length; off += 256) req.write(body.subarray(off, off + 256))
      req.end()
    } else req.end(body)
  })
}

test('under the cap: the whole body comes back (declared and chunked)', async () => {
  await withServer(async (port) => {
    assert.equal(await post(port, Buffer.alloc(LIMIT, 'a'), false), `200 ${LIMIT}`)
    assert.equal(await post(port, Buffer.alloc(LIMIT, 'a'), true), `200 ${LIMIT}`)
  })
})

test('over the cap: refused (declared Content-Length and chunked)', async () => {
  await withServer(async (port) => {
    assert.ok(['413', 'reset'].includes(await post(port, Buffer.alloc(LIMIT + 1, 'a'), false)))
    assert.ok(['413', 'reset'].includes(await post(port, Buffer.alloc(LIMIT * 64, 'a'), true)))
  })
})

test('declaredTooLarge reads Content-Length only', () => {
  const req = (h: Record<string, string>) => ({ headers: h }) as any
  assert.equal(declaredTooLarge(req({ 'content-length': String(LIMIT + 1) }), LIMIT), true)
  assert.equal(declaredTooLarge(req({ 'content-length': String(LIMIT) }), LIMIT), false)
  assert.equal(declaredTooLarge(req({}), LIMIT), false)
  assert.equal(declaredTooLarge(req({ 'content-length': 'nonsense' }), LIMIT), true)
})

test('defaults: /mcp fits a large scan_html page, OAuth bodies stay small', () => {
  assert.equal(MCP_MAX_BODY_BYTES, 5 * 1024 * 1024)
  assert.equal(OAUTH_MAX_BODY_BYTES, 64 * 1024)
})
