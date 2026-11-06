/**
 * Machine-readable errors and long-job hints (note 2026-11-05-learn-from-best-mcps, changes 3 and 4).
 *
 * 1. Every isError result carries structuredContent.error = { code, retriable, next }
 *    and keeps its prose text block.
 * 2. start_audit / get_audit return { id, status, pollAfterSeconds, next, expiresAt }
 *    in structuredContent; an unknown or expired id is an execution error with a next step.
 */
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

process.env.HOME = mkdtempSync(join(tmpdir(), 'wa-struct-home-'))
delete process.env.WEBABILITY_API_KEY
delete process.env.ABILYO_API_KEY
delete process.env.XDG_CONFIG_HOME
delete process.env.WEBABILITY_SCAN_TELEMETRY
process.env.WEBABILITY_SCAN_LOG = 'off'

import assert from 'node:assert/strict'
import { afterEach, beforeEach, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

const realFetch = globalThis.fetch
let auditRoute: (url: string) => Response = () => new Response(null, { status: 204 })
beforeEach(() => {
  globalThis.fetch = (async (input: any) => auditRoute(String(input))) as typeof fetch
})
afterEach(() => {
  globalThis.fetch = realFetch
})

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

async function call(name: string, args: Record<string, unknown>, opts: Record<string, unknown> = { remote: true, authToken: 'test-token' }) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const cl = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([createServer(opts as any).connect(s), cl.connect(c)])
  const r: any = await cl.callTool({ name, arguments: args })
  await cl.close()
  return r
}

test('isError result keeps its text and gains structuredContent.error', async () => {
  const r = await call('scan_page', {})
  assert.equal(r.isError, true)
  assert.match(r.content[0].text, /url is required/)
  const e = r.structuredContent?.error
  assert.ok(e, 'structuredContent.error is missing')
  assert.equal(e.code, 'invalid_args')
  assert.equal(e.retriable, false)
  assert.equal(e.next.tool, 'scan_page')
})

test('a rate-limited failure is retriable', async () => {
  auditRoute = () => new Response('slow down', { status: 429 })
  const r = await call('start_audit', { url: 'https://example.com' })
  assert.equal(r.isError, true)
  assert.equal(r.structuredContent?.error?.code, 'rate_limited')
  assert.equal(r.structuredContent?.error?.retriable, true)
})

test('start_audit returns typed poll hints', async () => {
  auditRoute = () => json({ id: 7, status: 'pending' })
  const r = await call('start_audit', { url: 'https://example.com' })
  assert.notEqual(r.isError, true)
  const sc = r.structuredContent
  assert.equal(sc.id, 7)
  assert.equal(sc.status, 'pending')
  assert.equal(sc.pollAfterSeconds, 15)
  assert.deepEqual(sc.next, { tool: 'get_audit', args: { id: 7 } })
  assert.ok('expiresAt' in sc, 'expiresAt key is missing')
  assert.match(r.content[0].text, /poll `get_audit`/)
})

test('get_audit returns poll hints while running and none once complete', async () => {
  auditRoute = () => json({ id: 7, status: 'running', url: 'https://example.com', currentStep: 'scan', steps: [] })
  const running = await call('get_audit', { id: 7 })
  assert.equal(running.structuredContent.status, 'running')
  assert.equal(running.structuredContent.pollAfterSeconds, 15)
  assert.deepEqual(running.structuredContent.next, { tool: 'get_audit', args: { id: 7 } })

  auditRoute = () => json({ id: 7, status: 'complete', url: 'https://example.com', summary: { total: 1, Critical: 0, High: 1 }, steps: [] })
  const done = await call('get_audit', { id: 7 })
  assert.equal(done.structuredContent.status, 'complete')
  assert.equal(done.structuredContent.pollAfterSeconds, null)
  assert.equal(done.structuredContent.next, null)
})

test('an unknown or expired audit id is an execution error with a next step', async () => {
  auditRoute = () => new Response('not found', { status: 404 })
  const r = await call('get_audit', { id: 999 })
  assert.equal(r.isError, true)
  assert.match(r.content[0].text, /No audit #999/)
  const e = r.structuredContent?.error
  assert.equal(e?.code, 'audit_not_found')
  assert.equal(e?.retriable, false)
  assert.equal(e?.next?.tool, 'start_audit')
})

test('an expired token (401/403) points at sign-in, not at a plain retry', async () => {
  for (const status of [401, 403]) {
    auditRoute = () => new Response('nope', { status })
    const r = await call('get_audit', { id: 7 })
    assert.equal(r.isError, true)
    const e = r.structuredContent?.error
    assert.equal(e?.code, 'auth_required', `status ${status}`)
    assert.equal(e?.retriable, false)
    assert.match(e?.next?.action ?? '', /sign in|login/i)
  }
})
