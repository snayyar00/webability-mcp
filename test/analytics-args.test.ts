/**
 * MCP dogfood 2026-10-03 (Claude, hosted): check_aria, verify_fix and
 * get_rules answered `unknown argument 'context' — valid keys: url, selector,
 * wcag, viewport, tunnel_secret` although their advertised schema listed
 * `context` and `llm_model` — as REQUIRED. @posthog/mcp injects those
 * analytics args (plus `conversation_id`) into every schema and strips them
 * from a call only when that same server instance served tools/list first.
 * The hosted transport builds a fresh server per request, so the call
 * arrived with them and the strict validators refused it.
 *
 * PostHog runs ON in this file (dummy key, dead host) — that is production's
 * shape on the hosted server.
 */
process.env.POSTHOG_PROJECT_API_KEY = 'phc_test_dummy'
process.env.POSTHOG_HOST = 'http://127.0.0.1:9'
process.env.POSTHOG_FLUSH_AT = '100000'
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import * as serverMod from '../src/server.ts'

const { createServer } = serverMod
const ANALYTICS_ARG_KEYS = ['context', 'llm_model', 'conversation_id']
const strictArgError = (name: string, args: Record<string, unknown>): string | null => {
  const fn = (serverMod as any).strictArgError
  assert.equal(typeof fn, 'function', 'server.ts must export strictArgError')
  return fn(name, args)
}

async function connect(remote: boolean) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const server = createServer(remote ? { remote: true, authToken: 'test-token' } : {})
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(s), client.connect(c)])
  return client
}
const firstText = (r: any) => String(r?.content?.find((c: any) => c?.type === 'text')?.text ?? '')
const analytics = { context: 'Checking a page for accessibility problems for a user.', llm_model: 'claude-sonnet-5-5', conversation_id: 'conv-123' }

test('advertised analytics args are optional, never required', async () => {
  for (const remote of [false, true]) {
    const tools = (await (await connect(remote)).listTools()).tools
    const injected = tools.filter((t) => 'llm_model' in ((t.inputSchema as any).properties ?? {}))
    assert.ok(injected.length > 0, 'PostHog should have injected llm_model — the test must exercise the injected schema')
    for (const t of tools) {
      const req: string[] = (t.inputSchema as any).required ?? []
      for (const k of ANALYTICS_ARG_KEYS) assert.ok(!req.includes(k), `${remote ? 'hosted' : 'local'} ${t.name}: '${k}' must not be required`)
    }
  }
})

// A fresh server per call with no tools/list first — the hosted per-request shape.
for (const [name, args, remote] of [
  ['get_rules', { tags: ['wcag143'], ...analytics }, true],
  ['verify_fix', { url: 'http://127.0.0.1:9/', selector: '#x', ...analytics }, false],
  ['check_aria', { html: '<button aria-pressed="maybe">x</button>', ...analytics }, false],
] as const) {
  test(`${name} accepts the analytics args on a cold server`, async () => {
    const client = await connect(remote)
    const r = await client.callTool({ name, arguments: args as Record<string, unknown> }, undefined, { timeout: 60_000 })
    assert.doesNotMatch(firstText(r), /unknown argument/, firstText(r).slice(0, 200))
  })
}

test('every advertised property of every tool passes the strict-args gate', async () => {
  for (const remote of [false, true]) {
    for (const t of (await (await connect(remote)).listTools()).tools) {
      for (const prop of Object.keys((t.inputSchema as any).properties ?? {})) {
        const err = strictArgError(t.name, { [prop]: 'x' })
        assert.equal(err, null, `${remote ? 'hosted' : 'local'} ${t.name}: advertised '${prop}' rejected: ${err}`)
      }
    }
  }
})

test('truly unknown keys are still rejected by the strict tools', () => {
  for (const name of ['get_rules', 'verify_fix', 'check_aria']) {
    assert.match(String(strictArgError(name, { bogus: 1 })), /unknown argument 'bogus'/, name)
  }
})

// Persona round 4 friction #4 (18/80 runs): the injected `conversation_id`
// told the model to "echo the conversation_id from the server's previous
// response", and no response ever carries one. It is no longer advertised
// anywhere; a call that still sends it is accepted and the value ignored.
test('conversation_id is not advertised by any tool (property, required, or description)', async () => {
  for (const remote of [false, true]) {
    const tools = (await (await connect(remote)).listTools()).tools
    assert.ok(tools.some((t) => 'llm_model' in ((t.inputSchema as any).properties ?? {})), 'PostHog must still inject llm_model — or this test exercises nothing')
    for (const t of tools) {
      const schema = t.inputSchema as any
      assert.ok(!('conversation_id' in (schema.properties ?? {})), `${remote ? 'hosted' : 'local'} ${t.name}: conversation_id property still advertised`)
      assert.ok(!(schema.required ?? []).includes('conversation_id'), `${t.name}: conversation_id required`)
      assert.doesNotMatch(JSON.stringify(t), /conversation_id/, `${remote ? 'hosted' : 'local'} ${t.name}: conversation_id still mentioned`)
    }
  }
})

test('a call that still sends conversation_id is accepted on both transports', async () => {
  for (const remote of [false, true]) {
    const client = await connect(remote)
    const r = await client.callTool({ name: 'get_rules', arguments: { rule: 'image-alt', conversation_id: 'conv-xyz' } })
    assert.notEqual((r as any).isError, true, firstText(r))
    assert.match(firstText(r), /^[1-9]\d* rules? matching/)
  }
})
