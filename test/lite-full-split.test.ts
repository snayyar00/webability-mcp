/**
 * Lite (local stdio) and Full (hosted) must not advertise the same tools.
 *
 * Before this split both transports listed everything, so an agent on Lite
 * would call visual_audit / start_audit / get_audit and get a runtime failure
 * with nothing in the listing explaining why. The fix is not to hide them —
 * that loses the upgrade path — but to list them as stubs that say what they
 * are and how to get them.
 *
 * These drive the real createServer() over an in-memory transport, so they
 * exercise the actual tools/list and dispatch, not a mock.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

async function connect(remote: boolean) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer(remote ? { remote: true, authToken: 'test-token' } : {})
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return client
}

const names = (tools: Array<{ name: string }>) => tools.map((t) => t.name)

test('Lite keeps the local-only tools; Full does not have them', async () => {
  // find_source searches a local project and scan_history reads a local log —
  // neither exists server-side, so listing them on Full promises nothing.
  const lite = await (await connect(false)).listTools()
  const full = await (await connect(true)).listTools()

  for (const local of ['find_source', 'scan_history']) {
    assert.ok(names(lite.tools).includes(local), `Lite must offer ${local}`)
    assert.ok(!names(full.tools).includes(local), `Full must NOT offer ${local}`)
  }
})

test('Lite still LISTS the Full tools, as labelled stubs', async () => {
  // Hiding them would remove the only place an agent learns they exist.
  const { tools } = await (await connect(false)).listTools()
  for (const full of ['visual_audit', 'start_audit', 'get_audit']) {
    const tool = tools.find((t) => t.name === full)
    assert.ok(tool, `${full} must stay visible on Lite`)
    assert.match(tool!.description!, /^\[Full/, `${full} must be labelled as Full`)
    assert.match(tool!.description!, /FREE with a WebAbility account/, `${full} must name the (free) upgrade path`)
  }
})

test('Full does NOT carry the Lite stub prefix', async () => {
  // The stub prefix on the transport that can actually run the tool would be
  // nonsense, and it is the shape a naive "always prefix" fix would produce.
  const { tools } = await (await connect(true)).listTools()
  const va = tools.find((t) => t.name === 'visual_audit')!
  assert.doesNotMatch(va.description!, /^\[Full/)
})

test('calling a Full tool on Lite explains the upgrade instead of failing', async () => {
  // The old behaviour was a runtime error from the tool body; this is the
  // whole point of the split.
  const client = await connect(false)
  const res: any = await client.callTool({
    name: 'visual_audit',
    arguments: { url: 'https://example.com', context: 'Verifying that Lite refuses a Full tool with an actionable upgrade message rather than a runtime failure.' },
  })
  const text = res.content.map((c: any) => c.text).join('\n')
  assert.match(text, /WebAbility MCP Full/)
  assert.match(text, /mcp\.webability\.io/, 'must name where to connect')
  assert.doesNotMatch(text, /Error:|failed/i, 'must not read as a crash')
})

test('the scan/fix/verify loop is on BOTH transports', async () => {
  // The split must not accidentally gate the free core loop.
  const lite = names((await (await connect(false)).listTools()).tools)
  const full = names((await (await connect(true)).listTools()).tools)
  for (const core of ['scan_page', 'detect_framework', 'generate_ai_fix', 'verify_fix', 'flow_scan', 'scan_html']) {
    assert.ok(lite.includes(core), `Lite must offer ${core}`)
    assert.ok(full.includes(core), `Full must offer ${core}`)
  }
})

test('hosted check_aria does not point at scan_history (the hosted server keeps none); local still does', async () => {
  const full = (await (await connect(true)).listTools()).tools.find((t) => t.name === 'check_aria')!
  const lite = (await (await connect(false)).listTools()).tools.find((t) => t.name === 'check_aria')!
  assert.doesNotMatch(full.description!, /scan_history/)
  assert.match(full.description!, /nodeLimit/)
  assert.match(lite.description!, /scan_history/)
})

test('hosted instructions: scan/check tools need no token, key or account; a free account (client sign-in) unlocks the three Full tools', async () => {
  const text = (await connect(true)).getInstructions() ?? ''
  // "tokens" also appears as LLM output size (format: "compact"); only an
  // auth-token requirement is wrong.
  assert.doesNotMatch(text, /(webability|your|that|auth|api|access)\s+token|token\s+(is\s+)?required|need[s]?\s+(a\s+)?token/i, 'the hosted model is free: no token is required for any scan tool')
  assert.match(text, /no account or key/i)
  assert.match(text, /fair-use limits per IP/i)
  assert.match(text, /sign-in prompted by your client/i)
  for (const t of ['visual_audit', 'start_audit', 'get_audit']) assert.ok(text.includes(t), t)
  assert.doesNotMatch(text, /abilyo/i)
  const lite = (await connect(false)).getInstructions() ?? ''
  assert.match(lite, /webability login/)
  assert.match(lite, /@webability\/cli/)
})
