/**
 * Directory review (Claude connectors directory, ChatGPT plugin directory)
 * requires every tool to carry a human `title` and EXPLICIT behaviour hints:
 * readOnlyHint, destructiveHint, idempotentHint, openWorldHint. A tool with
 * no hints is treated as "may write, may destroy" and fails review.
 * Drives the real tools/list on both transports.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

async function list(remote: boolean) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const server = createServer(remote ? { remote: true, authToken: 'test-token' } : {})
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(s), client.connect(c)])
  return (await client.listTools()).tools
}

for (const remote of [false, true]) {
  test(`every ${remote ? 'hosted' : 'local'} tool has a title and all four explicit hints`, async () => {
    for (const tool of await list(remote)) {
      const a = tool.annotations as Record<string, unknown> | undefined
      assert.ok(a, `${tool.name}: no annotations`)
      assert.equal(typeof a.title, 'string', `${tool.name}: annotations.title`)
      assert.ok((a.title as string).length > 0 && (a.title as string).length <= 64, `${tool.name}: title length`)
      for (const k of ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint']) {
        assert.equal(typeof a[k], 'boolean', `${tool.name}: ${k} must be an explicit boolean`)
      }
      assert.equal(tool.title, a.title, `${tool.name}: top-level title should match annotations.title`)
      // Nothing we ship deletes user data. generate_report_pdf overwrites the
      // same-day report for a host, and posts findings to our API.
      assert.equal(a.destructiveHint, tool.name === 'generate_report_pdf', `${tool.name}: destructiveHint`)
      if (tool.name === 'generate_report_pdf') assert.equal(a.openWorldHint, true, 'generate_report_pdf: openWorldHint')
    }
  })
}

test('tools that create something, spend credit, or send page content are not read-only', async () => {
  const tools = await list(false)
  const writes = tools.filter((t) => (t.annotations as any).readOnlyHint === false).map((t) => t.name).sort()
  // start_audit: creates a server-side job (credit). generate_report_pdf:
  // writes a file and posts findings to the API. generate_ai_fix /
  // visual_audit: send an HTML snippet / screenshot to a third-party model.
  // add_site: adds a site to the account. create_upgrade_link: creates a
  // Stripe Checkout session.
  assert.deepEqual(writes, ['add_site', 'create_upgrade_link', 'generate_ai_fix', 'generate_report_pdf', 'start_audit', 'visual_audit'])
})
