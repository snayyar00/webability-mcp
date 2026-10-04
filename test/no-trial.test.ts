/**
 * The anonymous "50-call trial" is gone (platform deleted /cli/mcp-trial/* in
 * PR #1064). The product is FREE for everyone: anonymous scan/check tools under
 * fair-use limits; a free account unlocks visual_audit / start_audit / get_audit.
 * Nothing user-facing may mention trial, claim tokens, paid tiers or credits.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
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

const BANNED = /trial|claimToken|paid|credit/i

for (const remote of [false, true]) {
  const label = remote ? 'hosted (Full)' : 'local (Lite)'

  test(`${label}: no trial/paid/credit wording in tool descriptions or schemas`, async () => {
    const { tools } = await (await connect(remote)).listTools()
    for (const t of tools) {
      assert.doesNotMatch(t.description ?? '', BANNED, `${t.name} description`)
      assert.doesNotMatch(JSON.stringify(t.inputSchema), BANNED, `${t.name} input schema`)
    }
  })

  test(`${label}: no trial/paid/credit wording in instructions`, async () => {
    const instructions = (await connect(remote)).getInstructions() ?? ''
    assert.doesNotMatch(instructions, BANNED)
  })
}

test('source files carry no dead trial plumbing', () => {
  for (const f of ['../src/http.ts', '../src/server.ts']) {
    const src = readFileSync(new URL(f, import.meta.url), 'utf8')
    assert.ok(!src.includes('mcp-trial'), `${f} mentions mcp-trial`)
    assert.ok(!src.includes('MCP_TRIAL'), `${f} mentions MCP_TRIAL`)
  }
})
