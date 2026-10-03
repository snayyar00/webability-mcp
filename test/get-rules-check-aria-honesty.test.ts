/**
 * Tool honesty for get_rules + check_aria (loop bug #7).
 *
 * get_rules:
 *  - a bogus `engine` silently returned ALL rules (the `!== 'webability'` /
 *    `!== 'axe'` guards only exclude exact matches) — must be a validation
 *    error naming the valid values.
 *  - unknown args (e.g. `tag` instead of `tags`) were silently swallowed —
 *    must error naming the offender and the valid keys.
 *  - validation was per-field (fixability only) — engine/tags must validate
 *    too, before any engine runs.
 *
 * check_aria:
 *  - nodes were silently capped at 5 per rule with no disclosure — each rule
 *    must report nodesTotal + truncated, following the scan_page vocabulary.
 *  - recovery was impossible: check_aria is scan_history-logged but never
 *    registered its full result, so history stored the truncated response.
 *    The full node set must be recoverable via scan_history(id), and a
 *    nodeLimit arg must allow direct recovery (hosted servers keep no
 *    history).
 */
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

const dir = mkdtempSync(join(tmpdir(), 'wa-honest-'))
process.env.WEBABILITY_SCAN_LOG_DIR = dir

const { createServer } = await import('../src/server.ts')

async function connect() {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer({})
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return client
}

const firstText = (res: any) => String(res.content[0].text)
const jsonBlock = (res: any) => JSON.parse(String(res.content[1].text).replace(/^```json\n|\n```$/g, ''))

// ── get_rules ───────────────────────────────────────────────────────────────

test('get_rules rejects a bogus engine instead of returning everything', async () => {
  const res: any = await (await connect()).callTool({ name: 'get_rules', arguments: { engine: 'bogus' } })
  assert.match(firstText(res), /^Error: engine must be one of all \| axe \| webability/)
})

test('get_rules rejects unknown args instead of swallowing them', async () => {
  const res: any = await (await connect()).callTool({ name: 'get_rules', arguments: { tag: ['wcag21aa'] } as any })
  assert.match(firstText(res), /^Error: unknown argument 'tag'/)
  assert.match(firstText(res), /tags, fixability, engine/)
})

test('get_rules rejects non-array tags', async () => {
  const res: any = await (await connect()).callTool({ name: 'get_rules', arguments: { tags: 'wcag21aa' } as any })
  assert.match(firstText(res), /^Error: tags must be an array of strings/)
})

test('get_rules control: engine=axe returns axe rules only', async () => {
  const res: any = await (await connect()).callTool({ name: 'get_rules', arguments: { engine: 'axe' } })
  const rules = jsonBlock(res)
  assert.ok(rules.length > 50, `expected dozens of axe rules, got ${rules.length}`)
  assert.ok(rules.every((r: any) => r.engine === 'axe-core'))
})

// ── check_aria ──────────────────────────────────────────────────────────────

// Six nameless role=button divs → one rule (button-name) with 6 nodes.
const SIX_BAD_BUTTONS = `<!DOCTYPE html><html lang="en"><head><title>t</title></head><body><main>${'<div role="button" tabindex="0"></div>'.repeat(6)}</main></body></html>`

test('check_aria discloses per-rule node truncation', async () => {
  const res: any = await (await connect()).callTool({ name: 'check_aria', arguments: { html: SIX_BAD_BUTTONS } })
  const { violations } = jsonBlock(res)
  const rule = violations.find((v: any) => /command-name|button-name/.test(v.id))
  assert.ok(rule, 'expected the unnamed-command rule')
  assert.equal(rule.nodes.length, 5)
  assert.equal(rule.nodesTotal, 6)
  assert.equal(rule.truncated, true)
  assert.match(firstText(res), /truncat/i)
})

test('check_aria nodeLimit recovers beyond the default cap', async () => {
  const res: any = await (await connect()).callTool({ name: 'check_aria', arguments: { html: SIX_BAD_BUTTONS, nodeLimit: 10 } })
  const { violations } = jsonBlock(res)
  const rule = violations.find((v: any) => /command-name|button-name/.test(v.id))
  assert.ok(rule, 'expected the unnamed-command rule')
  assert.equal(rule.nodes.length, 6)
  assert.equal(rule.truncated, false)
})

test('check_aria full node set is recoverable via scan_history(id)', async () => {
  const client = await connect()
  const res: any = await client.callTool({ name: 'check_aria', arguments: { html: SIX_BAD_BUTTONS } })
  assert.match(firstText(res), /scan_history/i)
  const list: any = await client.callTool({ name: 'scan_history', arguments: { limit: 5 } })
  const id = /id=([^\s]+)/.exec(firstText(list))?.[1]
  assert.ok(id, 'expected a history id for the check_aria call')
  const full: any = await client.callTool({ name: 'scan_history', arguments: { id } })
  const stored = JSON.parse(firstText(full).replace(/^```json\n|\n```$/g, ''))
  const archivedJson = stored.response.content.find((c: any) => String(c.text).startsWith('```json'))
  const payload = JSON.parse(String(archivedJson.text).replace(/^```json\n|\n```$/g, ''))
  const rule = (payload.violations || []).find((v: any) => /command-name|button-name/.test(v.id))
  assert.ok(rule, 'expected the unnamed-command rule in the archived result')
  assert.equal(rule.nodes.length, 6)
})

test('check_aria control: at-or-under the cap reports truncated=false', async () => {
  const html = `<!DOCTYPE html><html lang="en"><head><title>t</title></head><body><main>${'<div role="button" tabindex="0"></div>'.repeat(3)}</main></body></html>`
  const res: any = await (await connect()).callTool({ name: 'check_aria', arguments: { html } })
  const { violations } = jsonBlock(res)
  const rule = violations.find((v: any) => /command-name|button-name/.test(v.id))
  assert.ok(rule, 'expected the unnamed-command rule')
  assert.equal(rule.nodes.length, 3)
  assert.equal(rule.truncated, false)
})
