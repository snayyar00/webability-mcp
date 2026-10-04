/**
 * Persona round 4 (friction #13): get_rules `rule: "link"` substring-matched
 * `blink`, and `category: "landmarks"` / tags ["cat.landmarks"] answered
 * "0 rules" with no hint that no such category exists. `rule` now matches
 * whole words of a rule id; an unknown tag or category is an error listing
 * the valid categories (read from axe at runtime, not a hand-written list).
 */
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
process.env.WEBABILITY_SCAN_LOG = 'off'

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import * as rulesArgs from '../src/getRulesArgs.ts'
import { createServer } from '../src/server.ts'

async function call(args: Record<string, unknown>, remote = false) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([createServer(remote ? { remote: true, authToken: 't' } : {}).connect(s), client.connect(c)])
  const r: any = await client.callTool({ name: 'get_rules', arguments: args })
  const first = String(r.content[0].text)
  const list = r.isError ? [] : (JSON.parse(String(r.content[1].text).replace(/^```json\n|\n```$/g, '')) as any[])
  return { isError: r.isError === true, first, ids: list.map((x) => String(x.ruleId)) }
}

test('ruleIdMatches (pure): whole words of the id, plural-tolerant, never inside a word', () => {
  const m = (rulesArgs as any).ruleIdMatches
  assert.equal(typeof m, 'function', 'getRulesArgs must export ruleIdMatches')
  assert.equal(m('blink', 'link'), false)
  assert.equal(m('link-name', 'link'), true)
  assert.equal(m('identical-links-same-purpose', 'link'), true)
  assert.equal(m('empty_link', 'link'), true)
  assert.equal(m('color-contrast-enhanced', 'color-contrast'), true)
  assert.equal(m('color-contrast', 'color_contrast'), true)
  assert.equal(m('contrast_insufficient', 'color-contrast'), false)
  assert.equal(m('image-alt', 'image-alt'), true)
  assert.equal(m('role-img-alt', 'image-alt'), false)
  assert.equal(m('aria-allowed-attr', 'ARIA'), true)
  assert.equal(m('variant', 'aria'), false)
})

for (const remote of [false, true]) {
  const where = remote ? 'hosted' : 'local'

  test(`${where}: rule "link" lists link rules and not blink`, async () => {
    const r = await call({ rule: 'link' }, remote)
    assert.equal(r.isError, false, r.first)
    assert.ok(r.ids.includes('link-name'), r.ids.join(','))
    assert.ok(!r.ids.includes('blink'), 'blink is not a link rule')
  })

  test(`${where}: category "landmarks" is an error listing the real categories`, async () => {
    const r = await call({ category: 'landmarks' }, remote)
    assert.equal(r.isError, true, r.first)
    assert.match(r.first, /landmarks/)
    assert.match(r.first, /cat\.aria/)
    assert.match(r.first, /cat\.semantics/)
  })

  test(`${where}: tags ["cat.landmarks"] is an error too, never a silent 0`, async () => {
    const r = await call({ tags: ['cat.landmarks'] }, remote)
    assert.equal(r.isError, true, r.first)
    assert.match(r.first, /cat\.keyboard/)
  })
}

test('category without the cat. prefix resolves (category: "aria" = cat.aria)', async () => {
  const short = await call({ category: 'aria' })
  const full = await call({ tags: ['cat.aria'] })
  assert.equal(short.isError, false, short.first)
  assert.ok(short.ids.length > 0)
  assert.deepEqual(short.ids.sort(), full.ids.sort())
})

test('known non-category tags keep working (best-practice, wcag143, section508)', async () => {
  for (const tags of [['best-practice'], ['wcag143'], ['section508']]) {
    const r = await call({ tags })
    assert.equal(r.isError, false, `${tags}: ${r.first}`)
    assert.ok(r.ids.length > 0, String(tags))
  }
})

test('an unknown plain tag is an error naming valid forms', async () => {
  const r = await call({ tags: ['dragging'] })
  assert.equal(r.isError, true)
  assert.match(r.first, /unknown tag "dragging"/)
  assert.match(r.first, /wcag2aa/)
})

test('a rule word that matches nothing says so and how to widen', async () => {
  const r = await call({ rule: 'zzqx' })
  assert.equal(r.isError, false)
  assert.match(r.first, /^0 rules/)
  assert.match(r.first, /no rule id contains the word/)
})

test('empty args still list every rule', async () => {
  const r = await call({})
  assert.ok(r.ids.length > 150, String(r.ids.length))
})

// Critic pass: level A / AAA expand to wcag22a / wcag21aaa, which axe does
// not carry — the expansion must not be rejected as an unknown tag.
test('level A and AAA (and wcag: "AAA") still list rules', async () => {
  for (const args of [{ level: 'A' }, { level: 'AAA' }, { wcag: 'AAA' }, { level: 'AA' }]) {
    const r = await call(args)
    assert.equal(r.isError, false, `${JSON.stringify(args)}: ${r.first}`)
    assert.ok(r.ids.length > 0, JSON.stringify(args))
  }
})

test('a WCAG criterion no rule covers says so in WCAG terms', async () => {
  const r = await call({ wcag: '1.3.6' })
  assert.match(r.first, /no rule covers WCAG 1\.3\.6/)
  assert.doesNotMatch(r.first, /unknown tag/)
})
