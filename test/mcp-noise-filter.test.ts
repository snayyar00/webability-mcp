import assert from 'node:assert/strict'
import { test } from 'node:test'

import { isCallerMisuseNoise } from '../src/posthog.ts'

const noise = [
  'Error: Unknown tool: __mcpcheckup_probe_nonexistent_tool__',
  'Error: Unknown tool: __verifymcp_auth_probe_e93d1b3ef66ad230__',
  "Error: unknown argument 'context' — valid keys: html, nodeLimit",
  'Error: foreground and background are required',
  'Error: engine must be one of all | axe | webability',
  'Error: pass foreground and background colors, or `url` + `selector` to read them from an element',
  'Error: pass `html` (a markup snippet) or `url` (a live page to check).',
  'Error: visual_audit needs a free WebAbility account, and this connection is not signed in.',
  'Error: selector "h1" matches no element on https://example.com — nothing was checked.',
  'Error: BLOCKED: https://www.ikea.com/gb/en/ was not actually scanned. Scan did not reach the real page.',
]

for (const value of noise) {
  test(`drops caller misuse: ${value.slice(0, 60)}`, () => {
    assert.equal(
      isCallerMisuseNoise({
        event: '$exception',
        properties: { $exception_list: [{ type: 'Error', value }] },
      }),
      true,
    )
  })
}

test('keeps real backend and scan failures', () => {
  for (const value of [
    'Error: AI service unavailable (500) and no safe deterministic fallback exists',
    'Error: Scan failed: page.goto: net::ERR_HTTP2_PROTOCOL_ERROR at https://accesio.ro/',
    'Error: Visual audit failed (502): <!DOCTYPE html>',
    'TypeError: t.entries.at is not a function',
  ]) {
    assert.equal(
      isCallerMisuseNoise({
        event: '$exception',
        properties: { $exception_list: [{ type: 'Error', value }] },
      }),
      false,
    )
  }
})

test('ignores non-exception events and malformed payloads', () => {
  assert.equal(isCallerMisuseNoise({ event: '$mcp_tool_call', properties: {} }), false)
  assert.equal(isCallerMisuseNoise({ event: '$exception', properties: {} }), false)
  assert.equal(isCallerMisuseNoise({ event: '$exception' }), false)
})
