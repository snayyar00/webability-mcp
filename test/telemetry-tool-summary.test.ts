/**
 * `find_source` is the one tool whose "nothing found" answer is still a useful
 * datum — it tells us callers point selectors at the wrong root, which no scan
 * row can show. extractToolTelemetry recognises that answer by its opening
 * words, so the matcher and the tool's own message text must agree. They had
 * drifted: server.ts emits `No source files under ${rootDir} matched ...` while
 * telemetry.ts tested for `No source files matched ...`, so every zero-match
 * call was recorded as "no summary" instead of total 0 (telemetry.e2e.mjs
 * caught it).
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { extractToolTelemetry } from '../src/telemetry.ts'

const reply = (text: string) => ({ content: [{ type: 'text', text }] })

// The exact text src/server.ts emits for a selector with no source matches.
const NO_MATCH_TEXT =
  'No source files under /app/src matched the id/class/attribute tokens of "#nonexistent-thing-xyz .some-class". Try a more specific selector, or scan a dev build — scan_page reads `source` pointers straight from React/Vue dev builds.'

test('find_source records total 0 when the tool reports no source matches', () => {
  assert.deepEqual(extractToolTelemetry('find_source', reply(NO_MATCH_TEXT)), { summary: { total: 0 }, meta: null })
})

test('find_source records the candidate count when files match', () => {
  const text = 'Source candidates for `#hero`:\n\n- /app/src/Hero.tsx\n- /app/src/hero.css\n\nUse Read on the most likely file, then apply the fix.'
  assert.deepEqual(extractToolTelemetry('find_source', reply(text)), { summary: { total: 2 }, meta: null })
})

test('find_source records no summary for answers that are neither matches nor a zero', () => {
  for (const text of [
    'Error: selector is required',
    'find_source is disabled on the hosted MCP server — it searches a local project, which does not exist server-side.',
  ]) {
    assert.equal(extractToolTelemetry('find_source', reply(text)).summary, null, text)
  }
})
