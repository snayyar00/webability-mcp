/**
 * The brand-palette fetch must carry the SSRF guard on hosted.
 *
 * It is the only browser context in server.ts that was gated on something
 * other than `remote`, and that exception was invisible: every neighbouring
 * line reads `if (opts.remote) await installSsrfRoute(...)`, so the odd one
 * out looked like the others. On hosted with no tunnel it installed nothing,
 * which is a live SSRF into our own cloud via generate_ai_fix and
 * check_color_contrast.
 *
 * Structural, because reaching the real thing needs Playwright and a hosted
 * transport. What is pinned is the condition, which is what broke.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const SRC = readFileSync(fileURLToPath(new URL('../src/server.ts', import.meta.url)), 'utf8')
const PALETTE = SRC.slice(SRC.indexOf('async function extractBrandPaletteFromUrl'), SRC.indexOf('/** Server-side Full tools'))

test('the palette fetch installs the SSRF guard whenever remote', () => {
  assert.match(PALETTE, /remote \|\| tunnel \? installSsrfRoute\(context, tunnel\)/)
  // The bug, named: gating on the tunnel alone leaves hosted unguarded.
  assert.doesNotMatch(PALETTE, /\(tunnel \? installSsrfRoute/)
})

test('every caller passes the remote flag through', () => {
  const calls = SRC.match(/extractBrandPaletteFromUrl\([^)]*\)/g) ?? []
  const callSites = calls.filter((c) => !c.includes('url: string'))
  assert.ok(callSites.length >= 2, `expected the two palette call sites, found ${callSites.length}`)
  for (const call of callSites) {
    assert.match(call, /opts\.remote/, `caller does not pass remote: ${call}`)
  }
})

test('no browser context in this file is gated on tunnel instead of remote', () => {
  // The general form of the defect. A future context added with `if (tunnel)`
  // would be unguarded on hosted in exactly the same silent way.
  const bad = SRC.match(/\(tunnel \? installSsrfRoute|if \(tunnel\)\s*await installSsrfRoute/g) ?? []
  assert.deepEqual(bad, [], 'installSsrfRoute must be gated on remote (optionally || tunnel), never on tunnel alone')
})
