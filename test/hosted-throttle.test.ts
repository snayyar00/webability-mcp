/**
 * Codex P1 on PR #68: diff_scan with baselineUrl + url launches TWO Chromium
 * scans, but the hosted anonymous rate limit only knows the names in
 * HEAVY_TOOLS. Every tool that can launch a browser must be in that set.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const GATE = readFileSync(fileURLToPath(new URL('../src/anonGate.ts', import.meta.url)), 'utf8')
const SERVER = readFileSync(fileURLToPath(new URL('../src/server.ts', import.meta.url)), 'utf8')

test('every browser-launching tool is rate-limited for anonymous hosted callers', () => {
  const m = /HEAVY_TOOLS = new Set\(\[([^\]]+)\]\)/.exec(GATE)
  assert.ok(m, 'HEAVY_TOOLS not found in anonGate.ts')
  const heavy = new Set(m[1].split(',').map((s) => s.trim().replace(/['"]/g, '')).filter(Boolean))
  // Handlers that reach playwright: scanWithSourcePointers, withTunnelPage, a direct chromium launch,
  // or extractBrandPaletteFromUrl (check_color_contrast with a url).
  const launching = ['scan_page', 'flow_scan', 'diff_scan', 'verify_fix', 'detect_framework', 'check_aria', 'check_color_contrast']
  for (const tool of launching) {
    const body = SERVER.slice(SERVER.indexOf(`name === '${tool}'`)).slice(0, 6000)
    assert.ok(/scanWithSourcePointers\(|withTunnelPage\(|openSession\(|await scan\(|extractBrandPaletteFromUrl\(/.test(body), `${tool} handler should launch a browser (test premise)`)
    // check_color_contrast only launches with a url, so anonLimitClass gates it on its arguments.
    if (tool === 'check_color_contrast') assert.ok(/name === 'check_color_contrast'/.test(GATE), 'check_color_contrast must be gated on its url in anonGate.ts')
    else assert.ok(heavy.has(tool), `${tool} launches Chromium but is not in HEAVY_TOOLS`)
  }
})
