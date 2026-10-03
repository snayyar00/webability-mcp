/**
 * Codex P1 on PR #68: diff_scan with baselineUrl + url launches TWO Chromium
 * scans, but the hosted anonymous rate limit only knows the names in
 * HEAVY_TOOLS. Every tool that can launch a browser must be in that set.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const HTTP = readFileSync(fileURLToPath(new URL('../src/http.ts', import.meta.url)), 'utf8')
const SERVER = readFileSync(fileURLToPath(new URL('../src/server.ts', import.meta.url)), 'utf8')

test('every browser-launching tool is rate-limited for anonymous hosted callers', () => {
  const m = /HEAVY_TOOLS = new Set\(\[([^\]]+)\]\)/.exec(HTTP)
  assert.ok(m, 'HEAVY_TOOLS not found in http.ts')
  const heavy = new Set(m[1].split(',').map((s) => s.trim().replace(/['"]/g, '')).filter(Boolean))
  // Handlers that reach playwright: scanWithSourcePointers, withTunnelPage, or a direct chromium launch.
  const launching = ['scan_page', 'flow_scan', 'diff_scan', 'verify_fix', 'detect_framework', 'check_aria']
  for (const tool of launching) {
    const body = SERVER.slice(SERVER.indexOf(`name === '${tool}'`)).slice(0, 6000)
    assert.ok(/scanWithSourcePointers\(|withTunnelPage\(|chromium\.launch\(|await scan\(/.test(body), `${tool} handler should launch a browser (test premise)`)
    assert.ok(heavy.has(tool), `${tool} launches Chromium but is not in HEAVY_TOOLS`)
  }
})
