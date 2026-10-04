/**
 * Every browser launch in the MCP goes through src/browser.ts. A bare
 * `chromium.launch(` skips the missing-browser recovery and the HTTP/2
 * fallback, so a fresh machine gets Playwright's raw "Executable doesn't
 * exist" banner (friction register rows 1, 2, 13).
 */
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const SRC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src')

test('server.ts has no bare chromium.launch( left', () => {
  const src = readFileSync(path.join(SRC, 'server.ts'), 'utf8')
  const hits = src.split('\n').filter((l) => /chromium\.launch\(/.test(l))
  assert.deepEqual(hits, [])
})

test('only browser.ts calls chromium.launch( in src/', () => {
  const offenders = readdirSync(SRC)
    .filter((f) => f.endsWith('.ts') && f !== 'browser.ts')
    .filter((f) => /chromium\.launch\(/.test(readFileSync(path.join(SRC, f), 'utf8')))
  assert.deepEqual(offenders, [])
})

test('withTunnelPage takes the real remote mode, with no default', () => {
  const src = readFileSync(path.join(SRC, 'server.ts'), 'utf8')
  const sig = /async function withTunnelPage[^\n]*/.exec(src)?.[0] ?? ''
  assert.match(sig, /remote: boolean\)/, 'remote must be a required boolean')
  assert.doesNotMatch(sig, /remote = true/)
})

test('every withTunnelPage call passes the real remote mode as its last argument', () => {
  const src = readFileSync(path.join(SRC, 'server.ts'), 'utf8')
  const calls = src.split('\n').filter((l) => /\bwithTunnelPage\(/.test(l) && !/async function/.test(l))
  assert.ok(calls.length >= 3, `expected 3 call sites, found ${calls.length}`)
  for (const c of calls) assert.match(c, /(!!opts\.remote|\bremote)\)\s*$/, `call omits remote: ${c.trim()}`)
})

test('scan_html and check_aria close their session in a finally, never a bare browser.close()', () => {
  const src = readFileSync(path.join(SRC, 'server.ts'), 'utf8')
  assert.equal((src.match(/await browser\.close\(\)/g) ?? []).length, 0, 'a throw between launch and a bare close() leaks Chromium')
  for (const tool of ["name === 'scan_html'", "name === 'check_aria'"]) {
    const body = src.slice(src.indexOf(tool)).slice(0, 4000)
    assert.match(body, /finally\s*\{\s*await session\.close\(\)/, `${tool} must close in finally`)
  }
})

test('every openSession call in server.ts installs the SSRF guard in remote mode via setupContext', () => {
  const src = readFileSync(path.join(SRC, 'server.ts'), 'utf8')
  const parts = src.split(/await openSession\(\{/).slice(1)
  assert.ok(parts.length >= 8, `expected 8+ call sites, found ${parts.length}`)
  for (const part of parts) {
    const opts = part.slice(0, part.indexOf('\n      })') > 0 ? part.search(/\}\)\n/) : 400)
    assert.match(opts, /remote(: opts\.remote)?,|remote: /, `call sets remote: ${opts.slice(0, 80)}`)
    assert.match(opts, /setupContext:[^\n]*(remote|opts\.remote)[^\n]*installSsrfRoute/, `call must install installSsrfRoute when remote: ${opts.slice(0, 120)}`)
  }
})
