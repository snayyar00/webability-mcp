/**
 * Do the tools that ADVERTISE tunnel support actually use it?
 *
 * The first version of this PR added `tunnel_secret` to seven tool schemas
 * while only two of them could send the header: the rest hand a URL to
 * `scan()`, which launches its own browser with no route hook. The relay would
 * have refused every request from the two tools the feature exists for.
 *
 * Structural, because the alternative is a real browser and a real relay per
 * assertion. What is pinned is the wiring, which is exactly what broke.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const SRC = readFileSync(fileURLToPath(new URL('../src/server.ts', import.meta.url)), 'utf8')

test('the tunnel target is read from startUrl as well as url', () => {
  // flow_scan supplies startUrl. Reading only `url` made every tunnelled flow
  // scan fail with a null target and no explanation.
  assert.match(SRC, /parseTunnelTarget\(String\(\(args as any\)\?\.url \?\? \(args as any\)\?\.startUrl \?\? ''\)/)
})

test('scan_page and verify_fix scan a page WE opened when tunnelling', () => {
  // scan(url) launches its own browser with no route hook — the header never
  // gets attached. scan(page) scans what we hand it.
  // verify_fix hands scan() a page from withTunnelPage directly.
  assert.match(SRC, /tunnel\s*\n?\s*\? await withTunnelPage\(url, tunnel/, 'verify_fix must route through withTunnelPage')
  // scan_page (and diff_scan) go through scanWithSourcePointers — which keeps
  // the DOM open for the framework source pointers — and THAT must still hand
  // the tunnelled case to withTunnelPage rather than open its own context.
  const helper = SRC.slice(SRC.indexOf('async function scanWithSourcePointers'), SRC.indexOf('async function attachSourceCandidates'))
  assert.match(helper, /if \(tunnel\) return withTunnelPage\(url, tunnel, VIEWPORT_FOR_TUNNEL\(viewportPreset\)/, 'scanWithSourcePointers must route tunnelled scans through withTunnelPage')
  const scanPage = SRC.slice(SRC.indexOf("name === 'scan_page'"), SRC.indexOf("name === 'verify_fix'"))
  assert.match(scanPage, /await scanWithSourcePointers\(url, tunnel,/, 'scan_page must pass its tunnel target to scanWithSourcePointers')
})

test('withTunnelPage installs the route before navigating', () => {
  // Installing after goto would miss the main document — the one request that
  // must carry the secret.
  const fn = SRC.slice(SRC.indexOf('async function withTunnelPage'), SRC.indexOf('async function extractBrandPaletteFromUrl'))
  assert.ok(fn.indexOf('installSsrfRoute') < fn.indexOf('page.goto'), 'route must be installed before the first navigation')
})

test('the brand-palette fetch carries the tunnel too', () => {
  // Otherwise a tunnelled URL yields an empty palette rather than an error —
  // a silent wrong answer, which is worse than a failure.
  // Signature gained a `remote` flag: the SSRF guard is gated on remote like
  // every other context, and the tunnel rides alongside it.
  assert.match(SRC, /extractBrandPaletteFromUrl\(url: string, remote: boolean, tunnel: TunnelTarget \| null = null\)/)
  assert.equal((SRC.match(/extractBrandPaletteFromUrl\(url, !!opts\.remote, tunnel\)/g) ?? []).length, 2)
})

test('every tool advertising tunnel_secret can actually send it', () => {
  // The finding in one assertion: the schema promise and the plumbing must not
  // drift apart again.
  const advertised = /LOCALHOST_CAPABLE_TOOLS = new Set\(\[([^\]]+)\]\)/.exec(SRC)
  assert.ok(advertised, 'tool list not found')
  const tools = advertised[1].split(',').map((t) => t.trim().replace(/['"]/g, '')).filter(Boolean)
  // Each of these reaches the network through a context we route, one way or
  // another: withTunnelPage, installSsrfRoute directly, or the palette helper.
  for (const tool of tools) {
    const handler = SRC.slice(SRC.indexOf(`name === '${tool}'`))
    const body = handler.slice(0, 4000)
    const wired = /withTunnelPage|scanWithSourcePointers\(\w+, (tunnel|t),|installSsrfRoute\(context, tunnel\)|extractBrandPaletteFromUrl\(url, !!opts\.remote, tunnel\)/.test(body)
    assert.ok(wired, `${tool} advertises tunnel_secret but nothing in its handler attaches the header`)
  }
})
