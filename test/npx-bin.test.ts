/**
 * `npx -y @webability/mcp` — the install line in every doc and listing — only
 * works if npm can pick ONE bin: with several bins, npx runs the one named after
 * the unscoped package name. Without it: "npm error could not determine
 * executable to run" (every client, 2026-10-03 agent matrix).
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const pkg = JSON.parse(readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8'))

test('npx @webability/mcp resolves to the stdio server', () => {
  const bins = typeof pkg.bin === 'string' ? { [pkg.name.split('/').pop()]: pkg.bin } : pkg.bin
  const unscoped = pkg.name.split('/').pop()
  const chosen = Object.keys(bins).length === 1 ? Object.values(bins)[0] : bins[unscoped]
  assert.ok(chosen, `npx cannot choose among bins ${Object.keys(bins).join(', ')}: add a "${unscoped}" bin`)
  assert.equal(String(chosen).replace(/^\.\//, ''), 'dist/index.js')
})
