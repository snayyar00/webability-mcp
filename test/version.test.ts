/**
 * Drift guard: the MCP handshake version (src/version.ts) must match
 * package.json. A stale published build and a fresh deploy are otherwise
 * indistinguishable — same incident that gave core its CORE_VERSION guard.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { test } from 'node:test'

import { MCP_VERSION } from '../src/version.ts'

test('MCP_VERSION matches package.json (drift guard)', () => {
  const pkg = JSON.parse(readFileSync(join(import.meta.dirname, '../package.json'), 'utf8'))
  assert.equal(MCP_VERSION, pkg.version)
})

test('server.json registry entries match package.json too', () => {
  const pkg = JSON.parse(readFileSync(join(import.meta.dirname, '../package.json'), 'utf8'))
  const meta = JSON.parse(readFileSync(join(import.meta.dirname, '../server.json'), 'utf8'))
  assert.equal(meta.version, pkg.version)
  for (const p of meta.packages ?? []) assert.equal(p.version, pkg.version)
})
