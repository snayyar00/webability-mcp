/**
 * package.json `description` ships unchanged to the npm package page
 * (scripts/build-mirror.mjs copies it), so it follows the same rule as tool
 * output: no `incomplete` / "needs review" bucket.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

const BANNED = /needs[ -]review|need(?:s)? human review|human review|do NOT auto-fix|incomplete/i

test('the npm package description mentions no review bucket', () => {
  const { description } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
  assert.doesNotMatch(description, BANNED, description.match(BANNED)?.[0])
})
