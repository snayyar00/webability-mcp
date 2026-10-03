/**
 * The tunnel client here must stay byte-identical to the relay's copy.
 *
 * These three files decide what leaves a developer's machine. They live in two
 * repos — the relay in webability-platform, the client shipped to customers
 * here — and a silent divergence in `localTargetUrl` or `hasTraversal` is the
 * difference between a scan path and a hole into someone's network.
 *
 * Same approach as authWall: pin the hash, and make a well-meant local edit
 * fail loudly instead of drifting. When you change one side, change both and
 * update the hash in the same commit.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

/** sha256 of each file as it exists in webability-platform/tunnel-relay/src. */
const PINNED: Record<string, string> = {
  'client.ts': '3d1b38a99da9b4402aaccbf16099ae030165751e3253a9866667d7b9c93d7fac',
  'localFetch.ts': 'f7f8813793d8a6b9ad23f607ef4c20216c5e6b21bf6b6fae53e23bb26d16a3a6',
  'requestGuard.ts': '11215cd56d50e630a2d37509dd28841a01e7f0c6fe8bc26482cb872c339ffe95',
}

for (const [name, expected] of Object.entries(PINNED)) {
  test(`tunnel/${name} matches the relay copy`, () => {
    const body = readFileSync(fileURLToPath(new URL(`../src/tunnel/${name}`, import.meta.url)), 'utf8')
    const actual = createHash('sha256').update(body).digest('hex')
    assert.equal(actual, expected, `src/tunnel/${name} has drifted from webability-platform/tunnel-relay/src/${name}. Change both, then update the hash here.`)
  })
}
