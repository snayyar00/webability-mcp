/**
 * On a cold CI runner Chromium sometimes dies between launch and the first
 * newContext ("Target page, context or browser has been closed"). One fresh
 * launch gets through; any other error, or a second crash, still throws.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { createSessionOpener } from '../src/browser.ts'

const CLOSED = new Error('browser.newContext: Target page, context or browser has been closed')

function world(failFirst: Error[]) {
  let launches = 0
  let closes = 0
  const launch = async () => {
    const idx = launches++
    return {
      newContext: async () => {
        if (failFirst[idx]) throw failFirst[idx]
        return { newPage: async () => ({ idx, goto: async () => ({ status: () => 200 }) }) }
      },
      close: async () => { closes++ },
    }
  }
  return { launch, stats: () => ({ launches, closes }) }
}

test('a browser that dies before its first context is relaunched once', async () => {
  const w = world([CLOSED])
  const s = await createSessionOpener(w.launch)()
  assert.equal(s.page.idx, 1)
  assert.deepEqual(w.stats(), { launches: 2, closes: 1 })
})

test('a second startup crash is thrown, not retried forever', async () => {
  const w = world([CLOSED, CLOSED])
  await assert.rejects(createSessionOpener(w.launch)(), /has been closed/)
  assert.equal(w.stats().launches, 2)
})

test('other newContext errors are not retried', async () => {
  const w = world([new Error('bad contextOptions')])
  await assert.rejects(createSessionOpener(w.launch)(), /bad contextOptions/)
  assert.equal(w.stats().launches, 1)
})
