/**
 * Recovery of the scan_html engine after a deadline.
 *
 * A cold thread costs 1-4 s of work (jsdom require, then axe-core and the
 * detector kernel binding to the ambient window). The deadline used to
 * terminate it mid-warm-up, discarding that work and handing the next caller
 * another cold start inside ITS deadline: under MCP_SCAN_HTML_DEADLINE_MS=1500
 * on a loaded runner every retry was killed before ready and scan_html never
 * came back (the 503-recovery test in scan-html-caps.test.ts is the repro).
 *
 * Rules under test:
 *  - a deadline only terminates a thread that is READY and running THIS job;
 *  - a deadline that fires during warm-up keeps the thread (its work is the
 *    next caller's warm engine);
 *  - after a terminate the replacement starts warming immediately, not on the
 *    next dispatch.
 *
 * The file must stay cold-first: node runs each test file in its own process,
 * so the first test here sees no engine thread and pays the real cold start.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { Worker } from 'node:worker_threads'

import { fastScanHtml } from '../src/fastScan.ts'

const SMALL = '<main><h1>T</h1><img src="a.png"><button></button></main>'
/** Same shape the caps test uses to occupy the thread: seconds of real work. */
const spans = (n: number) => '<main><h1>T</h1><img src="a.png">' + '<span>text</span>'.repeat(n) + '</main>'
/**
 * One turn of the event loop, without a clock: `setImmediate` runs after the
 * nextTick queue, which is where Node emits its `worker` event.
 */
async function nextTurn(): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<void>()
  setImmediate(resolve)
  await promise
}

test('a deadline during warm-up keeps the cold thread alive, and the next call scans on it', async () => {
  const realTerminate = Worker.prototype.terminate
  let terminated = 0
  Object.assign(Worker.prototype, {
    terminate(this: Worker) {
      terminated++
      return realTerminate.call(this)
    },
  })
  try {
    // No thread exists yet, so this call pays the whole cold start; its 1 ms
    // budget is spent long before the thread can report ready.
    await assert.rejects(fastScanHtml(SMALL, { deadlineMs: 1 }), /scan_html did not finish within/)
    assert.equal(terminated, 0, 'a deadline must not terminate a thread that is still warming up')

    // The warming thread survived, so this scan runs on the engine it built.
    const r = await fastScanHtml(SMALL)
    assert.ok(r.issues.length >= 2, `the warm engine still reports issues: ${r.issues.map((i) => i.type).join(',')}`)
    assert.equal(terminated, 0, 'a successful scan never terminates the thread')
  } finally {
    Object.assign(Worker.prototype, { terminate: realTerminate })
  }
})

test('a deadline on a ready thread terminates it, and the replacement warms up immediately', async () => {
  // Prerequisite, outside the counted window: a warm, idle engine.
  await fastScanHtml(SMALL)

  const realTerminate = Worker.prototype.terminate
  let terminated = 0
  Object.assign(Worker.prototype, {
    terminate(this: Worker) {
      terminated++
      return realTerminate.call(this)
    },
  })
  // Node emits `worker` on the process for every thread it starts — on a
  // nextTick — which is the way to see a spawn this call made and has not
  // dispatched a job to yet.
  const spawns: unknown[] = []
  const onSpawn = (worker: unknown) => spawns.push(worker)
  process.on('worker', onSpawn)
  try {
    await assert.rejects(fastScanHtml(spans(240), { deadlineMs: 250 }), /scan_html did not finish within/)
    assert.equal(terminated, 1, 'a deadline on a ready thread is still real preemption')
    // No clock, no guess: the spawn event is emitted on the nextTick that
    // follows the rejection, so one turn of the loop shows it. A respawn
    // deferred to the next dispatch would still read zero here.
    await nextTurn()
    assert.equal(spawns.length, 1, 'the replacement thread is spawned eagerly, not on the next dispatch')
    // And it is the thread the next scan runs on: a respawn deferred to dispatch
    // would show a second spawn here instead.
    const r = await fastScanHtml(SMALL)
    assert.ok(r.issues.length >= 2)
    assert.equal(spawns.length, 1, 'the next scan reuses the eagerly spawned replacement')
  } finally {
    process.off('worker', onSpawn)
    Object.assign(Worker.prototype, { terminate: realTerminate })
  }
})

test("a queued call's deadline never fails a scan that is still inside its own budget", async () => {
  // Warm first, so the long scan runs on a ready thread.
  await fastScanHtml(SMALL)
  const long = fastScanHtml(spans(240), { deadlineMs: 24_000 })
  // Both queue behind the long scan and time out while still queued.
  const queuedA = fastScanHtml(SMALL, { deadlineMs: 100 }).then(() => 'ok', (e: Error) => e.name)
  const queuedB = fastScanHtml(SMALL, { deadlineMs: 300 }).then(() => 'ok', (e: Error) => e.name)
  const [a, b] = await Promise.all([queuedA, queuedB])
  assert.equal(a, 'DeadlineError')
  assert.equal(b, 'DeadlineError')
  const r = await long
  assert.ok(r.summary, 'the long scan finishes on its own budget, not killed by a queued call')
})
