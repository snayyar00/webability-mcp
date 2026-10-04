/**
 * visual_audit on the hosted server died at ~127s with the client's opaque
 * "The operation timed out." (most hosted calls in the 2026-09-23..26 log). The
 * backend vision call alone took ~134s. The tool must give up inside the
 * client's window and say which phase ran out, and must never leak a browser.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { DeadlineError, withDeadline } from '../src/deadline.ts'

test('withDeadline resolves when the work finishes in time', async () => {
  assert.equal(await withDeadline(async () => 42, 1000, 'capture'), 42)
})

test('withDeadline rejects with the phase name when time runs out', async () => {
  await assert.rejects(
    withDeadline(() => new Promise(() => {}), 50, 'page load'),
    (err: unknown) => err instanceof DeadlineError && err.phase === 'page load' && /page load/.test(err.message) && /0\.05s|50ms/.test(err.message),
  )
})

test('withDeadline aborts the signal it hands the work', async () => {
  let aborted = false
  await assert.rejects(
    withDeadline((signal) => {
      signal.addEventListener('abort', () => {
        aborted = true
      })
      return new Promise(() => {})
    }, 30, 'capture'),
  )
  assert.equal(aborted, true, 'the work must be told to stop, not left running')
})

test('withDeadline passes other errors through untouched', async () => {
  await assert.rejects(
    withDeadline(async () => {
      throw new Error('net::ERR_NAME_NOT_RESOLVED')
    }, 1000, 'capture'),
    /ERR_NAME_NOT_RESOLVED/,
  )
})

const SRC = readFileSync(fileURLToPath(new URL('../src/server.ts', import.meta.url)), 'utf8')
const HANDLER_START = SRC.indexOf("if (name === 'visual_audit')")
const HANDLER = SRC.slice(HANDLER_START, SRC.indexOf("if (name === 'find_source')", HANDLER_START))

test('the visual_audit handler is found', () => {
  assert.ok(HANDLER_START > 0 && HANDLER.length > 500, 'handler slice is empty — the markers moved')
})

test('visual_audit bounds the capture and the vision call inside one budget under the client window', () => {
  assert.match(HANDLER, /withDeadline\(/, 'capture must run under a deadline')
  const total = Number(/VISUAL_AUDIT_TOTAL_MS = ([\d_]+)/.exec(SRC)?.[1].replace(/_/g, ''))
  const capture = Number(/VISUAL_AUDIT_CAPTURE_MS = ([\d_]+)/.exec(SRC)?.[1].replace(/_/g, ''))
  assert.ok(total > 0 && total < 120_000, `total ${total}ms must end before the ~120s client timeout`)
  assert.ok(capture > 0 && capture < total / 2, 'capture is ~2s in practice; it must not eat the vision budget')
  // The vision call gets what the capture left, not a fixed slice: hosted
  // successes took 87-126s, so a fixed 85s cap would fail calls that work today.
  assert.match(HANDLER, /signal: AbortSignal\.timeout\(VISUAL_AUDIT_TOTAL_MS - \(Date\.now\(\) - started\)\)/)
})

test('a deadline that fires during browser launch stops the capture', () => {
  assert.match(HANDLER, /if \(signal\.aborted\)/, 'launch can resolve after the deadline; the work must stop there')
})

test('visual_audit closes the browser on every path', () => {
  assert.match(HANDLER, /finally\s*\{[^}]*session\.close\(\)/, 'session.close() must sit in a finally block')
})

test('visual_audit reports an HTTP error page instead of auditing it', () => {
  // A closed tunnel or a missing secret serves the relay's 401/404 page; the
  // vision pass then "finds no issues" on a page that was never the target.
  assert.match(HANDLER, /const response = await session\.goto\(/, 'keep the navigation response')
  assert.match(HANDLER, /response\.status\(\) >= 400/, 'an HTTP error status must stop the audit')
})
