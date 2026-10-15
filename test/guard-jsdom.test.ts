/**
 * The in-process scan_html engine runs the detectors against jsdom, where the
 * ambient globals are only window / document / Node / Element / HTMLElement
 * (see fastScan.sharedWindow): no getSelection, Range or MutationObserver.
 * The invariant-P guard must still detect a tool that leaves focus there, and
 * not silently skip the check (a skipped check reported as `internal_bugs: []`).
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { guardDetectorState } from '../../core/src/engines/tooling.js'
import { createDomPage } from '../../core/src/dom.js'

const require = createRequire(import.meta.url)

test('guardDetectorState under the fastScan jsdom globals: a tool that leaves focus is reported and restored', async () => {
  const { JSDOM } = require('jsdom') as typeof import('jsdom')
  const dom = new JSDOM('<!doctype html><html><body><a id="a" href="/">A</a><a id="b" href="/b">B</a></body></html>', { pretendToBeVisual: true })
  const win = dom.window as any
  const g = globalThis as any
  g.window = win; g.document = win.document; g.Node = win.Node; g.Element = win.Element; g.HTMLElement = win.HTMLElement; g.getComputedStyle = win.getComputedStyle
  const page = createDomPage(win)
  const bugs: any[] = []
  await guardDetectorState(page as any, 'planted:leaveFocus', [], async () => {
    win.document.getElementById('a').focus()
  }, { bugs })
  assert.equal(win.document.activeElement.tagName, 'BODY', 'focus restored')
  assert.equal(bugs.length, 1)
  assert.equal(bugs[0].tool, 'planted:leaveFocus')
  assert.equal(bugs[0].kind, 'state-not-restored')
})
