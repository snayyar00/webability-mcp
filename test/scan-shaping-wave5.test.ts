/**
 * MCP dogfood 2026-10-03 (allbirds.com, live rows from scan_page):
 *
 *  - button.swiper-prev-button came back as svg_missing_name (1.1.1) AND
 *    unlabeled_button (4.1.2): one icon button with no name, one fix
 *    (aria-label on the button), two issues.
 *  - duplicate_id (4.1.1) and HTML_CodeSniffer f77 (4.1.1) were reported as
 *    issues. 4.1.1 Parsing is obsolete in WCAG 2.2 and always satisfied for
 *    HTML; a duplicate id only hurts when a reference resolves to it, which
 *    the 1.3.1 / 4.1.2 rules (and axe duplicate-id-aria, tagged 4.1.2)
 *    already report.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import * as shaping from '../src/scanShaping.ts'

const { mergeSameElement } = shaping
const PREV = 'button.swiper-prev-button.z-content.absolute'
const NEXT = 'button.swiper-next-button.z-content.absolute'
const btnFix = { attribute: 'aria-label', currentValue: '', needsManualReview: true, op: 'add-attribute' }

test('merge: svg_missing_name + unlabeled_button on one button are one issue', () => {
  const out = mergeSameElement([
    { id: 'wa-svg_missing_name-x4gu3q', impact: 'serious', wcag: '1.1.1', type: 'svg_missing_name', selector: PREV, fix: btnFix, fixability: 'contextual' },
    { id: 'wa-unlabeled_button-x4gu3q', impact: 'serious', wcag: '4.1.2', type: 'unlabeled_button', selector: PREV, fix: btnFix, fixability: 'contextual' },
    { id: 'wa-unlabeled_button-a8ni5i', impact: 'serious', wcag: '4.1.2', type: 'unlabeled_button', selector: NEXT, fix: btnFix, fixability: 'contextual' },
  ] as any[])
  assert.equal(out.length, 2)
  const prev = out.find((i) => i.selector === PREV)!
  assert.deepEqual([...prev.rules!].sort(), ['svg_missing_name', 'unlabeled_button'])
  assert.equal(prev.wcag, '1.1.1,4.1.2')
  assert.equal(out.find((i) => i.selector === NEXT)!.rules, undefined, 'a different element is never merged in')
})

test('merge: axe button-name + unlabeled_button on one button are one issue', () => {
  const out = mergeSameElement([
    { id: 'axe-button-name-1', impact: 'critical', wcag: '4.1.2', type: 'button-name', selector: PREV, fix: { op: 'add-attribute', attribute: 'aria-label' }, fixability: 'contextual' },
    { id: 'wa-unlabeled_button-1', impact: 'serious', wcag: '4.1.2', type: 'unlabeled_button', selector: PREV, fix: btnFix, fixability: 'contextual' },
  ] as any[])
  assert.equal(out.length, 1)
  assert.equal(out[0]!.impact, 'critical')
})

test('merge guard holds: two svg_missing_name rows on one shared selector stay two', () => {
  const out = mergeSameElement([
    { id: 'a', impact: 'serious', wcag: '1.1.1', type: 'svg_missing_name', selector: PREV, fix: btnFix },
    { id: 'b', impact: 'serious', wcag: '1.1.1', type: 'svg_missing_name', selector: PREV, fix: btnFix },
    { id: 'c', impact: 'serious', wcag: '4.1.2', type: 'unlabeled_button', selector: PREV, fix: btnFix },
  ] as any[])
  assert.equal(out.length, 3)
})

test('4.1.1-only findings move from issues to needs-review with the reason, and are counted', () => {
  const fn = (shaping as any).demoteObsoleteParsing
  assert.equal(typeof fn, 'function', 'scanShaping must export demoteObsoleteParsing')
  const issues = [
    { id: 'wa-duplicate_id-1', impact: 'moderate', wcag: '4.1.1', type: 'duplicate_id', selector: 'svg > g' },
    { id: 'htmlcs-f77-1', impact: 'moderate', wcag: '4.1.1', type: 'f77', selector: 'a > svg > g' },
    { id: 'axe-duplicate-id-aria-1', impact: 'critical', wcag: '4.1.2', type: 'duplicate-id-aria', selector: '#lbl' },
    { id: 'wa-missing_alt-1', impact: 'serious', wcag: '1.1.1', type: 'missing_alt', selector: 'img' },
  ]
  const incomplete = [{ id: 'x', impact: 'moderate', wcag: '1.4.3', type: 'contrast_insufficient', selector: 'p' }]
  const r = fn(issues, incomplete)
  assert.deepEqual(r.issues.map((i: any) => i.type), ['duplicate-id-aria', 'missing_alt'], 'duplicate-id-aria is 4.1.2 and stays')
  assert.deepEqual(r.incomplete.map((i: any) => i.type).sort(), ['contrast_insufficient', 'duplicate_id', 'f77'])
  assert.equal(r.demoted, 2)
  for (const i of r.incomplete.filter((x: any) => x.wcag === '4.1.1')) {
    assert.match(i.reviewReason, /4\.1\.1.*obsolete/i)
    assert.equal(i.confidence, 'needs_review')
  }
})
