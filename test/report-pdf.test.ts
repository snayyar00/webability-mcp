/**
 * Unit coverage for the generate_report_pdf mapping: score ladder,
 * functionality buckets, the ByFunctions shape, and the empty-suggestedValue
 * guard (an accessible-name fix with an empty value would DELETE the name).
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { functionalityFor, localScore, toReportData } from '../src/reportPdf.ts'

test('score ladder matches the platform penalty weights', () => {
  assert.equal(localScore([]), 100)
  assert.equal(localScore([{ impact: 'critical' }, { impact: 'serious' }]), 90)
  assert.equal(localScore([{ impact: 'moderate' }]), 98)
  assert.equal(localScore([{ impact: 'minor' }]), 99)
  // 21 criticals = -105 → clamped at 0, never negative
  assert.equal(localScore(Array.from({ length: 21 }, () => ({ impact: 'critical' }))), 0)
})

test('functionality buckets route by type/message keywords', () => {
  assert.equal(functionalityFor({ type: 'color_contrast', message: 'low contrast text' }), 'Low Vision')
  assert.equal(functionalityFor({ type: 'focusable', message: 'no keyboard focus' }), 'Mobility')
  assert.equal(functionalityFor({ type: 'missing_label', message: 'form input has no label' }), 'Navigation')
  assert.equal(functionalityFor({ type: 'img_alt', message: 'image missing alt' }), 'Content')
  // NB: bucket order matters — "heading_skip" hits Navigation's `skip` keyword
  // first (ported verbatim from the extension), so use a skip-free heading case here.
  assert.equal(functionalityFor({ type: 'heading_level', message: 'heading level jumps' }), 'Cognitive')
  assert.equal(functionalityFor({ type: 'something_new', message: '' }), 'Other')
})

test('ByFunctions shape carries url, score, widget status and grouped errors', () => {
  const data = toReportData(
    'https://example.com',
    [
      { message: 'low contrast', type: 'contrast', wcag: '1.4.3', selector: '.x', html: '<div class=x>', impact: 'serious', fix: { attribute: 'style', suggestedValue: 'color:#000' } },
      { message: 'no alt', type: 'img_alt', impact: 'critical' },
    ],
    true,
  )
  assert.equal(data.url, 'https://example.com')
  assert.equal(data.score, 90)
  assert.equal(data.scanFailed, false)
  const groups = data.ByFunctions as Array<{ FunctionalityName: string; Errors: unknown[] }>
  assert.deepEqual(groups.map((g) => g.FunctionalityName), ['Low Vision', 'Content'])
  const err = groups[0].Errors[0] as Record<string, unknown>
  assert.equal(err.wcag_code, 'WCAG 1.4.3')
  assert.equal(err.recommended_action, 'Set style="color:#000"')
})

test('an EMPTY suggestedValue never renders a recommended action', () => {
  const data = toReportData('https://example.com', [{ message: 'button has no name', type: 'button_name', impact: 'critical', fix: { attribute: 'aria-label', suggestedValue: '' } }])
  const group = (data.ByFunctions as Array<{ Errors: Array<Record<string, unknown>> }>)[0]
  assert.equal(group.Errors[0].recommended_action, undefined)
})
