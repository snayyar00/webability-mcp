/**
 * DEV-1089 items 1+2: every issue carries a closed-set fix `op` and a
 * `fixability` tier so an agent can triage without a round-trip.
 *
 *   op:          add-attribute | set-attribute | remove-attribute | add-element
 *                | remove-element | add-text-content | suggest
 *   fixability:  mechanical (deterministic value, apply blind)
 *                | contextual (needs DOM context / LLM judgment for the value)
 *                | visual (needs rendered output — contrast, focus ring, size)
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { WCAG_BY_ISSUE } from '@webability/core'

import { FIX_OPS, FIXABILITY_TIERS, axeRuleFixMeta, enrichIssue, structuredFix, webabilityRuleFixMeta } from '../src/fixOps.ts'

const base = { id: 'wa-x-1', source: 'webability', wcag: '1.1.1', level: 'A', impact: 'serious', message: '', selector: 'img.hero' } as const

test('closed sets are exactly the seven ops and three tiers', () => {
  assert.deepEqual([...FIX_OPS], ['add-attribute', 'set-attribute', 'remove-attribute', 'add-element', 'remove-element', 'add-text-content', 'suggest'])
  assert.deepEqual([...FIXABILITY_TIERS], ['mechanical', 'contextual', 'visual'])
})

test('known value on a missing attribute → add-attribute, mechanical', () => {
  const fix = structuredFix({ ...base, type: 'missing_button_type', fix: { attribute: 'type', currentValue: '', suggestedValue: 'button', needsManualReview: false } })
  assert.deepEqual(fix, { op: 'add-attribute', attribute: 'type', value: 'button', fixability: 'mechanical' })
})

test('known value on an existing attribute → set-attribute, mechanical', () => {
  const fix = structuredFix({ ...base, type: 'redundant_role', fix: { attribute: 'tabindex', currentValue: '5', suggestedValue: '0', needsManualReview: false } })
  assert.equal(fix.op, 'set-attribute')
  assert.equal(fix.fixability, 'mechanical')
})

test('remove_attribute convention → remove-attribute naming the attribute', () => {
  // Detectors emit attribute="remove_attribute" + fixValue="<name>" (widget convention).
  const fix = structuredFix({ ...base, type: 'redundant_role', fix: { attribute: 'remove_attribute', currentValue: 'button', suggestedValue: 'role', needsManualReview: false } })
  assert.deepEqual(fix, { op: 'remove-attribute', attribute: 'role', fixability: 'mechanical' })
})

test('needs AI for the value → same attribute op, but contextual and no value', () => {
  const fix = structuredFix({ ...base, type: 'missing_alt', fix: { attribute: 'alt', currentValue: '', needsManualReview: true } })
  assert.equal(fix.op, 'add-attribute')
  assert.equal(fix.attribute, 'alt')
  assert.equal(fix.value, undefined)
  assert.equal(fix.fixability, 'contextual')
})

test('textContent → add-text-content', () => {
  const fix = structuredFix({ ...base, type: 'empty_link', fix: { attribute: 'textContent', currentValue: '', needsManualReview: true } })
  assert.equal(fix.op, 'add-text-content')
  assert.equal(fix.fixability, 'contextual')
})

test('structural attributes (thead / caption / prepend) → add-element', () => {
  for (const attribute of ['thead', 'caption', 'prepend']) {
    const fix = structuredFix({ ...base, type: 'missing_table_header', fix: { attribute, currentValue: '', suggestedValue: '<caption>…</caption>', needsManualReview: true } })
    assert.equal(fix.op, 'add-element', attribute)
  }
})

test('review-marker data-* attributes and tagName changes → suggest', () => {
  const marker = structuredFix({ ...base, type: 'meaningful_sequence', fix: { attribute: 'data-sequence-review', currentValue: '', suggestedValue: 'true', needsManualReview: true } })
  assert.equal(marker.op, 'suggest')
  const tag = structuredFix({ ...base, type: 'missing_button_role', fix: { attribute: 'tagName', currentValue: 'div', suggestedValue: 'button', needsManualReview: false } })
  assert.equal(tag.op, 'suggest')
})

test('contrast and other render-dependent rules are visual even with a value', () => {
  const fix = structuredFix({ ...base, type: 'contrast_insufficient', fix: { attribute: 'style', currentValue: 'color:#999', suggestedValue: 'color:#595959;', needsManualReview: true } })
  assert.equal(fix.fixability, 'visual')
  assert.equal(fix.op, 'set-attribute')
  for (const type of ['focus_not_visible', 'target_too_small', 'non_text_contrast_insufficient', 'image_of_text', 'reflow_overflow']) {
    assert.equal(webabilityRuleFixMeta(type).fixability, 'visual', type)
  }
})

test('needs_review confidence never yields mechanical', () => {
  const fix = structuredFix({ ...base, type: 'missing_button_type', confidence: 'needs_review', fix: { attribute: 'type', currentValue: '', suggestedValue: 'button', needsManualReview: true } })
  assert.notEqual(fix.fixability, 'mechanical')
})

test('an issue without a fix object still gets op=suggest + a tier', () => {
  const fix = structuredFix({ ...base, type: 'keyboard_trap' })
  assert.equal(fix.op, 'suggest')
  assert.ok(FIXABILITY_TIERS.has(fix.fixability))
})

test('enrichIssue keeps the legacy fix fields and adds op/value/fixability on it', () => {
  const out = enrichIssue({ ...base, type: 'missing_button_type', fix: { attribute: 'type', currentValue: '', suggestedValue: 'button', needsManualReview: false } })
  assert.equal(out.fix.attribute, 'type')
  assert.equal(out.fix.suggestedValue, 'button')
  assert.equal(out.fix.op, 'add-attribute')
  assert.equal(out.fix.value, 'button')
  assert.equal(out.fixability, 'mechanical')
})

test('every WebAbility rule id has a tier (no rule falls through to a default silently)', () => {
  // WCAG_BY_ISSUE is the census of rule ids; each must be classified on purpose.
  for (const type of Object.keys(WCAG_BY_ISSUE)) {
    const meta = webabilityRuleFixMeta(type)
    assert.ok(FIXABILITY_TIERS.has(meta.fixability), `${type} has tier ${meta.fixability}`)
    assert.ok(FIX_OPS.has(meta.op), `${type} has op ${meta.op}`)
  }
})

test('axe rules: contrast is visual, alt/name rules are contextual with a real op, lang is mechanical', () => {
  assert.equal(axeRuleFixMeta('color-contrast').fixability, 'visual')
  assert.deepEqual(axeRuleFixMeta('image-alt'), { op: 'add-attribute', attribute: 'alt', fixability: 'contextual' })
  assert.deepEqual(axeRuleFixMeta('html-has-lang'), { op: 'add-attribute', attribute: 'lang', fixability: 'contextual' })
  assert.equal(axeRuleFixMeta('link-name').op, 'add-text-content')
  assert.equal(axeRuleFixMeta('aria-hidden-body').op, 'remove-attribute')
  // Unknown rule → suggest / contextual, never a crash
  assert.deepEqual(axeRuleFixMeta('some-rule-that-does-not-exist'), { op: 'suggest', fixability: 'contextual' })
})

