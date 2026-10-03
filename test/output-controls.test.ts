/**
 * DEV-1089 item 5: output controls shared by scan_page / flow_scan /
 * scan_html / diff_scan — `minImpact`, `rules[]`, `wcag[]` allow-lists and
 * `format: "compact"` (one line per element, shared rule metadata once).
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { compactText, filterIssues, parseOutputControls } from '../src/outputControls.ts'

const mk = (over: Record<string, unknown>) => ({
  id: 'x', impact: 'moderate', wcag: '1.1.1', type: 'missing_alt', message: 'Image has no alt', selector: 'img.a', fixability: 'contextual',
  fix: { op: 'add-attribute', attribute: 'alt', currentValue: '', needsManualReview: true }, ...over,
})

test('parseOutputControls validates and normalises', () => {
  const c = parseOutputControls({ minImpact: 'serious', rules: ['image-alt', 'missing_alt'], wcag: ['1.4.3', '2.4'], format: 'compact' })
  assert.equal(c.minImpact, 'serious')
  assert.deepEqual([...c.rules!], ['image-alt', 'missing_alt'])
  assert.deepEqual([...c.wcag!], ['1.4.3', '2.4'])
  assert.equal(c.format, 'compact')
  assert.equal(parseOutputControls({}).format, 'json')
  assert.throws(() => parseOutputControls({ minImpact: 'huge' }), /minImpact/)
  assert.throws(() => parseOutputControls({ format: 'yaml' }), /format/)
})

test('minImpact keeps that level and above', () => {
  const list = [mk({ id: 'c', impact: 'critical' }), mk({ id: 's', impact: 'serious' }), mk({ id: 'm', impact: 'moderate' }), mk({ id: 'n', impact: 'minor' })]
  assert.deepEqual(filterIssues(list, parseOutputControls({ minImpact: 'serious' })).map((i) => i.id), ['c', 's'])
  assert.equal(filterIssues(list, parseOutputControls({})).length, 4)
})

test('rules[] matches the rule id (WebAbility type or axe rule id)', () => {
  const list = [mk({ id: 'a', type: 'missing_alt' }), mk({ id: 'b', type: 'image-alt' }), mk({ id: 'c', type: 'weak_link_name' })]
  assert.deepEqual(filterIssues(list, parseOutputControls({ rules: ['image-alt'] })).map((i) => i.id), ['b'])
})

test('wcag[] matches exact criteria and prefixes (guideline / principle)', () => {
  const list = [mk({ id: 'a', wcag: '1.4.3' }), mk({ id: 'b', wcag: '1.4.11' }), mk({ id: 'c', wcag: '2.4.4' }), mk({ id: 'd', wcag: '1.1.1' })]
  assert.deepEqual(filterIssues(list, parseOutputControls({ wcag: ['1.4.3'] })).map((i) => i.id), ['a'])
  // "1.4" is a guideline prefix: must not match 1.4.11 by accident of string prefix on "1.4.1"
  assert.deepEqual(filterIssues(list, parseOutputControls({ wcag: ['1.4'] })).map((i) => i.id), ['a', 'b'])
  assert.deepEqual(filterIssues(list, parseOutputControls({ wcag: ['1.4.1'] })).map((i) => i.id), [])
})

test('compact: one header per rule with shared metadata, one line per element', () => {
  const list = [
    mk({ id: 'a', selector: 'img.a' }),
    mk({ id: 'b', selector: 'img.b', source: { file: 'src/Hero.tsx', line: 12, component: 'Hero' } }),
    mk({ id: 'c', type: 'missing_button_type', wcag: '3.2.2', impact: 'minor', message: 'Button has no type', selector: 'button.x', fixability: 'mechanical', fix: { op: 'add-attribute', attribute: 'type', value: 'button', currentValue: '', needsManualReview: false } }),
  ]
  const text = compactText(list)
  const lines = text.split('\n')
  // Rule header carries wcag / impact / fixability / op and the message ONCE.
  assert.equal(lines.filter((l) => l.includes('Image has no alt')).length, 1)
  assert.match(text, /missing_alt .*1\.1\.1.*moderate.*contextual.*add-attribute alt/)
  assert.match(text, /missing_button_type .*3\.2\.2.*minor.*mechanical.*add-attribute type="button"/)
  // Element lines: selector, and the source pointer when known.
  assert.match(text, /^\s+img\.a$/m)
  assert.match(text, /^\s+img\.b\s+→ src\/Hero\.tsx:12 \(Hero\)$/m)
  assert.match(text, /^\s+button\.x$/m)
  assert.equal(compactText([]), '(no findings)')
})

test('compact never prints an empty arrow when `source` is the engine string, not a pointer', () => {
  const text = compactText([{ id: 'wa-x-1', type: 'decorative_icon', impact: 'moderate', wcag: '4.1.2', message: 'm', selector: '#gsi_1_2', source: 'webability' as any }])
  assert.ok(!text.includes('→'), text)
})

// pullfrog on PR #68: the browser-engine scan_html joins a violation's
// criteria into one string ("2.4.4,4.1.2"), which an exact / prefix match can
// never hit — multi-criterion axe rules were silently dropped by `wcag`.
test('a multi-criterion wcag string matches on ANY of its criteria', () => {
  const rows = [
    { id: 'axe-link-name-1', type: 'link-name', impact: 'serious', wcag: '2.4.4,4.1.2', message: 'm', selector: 'a' },
    { id: 'axe-x-2', type: 'x', impact: 'serious', wcag: '2.4.4, 4.1.2', message: 'm', selector: 'b' },
    { id: 'axe-y-3', type: 'y', impact: 'serious', wcag: '1.1.1', message: 'm', selector: 'c' },
  ]
  assert.deepEqual(filterIssues(rows, parseOutputControls({ wcag: ['4.1.2'] })).map((r) => r.id), ['axe-link-name-1', 'axe-x-2'])
  assert.deepEqual(filterIssues(rows, parseOutputControls({ wcag: ['2.4'] })).map((r) => r.id), ['axe-link-name-1', 'axe-x-2'])
  assert.deepEqual(filterIssues(rows, parseOutputControls({ wcag: ['4.1.1'] })), [])
})
