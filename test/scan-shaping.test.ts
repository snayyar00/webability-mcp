/**
 * Wave 4 — scan output shaping.
 *
 * demo.vercel.store (live 2026-10-03): the search input
 * `input.text-md.w-full.rounded-lg` was reported twice for one problem —
 * wa-missing_label (1.3.1 serious, add aria-label) and HTML_CodeSniffer
 * h91_inputtext_name (4.1.2 moderate, suggest). Its 1.4.11 border-contrast
 * finding is a different problem and must stay separate.
 *
 * vite.dev/guide/ (live 2026-10-03): 36 of 64 issues were new_window_link
 * with the same fix, and the 50 cap truncated the list.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { collapseRepeats, mergeSameElement, nameFamilyKey, recountSummary, truncationNote } from '../src/scanShaping.ts'
import { compactText, filterIssues, parseOutputControls } from '../src/outputControls.ts'

const SEL = 'input.text-md.w-full.rounded-lg'
const vercelInput = () => [
  { id: 'wa-missing_label-qldjiv', impact: 'serious', wcag: '1.3.1', type: 'missing_label', message: 'missing label: missing aria-label', selector: SEL, fix: { op: 'add-attribute', attribute: 'aria-label' }, fixability: 'contextual' },
  { id: 'wa-non_text_contrast_insufficient-qldjiv', impact: 'moderate', wcag: '1.4.11', type: 'non_text_contrast_insufficient', message: 'border contrast', selector: SEL, fix: { op: 'set-attribute', attribute: 'style', value: 'border: 1px solid #909294;' }, fixability: 'visual' },
  { id: 'htmlcs-1-qldjiv', impact: 'moderate', wcag: '4.1.2', type: 'h91_inputtext_name', message: 'This textinput element does not have a name', selector: SEL, fix: { op: 'suggest' }, fixability: 'contextual' },
]

test('merge: missing_label + h91_inputtext_name on one element become one issue; 1.4.11 stays separate', () => {
  const out = mergeSameElement(vercelInput())
  assert.equal(out.length, 2)
  const merged = out.find((i) => i.type === 'missing_label')!
  assert.equal(merged.id, 'wa-missing_label-qldjiv', 'the richest fix (add-attribute) wins over suggest')
  assert.equal(merged.impact, 'serious', 'higher severity kept')
  assert.equal(merged.wcag, '1.3.1,4.1.2')
  assert.equal(merged.fix.op, 'add-attribute')
  assert.deepEqual(merged.rules, ['missing_label', 'h91_inputtext_name'])
  assert.deepEqual(merged.alsoReportedAs, ['htmlcs-1-qldjiv'])
  const contrast = out.find((i) => i.type === 'non_text_contrast_insufficient')!
  assert.equal(contrast.wcag, '1.4.11')
  assert.equal((contrast as any).rules, undefined)
})

test('merge: the richer fix wins even when it carries the lower severity', () => {
  const out = mergeSameElement([
    { id: 'axe-label-1', impact: 'critical', wcag: '4.1.2', type: 'label', selector: '#q', fix: { op: 'suggest' } },
    { id: 'wa-missing_label-1', impact: 'serious', wcag: '1.3.1', type: 'missing_label', selector: '#q', fix: { op: 'add-attribute', attribute: 'aria-label', value: 'Search' } },
  ])
  assert.equal(out.length, 1)
  assert.equal(out[0]!.id, 'wa-missing_label-1')
  assert.equal(out[0]!.impact, 'critical')
  assert.equal(out[0]!.fix.value, 'Search')
  assert.equal(out[0]!.wcag, '1.3.1,4.1.2')
})

test('no merge: same family on DIFFERENT elements, or different problems on one element', () => {
  const twoInputs = mergeSameElement([
    { id: 'a', impact: 'serious', wcag: '1.3.1', type: 'missing_label', selector: '#a', fix: { op: 'add-attribute', attribute: 'aria-label' } },
    { id: 'b', impact: 'moderate', wcag: '4.1.2', type: 'h91_inputtext_name', selector: '#b', fix: { op: 'suggest' } },
  ])
  assert.equal(twoInputs.length, 2)
  const img = mergeSameElement([
    { id: 'c', impact: 'serious', wcag: '1.1.1', type: 'missing_alt', selector: 'img.x', fix: { op: 'add-attribute', attribute: 'alt' } },
    { id: 'd', impact: 'moderate', wcag: '1.4.3', type: 'contrast_insufficient', selector: 'img.x', fix: { op: 'set-attribute', attribute: 'style' } },
  ])
  assert.equal(img.length, 2)
})

test('merge: image and link families (missing_alt + image-alt + h37, empty_link + link-name)', () => {
  const out = mergeSameElement([
    { id: 'wa-alt', impact: 'serious', wcag: '1.1.1', type: 'missing_alt', selector: 'img.hero', fix: { op: 'add-attribute', attribute: 'alt' } },
    { id: 'axe-alt', impact: 'critical', wcag: '1.1.1', type: 'image-alt', selector: 'img.hero', fix: { op: 'suggest' } },
    { id: 'htmlcs-7-x', impact: 'moderate', wcag: '1.1.1', type: 'h37', selector: 'img.hero', fix: { op: 'suggest' } },
    { id: 'wa-link', impact: 'serious', wcag: '2.4.4', type: 'empty_link', selector: 'a.logo', fix: { op: 'add-attribute', attribute: 'aria-label' } },
    { id: 'axe-link', impact: 'serious', wcag: '2.4.4,4.1.2', type: 'link-name', selector: 'a.logo', fix: { op: 'suggest' } },
  ])
  assert.equal(out.length, 2)
  const img = out.find((i) => i.selector === 'img.hero')!
  assert.equal(img.impact, 'critical')
  assert.equal(img.wcag, '1.1.1')
  assert.deepEqual(img.alsoReportedAs, ['axe-alt', 'htmlcs-7-x'])
  const link = out.find((i) => i.selector === 'a.logo')!
  assert.equal(link.wcag, '2.4.4,4.1.2')
})

test('merge is idempotent — re-merging an archived (already merged) list changes nothing', () => {
  const once = mergeSameElement(vercelInput())
  const twice = mergeSameElement(once)
  assert.deepEqual(twice, once)
})

test('merge folds a stored merged entry and a fresh duplicate without losing rules / alsoReportedAs', () => {
  const [merged] = mergeSameElement(vercelInput()).filter((i) => i.type === 'missing_label')
  const out = mergeSameElement([merged!, { id: 'axe-label-z', impact: 'critical', wcag: '4.1.2', type: 'label', selector: SEL, fix: { op: 'suggest' } }])
  assert.equal(out.length, 1)
  assert.deepEqual(out[0]!.rules, ['missing_label', 'h91_inputtext_name', 'label'])
  assert.deepEqual(out[0]!.alsoReportedAs, ['htmlcs-1-qldjiv', 'axe-label-z'])
})

test('recountSummary counts the merged list', () => {
  const issues = mergeSameElement(vercelInput())
  assert.deepEqual(recountSummary(issues), { total: 2, critical: 0, serious: 1, moderate: 1, minor: 0 })
})

test('filterIssues rules[] matches a merged-in rule id', () => {
  const issues = mergeSameElement(vercelInput())
  const got = filterIssues(issues, parseOutputControls({ rules: ['h91_inputtext_name'] }))
  assert.equal(got.length, 1)
  assert.equal(got[0]!.id, 'wa-missing_label-qldjiv')
})

const link = (n: number, op = 'add-attribute') => ({ id: `wa-new_window_link-${op}-${n}`, impact: 'minor', wcag: '3.2.5', type: 'new_window_link', message: 'opens a new window', selector: `a.l${n}`, fix: { op, attribute: 'aria-label' } })

test('collapse: a rule repeating >=4 times with the same op+attribute becomes one entry with count', () => {
  const list = [...Array.from({ length: 12 }, (_, i) => link(i)), { id: 'x', impact: 'minor', wcag: '1.3.1', type: 'other', selector: 'p', fix: { op: 'suggest' } }]
  const { list: out, collapsedGroups } = collapseRepeats(list, parseOutputControls({}))
  assert.equal(out.length, 2)
  assert.equal(collapsedGroups, 1)
  const c = out[0]!
  assert.equal(c.count, 12)
  assert.equal(c.examples!.length, 10)
  assert.equal(c.examples![0], 'a.l0')
  assert.match(c.expand!, /rules: \["new_window_link"\]/)
  assert.doesNotMatch(c.expand!, /abilyo/i)
})

test('collapse: 3 repeats stay as-is; different ops collapse separately', () => {
  assert.equal(collapseRepeats([link(1), link(2), link(3)], parseOutputControls({})).list.length, 3)
  const mixed = [...[1, 2, 3, 4, 5].map((n) => link(n, 'add-attribute')), ...[6, 7, 8, 9, 10].map((n) => link(n, 'set-attribute'))]
  const out = collapseRepeats(mixed, parseOutputControls({})).list
  assert.equal(out.length, 2)
  assert.deepEqual(out.map((i) => i.count), [5, 5])
})

test('collapse: a rule named in rules[] is never collapsed', () => {
  const list = Array.from({ length: 8 }, (_, i) => link(i))
  assert.equal(collapseRepeats(list, parseOutputControls({ rules: ['new_window_link'] })).list.length, 8)
})

test('compact output prints the true instance count for a collapsed entry', () => {
  const { list } = collapseRepeats(Array.from({ length: 6 }, (_, i) => link(i)), parseOutputControls({}))
  const text = compactText(list)
  assert.match(text, /new_window_link ×6/)
  assert.match(text, /a\.l5/)
})

test('truncation note: hosted never points at scan_history; local may', () => {
  const remote = truncationNote({ remote: true, cap: 50, returned: 50, total: 64, stratified: false })
  assert.doesNotMatch(remote, /scan_history/)
  for (const hint of ['minImpact', 'rules', 'wcag', 'format: "compact"', 'rootSelector', 'start_audit']) assert.ok(remote.includes(hint), hint)
  const local = truncationNote({ remote: false, cap: 50, returned: 50, total: 64, stratified: false })
  assert.match(local, /scan_history/)
})

test('critic: visual-tier findings (contrast, per-element ratios) are never collapsed', () => {
  const contrast = Array.from({ length: 6 }, (_, n) => ({ id: `c${n}`, impact: 'moderate', wcag: '1.4.3', type: 'color-contrast', selector: `p.t${n}`, fixability: 'visual', message: `ratio ${n}`, fix: { op: 'set-attribute', attribute: 'style' } }))
  assert.equal(collapseRepeats(contrast, parseOutputControls({})).list.length, 6)
})

test('critic: a rule named in rules[] that matched through a merged rules[] entry is not collapsed', () => {
  const merged = Array.from({ length: 5 }, (_, n) => ({ id: `m${n}`, impact: 'serious', wcag: '1.3.1,4.1.2', type: 'missing_label', rules: ['missing_label', 'h91_inputtext_name'], selector: `#i${n}`, fix: { op: 'add-attribute', attribute: 'aria-label' } }))
  assert.equal(collapseRepeats(merged, parseOutputControls({ rules: ['h91_inputtext_name'] })).list.length, 5)
})

test('critic: two findings of ONE rule on a shared selector are two elements, not merged', () => {
  const out = mergeSameElement([
    { id: 'axe-image-alt-1', impact: 'critical', wcag: '1.1.1', type: 'image-alt', selector: 'img.logo', fix: { op: 'suggest' } },
    { id: 'axe-image-alt-2', impact: 'critical', wcag: '1.1.1', type: 'image-alt', selector: 'img.logo', fix: { op: 'suggest' } },
  ])
  assert.equal(out.length, 2)
})

test('critic: nameFamilyKey gives a merged finding and either of its engines the same key', () => {
  const [merged] = mergeSameElement(vercelInput()).filter((i) => i.type === 'missing_label')
  assert.equal(nameFamilyKey(merged!), nameFamilyKey({ type: 'h91_inputtext_name', selector: SEL }))
  assert.equal(nameFamilyKey({ type: 'contrast_insufficient', selector: SEL }), undefined)
})

// Review of #113: a collapsed entry kept the FIRST element's fix.value and
// tier, so an agent told to apply mechanical fixes "as given" would write
// aria-label="Email" on every input.
test('collapse never presents one element\'s value as the fix for all when values differ', () => {
  const mk = (n: number, v: string, fx: string) => ({ id: `wa-${n}`, type: 'missing_label', selector: `#f${n}`, impact: 'serious', wcag: '1.3.1', fixability: fx, fix: { op: 'add-attribute', attribute: 'aria-label', value: v } })
  const r = collapseRepeats([mk(1, 'Email', 'mechanical'), mk(2, 'Phone', 'mechanical'), mk(3, 'Zip', 'mechanical'), mk(4, '', 'contextual')] as any[], parseOutputControls({}))
  assert.equal(r.list.length, 1)
  const c = r.list[0] as any
  assert.equal(c.count, 4)
  assert.equal(c.fix.value, undefined)
  assert.notEqual(c.fixability, 'mechanical')
  assert.match(c.expand, /differ/)
  assert.doesNotMatch(compactText(r.list as any), /aria-label="Email"/)
})

test('collapse keeps the shared value when every element has the same one', () => {
  const mk = (n: number) => ({ id: `wa-${n}`, type: 'missing_lang', selector: `#p${n}`, impact: 'serious', wcag: '3.1.1', fixability: 'mechanical', fix: { op: 'add-attribute', attribute: 'lang', value: 'en' } })
  const c = collapseRepeats([1, 2, 3, 4].map(mk) as any[], parseOutputControls({})).list[0] as any
  assert.equal(c.fix.value, 'en')
  assert.equal(c.fixability, 'mechanical')
})

// Review of #113: two same-rule findings on a non-unique selector plus a
// third rule on it were folded into ONE finding, dropping a critical.
test('merge leaves a group alone when any rule appears more than once on the selector', () => {
  const list = [
    { id: 'axe-label-1', type: 'label', selector: 'input', impact: 'critical', wcag: '4.1.2', fix: { op: 'add-attribute', attribute: 'aria-label', value: 'Email' } },
    { id: 'axe-label-2', type: 'label', selector: 'input', impact: 'critical', wcag: '4.1.2', fix: { op: 'add-attribute', attribute: 'aria-label', value: 'Phone' } },
    { id: 'htmlcs-3', type: 'h91_inputtext_name', selector: 'input', impact: 'moderate', wcag: '4.1.2', fix: { op: 'suggest' } },
  ] as any[]
  const out = mergeSameElement(list)
  assert.equal(out.length, 3)
  assert.equal(recountSummary(out, []).critical, 2)
})
