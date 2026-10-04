/**
 * Persona round 4 (2026-10-03), friction #1 (24/80 runs):
 *
 *  1. The headline said "Found 67 high-confidence issue(s)" and then
 *     "issues[] has 34 entries for 67 issue(s)", while the compact listing
 *     printed "## Issues (34)". Personas asked "which number do I tell
 *     legal". One number is the issue count; entries are a listing detail.
 *
 * Drives the real scan_page (local transport) on a localhost fixture that
 * yields 11 issues, of which 6 missing_alt collapse into one entry.
 */
import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'

import { headingCounts, startCountsFixture, type ScanText } from './_countsFixture.ts'

let fx: Awaited<ReturnType<typeof startCountsFixture>>
let url = ''
let page: ScanText
const scanPage = (extra: Record<string, unknown>) => fx.scanPage(extra)
before(async () => {
  fx = await startCountsFixture()
  url = fx.url
  page = await scanPage({ format: 'json' })
})
after(() => fx?.close())

test('fixture exercises grouping: 11 issues, missing_alt collapsed into one entry', () => {
  assert.equal(page.json.summary.total, 11, page.headline)
  assert.ok(page.json.issueEntries < page.json.issuesTotal, 'fixture must collapse at least one rule or it tests nothing')
})

// ---- 1. one unambiguous count -------------------------------------------

test('headline: one issue count to report, entries explained as grouping', () => {
  const total = page.json.summary.total
  assert.match(page.headline, new RegExp(`^Found ${total} high-confidence issues on `))
  assert.match(page.headline, new RegExp(`Total to report: ${total} issues`))
  assert.match(page.headline, new RegExp(`grouped into ${page.json.issueEntries} entries`))
  assert.doesNotMatch(page.headline, /entries for \d+ issue/, 'old "N entries for M issue(s)" phrasing')
  // Every "<n> issue(s)" in the headline names the same number.
  for (const m of page.headline.matchAll(/(\d+) (?:high-confidence )?issues?\b/g)) assert.equal(Number(m[1]), total, page.headline)
})

test('json: summary.total, issuesTotal and the headline agree', () => {
  assert.equal(page.json.summary.total, page.json.issuesTotal)
  assert.equal(page.json.pageSummary, undefined, 'no pageSummary without filters')
})

test('compact: the Issues heading leads with the issue count, not the entry count', async () => {
  const r = await scanPage({ format: 'compact' })
  assert.equal(r.headline, page.headline.replace(/http:\/\/127\.0\.0\.1:\d+\//, url), 'same headline in every format')
  assert.deepEqual(headingCounts(r.body), [11], r.body.slice(0, 300))
  assert.match(r.body, /^## Issues \(11 issues, grouped into \d+ entries\)/m)
})

test('default format: same headline and counts as json', async () => {
  const r = await scanPage({})
  assert.equal(r.headline, page.headline)
  assert.equal(r.json.summary.total, 11)
})


test('scanHeadline (pure): zero issues, no grouping clause; singular noun', async () => {
  const shaping: any = await import('../src/scanShaping.ts')
  assert.equal(typeof shaping.scanHeadline, 'function', 'scanShaping must export scanHeadline')
  const zero = { total: 0, critical: 0, serious: 0, moderate: 0, minor: 0, incomplete: 0 }
  const h0 = shaping.scanHeadline({ url: 'https://x.test/', shown: zero, issueEntries: 0, incompleteEntries: 0, collapsedGroups: 0 })
  assert.match(h0, /^Found 0 high-confidence issues on https:\/\/x\.test\/: 0 critical/)
  assert.match(h0, /Total to report: 0 issues/)
  assert.doesNotMatch(h0, /grouped|need human review/)
  const one = { ...zero, total: 1, serious: 1 }
  const h1 = shaping.scanHeadline({ url: 'https://x.test/', shown: one, issueEntries: 1, incompleteEntries: 0, collapsedGroups: 0 })
  assert.match(h1, /^Found 1 high-confidence issue on /)
  assert.match(h1, /Total to report: 1 issue\b/)
})
