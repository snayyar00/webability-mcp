/**
 * DEV-1089 item 6: scan_html runs IN-PROCESS by default — jsdom + the
 * WebAbility detectors + axe-core, no browser, no network. Milliseconds, not
 * seconds. Visual-tier rules (contrast, target size, focus) need real layout,
 * so they are dropped and the count is reported, never silently.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { fastScanHtml } from '../src/fastScan.ts'

const PAGE = '<!doctype html><html lang="en"><head><title>t</title></head><body><main><h1>Hi</h1><img src="x.png"><button></button><a href="#"></a><p style="color:#aaa;background:#fff">low</p></main></body></html>'

test('finds the structural issues with fix op + fixability, in well under a second', async () => {
  const t0 = Date.now()
  const r = await fastScanHtml(PAGE)
  const ms = Date.now() - t0
  const ids = r.issues.map((i) => i.type)
  assert.ok(ids.includes('image-alt') || ids.includes('missing_alt'), `alt: ${ids}`)
  assert.ok(ids.includes('button-name') || ids.includes('unlabeled_button'), `button: ${ids}`)
  for (const i of r.issues) {
    assert.ok(i.fix?.op, `${i.id} has fix.op`)
    assert.ok(i.fixability, `${i.id} has fixability`)
    assert.notEqual(i.fixability, 'visual', `${i.id} visual rules are not reported from jsdom`)
  }
  // ~550ms cold on a laptop; the claim is "no browser launch" (a Chromium
  // scan is 3-8s), not a micro-benchmark — under the full parallel suite this
  // hit 1539ms once (2026-08-26), so the bound is load-tolerant.
  assert.ok(ms < 4000, `took ${ms}ms`)
  assert.equal(r.engine, 'in-process')
})

test('a visible h1 is NOT reported missing (jsdom has no layout — client rects are shimmed)', async () => {
  const r = await fastScanHtml(PAGE)
  assert.ok(!r.issues.some((i) => i.type === 'missing_h1'), 'missing_h1 false positive')
})

test('media elements do not stall the scan (axe preload waits on readyState)', async () => {
  const t0 = Date.now()
  const r = await fastScanHtml('<!doctype html><html lang="en"><head><title>t</title></head><body><main><h1>v</h1><video src="v.mp4" autoplay></video></main></body></html>')
  assert.ok(Date.now() - t0 < 3000, 'video page took too long — axe media preload is waiting')
  assert.ok(r.issues.some((i) => i.type === 'unsafe_autoplay' || i.type === 'missing_media_controls'), r.issues.map((i) => i.type).join(','))
})

test('a fragment is wrapped into a document and scanned', async () => {
  const r = await fastScanHtml('<img src="a.png"><button></button>')
  assert.ok(r.issues.length >= 2)
  assert.equal(r.fragment, true)
})

test('summary + skippedVisual are reported', async () => {
  const r = await fastScanHtml(PAGE)
  assert.equal(typeof r.summary.total, 'number')
  assert.equal(typeof r.skippedVisual, 'number')
})
