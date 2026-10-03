/**
 * Telemetry target is the most identifying field we hold: describeScanTarget
 * passes the FULL URL — query strings (tokens, emails, session ids) and hash
 * fragments — into the mcp_scan_events row. Scrub URL-shaped targets to
 * origin + path before they leave the machine. Non-URL labels (selectors,
 * tags, color pairs, list/id markers) pass through untouched, and the LOCAL
 * scan log keeps the full URL (it never leaves the machine).
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { describeTelemetryTarget } from '../src/telemetry.ts'

test('strips query string and hash from URL targets', () => {
  assert.equal(
    describeTelemetryTarget('scan_page', { url: 'https://example.com/report?token=abc&email=a@b.com#section' }),
    'https://example.com/report',
  )
})

test('keeps origin + path for tunnel and localhost URLs', () => {
  assert.equal(
    describeTelemetryTarget('verify_fix', { url: 'http://127.0.0.1:8090/?page_id=108&x=1' }),
    'http://127.0.0.1:8090/',
  )
})

test('leaves non-URL labels untouched', () => {
  assert.equal(describeTelemetryTarget('find_source', { selector: '#a .b?x' }), '#a .b?x')
  assert.equal(describeTelemetryTarget('get_rules', { tags: ['wcag21aa'] }), 'tags:wcag21aa')
  assert.equal(describeTelemetryTarget('scan_history', {}), 'list')
  assert.equal(
    describeTelemetryTarget('check_color_contrast', { foreground: '#777777', background: '#ffffff' }),
    '#777777 on #ffffff',
  )
})

test('still caps labels at 300 chars', () => {
  const long = 'https://example.com/' + 'p/'.repeat(200) + '?q=1'
  const out = describeTelemetryTarget('scan_page', { url: long })
  assert.ok(out.length <= 300)
  assert.ok(!out.includes('?q=1'))
})

test('scrubs URLs containing literal whitespace whole (no tail leak)', () => {
  assert.equal(
    describeTelemetryTarget('scan_page', { url: 'https://example.com/a b?token=secret#frag' }),
    'https://example.com/a%20b',
  )
})

test('preserves flow_scan page-count suffix after the scrubbed URL', () => {
  assert.equal(
    describeTelemetryTarget('flow_scan', { startUrl: 'https://example.com/start?x=1', autoNavigate: ['a', 'b', 'c'] }),
    'https://example.com/start (+3 pages)',
  )
})
