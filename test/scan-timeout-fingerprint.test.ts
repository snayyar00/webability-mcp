import assert from 'node:assert/strict'
import { test } from 'node:test'

import { redactSensitiveMcpPayloads, stabilizeScanTimeoutFingerprint } from '../src/posthog.ts'

const SCAN_PAGE_TIMEOUT =
  'https://slow-site.example/ took longer than 55s to scan, so it stopped at the hosted limit for one tool call. Try again, or use start_audit for slow or large sites.'
const DIFF_SCAN_TIMEOUT =
  'diff_scan of https://baseline.example/ and https://slow-site.example/ took longer than 55s to scan, so it stopped at the hosted limit for one tool call. Try again, or use start_audit for slow or large sites.'

function exceptionEvent(value: string) {
  return {
    event: '$exception',
    properties: {
      $exception_list: [{ type: 'Error', value }],
      $mcp_tool_name: 'scan_page',
    },
  }
}

test('scan_page deadline timeout gets a stable fingerprint', () => {
  const event = stabilizeScanTimeoutFingerprint(exceptionEvent(SCAN_PAGE_TIMEOUT))
  assert.equal(event.properties.$exception_fingerprint, 'webability-mcp:hosted-scan-deadline-timeout')
})

test('diff_scan deadline timeout gets the same stable fingerprint', () => {
  const event = stabilizeScanTimeoutFingerprint(exceptionEvent(DIFF_SCAN_TIMEOUT))
  assert.equal(event.properties.$exception_fingerprint, 'webability-mcp:hosted-scan-deadline-timeout')
})

test('every slow site groups into one issue instead of one per URL', () => {
  const a = stabilizeScanTimeoutFingerprint(
    exceptionEvent('https://a.example/ took longer than 55s to scan, so it stopped at the hosted limit for one tool call.'),
  )
  const b = stabilizeScanTimeoutFingerprint(
    exceptionEvent('https://b.example/ took longer than 55s to scan, so it stopped at the hosted limit for one tool call.'),
  )
  assert.equal(a.properties.$exception_fingerprint, b.properties.$exception_fingerprint)
})

test('the timeout event is still captured, not dropped as misuse noise', () => {
  const event = redactSensitiveMcpPayloads(exceptionEvent(SCAN_PAGE_TIMEOUT))
  assert.ok(event, 'timeout event must survive beforeSend so the timeout rate stays visible')
  assert.equal(event.properties.$exception_fingerprint, 'webability-mcp:hosted-scan-deadline-timeout')
})

test('other exceptions keep their default fingerprint', () => {
  const event = stabilizeScanTimeoutFingerprint(
    exceptionEvent('Error: Scan failed: page.goto: net::ERR_HTTP2_PROTOCOL_ERROR at https://accesio.ro/'),
  )
  assert.equal(event.properties.$exception_fingerprint, undefined)
})

test('non-exception events are untouched', () => {
  const event = stabilizeScanTimeoutFingerprint({
    event: '$mcp_tool_call',
    properties: { $mcp_tool_name: 'scan_page' },
  })
  assert.equal(event.properties.$exception_fingerprint, undefined)
})

// ---- the error text itself -------------------------------------------------
// beforeSend deleted $mcp_parameters/$mcp_response, then handed $exception on
// untouched. Exception text is just as capable of carrying a customer URL with
// a token in the query, an e-mail address or a bearer value — and unlike tool
// args it reaches PostHog verbatim.

interface CaptureEvent {
  event: string
  properties: Record<string, unknown>
}
interface ExceptionItem {
  type?: unknown
  value?: unknown
  stacktrace?: { frames: { raw: string }[] }
}

// beforeSend returns MaybePromise<PostHogCaptureEvent | null>; these events are
// hand-built and synchronous, so narrow to the shape under test.
const redact = (event: CaptureEvent): CaptureEvent => redactSensitiveMcpPayloads(event) as CaptureEvent
const items = (event: CaptureEvent): ExceptionItem[] => event.properties.$exception_list as ExceptionItem[]

test('an exception value drops the URL query, emails and tokens it was carrying', () => {
  const event = redact({
    event: '$exception',
    properties: {
      $exception_list: [
        {
          type: 'Error',
          value:
            'page.goto: net::ERR_HTTP2_PROTOCOL_ERROR at https://portal.example.com/checkout?session=abc123&token=sk_live_9f8e7d6c5b4a failed; owner alice@example.com, Authorization: Bearer sk_live_0123456789abcdef',
        },
      ],
      $mcp_error_message: 'scan failed for https://portal.example.com/report?customer=acme',
    },
  })
  const value = items(event)[0].value
  assert.ok(typeof value === 'string')
  assert.doesNotMatch(value, /abc123|sk_live_9f8e7d6c5b4a/)
  assert.doesNotMatch(value, /alice@example\.com/)
  assert.doesNotMatch(value, /0123456789abcdef/)
  assert.match(value, /net::ERR_HTTP2_PROTOCOL_ERROR/, 'the shape of the failure survives')
  assert.match(value, /portal\.example\.com/, 'the host survives — it is what tells us whose site broke')
  assert.doesNotMatch(String(event.properties.$mcp_error_message), /customer=acme/)
})

test('stack frames are left alone so PostHog can still symbolicate', () => {
  const frame = '    at scanPage (file:///Users/sidharth/app/dist/http.js:120:9)'
  const event = redact({
    event: '$exception',
    properties: { $exception_list: [{ type: 'Error', value: 'boom', stacktrace: { frames: [{ raw: frame }] } }] },
  })
  assert.equal(items(event)[0].stacktrace?.frames[0].raw, frame)
})

test('the scrubber keeps the exception type it groups on', () => {
  const event = redact({
    event: '$exception',
    properties: { $exception_list: [{ type: 'TimeoutError', value: 'took too long' }], $mcp_error_type: 'TimeoutError' },
  })
  assert.equal(items(event)[0].type, 'TimeoutError')
  assert.equal(event.properties.$mcp_error_type, 'TimeoutError')
})

test('a scrubbed deadline timeout still gets its stable fingerprint', () => {
  const event = redact(
    exceptionEvent(
      'https://slow-site.example/watch?token=abc took longer than 55s to scan, so it stopped at the hosted limit for one tool call. Try again, or use start_audit for slow or large sites.',
    ),
  )
  assert.equal(event.properties.$exception_fingerprint, 'webability-mcp:hosted-scan-deadline-timeout')
  assert.doesNotMatch(String(items(event)[0].value), /token=abc/)
})

test('a non-string value in the exception list is left as it is', () => {
  // $exception_list is caller-supplied in shape: a non-string value must not be
  // coerced into "[object Object]" or crash beforeSend.
  const event = redact({
    event: '$exception',
    properties: { $exception_list: [{ type: 'Error', value: 42 }, null, 'oops'] },
  })
  assert.deepEqual(event.properties.$exception_list, [{ type: 'Error', value: 42 }, null, 'oops'])
})
