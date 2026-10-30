/**
 * The hosted sign-in page updates its status text while it starts sign-in
 * (opening, error). Without live-region semantics a screen reader user hears
 * none of it (WCAG 4.1.3).
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { authorizePage } from '../src/oauth.ts'

test('sign-in status updates are announced (role="status")', () => {
  const html = authorizePage({ client_label: 'Test client' } as any)
  assert.match(html, /<p id="status" role="status">/)
})

test('sign-in continues in the same window, never a second tab', () => {
  const html = authorizePage({ client_label: 'Test client' } as any)
  // replace(), not href: Back from the platform page must not re-run this
  // script and mint another device code.
  assert.match(html, /location\.replace\(start\.continueUrl\)/)
  assert.doesNotMatch(html, /location\.href =/)
  assert.doesNotMatch(html, /_blank|window\.open|authorize\/poll/)
})
