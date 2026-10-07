/**
 * The hosted sign-in page updates its status text while it polls (waiting,
 * connected, error). Without live-region semantics a screen reader user hears
 * none of it (WCAG 4.1.3). Both the initial and the re-created status element
 * carry role="status".
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { authorizePage } from '../src/oauth.ts'

test('sign-in status updates are announced (role="status" on both status elements)', () => {
  const html = authorizePage({ client_label: 'Test client' } as any)
  assert.match(html, /<p id="status" role="status">/)
  assert.match(html, /status\.setAttribute\('role', 'status'\)/)
})
