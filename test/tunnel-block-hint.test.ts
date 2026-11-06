import assert from 'node:assert/strict'
import { test } from 'node:test'

import { tunnelBlockHint } from '../src/tunnelAuth.ts'

const URL = 'https://tunnel.webability.io/t/ce897b9c71e7bcd14e38b810400730d8/'

test('a refused tunnel request names the secret', () => {
  assert.match(tunnelBlockHint(URL, 401), /tunnel_secret/)
  assert.match(tunnelBlockHint(URL, 404), /tunnel_secret/)
})

test('a tunnel that answered with a server error gets no secret hint', () => {
  assert.equal(tunnelBlockHint(URL, 500), '')
})

test('a normal site gets no hint', () => {
  assert.equal(tunnelBlockHint('https://example.org/', 404), '')
})
