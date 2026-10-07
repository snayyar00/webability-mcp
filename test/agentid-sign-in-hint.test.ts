import assert from 'node:assert/strict'
import { test } from 'node:test'

import { signInRequired } from '../src/signIn.js'

// Agents only learn they can sign themselves up if the text they actually
// receive says so: the account-tool refusal (and the anonymous 429, which
// shares signInSteps) must name AgentID.
test('account-tool refusal tells an agent it can sign in with AgentID', () => {
  const msg = signInRequired('start_audit')
  assert.match(msg, /Sign in with AgentID/)
  assert.match(msg, /AgentMail inbox/)
})
