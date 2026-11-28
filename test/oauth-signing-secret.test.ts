/**
 * #227 / #229-3: OAUTH_SIGNING_SECRET signs client_ids and refresh-token
 * bindings, and it used to fall back to MCP_AUTH_TOKEN and then to a random
 * key minted per boot. The first fallback gave the shared operator secret a
 * signing role; the second silently invalidated every issued client_id and
 * bound refresh token on every restart. It is now required, and the server
 * refuses to start without it.
 */
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:net'
import { test } from 'node:test'
import { setTimeout as sleep } from 'node:timers/promises'

import { SIGNING_SECRET_ENV, assertSigningSecret } from '../src/oauth.ts'

/**
 * The test runner's own env with both secrets removed, so a value exported in
 * the developer's shell can never satisfy the guard under test.
 */
function scrubbedEnv(overrides: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env }
  delete env.OAUTH_SIGNING_SECRET
  delete env.MCP_AUTH_TOKEN
  return { ...env, ...overrides }
}

/** Boot src/http.ts on a free port and wait for it to exit (or hang). */
async function boot(overrides: Record<string, string>): Promise<{ code: number | null; stderr: string }> {
  const probe = createServer()
  const listening = Promise.withResolvers<void>()
  probe.listen(0, listening.resolve)
  await listening.promise
  const address = probe.address()
  assert.ok(address && typeof address === 'object')
  const port = address.port
  const closed = Promise.withResolvers<void>()
  probe.close(closed.resolve)
  await closed.promise

  const child = spawn('./node_modules/.bin/tsx', ['src/http.ts'], {
    env: scrubbedEnv({ PORT: String(port), ...overrides }),
    stdio: ['ignore', 'ignore', 'pipe'],
  })
  let stderr = ''
  const exited = Promise.withResolvers<number | null>()
  child.on('exit', (code) => exited.resolve(code))
  // A broken guard fails FAST: http.ts announces the listener on stderr, so
  // report as soon as it does. That keeps the failure path quick even though
  // the hang ceiling has to be generous — a tsx cold start has taken over 20 s
  // on this machine while parallel suites were running.
  const ready = Promise.withResolvers<'listening'>()
  child.stderr?.on('data', (chunk: Buffer) => {
    stderr += chunk.toString()
    if (stderr.includes('listening on')) ready.resolve('listening')
  })
  const hang = sleep(120_000).then(() => 'hang' as const)
  const outcome = await Promise.race([exited.promise, ready.promise, hang])
  if (typeof outcome !== 'number') {
    child.kill()
    // 'listening' means the boot guard let it through; 'hang' means tsx never
    // got as far as the guard. Both fail the assertions below with stderr.
    return { code: null, stderr: `[${outcome}] ${stderr}` }
  }
  return { code: outcome, stderr }
}

test('in-process: assertSigningSecret throws the full explanation, naming the env var', () => {
  // The test process itself has no secret; oauth.ts is importable anyway, so
  // authorizePage() stays unit-testable without any env.
  assert.throws(assertSigningSecret, (err: Error) => {
    assert.match(err.message, new RegExp(SIGNING_SECRET_ENV))
    assert.match(err.message, /openssl rand -hex 32/)
    assert.match(err.message, /register and sign in again/)
    return true
  })
})

test('boot: no OAUTH_SIGNING_SECRET, no server — exit 1 with the reason', async () => {
  const { code, stderr } = await boot({})
  assert.equal(code, 1, `server should refuse to start; stderr: ${stderr}`)
  assert.match(stderr, /OAUTH_SIGNING_SECRET is required/)
})

test('boot: MCP_AUTH_TOKEN is not a signing secret', async () => {
  // The old fallback: the shared operator secret doubled as the HMAC key, so
  // anyone holding the operator token could mint a client_id for any
  // redirect_uri. It must not satisfy the boot guard.
  const { code, stderr } = await boot({ MCP_AUTH_TOKEN: 'operator-shared-token-0123456789abcdefghijkl' })
  assert.equal(code, 1, `shared operator token must not sign anything; stderr: ${stderr}`)
  assert.match(stderr, /OAUTH_SIGNING_SECRET is required/)
})

test('boot: a blank OAUTH_SIGNING_SECRET is the same as unset', async () => {
  const { code } = await boot({ OAUTH_SIGNING_SECRET: '   ' })
  assert.equal(code, 1)
})
