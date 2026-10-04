/**
 * OpenAI apps domain verification: GET /.well-known/openai-apps-challenge must
 * return exactly the token from OPENAI_APPS_CHALLENGE_TOKEN as text/plain, and
 * 404 when it is unset.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { createServer } from 'node:net'

const PATH = '/.well-known/openai-apps-challenge'
const TOKEN = 'tok_Abc123-xyz_PUBLIC'

async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer().listen(0, () => {
      const p = (s.address() as { port: number }).port
      s.close(() => resolve(p))
    })
  })
}

async function start(env: Record<string, string>): Promise<{ proc: ChildProcess; base: string }> {
  const port = await freePort()
  const childEnv: NodeJS.ProcessEnv = { ...process.env, PORT: String(port), ...env }
  if (!('OPENAI_APPS_CHALLENGE_TOKEN' in env)) delete childEnv.OPENAI_APPS_CHALLENGE_TOKEN
  const proc = spawn('./node_modules/.bin/tsx', ['src/http.ts'], { env: childEnv, stdio: ['ignore', 'ignore', 'pipe'] })
  const base = `http://127.0.0.1:${port}`
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(base + '/health')).ok) return { proc, base }
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100))
  }
  proc.kill()
  throw new Error('server did not start')
}

let withTok: { proc: ChildProcess; base: string }
let noTok: { proc: ChildProcess; base: string }
before(async () => {
  ;[withTok, noTok] = await Promise.all([start({ OPENAI_APPS_CHALLENGE_TOKEN: TOKEN }), start({})])
})
after(() => { withTok?.proc.kill(); noTok?.proc.kill() })

test('token set: 200, exact body, text/plain', async () => {
  const r = await fetch(withTok.base + PATH)
  assert.equal(r.status, 200)
  assert.match(r.headers.get('content-type') || '', /^text\/plain/)
  assert.equal(await r.text(), TOKEN)
})

test('token unset: 404', async () => {
  assert.equal((await fetch(noTok.base + PATH)).status, 404)
})

test('empty token counts as unset: 404', async () => {
  const s = await start({ OPENAI_APPS_CHALLENGE_TOKEN: '' })
  try { assert.equal((await fetch(s.base + PATH)).status, 404) } finally { s.proc.kill() }
})

test('other well-known paths unaffected', async () => {
  const r = await fetch(withTok.base + '/.well-known/other')
  assert.equal(r.status, 404)
  assert.notEqual(await r.text(), TOKEN)
  assert.equal((await fetch(withTok.base + '/health')).status, 200)
})

test('POST is refused and does not leak the token', async () => {
  const r = await fetch(withTok.base + PATH, { method: 'POST', body: '{}' })
  assert.ok([404, 405].includes(r.status), `got ${r.status}`)
  assert.notEqual(await r.text(), TOKEN)
})

test('pasted whitespace is trimmed; whitespace-only counts as unset', async () => {
  const s = await start({ OPENAI_APPS_CHALLENGE_TOKEN: `  ${TOKEN}\n` })
  const blank = await start({ OPENAI_APPS_CHALLENGE_TOKEN: ' \n' })
  try {
    assert.equal(await (await fetch(s.base + PATH)).text(), TOKEN)
    assert.equal((await fetch(blank.base + PATH)).status, 404)
  } finally { s.proc.kill(); blank.proc.kill() }
})
