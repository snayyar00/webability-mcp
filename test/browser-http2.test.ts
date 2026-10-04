/**
 * Some sites (accesio.ro) reset Chromium's HTTP/2 stream:
 * net::ERR_HTTP2_PROTOCOL_ERROR. One retry in a fresh browser launched with
 * --disable-http2 gets through. Only on that error, only once.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { createSessionOpener } from '../src/browser.ts'

const H2 = new Error('page.goto: net::ERR_HTTP2_PROTOCOL_ERROR at https://accesio.ro/')

/** Each launched browser gets a script of goto outcomes. */
function world(scripts: Array<Array<Error | { ok: true }>>) {
  const launches: any[] = []
  const closed: number[] = []
  const launch = async (o: any) => {
    const idx = launches.length
    launches.push(o)
    const script = [...(scripts[idx] ?? [{ ok: true }])]
    return {
      newContext: async () => ({
        newPage: async () => ({
          idx,
          goto: async () => {
            const step = script.shift() ?? { ok: true as const }
            if (step instanceof Error) throw step
            return { status: () => 200, from: idx }
          },
        }),
      }),
      close: async () => void closed.push(idx),
    }
  }
  return { launch, launches, closed }
}

test('ERR_HTTP2_PROTOCOL_ERROR retries once in a fresh browser with --disable-http2', async () => {
  const w = world([[H2], [{ ok: true }]])
  let setups = 0
  const open = createSessionOpener(w.launch)
  const s = await open({ remote: true, setupContext: () => void setups++ })
  const res = await s.goto('https://accesio.ro/')
  assert.equal(res.from, 1)
  assert.equal(s.page.idx, 1, 'session now points at the retry page')
  assert.equal(w.launches.length, 2)
  assert.deepEqual(w.launches[1].args, ['--disable-http2'])
  assert.equal(w.launches[0].args, undefined, 'first launch keeps HTTP/2')
  assert.equal(w.launches[1].remote, true, 'retry keeps remote mode (no install, SSRF guard)')
  assert.equal(setups, 2, 'SSRF/relay guard is installed on the retry context too')
  assert.deepEqual(w.closed, [0], 'the failed browser is closed')
  await s.close()
  assert.deepEqual(w.closed, [0, 1])
})

test('the retry happens once: a second HTTP/2 error propagates', async () => {
  const w = world([[H2], [H2]])
  const s = await createSessionOpener(w.launch)({})
  await assert.rejects(s.goto('https://accesio.ro/'), (e: Error) => e === H2)
  assert.equal(w.launches.length, 2)
})

test('later navigations in the same session do not retry again', async () => {
  const w = world([[H2], [{ ok: true }, H2]])
  const s = await createSessionOpener(w.launch)({})
  await s.goto('https://a.example/')
  await assert.rejects(s.goto('https://b.example/'), (e: Error) => e === H2)
  assert.equal(w.launches.length, 2)
})

test('other navigation errors never retry', async () => {
  const dns = new Error('page.goto: net::ERR_NAME_NOT_RESOLVED at https://nope.invalid/')
  const w = world([[dns]])
  const s = await createSessionOpener(w.launch)({})
  await assert.rejects(s.goto('https://nope.invalid/'), (e: Error) => e === dns)
  assert.equal(w.launches.length, 1)
  assert.deepEqual(w.closed, [])
})

test('a scheme-less url reaches page.goto as https:// (core scan() used to add it)', async () => {
  const seen: string[] = []
  const open = createSessionOpener(async () => ({
    newContext: async () => ({ newPage: async () => ({ goto: async (u: string) => (seen.push(u), { status: () => 200 }) }) }),
    close: async () => {},
  }))
  const s = await open({})
  await s.goto('example.com')
  await s.goto('http://localhost:3000/x')
  await s.goto('https://a.example/')
  assert.deepEqual(seen, ['https://example.com', 'http://localhost:3000/x', 'https://a.example/'])
})

test('setupContext (SSRF/relay guard) runs before the first goto, and again before the HTTP/2 retry goto', async () => {
  const events: string[] = []
  let n = 0
  const open = createSessionOpener(async () => {
    const id = n++
    return {
      newContext: async () => ({
        newPage: async () => ({
          goto: async () => {
            events.push(`goto${id}`)
            if (id === 0) throw H2
            return { status: () => 200 }
          },
        }),
      }),
      close: async () => {},
    }
  })
  const s = await open({ remote: true, setupContext: () => void events.push(`guard${n - 1}`) })
  await s.goto('https://accesio.ro/')
  assert.deepEqual(events, ['guard0', 'goto0', 'guard1', 'goto1'])
})
