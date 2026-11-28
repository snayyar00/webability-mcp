/**
 * The tunnel token is a credential, and where it arrives from decides whether it
 * leaks: `--token <t>` lands in argv, which `ps`, a CI runner's log and a shell
 * history all record. The resolver therefore has to keep honouring `--token`
 * (existing scripts pass it) while preferring the environment, and must say so
 * on stderr when the flag is used. It also must not hang on an idle stdin.
 */
import assert from 'node:assert/strict'
import { PassThrough } from 'node:stream'
import test from 'node:test'
import { readStdinLine, resolveTunnelToken } from '../src/tunnelToken.ts'

const CONFIG_TOKEN = 'from-config'
const resolve = (argv: string[], env: Record<string, string> = {}, stdin = '', config = CONFIG_TOKEN) =>
  resolveTunnelToken({ argv, env, readStdin: async () => stdin, readConfig: () => config })

test('tunnel token: --token still works and warns that argv is visible', async () => {
  const got = await resolve(['node', 'webability-tunnel', '--port', '3000', '--token', 'from-flag'])
  assert.equal(got.token, 'from-flag', 'existing scripts keep working')
  assert.equal(got.source, 'flag')
  assert.match(got.warning ?? '', /deprecated/i)
  assert.match(got.warning ?? '', /WEBABILITY_API_KEY/, 'the warning names the replacement')
})

test('tunnel token: the environment is preferred over stdin and config', async () => {
  const got = await resolve(['node', 'webability-tunnel', '--port', '3000'], { WEBABILITY_API_KEY: 'from-env' }, 'from-stdin')
  assert.equal(got.token, 'from-env')
  assert.equal(got.source, 'env')
  assert.equal(got.warning, undefined, 'the documented channel is not deprecated')
})

test('tunnel token: ABILYO_API_KEY is honoured like WEBABILITY_API_KEY', async () => {
  const got = await resolve(['node', 'webability-tunnel'], { ABILYO_API_KEY: 'from-abilyo' })
  assert.equal(got.token, 'from-abilyo')
  assert.equal(got.source, 'env')
})

test('tunnel token: a piped stdin is used when the environment is empty', async () => {
  const got = await resolve(['node', 'webability-tunnel'], {}, '  from-stdin\n')
  assert.equal(got.token, 'from-stdin', 'the newline a pipe adds is trimmed')
  assert.equal(got.source, 'stdin')
})

test('tunnel token: an empty stdin falls through to the login config', async () => {
  const got = await resolve(['node', 'webability-tunnel'], {}, '   ')
  assert.equal(got.token, CONFIG_TOKEN)
  assert.equal(got.source, 'config')
})

test('tunnel token: nothing anywhere resolves to an empty token, not a crash', async () => {
  const got = await resolve(['node', 'webability-tunnel'], {}, '', '')
  assert.equal(got.token, '')
  assert.equal(got.source, 'config')
})

test('tunnel token: --token keeps its positional value form', async () => {
  const got = await resolve(['node', 'webability-tunnel', '--token', '--port', '3000'], {}, 'from-stdin')
  assert.equal(got.token, '--port', 'documented behaviour: the next argv entry is the value')
  assert.equal(got.source, 'flag')
})

test('stdin: a line resolves without waiting for the stream to close', async () => {
  const stream = new PassThrough()
  const pending = readStdinLine(stream, 5000)
  stream.write('secret-from-ci\nmore output that must not be read\n')
  assert.equal(await pending, 'secret-from-ci')
})

test('stdin: an open pipe with nothing in it gives up instead of hanging', async () => {
  const stream = new PassThrough()
  const started = Date.now()
  assert.equal(await readStdinLine(stream, 60), '')
  assert.ok(Date.now() - started < 2000, 'the bounded read returned')
})

test('stdin: text without a trailing newline is still a token', async () => {
  const stream = new PassThrough()
  const pending = readStdinLine(stream, 1000)
  stream.end('unterminated')
  assert.equal(await pending, 'unterminated')
})
