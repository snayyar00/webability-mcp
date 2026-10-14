/**
 * The AI judge through the tools: scan_page promotes a judged violation
 * (text on a mixed gradient the pixel resolver could not settle), verify_fix
 * sees it on the unfixed page and clears it on the fixed page, scan_html
 * judges text-only, and no output ever carries review wording.
 *
 * The model is a local stub of the OpenAI-compatible chat endpoint, reached
 * through the same env the operator would set (OPENROUTER_API_KEY +
 * WEBABILITY_JUDGE_BASE_URL).
 */
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
process.env.WEBABILITY_SCAN_LOG = 'off'

import assert from 'node:assert/strict'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { after, before, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

const BEFORE = `<!doctype html><html lang="en"><head><title>Before</title></head><body style="background:#fff;color:#111;font:16px sans-serif">
<main><h1>Before</h1><div style="background:linear-gradient(90deg,#222,#fff);padding:20px"><p id="g" style="color:#999">Mixed gradient text</p></div></main></body></html>`
const AFTER = `<!doctype html><html lang="en"><head><title>After</title></head><body style="background:#fff;color:#111;font:16px sans-serif">
<main><h1>After</h1><div style="background:#222;padding:20px"><p id="g" style="color:#ffffff">Mixed gradient text</p></div></main></body></html>`
// axe reports video-caption as incomplete in jsdom (it cannot hear the track).
const SNIPPET = `<video src="/v.mp4" controls width="320" height="180"></video>`

const BANNED = /needs[ -]review|need(?:s)? human review|human review|do NOT auto-fix|incomplete/i

let site: HttpServer
let model: HttpServer
let base = ''
const modelCalls: Array<{ model: string; hasImage: boolean; ids: string[] }> = []
let client: Client

before(async () => {
  site = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end(req.url?.startsWith('/after') ? AFTER : BEFORE)
  })
  await new Promise<void>((r) => site.listen(0, '127.0.0.1', () => r()))
  base = `http://127.0.0.1:${(site.address() as any).port}`

  // Stub model: every id in the request is a violation with a fix.
  model = createHttpServer((req, res) => {
    let body = ''
    req.on('data', (c) => (body += c))
    req.on('end', () => {
      const parsed = JSON.parse(body)
      const text = JSON.stringify(parsed.messages)
      const ids = [...new Set([...text.matchAll(/\\"id\\": \\"([^"\\]+)\\"/g)].map((m) => m[1]))]
      modelCalls.push({ model: parsed.model, hasImage: /image_url/.test(text), ids })
      const verdicts = ids.map((id) => ({ id, verdict: 'violation', reason: id.includes('contrast') ? 'not readable over the dark half' : 'spoken content with no captions', ...(id.includes('contrast') ? { fix: { attribute: 'style', value: '#ffffff' } } : {}) }))
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify(verdicts) } }] }))
    })
  })
  await new Promise<void>((r) => model.listen(0, '127.0.0.1', () => r()))
  process.env.OPENROUTER_API_KEY = 'test-key-not-real'
  process.env.WEBABILITY_JUDGE_BASE_URL = `http://127.0.0.1:${(model.address() as any).port}/v1`

  const [c, s] = InMemoryTransport.createLinkedPair()
  const server = createServer({})
  client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(s), client.connect(c)])
})
after(() => {
  site?.close()
  model?.close()
})

const call = async (name: string, args: Record<string, unknown>) => {
  const r: any = await client.callTool({ name, arguments: args }, undefined, { timeout: 180_000 })
  const text = (r.content as any[]).map((x) => String(x.text ?? '')).join('\n')
  const m = text.match(/```json\n([\s\S]*?)\n```/)
  return { text, json: m ? JSON.parse(m[1]) : null }
}

test('scan_page: the judge promotes the mixed-gradient contrast finding with a colour fix and records the verdict', async () => {
  const { text, json } = await call('scan_page', { url: `${base}/before`, format: 'json' })
  assert.doesNotMatch(text, BANNED, text.match(BANNED)?.[0])
  const hit = (json.issues as any[]).find((i) => i.wcag === '1.4.3' && /Mixed gradient/.test(i.html || ''))
  assert.ok(hit, 'promoted 1.4.3 violation on #g\n' + text.slice(0, 600))
  assert.match(hit.message, /\d\.\d\d:1 at worst/)
  assert.equal(hit.fix.attribute, 'style')
  // The stub's #ffffff passes on both measured ends behind this short text, so it is kept.
  assert.equal(hit.fix.suggestedValue, 'color:#ffffff !important;')
  assert.equal(hit.fixability, 'visual')
  assert.ok((json.judged as any[]).some((j) => j.verdict === 'violation' && j.id === hit.id), 'judged[] carries the verdict')
  assert.ok(modelCalls.some((c) => c.hasImage && c.model === 'anthropic/claude-haiku-4.5'), 'vision model used for a page scan')
})

test('verify_fix: still a violation on the unfixed page, verified on the fixed page', async () => {
  const before = await call('verify_fix', { url: `${base}/before`, selector: '#g', wcag: '1.4.3' })
  assert.equal(before.json.verified, false, before.text)
  assert.equal(before.json.remainingCount, 1, before.text)
  const after = await call('verify_fix', { url: `${base}/after`, selector: '#g', wcag: '1.4.3' })
  assert.equal(after.json.verified, true, after.text)
  assert.equal(after.json.remainingCount, 0)
  assert.doesNotMatch(before.text + after.text, BANNED)
})

test('scan_html: an undecided video-caption finding is judged text-only with the text model', async () => {
  modelCalls.length = 0
  const { text, json } = await call('scan_html', { html: SNIPPET })
  assert.doesNotMatch(text, BANNED, text.match(BANNED)?.[0])
  const hit = (json.issues as any[]).find((i) => i.type === 'video-caption')
  assert.ok(hit, 'video-caption promoted\n' + text)
  assert.ok((json.judged as any[])?.some((j) => j.id === hit.id && j.verdict === 'violation'), 'judged[] present')
  assert.equal(modelCalls.length, 1)
  assert.equal(modelCalls[0].model, 'deepseek/deepseek-v4-flash')
  assert.equal(modelCalls[0].hasImage, false)
})
