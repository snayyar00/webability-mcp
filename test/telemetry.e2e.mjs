#!/usr/bin/env node
/**
 * E2E test for usage telemetry — EVERY tool call emits one event.
 *
 * Speaks real MCP over stdio to the BUILT server (dist/index.js) with
 * WEBABILITY_API_URL pointed at a local mock receiver, then verifies:
 *   1. non-scan tools (get_rules, check_color_contrast, find_source,
 *      scan_history, generate_ai_fix) emit events with sensible targets
 *   2. enrichment: fix-returned flag, AA pass/fail, counts
 *   3. no page content / HTML ever appears in an event
 *   4. WEBABILITY_SCAN_TELEMETRY=off sends nothing
 *
 * Fully offline — no tool here touches the network beyond the mock receiver.
 * Run: node test/telemetry.e2e.mjs   (from packages/mcp, after a build)
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { createServer } from 'http'
import { mkdtempSync } from 'fs'
import { tmpdir } from 'os'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const here = dirname(fileURLToPath(import.meta.url))
const serverEntry = join(here, '..', 'dist', 'index.js')

let failures = 0
function check(name, cond, detail = '') {
  console.log(`${cond ? '  ✓' : '  ✗'} ${name}${cond ? '' : '  ' + detail}`)
  if (!cond) failures++
}

// --- mock telemetry receiver ------------------------------------------------
const events = []
const receiver = createServer((req, res) => {
  let body = ''
  req.on('data', (c) => (body += c))
  req.on('end', () => {
    if (req.url === '/mcp/scan-events' && req.method === 'POST') {
      try { events.push(JSON.parse(body)) } catch { events.push({ parseError: body }) }
    }
    res.statusCode = 204
    res.end()
  })
})
await new Promise((r) => receiver.listen(0, '127.0.0.1', r))
const port = receiver.address().port

async function withClient(env, fn) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverEntry],
    env: {
      ...process.env,
      WEBABILITY_API_URL: `http://127.0.0.1:${port}`,
      WEBABILITY_SCAN_LOG_DIR: mkdtempSync(join(tmpdir(), 'mcp-telemetry-e2e-')),
      ...env,
    },
  })
  const client = new Client({ name: 'telemetry-e2e', version: '0.0.0' })
  await client.connect(transport)
  try {
    return await fn(client)
  } finally {
    await client.close()
  }
}

const SECRET_HTML = '<div role="bogusrole" aria-label="tok-secret-value">hi</div>'

await withClient({}, async (client) => {
  const call = (name, args) => client.callTool({ name, arguments: args })
  await call('get_rules', { tags: ['wcag21aa'] })
  await call('check_color_contrast', { foreground: '#777777', background: '#ffffff', fontSize: 16 })
  await call('find_source', { selector: '#nonexistent-thing-xyz .some-class', rootDir: join(here, '..', 'src') })
  await call('scan_history', {})
  await call('check_aria', { html: SECRET_HTML })
  // /cli/ai-fix on the mock receiver returns an empty 204 → json parse fails →
  // "AI fix failed:" — exercises the ok=false + fix:no path with zero network.
  await call('generate_ai_fix', {
    issue: { type: 'image-alt', wcag: '1.1.1', selector: 'img', message: 'missing alt' },
    html: '<img src="x.png">',
    framework: 'plain-css',
  })
  await new Promise((r) => setTimeout(r, 1500)) // let fire-and-forget flushes land
})

const byTool = (t) => events.find((e) => e.tool === t)

check('one event per tool call (6 calls → 6 events)', events.length === 6, `got ${events.length}: ${events.map((e) => e.tool).join(',')}`)

const rules = byTool('get_rules')
check('get_rules: target is the tag filter', rules?.target === 'tags:wcag21aa', JSON.stringify(rules))
check('get_rules: rule count in summary.total', typeof rules?.summary?.total === 'number' && rules.summary.total > 0, JSON.stringify(rules))

const contrast = byTool('check_color_contrast')
check('check_color_contrast: target is the color pair', contrast?.target === '#777777 on #ffffff', JSON.stringify(contrast))
check('check_color_contrast: AA verdict in meta', contrast?.meta === 'aa:fail', JSON.stringify(contrast))

const src = byTool('find_source')
check('find_source: target is the selector', src?.target === '#nonexistent-thing-xyz .some-class', JSON.stringify(src))
check('find_source: match count in summary.total', src?.summary?.total === 0, JSON.stringify(src))

const hist = byTool('scan_history')
check('scan_history: target is "list"', hist?.target === 'list', JSON.stringify(hist))

const aria = byTool('check_aria')
check('check_aria: synthetic size target (no HTML)', /^inline-html \(/.test(aria?.target ?? ''), JSON.stringify(aria))

const fix = byTool('generate_ai_fix')
check('generate_ai_fix: target is issue type + WCAG SC', fix?.target === 'image-alt wcag:1.1.1', JSON.stringify(fix))
check('generate_ai_fix: fix-returned flag in meta', fix?.meta === 'fix:no', JSON.stringify(fix))
check('generate_ai_fix: ok=false when AI service failed', fix?.ok === false, JSON.stringify(fix))

const wire = JSON.stringify(events)
check('no page content leaks into any event', !wire.includes('tok-secret-value') && !wire.includes('<div') && !wire.includes('<img'), wire)
check('local events carry a clientId', events.every((e) => typeof e.clientId === 'string' && e.clientId.length > 0))

// --- opt-out ----------------------------------------------------------------
const before = events.length
await withClient({ WEBABILITY_SCAN_TELEMETRY: 'off' }, async (client) => {
  await client.callTool({ name: 'get_rules', arguments: { tags: ['wcag21aa'] } })
  await client.callTool({ name: 'check_color_contrast', arguments: { foreground: '#000', background: '#fff' } })
  await new Promise((r) => setTimeout(r, 1000))
})
check('WEBABILITY_SCAN_TELEMETRY=off sends nothing', events.length === before, `got ${events.length - before} extra event(s)`)

receiver.close()
console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
