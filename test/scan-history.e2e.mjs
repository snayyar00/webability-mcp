#!/usr/bin/env node
/**
 * E2E test for MCP scan logging + the scan_history tool.
 *
 * Speaks real MCP over stdio to the BUILT server (dist/index.js), runs a real
 * scan_html (headless Chromium + axe), then verifies:
 *   1. the scan was recorded in <logdir>/index.jsonl
 *   2. scan_history lists it
 *   3. scan_history {id} returns the full stored response
 *   4. WEBABILITY_SCAN_LOG=off disables logging
 *
 * Run: node test/scan-history.e2e.mjs   (from packages/mcp, after a build)
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { mkdtempSync, readFileSync, existsSync, readdirSync } from 'fs'
import { tmpdir } from 'os'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const here = dirname(fileURLToPath(import.meta.url))
const serverEntry = join(here, '..', 'dist', 'index.js')
const HTML = '<html lang="en"><body><main><h1>Test</h1><img src="x.png"></main></body></html>'

let failures = 0
function check(name, cond, detail = '') {
  console.log(`${cond ? '  ✓' : '  ✗'} ${name}${cond ? '' : '  ' + detail}`)
  if (!cond) failures++
}

async function withClient(env, fn) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverEntry],
    env: { ...process.env, ...env },
  })
  const client = new Client({ name: 'scan-history-e2e', version: '0.0.0' })
  await client.connect(transport)
  try {
    return await fn(client)
  } finally {
    await client.close()
  }
}

// ── 1-3: logging on, real scan, history readable ───────────────────────────
const logDir = mkdtempSync(join(tmpdir(), 'wa-scanlog-'))
await withClient({ WEBABILITY_SCAN_LOG_DIR: logDir }, async (client) => {
  const tools = await client.listTools()
  check('scan_history tool is listed', tools.tools.some((t) => t.name === 'scan_history'))

  const scanRes = await client.callTool({ name: 'scan_html', arguments: { html: HTML } })
  check('scan_html returned content', Array.isArray(scanRes.content) && scanRes.content.length > 0)

  const indexPath = join(logDir, 'index.jsonl')
  check('index.jsonl written', existsSync(indexPath))
  const entry = JSON.parse(readFileSync(indexPath, 'utf8').trim().split('\n').pop())
  check('entry has tool=scan_html', entry.tool === 'scan_html', JSON.stringify(entry))
  check('entry target describes inline html', /inline-html/.test(entry.target), entry.target)
  check('entry marked ok with duration', entry.ok === true && entry.durationMs > 0)
  check('full response stored', entry.file && existsSync(join(logDir, entry.file)))

  const hist = await client.callTool({ name: 'scan_history', arguments: {} })
  const histText = hist.content[0].text
  check('scan_history lists the scan', histText.includes('scan_html') && histText.includes(entry.id), histText.slice(0, 200))

  const full = await client.callTool({ name: 'scan_history', arguments: { id: entry.id } })
  check('scan_history {id} returns stored response', full.content[0].text.includes('"response"'))

  const filtered = await client.callTool({ name: 'scan_history', arguments: { filter: 'no-such-target-xyz' } })
  check('filter with no match says so', /No scans logged yet/.test(filtered.content[0].text))
})

// ── 4: logging off ──────────────────────────────────────────────────────────
const offDir = mkdtempSync(join(tmpdir(), 'wa-scanlog-off-'))
await withClient({ WEBABILITY_SCAN_LOG_DIR: offDir, WEBABILITY_SCAN_LOG: 'off' }, async (client) => {
  await client.callTool({ name: 'scan_html', arguments: { html: HTML } })
  check('WEBABILITY_SCAN_LOG=off writes nothing', readdirSync(offDir).length === 0)
})

console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
