#!/usr/bin/env node
/**
 * E2E test for optional PostHog MCP Analytics.
 *
 * Speaks real MCP over stdio to the BUILT server (dist/index.js), points
 * PostHog at a local mock ingestion endpoint, then verifies:
 *   1. MCP analytics emits events when POSTHOG_PROJECT_API_KEY is set
 *   2. raw tool parameters/responses are redacted before PostHog receives them
 *   3. WEBABILITY_POSTHOG_MCP_ANALYTICS=off suppresses PostHog events
 *
 * Run: node test/posthog-mcp.e2e.mjs   (from packages/mcp, after a build)
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { createServer } from 'http'
import { mkdtempSync } from 'fs'
import { tmpdir } from 'os'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { gunzipSync } from 'zlib'

const here = dirname(fileURLToPath(import.meta.url))
const serverEntry = join(here, '..', 'dist', 'index.js')

let failures = 0
function check(name, cond, detail = '') {
  console.log(`${cond ? '  ✓' : '  ✗'} ${name}${cond ? '' : '  ' + detail}`)
  if (!cond) failures++
}

const posthogBodies = []
const receiver = createServer((req, res) => {
  const chunks = []
  req.on('data', (c) => chunks.push(c))
  req.on('end', () => {
    if (chunks.length) {
      const raw = Buffer.concat(chunks)
      const text = req.headers['content-encoding'] === 'gzip' ? gunzipSync(raw).toString('utf8') : raw.toString('utf8')
      try { posthogBodies.push({ url: req.url, body: JSON.parse(text) }) } catch { posthogBodies.push({ url: req.url, body: text }) }
    }
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ status: 1 }))
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
      WEBABILITY_SCAN_TELEMETRY: 'off',
      WEBABILITY_SCAN_LOG_DIR: mkdtempSync(join(tmpdir(), 'mcp-posthog-e2e-')),
      POSTHOG_PROJECT_API_KEY: 'phc_test_project_key',
      POSTHOG_HOST: `http://127.0.0.1:${port}`,
      POSTHOG_FLUSH_AT: '1',
      POSTHOG_FLUSH_INTERVAL: '100',
      ...env,
    },
  })
  const client = new Client({ name: 'posthog-mcp-e2e', version: '0.0.0' })
  await client.connect(transport)
  try {
    return await fn(client)
  } finally {
    await client.close()
  }
}

const SECRET_HTML = '<div role="bogusrole" aria-label="posthog-secret-html">hi</div>'

await withClient({}, async (client) => {
  await client.listTools()
  await client.callTool({ name: 'check_aria', arguments: { html: SECRET_HTML } })
})
await new Promise((r) => setTimeout(r, 500))

const serialized = JSON.stringify(posthogBodies)
check('PostHog received MCP analytics events', posthogBodies.length > 0, 'no ingestion requests captured')
check('PostHog events include MCP analytics source', serialized.includes('posthog_mcp_analytics'), serialized.slice(0, 1000))
check('PostHog payloads do not include raw HTML', !serialized.includes('posthog-secret-html'))
check('PostHog parameters field is redacted', !serialized.includes('$mcp_parameters'))
check('PostHog response field is redacted', !serialized.includes('$mcp_response'))

posthogBodies.length = 0
await withClient({ WEBABILITY_POSTHOG_MCP_ANALYTICS: 'off' }, async (client) => {
  await client.listTools()
  await client.callTool({ name: 'check_aria', arguments: { html: SECRET_HTML } })
})
await new Promise((r) => setTimeout(r, 500))
check('WEBABILITY_POSTHOG_MCP_ANALYTICS=off sends no PostHog events', posthogBodies.length === 0, JSON.stringify(posthogBodies).slice(0, 300))

receiver.close()

if (failures) {
  console.error(`\n${failures} failure(s)`)
  process.exit(1)
}
console.log('\nALL PASS')
