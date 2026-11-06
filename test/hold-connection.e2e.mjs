/**
 * Holds one real client connection open past Cloudflare's 125s limit and
 * proves the server still works at the end. Sign-in plus a tool list passes
 * within seconds, so that check cannot see a failure that lands at 125s. That
 * is how a hung GET stream reached Cursor users.
 *
 * Runs against prod with no token and calls only tools/list.
 *
 *   node mcp/test/hold-connection.e2e.mjs
 *   MCP_URL=... HOLD_MS=... node mcp/test/hold-connection.e2e.mjs
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

const url = process.env.MCP_URL || 'https://mcp.webability.io/mcp'
const holdMs = Number(process.env.HOLD_MS || 180_000)

const errors = []
const getStatuses = []
const recordingFetch = async (input, init) => {
  const res = await fetch(input, init)
  if ((init?.method ?? 'GET') === 'GET') getStatuses.push(res.status)
  return res
}

const transport = new StreamableHTTPClientTransport(new URL(url), { fetch: recordingFetch })
const client = new Client({ name: 'webability-hold-check', version: '1' })
client.onerror = (e) => errors.push(e.message)

await client.connect(transport)
const before = (await client.listTools()).tools.length
console.log(`connected to ${url}: ${before} tools, holding ${holdMs}ms`)

await new Promise((r) => setTimeout(r, holdMs))

const after = (await client.listTools()).tools.length
await client.close().catch(() => {})
console.log(`after hold: ${after} tools, GET statuses ${JSON.stringify(getStatuses)}, errors ${JSON.stringify(errors)}`)

const problems = []
if (getStatuses.length === 0) problems.push('the GET stream never answered')
if (getStatuses.some((s) => s !== 200 && s !== 405)) problems.push(`GET answered ${getStatuses.join(', ')}`)
if (errors.length) problems.push(`client errors: ${errors.join('; ')}`)
if (after === 0) problems.push('no tools after the hold')

if (problems.length) {
  console.error(`FAIL: ${problems.join(' | ')}`)
  process.exit(1)
}
console.log('PASS')
process.exit(0)
