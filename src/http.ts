#!/usr/bin/env node
/**
 * Remote (Streamable HTTP) transport for the WebAbility MCP server.
 *
 * The default entry (index.ts) speaks stdio — for Claude Code / Cursor.
 * This entry exposes the SAME tools over HTTP so the server can be hosted and
 * added as a remote MCP server (e.g. a Lovable "chat connector", which only
 * accepts a remote URL + auth, never a local stdio/npx process).
 *
 * Stateless mode: a fresh server + transport per request, so concurrent clients
 * never share request state. Auth is an optional bearer token (MCP_AUTH_TOKEN).
 */
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'http'
import { timingSafeEqual } from 'crypto'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { createServer } from './server.js'

const PORT = Number(process.env.PORT || 8080)
const MCP_PATH = '/mcp'

// Fail closed: a public, browser-launching endpoint must never run unauthenticated.
const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN
if (!AUTH_TOKEN || AUTH_TOKEN.length < 32) {
  console.error('[mcp-http] FATAL: MCP_AUTH_TOKEN missing or shorter than 32 chars — refusing to start.')
  process.exit(1)
}
const TOKEN: string = AUTH_TOKEN

/** Constant-time bearer check (avoids leaking token length/prefix via timing). */
function isAuthorized(req: IncomingMessage): boolean {
  const provided = (req.headers.authorization || '').replace(/^Bearer\s+/i, '')
  const a = Buffer.from(provided)
  const b = Buffer.from(TOKEN)
  return a.length === b.length && timingSafeEqual(a, b)
}

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(body))
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(chunk as Buffer)
  if (chunks.length === 0) return undefined
  const raw = Buffer.concat(chunks).toString('utf8')
  return raw ? JSON.parse(raw) : undefined
}

const httpServer = createHttpServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`)

  // CORS preflight — Lovable connects server-side, but stay permissive + safe.
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, Mcp-Session-Id, Mcp-Protocol-Version',
    })
    res.end()
    return
  }

  if (url.pathname === '/health') {
    sendJson(res, 200, { ok: true, service: 'webability-mcp', transport: 'streamable-http' })
    return
  }

  if (url.pathname !== MCP_PATH) {
    sendJson(res, 404, { error: 'not_found' })
    return
  }

  // Bearer auth — always enforced (server refuses to start without a token).
  if (!isAuthorized(req)) {
    sendJson(res, 401, { jsonrpc: '2.0', error: { code: -32001, message: 'Unauthorized' }, id: null })
    return
  }

  try {
    const body = req.method === 'POST' ? await readJsonBody(req) : undefined
    const server = createServer({ remote: true })
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined })
    res.on('close', () => {
      transport.close().catch(() => {})
      server.close().catch(() => {})
    })
    await server.connect(transport)
    await transport.handleRequest(req, res, body)
  } catch (err) {
    console.error('[mcp-http] request error:', err)
    if (!res.headersSent) {
      sendJson(res, 500, { jsonrpc: '2.0', error: { code: -32603, message: 'Internal server error' }, id: null })
    }
  }
})

httpServer.listen(PORT, () => {
  console.error(`WebAbility MCP (Streamable HTTP) listening on :${PORT}${MCP_PATH}`)
})
