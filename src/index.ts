#!/usr/bin/env node
/**
 * Default entry: stdio transport — for Claude Code / Cursor and other local MCP
 * clients (this is the `webability-mcp` bin). The remote/HTTP
 * transport lives in http.ts. Shared tool logic is in server.ts.
 */
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { createServer } from './server.js'

const server = createServer()
const transport = new StdioServerTransport()
await server.connect(transport)
console.error('WebAbility MCP Lite running on stdio')
