/** Shared localhost fixture for honest-counts / filtered-headline tests: 11 issues, 6 missing_alt collapse into one entry. */
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
process.env.WEBABILITY_SCAN_LOG = 'off'

import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

const imgs = Array.from({ length: 6 }, (_, i) => `<img src="/p${i}.png" width="40" height="40">`).join('\n')
const PAGE = `<!doctype html><html lang="en"><head><title>Counts</title></head><body><main><h1>Counts</h1>${imgs}<button class="a"></button><button class="b"></button><p style="color:#bbb">low contrast</p></main></body></html>`

export type ScanText = { headline: string; body: string; json: any }

export async function startCountsFixture(): Promise<{ url: string; close: () => void; scanPage: (extra: Record<string, unknown>) => Promise<ScanText> }> {
  const http: HttpServer = createHttpServer((_, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(PAGE) })
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', () => r()))
  const url = `http://127.0.0.1:${(http.address() as any).port}/`
  const scanPage = async (extra: Record<string, unknown>): Promise<ScanText> => {
    const [c, s] = InMemoryTransport.createLinkedPair()
    const server = createServer({})
    const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
    await Promise.all([server.connect(s), client.connect(c)])
    const r: any = await client.callTool({ name: 'scan_page', arguments: { url, ...extra } }, undefined, { timeout: 180_000 })
    const texts = (r.content as any[]).map((x) => String(x.text ?? ''))
    const m = texts.join('\n').match(/```json\n([\s\S]*?)\n```/)
    return { headline: texts[0]!, body: texts.slice(1).join('\n'), json: m ? JSON.parse(m[1]!) : null }
  }
  return { url, close: () => http.close(), scanPage }
}

export const headingCounts = (body: string) => [...body.matchAll(/^## Issues \((\d+)/gm)].map((m) => Number(m[1]))
