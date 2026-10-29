/**
 * Hosted SSRF guard at the connection level.
 *
 * installSsrfRoute (context.route) sees the first request of a load only:
 * Playwright follows redirects inside Chromium without calling the route
 * handler again, so a public URL answering 302 -> http://169.254.169.254/
 * used to land a hosted scan on the private page (#198). Every hosted
 * browser context sends its traffic through this local proxy instead. It
 * resolves each destination itself, refuses any private address, and
 * connects to the address it checked, so every hop is covered: redirects,
 * sub-resources, websockets, and DNS answers that change between lookups.
 */
import dnsPromises from 'node:dns/promises'
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from 'node:http'
import { connect, isIP, type AddressInfo, type Socket } from 'node:net'

import { withDeadline } from './deadline.js'

/** True if an IP literal is loopback / private / link-local / cloud-metadata / CGNAT. */
export function isBlockedAddress(addr: string): boolean {
  const a = addr.toLowerCase()
  if (a === '::1' || a === '::' || a.startsWith('fe80') || a.startsWith('fc') || a.startsWith('fd')) return true
  const mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
  const ipv4 = mapped ? mapped[1] : a
  const m = ipv4.match(/^(\d+)\.(\d+)\.\d+\.\d+$/)
  if (m) {
    const o1 = parseInt(m[1], 10)
    const o2 = parseInt(m[2], 10)
    if (o1 === 0 || o1 === 127 || o1 === 10) return true          // this-host / loopback / private
    if (o1 === 169 && o2 === 254) return true                     // link-local + cloud metadata (169.254.169.254)
    if (o1 === 172 && o2 >= 16 && o2 <= 31) return true           // private
    if (o1 === 192 && o2 === 168) return true                     // private
    if (o1 === 100 && o2 >= 64 && o2 <= 127) return true          // CGNAT (often internal)
  }
  return false
}

/** A DNS lookup that hangs would hold a hosted request past the caller's 30s limit. */
const DNS_LOOKUP_DEADLINE_MS = 5_000

/** Playwright `proxy` settings for a hosted context. `<-loopback>` removes
 *  Chromium's built-in proxy bypass for localhost / 127.0.0.1 / [::1], so a
 *  redirect to loopback goes through the check too. */
export interface EgressProxySettings {
  server: string
  bypass: string
}

export interface EgressProxy {
  port: number
  settings: EgressProxySettings
  close(): Promise<void>
}

export interface EgressProxyOptions {
  /** Refuse this destination. Default: isBlockedAddress (the port is ignored). Tests inject a port check. */
  isBlocked?: (address: string, port: number) => boolean
}

class BlockedDestination extends Error {}

/** Resolve `host`, refuse if ANY address is blocked, return the address to connect to. */
async function checkedAddress(rawHost: string, port: number, isBlocked: (address: string, port: number) => boolean): Promise<string> {
  const host = rawHost.replace(/^\[(.*)\]$/, '$1')
  let addrs: string[]
  if (isIP(host)) {
    addrs = [host]
  } else {
    try {
      addrs = (await withDeadline(() => dnsPromises.lookup(host, { all: true }), DNS_LOOKUP_DEADLINE_MS, 'dns lookup')).map((r) => r.address)
    } catch {
      throw new BlockedDestination(`cannot resolve host "${host}"`)
    }
  }
  if (addrs.length === 0) throw new BlockedDestination(`no addresses for "${host}"`)
  for (const a of addrs) if (isBlocked(a, port)) throw new BlockedDestination(`"${host}" resolves to blocked address ${a}`)
  return addrs[0]
}

/** "host:port" / "[v6]:port" from a CONNECT request line. */
function parseAuthority(authority: string): { host: string; port: number } | null {
  const m = authority.match(/^(\[[^\]]+\]|[^:]+):(\d{1,5})$/)
  if (!m) return null
  const port = Number(m[2])
  return port > 0 && port < 65536 ? { host: m[1], port } : null
}

const HOP_BY_HOP = new Set(['proxy-connection', 'proxy-authorization', 'connection', 'keep-alive'])

export function startEgressProxy(opts: EgressProxyOptions = {}): Promise<EgressProxy> {
  const isBlocked = opts.isBlocked ?? ((address: string) => isBlockedAddress(address))
  const sockets = new Set<Socket>()
  const track = (s: Socket) => {
    sockets.add(s)
    s.once('close', () => sockets.delete(s))
  }

  // Plain http:// — Chromium sends the absolute URL as the request target.
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    let target: URL
    try {
      target = new URL(req.url ?? '')
    } catch {
      res.writeHead(400).end()
      return
    }
    if (target.protocol !== 'http:') {
      res.writeHead(400).end()
      return
    }
    const port = Number(target.port || 80)
    let address: string
    try {
      address = await checkedAddress(target.hostname, port, isBlocked)
    } catch {
      res.writeHead(403).end()
      req.resume()
      return
    }
    const headers: Record<string, string | string[]> = {}
    for (const [k, v] of Object.entries(req.headers)) if (v !== undefined && !HOP_BY_HOP.has(k)) headers[k] = v
    const upstream = httpRequest({ host: address, port, method: req.method, path: `${target.pathname}${target.search}`, headers, setHost: false }, (up) => {
      res.writeHead(up.statusCode ?? 502, up.headers)
      up.pipe(res)
    })
    upstream.on('error', () => {
      if (!res.headersSent) res.writeHead(502)
      res.end()
    })
    // The browser went away (tab closed, scan deadline) before the response
    // finished: drop the outbound request too. Without this an origin that
    // sends part of a body and stalls holds the shared proxy's socket forever.
    res.on('close', () => {
      if (!res.writableFinished) upstream.destroy()
    })
    req.pipe(upstream)
  })

  // https:// and ws(s):// — a byte tunnel to the checked address.
  server.on('connect', async (req: IncomingMessage, client: Socket, head: Buffer) => {
    track(client)
    client.on('error', () => client.destroy())
    const dest = parseAuthority(req.url ?? '')
    if (!dest) {
      client.end('HTTP/1.1 400 Bad Request\r\n\r\n')
      return
    }
    let address: string
    try {
      address = await checkedAddress(dest.host, dest.port, isBlocked)
    } catch {
      client.end('HTTP/1.1 403 Forbidden\r\n\r\n')
      return
    }
    let established = false
    const upstream = connect(dest.port, address, () => {
      established = true
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n')
      if (head.length) upstream.write(head)
      upstream.pipe(client)
      client.pipe(upstream)
    })
    track(upstream)
    upstream.on('error', () => {
      if (established) client.destroy()
      else client.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
    })
    // Either side closing tears down the other.
    client.on('close', () => upstream.destroy())
    // end(), not destroy(): bytes the origin sent last may still be queued
    // for the client. The timer covers a client that never closes its side.
    upstream.on('close', () => {
      if (client.destroyed) return
      client.end()
      setTimeout(() => client.destroy(), 5_000).unref()
    })
  })

  server.on('connection', track)

  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      server.unref()
      const port = (server.address() as AddressInfo).port
      resolve({
        port,
        settings: { server: `http://127.0.0.1:${port}`, bypass: '<-loopback>' },
        close: () =>
          new Promise<void>((done) => {
            for (const s of sockets) s.destroy()
            server.close(() => done())
          }),
      })
    })
  })
}
