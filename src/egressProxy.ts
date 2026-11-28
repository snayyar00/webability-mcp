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

/** Strip the brackets WHATWG URL keeps on an IPv6 hostname (`[::1]` -> `::1`). */
export function normalizeHost(host: string): string {
  const bracketed = host.match(/^\[(.+)\]$/)
  return (bracketed ? bracketed[1] : host).toLowerCase()
}

/** What a destination address is, for the two classifiers that act on it. */
type AddressClass = 'loopback' | 'private' | 'link-local' | 'metadata' | 'cgnat' | 'reserved' | 'other'

/** 8 groups of an IPv6 literal, or null when it does not parse. Accepts a trailing dotted quad. */
function ipv6Groups(addr: string): number[] | null {
  let text = addr
  const dotted = addr.match(/^(.+):(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (dotted) {
    const octets = [dotted[2], dotted[3], dotted[4], dotted[5]].map(Number)
    if (octets.some((o) => o > 255)) return null
    text = `${dotted[1]}:${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`
  }
  const halves = text.split('::')
  if (halves.length > 2) return null
  const parts = halves.map((h) => (h === '' ? [] : h.split(':')))
  const fill = 8 - parts[0].length - (parts[1]?.length ?? 0)
  // `::` compresses at least one group; without it the literal must be exactly 8.
  if (halves.length === 2 ? fill < 1 : fill !== 0) return null
  const groups: number[] = []
  for (const g of [...parts[0], ...Array<string>(fill).fill('0'), ...(parts[1] ?? [])]) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null
    groups.push(parseInt(g, 16))
  }
  return groups
}

/** IPv4 bytes carried inside IPv4-mapped (`::ffff:0:0/96`) or NAT64 (`64:ff9b::/96`) form. */
function embeddedIpv4(g: number[]): number[] | null {
  const mapped = g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff
  const nat64 = g[0] === 0x64 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0
  if (!mapped && !nat64) return null
  return [g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255]
}

function classifyIpv4([o1, o2, o3]: number[]): AddressClass {
  if (o1 === 0 || o1 === 127) return 'loopback'                 // this-host / loopback
  if (o1 === 10) return 'private'
  if (o1 === 172 && o2 >= 16 && o2 <= 31) return 'private'
  if (o1 === 192 && o2 === 168) return 'private'
  if (o1 === 169 && o2 === 254) return 'metadata'               // link-local + cloud metadata (169.254.169.254)
  if (o1 === 100 && o2 >= 64 && o2 <= 127) return 'cgnat'       // CGNAT (often internal)
  if (o1 === 192 && o2 === 0 && o3 === 0) return 'reserved'     // 192.0.0.0/24 (IETF protocol assignments)
  if (o1 === 198 && (o2 === 18 || o2 === 19)) return 'reserved' // 198.18.0.0/15 (benchmarking)
  if (o1 >= 240) return 'reserved'                              // 240.0.0.0/4 + broadcast
  return 'other'
}

/** Classify an IP literal. One classifier for the guard, the proxy and the message. */
export function classifyAddress(addr: string): AddressClass {
  const a = normalizeHost(addr)
  const version = isIP(a)
  if (version === 4) return classifyIpv4(a.split('.').map(Number))
  const g = version === 6 ? ipv6Groups(a) : null
  if (!g) return 'other'
  if (g.every((x) => x === 0)) return 'loopback'                                   // `::`
  if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return 'loopback'         // `::1`
  const inner = embeddedIpv4(g)
  if (inner) return classifyIpv4(inner)
  if ((g[0] & 0xfe00) === 0xfc00) return 'private'                                 // fc00::/7 unique-local
  if (g[0] >= 0xfe80 && g[0] <= 0xfeff) return 'link-local'                        // fe80::/10 + deprecated fec0::/10 site-local
  if ((g[0] & 0xff00) === 0xff00) return 'reserved'                                // ff00::/8 multicast
  return 'other'
}

/** True if an IP literal is loopback / private / link-local / cloud-metadata / CGNAT / reserved.
 *  Accepts a bracketed literal (`[::1]`) and both IPv4-mapped IPv6 forms. */
export function isBlockedAddress(addr: string): boolean {
  return classifyAddress(addr) !== 'other'
}

/** The ports a hosted scan may reach. Without this the proxy is a general TCP
 *  relay: any token holder could reach SMTP, Redis, Postgres or MySQL. */
export const ALLOWED_PORTS: ReadonlySet<number> = new Set([80, 443, 8080, 8443])

/** Default proxy check: a blocked address, or a port a browser has no business on. */
export function isBlockedDestination(address: string, port: number): boolean {
  return isBlockedAddress(address) || !ALLOWED_PORTS.has(port)
}

/** A DNS lookup that hangs would hold a hosted request past the caller's deadline. */
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
  /** Refuse this destination. Default: isBlockedDestination (address + web-port allowlist). Tests inject their own. */
  isBlocked?: (address: string, port: number) => boolean
}

class BlockedDestination extends Error {}

/** Resolve `host`, refuse if ANY address is blocked, return the address to connect to. */
async function checkedAddress(rawHost: string, port: number, isBlocked: (address: string, port: number) => boolean): Promise<string> {
  const host = normalizeHost(rawHost)
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
  const isBlocked = opts.isBlocked ?? isBlockedDestination
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
