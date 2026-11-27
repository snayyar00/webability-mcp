import dnsPromises from 'node:dns/promises'
import { isIP } from 'node:net'
import { withDeadline } from './deadline.js'
import { isBlockedAddress } from './egressProxy.js'

export function schemeForBareUrl(raw: string): 'http' | 'https' {
  const authority = raw.split(/[/?#]/, 1)[0].toLowerCase()
  const host = authority.replace(/:\d+$/, '')
  return host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0' || host === '[::1]' || host.endsWith('.localhost')
    ? 'http'
    : 'https'
}

/** Bare domains ("webability.io") get https://, a bare local host gets http://
 *  (a dev server speaks plain HTTP). Anything that already names a scheme
 *  (http:example.com, file://, javascript:) is left alone, so the SSRF guard still judges
 *  and refuses it. "host:8080" is a port, not a scheme. Blank stays blank, so verify_fix
 *  can fall through from an empty `url` to its `pageUrl` alias. */
export function normalizeUrlArg(raw: string): string {
  const u = raw.trim()
  if (!u) return ''
  return /^[a-z][a-z0-9+.-]*:(?!\d)/i.test(u) ? u : `${schemeForBareUrl(u)}://${u}`
}

/** A DNS lookup that hangs would hold a hosted request past the caller's deadline. */
const DNS_LOOKUP_DEADLINE_MS = 5_000

/** SSRF guard: only http(s) to public, externally-resolvable addresses.
 *  Checks one URL. Redirect hops never reach a route handler, so hosted
 *  contexts also send every connection through the egress proxy
 *  (egressProxy.ts, wired in browser.ts openSession), which checks each hop. */
export async function assertSafeUrl(raw: string): Promise<void> {
  let u: URL
  try {
    u = new URL(raw)
  } catch {
    throw new Error(`invalid URL "${raw}"`)
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error(`scheme "${u.protocol}" not allowed`)
  let addrs: string[]
  const host = u.hostname.replace(/^\[|\]$/g, '')
  if (isIP(host)) {
    addrs = [host]
  } else {
    try {
      addrs = (await withDeadline(() => dnsPromises.lookup(u.hostname, { all: true }), DNS_LOOKUP_DEADLINE_MS, 'dns lookup')).map((r) => r.address)
    } catch {
      throw new Error(`cannot resolve host "${u.hostname}"`)
    }
  }
  if (addrs.length === 0) throw new Error(`no addresses for "${u.hostname}"`)
  for (const a of addrs) if (isBlockedAddress(a)) throw new Error(`"${u.hostname}" resolves to blocked internal address ${a}`)
}
