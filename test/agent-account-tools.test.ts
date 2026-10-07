/**
 * An AI agent signed in to its own WebAbility account (AgentID, or
 * `webability login`) must finish setup and get a paid plan with no UI:
 * add_site → get_install_snippet → create_upgrade_link (a Stripe Checkout
 * link it hands to its human owner). The webhook on the API activates the
 * plan when the owner pays.
 *
 * Drives the real createServer with fetch stubbed, so this pins exactly what
 * each tool sends to the platform API.
 */
import assert from 'node:assert/strict'
import { afterEach, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

const realFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = realFetch
})

type Call = { url: string; headers: Record<string, string>; body: any }

const SITES = [
  { id: 41, url: 'other.example.org', planTier: 'free', expiredAt: null, status: 'Active' },
  { id: 42, url: 'agent-shop.example.org', planTier: 'trial', expiredAt: '2026-11-06', status: 'Active' },
]

function stubApi(opts: { checkout?: { status: number; body: any }; addSiteError?: string } = {}) {
  const calls: Call[] = []
  globalThis.fetch = (async (input: any, init?: any) => {
    const url = String(input)
    const headers = Object.fromEntries(new Headers(init?.headers).entries())
    const body = init?.body ? JSON.parse(String(init.body)) : undefined
    // Only the account API calls; the MCP's own telemetry beacon is not one.
    if (url.endsWith('/graphql') || url.endsWith('/create-checkout-session')) calls.push({ url, headers, body })
    if (url.endsWith('/graphql')) {
      if (String(body?.query).includes('addSite')) {
        const payload = opts.addSiteError
          ? { errors: [{ message: opts.addSiteError }], data: null }
          : { data: { addSite: 'The site was successfully added.' } }
        return Response.json(payload)
      }
      return Response.json({ data: { getUserSites: { sites: SITES, total: SITES.length } } })
    }
    if (url.endsWith('/create-checkout-session')) {
      const c = opts.checkout ?? { status: 303, body: { url: 'https://checkout.stripe.com/c/pay/cs_test_123' } }
      return Response.json(c.body, { status: c.status })
    }
    return new Response(null, { status: 404 })
  }) as typeof fetch
  return calls
}

async function call(name: string, args: Record<string, unknown>, serverOpts: Record<string, unknown> = { remote: true, authToken: 'agent-jwt' }) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer(serverOpts as any)
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  const res: any = await client.callTool({ name, arguments: args })
  return { text: res.content.map((c: any) => c.text).join('\n'), isError: Boolean(res.isError) }
}

test('the hosted tool list offers the four agent account tools', async () => {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const server = createServer({ remote: true, authToken: 'agent-jwt' })
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(s), client.connect(c)])
  const names = (await client.listTools()).tools.map((t) => t.name)
  for (const n of ['add_site', 'list_sites', 'get_install_snippet', 'create_upgrade_link']) assert.ok(names.includes(n), n)
})

test('every account call sends the caller token and the dashboard Origin', async () => {
  const calls = stubApi()
  await call('add_site', { url: 'https://agent-shop.example.org/' })
  await call('create_upgrade_link', { domain: 'agent-shop.example.org' })
  assert.ok(calls.length >= 4)
  for (const c of calls) {
    assert.equal(c.headers.authorization, 'Bearer agent-jwt', c.url)
    assert.equal(c.headers.origin, 'https://app.webability.io', c.url)
  }
})

test('add_site adds the site, then reports its id, plan and the next steps', async () => {
  const calls = stubApi()
  const { text, isError } = await call('add_site', { url: 'https://agent-shop.example.org/' })
  assert.equal(isError, false)
  const add = calls.find((c) => String(c.body?.query).includes('addSite'))!
  assert.equal(add.body.variables.url, 'https://agent-shop.example.org')
  assert.match(text, /agent-shop\.example\.org/)
  assert.match(text, /\b42\b/)
  assert.match(text, /get_install_snippet/)
  assert.match(text, /create_upgrade_link/)
})

test('add_site passes the API refusal through as a tool error', async () => {
  stubApi({ addSiteError: 'This domain is already registered on WebAbility.' })
  const { text, isError } = await call('add_site', { url: 'taken.example.org' })
  assert.equal(isError, true)
  assert.match(text, /already registered/)
})

test('list_sites shows the plan end as a date when the API sends Unix seconds (prod does)', async () => {
  const { describeSite } = await import('../src/account.ts')
  // Measured on prod 2026-10-07: getUserSites returned expiredAt "1793931301".
  assert.match(describeSite({ id: 1, url: 'a.example.org', planTier: 'trial', expiredAt: '1793931301' }), /until 2026-11-06\b/)
  assert.match(describeSite({ id: 1, url: 'a.example.org', planTier: 'trial', expiredAt: '1793931301000' }), /until 2026-11-06\b/)
  assert.match(describeSite({ id: 1, url: 'a.example.org', planTier: 'trial', expiredAt: '2026-11-06T10:00:00Z' }), /until 2026-11-06\b/)
  assert.doesNotMatch(describeSite({ id: 1, url: 'a.example.org', planTier: 'free', expiredAt: null }), /until/)
  assert.doesNotMatch(describeSite({ id: 1, url: 'a.example.org', planTier: 'free', expiredAt: 'garbage' }), /until|NaN|Invalid/)
})

test('list_sites lists each site with id, plan and trial end', async () => {
  stubApi()
  const { text, isError } = await call('list_sites', {})
  assert.equal(isError, false)
  assert.match(text, /other\.example\.org/)
  assert.match(text, /agent-shop\.example\.org/)
  assert.match(text, /2026-11-06/)
})

test('create_upgrade_link sends the dashboard plan for that site, with a fixed return page and no promo code', async () => {
  const calls = stubApi()
  const { text, isError } = await call('create_upgrade_link', { domain: 'https://www.Agent-Shop.example.org/', billing_interval: 'yearly' })
  assert.equal(isError, false)
  const co = calls.find((c) => c.url.endsWith('/create-checkout-session'))!
  assert.deepEqual(co.body, {
    planName: 'single',
    billingInterval: 'YEARLY',
    domainId: 42,
    domain: 'agent-shop.example.org',
    returnUrl: 'https://www.webability.io/payment-complete',
    cardTrial: false,
  })
  assert.match(text, /https:\/\/checkout\.stripe\.com\/c\/pay\/cs_test_123/)
  assert.match(text, /owner/i)
})

test('create_upgrade_link defaults to monthly and ignores a caller return URL', async () => {
  const calls = stubApi()
  await call('create_upgrade_link', { domain: 'agent-shop.example.org', returnUrl: 'https://evil.example/', return_url: 'https://evil.example/' })
  const co = calls.find((c) => c.url.endsWith('/create-checkout-session'))!
  assert.equal(co.body.billingInterval, 'MONTHLY')
  assert.equal(co.body.returnUrl, 'https://www.webability.io/payment-complete')
})

test('create_upgrade_link for a site not on the account asks for add_site first and never calls checkout', async () => {
  const calls = stubApi()
  const { text, isError } = await call('create_upgrade_link', { domain: 'not-mine.example.org' })
  assert.equal(isError, true)
  assert.match(text, /add_site/)
  assert.equal(calls.some((c) => c.url.endsWith('/create-checkout-session')), false)
})

test('create_upgrade_link reports an API refusal and a response without a link', async () => {
  stubApi({ checkout: { status: 403, body: { error: 'User does not own this domain' } } })
  const refused = await call('create_upgrade_link', { domain: 'agent-shop.example.org' })
  assert.equal(refused.isError, true)
  assert.match(refused.text, /does not own this domain/)

  stubApi({ checkout: { status: 200, body: { success: true, amount: 0 } } })
  const noLink = await call('create_upgrade_link', { domain: 'agent-shop.example.org' })
  assert.equal(noLink.isError, true)
  assert.match(noLink.text, /no checkout link/i)
})

test('get_install_snippet returns the widget tag and needs no account or API call', async () => {
  const calls = stubApi()
  const { text, isError } = await call('get_install_snippet', {}, { remote: true, anonymous: true })
  assert.equal(isError, false)
  assert.match(text, /<script src="https:\/\/enhancer\.webability\.io\/widget\.min\.js"[^>]*defer><\/script>/)
  assert.equal(calls.length, 0)
})

for (const name of ['add_site', 'list_sites', 'create_upgrade_link']) {
  test(`${name} on an anonymous hosted connection returns the sign-in steps, not an API call`, async () => {
    const calls = stubApi()
    const { text, isError } = await call(name, { url: 'a.example.org', domain: 'a.example.org' }, { remote: true, anonymous: true })
    assert.equal(isError, true)
    assert.match(text, /Sign in with AgentID/)
    assert.equal(calls.length, 0)
  })
}

test('a refused account call is logged as ok:false, from isError, not from the text', async () => {
  stubApi()
  const lines: string[] = []
  const realError = console.error
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(' ')) }
  try {
    const { isError } = await call('add_site', { url: '' })
    assert.equal(isError, true)
  } finally {
    console.error = realError
  }
  const entry = lines.map((l) => { try { return JSON.parse(l) } catch { return null } }).find((e) => e?.tool === 'add_site')
  assert.ok(entry, 'no telemetry line for add_site')
  assert.equal(entry.ok, false)
})
