/**
 * Account tools for an agent signed in to its own WebAbility account (AgentID
 * on the sign-in page, or `webability login`): add a site, list sites, get the
 * widget tag, and get a Stripe Checkout link for its human owner to pay.
 *
 * Every call uses the same routes the dashboard uses, with the caller's own
 * token. Those routes resolve the organization from the Origin header, so a
 * server-side call must send the dashboard origin. When the owner pays, the
 * API's checkout.session.completed webhook activates the plan on the site.
 */

export const DASHBOARD_ORIGIN = (process.env.WEBABILITY_DASHBOARD_URL || 'https://app.webability.io').replace(/\/+$/, '')

/** The dashboard's only self-serve plan (`VITE_PLAN_NAME` on the dashboard, `products.type` in the API). */
export const UPGRADE_PLAN_NAME = 'single'

/** Where the owner lands after paying. Fixed on purpose: a caller-chosen URL would make the link an open redirect. */
export const UPGRADE_RETURN_URL = 'https://www.webability.io/payment-complete'

/** Same tag the dashboard's Install tab builds with its defaults. The widget keys off the page's domain, so it carries no site id. */
export const INSTALL_SNIPPET =
  '<script src="https://enhancer.webability.io/widget.min.js" data-asw-position="bottom-left-x-20-y-20" data-asw-lang="en" data-asw-icon-type="m-full" defer></script>'

export interface AccountSite {
  id: number
  url: string
  planTier?: string | null
  expiredAt?: string | null
  status?: string | null
}

export class AccountError extends Error {}

/** `https://www.Shop.example/` → `shop.example`, the form the API stores. */
export function normalizeDomain(input: string): string {
  return input
    .trim()
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
    .replace(/[/?#].*$/, '')
    .replace(/^www\./, '')
}

function headers(token: string): Record<string, string> {
  return { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, Origin: DASHBOARD_ORIGIN }
}

async function graphql<T>(apiUrl: string, token: string, query: string, variables: Record<string, unknown>): Promise<T> {
  const res = await fetch(`${apiUrl}/graphql`, { method: 'POST', headers: headers(token), body: JSON.stringify({ query, variables }) })
  if (res.status === 401 || res.status === 403) {
    throw new AccountError(`WebAbility could not authenticate this account (${res.status}). Sign in again, then retry.`)
  }
  const payload = (await res.json().catch(() => null)) as { data?: T; errors?: Array<{ message?: string }> } | null
  const message = payload?.errors?.[0]?.message
  if (message) throw new AccountError(message)
  if (!res.ok || !payload?.data) throw new AccountError(`WebAbility API error (${res.status}).`)
  return payload.data
}

export async function listSites(apiUrl: string, token: string): Promise<AccountSite[]> {
  const data = await graphql<{ getUserSites: { sites: AccountSite[] } }>(
    apiUrl,
    token,
    // No limit: the API then returns every site, so a site past page one is still found.
    'query AgentSites { getUserSites { sites { id url planTier expiredAt status } total } }',
    {},
  )
  return (data.getUserSites?.sites ?? []).filter((s): s is AccountSite => Boolean(s && s.url))
}

export function findSite(sites: AccountSite[], domain: string): AccountSite | undefined {
  const want = normalizeDomain(domain)
  return sites.find((s) => normalizeDomain(s.url) === want)
}

export async function addSite(apiUrl: string, token: string, url: string): Promise<AccountSite | undefined> {
  const clean = url.trim().replace(/\/+$/, '')
  await graphql<{ addSite: string }>(apiUrl, token, 'mutation AgentAddSite($url: String!) { addSite(url: $url) }', { url: clean })
  return findSite(await listSites(apiUrl, token), clean)
}

export async function createUpgradeLink(
  apiUrl: string,
  token: string,
  site: AccountSite,
  interval: 'MONTHLY' | 'YEARLY',
): Promise<string> {
  const res = await fetch(`${apiUrl}/create-checkout-session`, {
    method: 'POST',
    headers: headers(token),
    // No promoCode: the API turns a numeric or AppSumo code into a $0
    // subscription with no link. No cardTrial: the site already has its
    // 30-day trial from add_site.
    body: JSON.stringify({
      planName: UPGRADE_PLAN_NAME,
      billingInterval: interval,
      domainId: site.id,
      domain: site.url,
      returnUrl: UPGRADE_RETURN_URL,
      cardTrial: false,
    }),
    redirect: 'manual',
  })
  const body = (await res.json().catch(() => null)) as { url?: string; error?: string } | null
  if (res.status === 401) throw new AccountError('WebAbility could not authenticate this account (401). Sign in again, then retry.')
  if (body?.error) throw new AccountError(body.error)
  if (!res.ok && res.status !== 303) throw new AccountError(`WebAbility checkout failed (${res.status}).`)
  if (!body?.url) throw new AccountError('WebAbility returned no checkout link for this site. Open the dashboard (Sites → the site → Plan) to change its plan.')
  return body.url
}

/** The API sends expiredAt as Unix seconds in a string (measured on prod); accept ms and ISO too. */
export function planEndDate(raw: string | null | undefined): string | null {
  if (raw === null || raw === undefined || raw === '') return null
  const text = String(raw).trim()
  const n = Number(text)
  const ms = /^\d+$/.test(text) ? (n < 1e12 ? n * 1000 : n) : Date.parse(text)
  if (!Number.isFinite(ms)) return null
  return new Date(ms).toISOString().slice(0, 10)
}

export function describeSite(s: AccountSite): string {
  const plan = s.planTier || 'unknown'
  const end = planEndDate(s.expiredAt)
  const until = end ? `, until ${end}` : ''
  return `- ${s.url} (site id ${s.id}): plan ${plan}${until}${s.status ? `, ${s.status}` : ''}`
}
