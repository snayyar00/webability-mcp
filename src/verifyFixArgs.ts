/**
 * verify_fix argument aliases. 22/24 personas in the 2026-10 hill-climb passed
 * the rule / issue / page under another name; the tool ignored it silently and
 * returned an element-wide verdict. Canonical args (url, selector, wcag) always
 * win; an `issue` object (as returned by scan_page) fills in what is missing.
 */

export const VERIFY_FIX_VALID_KEYS = 'url, selector, wcag, viewport, tunnel_secret'

const URL_ALIASES = ['page', 'pageUrl'] as const
/** Every verify_fix arg that carries a URL — the hosted SSRF guard must cover all of them. */
export const VERIFY_FIX_URL_KEYS: readonly string[] = ['url', ...URL_ALIASES]
const SELECTOR_ALIASES = ['element', 'target'] as const
const RULE_ALIASES = ['rule', 'ruleId', 'rule_id', 'criterion', 'id'] as const
// tunnel_secret: the hosted transport adds it to the schema for the localhost-via-tunnel flow.
const KNOWN = new Set<string>(['url', 'selector', 'wcag', 'viewport', 'tunnel_secret', ...URL_ALIASES, ...SELECTOR_ALIASES, ...RULE_ALIASES, 'issue'])

export type VerifyFixArgs = { url?: string; selector?: string; wcag?: string; error?: string }

const nonEmpty = (s: string) => (s.trim() === '' ? undefined : s.trim())

function pickString(a: Record<string, unknown>, keys: readonly string[]): { value?: string; error?: string } {
  for (const k of keys) {
    const v = a[k]
    if (v === undefined || v === null) continue
    if (typeof v !== 'string') return { error: `Error: ${k} must be a string` }
    const t = nonEmpty(v)
    if (t) return { value: t }
  }
  return {}
}

export function resolveVerifyFixArgs(args: Record<string, unknown> | undefined): VerifyFixArgs {
  const a = args ?? {}
  const unknown = Object.keys(a).filter((k) => !KNOWN.has(k))
  if (unknown.length > 0) return { error: `Error: unknown argument '${unknown[0]}' — valid keys: ${VERIFY_FIX_VALID_KEYS}` }

  const url = pickString(a, ['url', ...URL_ALIASES])
  const selector = pickString(a, ['selector', ...SELECTOR_ALIASES])
  const rule = pickString(a, ['wcag', ...RULE_ALIASES])
  for (const r of [url, selector, rule]) if (r.error) return { error: r.error }

  let wcag = rule.value
  let sel = selector.value
  const issue = a.issue
  if (issue !== undefined && issue !== null) {
    if (typeof issue === 'string') {
      if (!wcag) wcag = nonEmpty(issue)
    } else if (typeof issue === 'object' && !Array.isArray(issue)) {
      const o = issue as Record<string, unknown>
      const strOf = (k: string) => (typeof o[k] === 'string' ? nonEmpty(o[k] as string) : undefined)
      if (!wcag) wcag = strOf('type') ?? strOf('ruleId') ?? strOf('rule') ?? strOf('id') ?? strOf('wcag')
      if (!sel) sel = strOf('selector')
    } else return { error: 'Error: issue must be a string or an issue object' }
  }
  return { url: url.value, selector: sel, wcag }
}

/** The URL verify_fix will load: canonical `url`, else the first non-empty alias. Undefined if none or invalid. */
export function verifyFixTargetUrl(args: Record<string, unknown> | undefined): string | undefined {
  const r = pickString(args ?? {}, ['url', ...URL_ALIASES])
  return r.error ? undefined : r.value
}
