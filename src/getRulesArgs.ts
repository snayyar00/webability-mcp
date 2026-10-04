/**
 * get_rules argument aliases. Every persona in the 2026-10 hill-climb guessed
 * wrong arg names (wcag / level / criterion / rule / ruleId / category /
 * filter / query). Map the common guesses onto the canonical args; canonical
 * always wins; anything else is an error naming the valid keys.
 */

export const GET_RULES_CANONICAL = ['tags', 'rule', 'fixability', 'engine'] as const
const TAG_ALIASES = ['tag', 'category', 'filter', 'wcag', 'level', 'criterion'] as const
const RULE_ALIASES = ['ruleId', 'rule_id', 'id', 'query'] as const
const KNOWN = new Set<string>([...GET_RULES_CANONICAL, ...TAG_ALIASES, ...RULE_ALIASES])

export const GET_RULES_VALID_KEYS = 'tags, rule, fixability, engine'

export const normRuleId = (s: string) => s.trim().toLowerCase().replace(/-/g, '_')

/** `expanded`: tags derived from level / wcag / criterion — tags the caller did not type. */
export type GetRulesArgs = { tags?: string[]; rule?: string; error?: string; expanded?: boolean }

const asList = (k: string, v: unknown): string[] | string => {
  if (typeof v === 'string') return [v]
  if (Array.isArray(v) && v.every((x) => typeof x === 'string')) return v as string[]
  return `Error: ${k} must be a string or an array of strings`
}

// "1.4.3" -> wcag143, "AA" -> wcag2aa/wcag21aa/wcag22aa, other values pass through lowercased.
function toTags(k: string, raw: string): string[] | string {
  const v = raw.trim()
  if (/^\d+\.\d+\.\d+$/.test(v)) return ['wcag' + v.replace(/\./g, '')]
  const l = v.toLowerCase()
  if ((k === 'level' || k === 'wcag' || k === 'criterion') && (l === 'a' || l === 'aa' || l === 'aaa')) {
    return [`wcag2${l}`, `wcag21${l}`, `wcag22${l}`]
  }
  if (k === 'level') return 'Error: level must be one of A | AA | AAA'
  return [v.toLowerCase()]
}

export function resolveGetRulesArgs(args: Record<string, unknown> | undefined): GetRulesArgs {
  const a = args ?? {}
  const unknown = Object.keys(a).filter((k) => !KNOWN.has(k))
  if (unknown.length > 0) return { error: `Error: unknown argument '${unknown[0]}' — valid keys: ${GET_RULES_VALID_KEYS}` }

  let tags = a.tags as string[] | undefined // canonical: validated by the caller
  let expanded = false
  if (tags === undefined) {
    for (const k of TAG_ALIASES) {
      const v = a[k]
      if (v === undefined || v === null) continue
      if (k === 'level' || k === 'wcag' || k === 'criterion') {
        if (typeof v !== 'string') return { error: `Error: ${k} must be a string` }
      }
      const list = asList(k, v)
      if (typeof list === 'string') return { error: list }
      const out: string[] = []
      for (const item of list) {
        if (item.trim() === '') continue
        const t = toTags(k, item)
        if (typeof t === 'string') return { error: t }
        out.push(...t)
      }
      if (out.length > 0) { tags = out; expanded = k === 'level' || k === 'wcag' || k === 'criterion'; break }
    }
  }

  let rule = a.rule as unknown
  if (rule === undefined) {
    for (const k of RULE_ALIASES) {
      if (a[k] !== undefined && a[k] !== null) { rule = a[k]; if (typeof rule !== 'string') return { error: `Error: ${k} must be a string` }; break }
    }
  } else if (typeof rule !== 'string') return { error: 'Error: rule must be a string' }
  const ruleStr = typeof rule === 'string' && rule.trim() !== '' ? normRuleId(rule) : undefined

  return { tags, rule: ruleStr, ...(expanded ? { expanded } : {}) }
}

/**
 * Word match on a rule id: the query's words appear in the id as consecutive
 * whole words (split on - and _), a trailing "s" tolerated either way.
 * "link" matches link-name and identical-links-same-purpose, never blink
 * (persona round 4: substring matching listed blink for "link").
 */
export function ruleIdMatches(ruleId: string, query: string): boolean {
  const words = normRuleId(ruleId).split('_').filter(Boolean)
  const want = normRuleId(query).split('_').filter(Boolean)
  if (want.length === 0 || want.length > words.length) return false
  const same = (a: string, b: string) => a === b || a === `${b}s` || `${a}s` === b
  for (let i = 0; i + want.length <= words.length; i++) {
    if (want.every((w, j) => same(words[i + j]!, w))) return true
  }
  return false
}
