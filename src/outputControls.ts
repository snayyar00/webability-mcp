/**
 * Output controls shared by scan_page / flow_scan / scan_html / diff_scan
 * (DEV-1089 item 5). Token cost is what a coding agent is judged on, so every
 * scan tool takes:
 *
 *   minImpact   'critical' | 'serious' | 'moderate' | 'minor' — keep this level and above
 *   rules[]     allow-list of rule ids (WebAbility type or axe rule id)
 *   wcag[]      allow-list of criteria; a prefix selects the guideline ("1.4") or principle ("1")
 *   format      'json' (default) | 'compact' — one line per element, rule metadata printed once
 */

export type Impact = 'critical' | 'serious' | 'moderate' | 'minor'
const IMPACTS: Impact[] = ['critical', 'serious', 'moderate', 'minor']
const RANK: Record<string, number> = { critical: 4, serious: 3, moderate: 2, minor: 1 }

export interface OutputControls {
  minImpact?: Impact
  rules?: Set<string>
  wcag?: Set<string>
  format: 'json' | 'compact'
}

/** JSON-schema fragment every scan tool spreads into its `properties`. */
export const OUTPUT_CONTROL_PROPERTIES = {
  minImpact: { type: 'string', enum: IMPACTS, description: 'Only findings at this severity or above (critical > serious > moderate > minor)' },
  rules: { type: 'array', items: { type: 'string' }, description: 'Only these rule ids (WebAbility type such as "missing_alt" or axe rule id such as "image-alt"). See get_rules.' },
  wcag: { type: 'array', items: { type: 'string' }, description: 'Only these WCAG criteria. A prefix selects the whole guideline ("1.4") or principle ("2").' },
  format: { type: 'string', enum: ['json', 'compact'], description: '"compact" prints one line per element with rule metadata once — far fewer tokens than the default JSON. Default json.' },
} as const

export function parseOutputControls(args: Record<string, unknown> | undefined): OutputControls {
  const a = args ?? {}
  const minImpact = a.minImpact as string | undefined
  if (minImpact !== undefined && !(minImpact in RANK)) throw new Error(`minImpact must be one of ${IMPACTS.join(' | ')}`)
  const format = (a.format as string | undefined) ?? 'json'
  if (format !== 'json' && format !== 'compact') throw new Error('format must be "json" or "compact"')
  const list = (v: unknown) => (Array.isArray(v) && v.length ? new Set(v.map((x) => String(x).trim()).filter(Boolean)) : undefined)
  return { ...(minImpact ? { minImpact: minImpact as Impact } : {}), rules: list(a.rules), wcag: list(a.wcag), format }
}

export interface IssueRow {
  id?: string
  type?: string
  wcag?: string
  impact?: string
  message?: string
  selector?: string
  html?: string
  fixability?: string
  fix?: { op?: string; attribute?: string; value?: string }
  source?: { file?: string; line?: number; column?: number; component?: string }
  foundOn?: string[]
  /** Every rule id merged into this finding (see scanShaping.mergeSameElement). */
  rules?: string[]
  /** Set on a collapsed entry: how many elements it stands for. */
  count?: number
  examples?: string[]
  expand?: string
}

const matchesWcag = (criteria: string | undefined, wanted: Set<string>) => {
  if (!criteria) return false
  // An issue may carry several criteria ("2.4.4,4.1.2" from axe's tag list);
  // it matches when ANY of them does.
  for (const criterion of criteria.split(/[,\s]+/).filter(Boolean)) {
    for (const w of wanted) {
      if (criterion === w) return true
      // Prefix must end on a dot boundary: "1.4" matches 1.4.3 and 1.4.11, never "1.4.1" → 1.4.11.
      if (criterion.startsWith(w + '.')) return true
    }
  }
  return false
}

export function filterIssues<T extends IssueRow>(list: readonly T[], c: OutputControls): T[] {
  return list.filter((i) => {
    if (c.minImpact && (RANK[i.impact ?? ''] ?? 0) < RANK[c.minImpact]) return false
    if (c.rules && !c.rules.has(String(i.type ?? '')) && !(i.rules ?? []).some((r) => c.rules!.has(r))) return false
    if (c.wcag && !matchesWcag(i.wcag, c.wcag)) return false
    return true
  })
}

/** True when any control narrows the list — used to label filtered totals. */
export const isFiltered = (c: OutputControls) => Boolean(c.minImpact || c.rules || c.wcag)

export function describeControls(c: OutputControls): string {
  const parts = [c.minImpact ? `minImpact=${c.minImpact}` : '', c.rules ? `rules=[${[...c.rules].join(',')}]` : '', c.wcag ? `wcag=[${[...c.wcag].join(',')}]` : ''].filter(Boolean)
  return parts.length ? ` (filtered: ${parts.join(' ')})` : ''
}

function formatOp(i: IssueRow): string {
  const f = i.fix
  if (!f?.op) return ''
  const attr = f.attribute ? ` ${f.attribute}` : ''
  const val = f.value !== undefined ? `="${String(f.value).replace(/"/g, '\\"').slice(0, 80)}"` : ''
  return `${f.op}${attr}${val}`
}

/**
 * One header per rule (id · wcag · impact · fixability · op · message), then
 * one indented line per element (selector, → source pointer when known,
 * @ pages for flow_scan). Sorted by severity, then rule id.
 */
export function compactText(list: readonly IssueRow[]): string {
  if (list.length === 0) return '(no findings)'
  const groups = new Map<string, IssueRow[]>()
  for (const i of list) {
    const k = String(i.type ?? i.id ?? '?')
    if (!groups.has(k)) groups.set(k, [])
    groups.get(k)!.push(i)
  }
  const ordered = [...groups.entries()].sort((a, b) => (RANK[b[1][0]!.impact ?? ''] ?? 0) - (RANK[a[1][0]!.impact ?? ''] ?? 0) || a[0].localeCompare(b[0]))
  const out: string[] = []
  for (const [rule, items] of ordered) {
    const h = items[0]!
    const meta = [h.wcag, h.impact, h.fixability, formatOp(h)].filter(Boolean).join(' · ')
    const instances = items.reduce((n, i) => n + (i.count ?? 1), 0)
    out.push(`${rule} ×${instances} — ${meta}${h.message ? ` — ${h.message}` : ''}`)
    for (const i of items) {
      const src = i.source && typeof i.source === 'object' ? ` → ${formatSourceInline(i.source)}` : ''
      const pages = i.foundOn?.length ? ` @ ${i.foundOn.join(', ')}` : ''
      if (i.count && i.examples) {
        for (const sel of i.examples) out.push(`  ${sel}${pages}`)
        if (i.count > i.examples.length) out.push(`  … +${i.count - i.examples.length} more — ${i.expand ?? `pass rules: ["${rule}"] to list every one`}`)
        continue
      }
      out.push(`  ${i.selector ?? '?'}${src}${pages}`)
    }
  }
  return out.join('\n')
}

function formatSourceInline(s: NonNullable<IssueRow['source']>): string {
  const loc = s.file ? `${s.file}${s.line !== undefined ? `:${s.line}` : ''}${s.line !== undefined && s.column !== undefined ? `:${s.column}` : ''}` : ''
  const comp = s.component ? `(${s.component})` : ''
  return [loc, comp].filter(Boolean).join(' ')
}
