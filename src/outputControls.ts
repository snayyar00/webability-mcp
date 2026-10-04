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
  /** True when the caller passed `format`; false when 'json' is the default. */
  formatExplicit?: boolean
}

/** JSON-schema fragment every scan tool spreads into its `properties`. */
export const OUTPUT_CONTROL_PROPERTIES = {
  minImpact: { type: 'string', enum: IMPACTS, description: 'Only findings at this severity or above (critical > serious > moderate > minor)' },
  rules: { type: 'array', items: { type: 'string' }, description: 'Only these rule ids (WebAbility type such as "missing_alt" or axe rule id such as "image-alt"). See get_rules.' },
  wcag: { type: 'array', items: { type: 'string' }, description: 'Only these WCAG criteria. A prefix selects the whole guideline ("1.4") or principle ("2").' },
  format: { type: 'string', enum: ['json', 'compact'], description: '"compact" prints one line per element with rule metadata once. "json" returns every field (html, fix values, source). Default: JSON when it fits inline (under ~24k chars), otherwise compact plus a JSON summary of every count.' },
} as const

export function parseOutputControls(args: Record<string, unknown> | undefined): OutputControls {
  const a = args ?? {}
  const minImpact = a.minImpact as string | undefined
  if (minImpact !== undefined && !(minImpact in RANK)) throw new Error(`minImpact must be one of ${IMPACTS.join(' | ')}`)
  const formatExplicit = a.format !== undefined && a.format !== null
  const format = (a.format as string | undefined) ?? 'json'
  if (format !== 'json' && format !== 'compact') throw new Error('format must be "json" or "compact"')
  const list = (v: unknown) => (Array.isArray(v) && v.length ? new Set(v.map((x) => String(x).trim()).filter(Boolean)) : undefined)
  return { ...(minImpact ? { minImpact: minImpact as Impact } : {}), rules: list(a.rules), wcag: list(a.wcag), format, formatExplicit }
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

/** The active filters as "minImpact=serious rules=[a,b]" ('' when none). */
export function controlsList(c: OutputControls): string {
  return [c.minImpact ? `minImpact=${c.minImpact}` : '', c.rules ? `rules=[${[...c.rules].join(',')}]` : '', c.wcag ? `wcag=[${[...c.wcag].join(',')}]` : ''].filter(Boolean).join(' ')
}

export function describeControls(c: OutputControls): string {
  const list = controlsList(c)
  return list ? ` (filtered: ${list})` : ''
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

/**
 * Inline budget for a scan response. MCP clients spill larger tool results to
 * a file (allbirds.com: 107,921 chars, MCP dogfood 2026-10-03), which loses
 * the answer for the very first "is my page accessible?" call.
 */
export const INLINE_BUDGET = 24_000

const LIST_KEYS = new Set(['issues', 'incomplete', 'new', 'fixed', 'remaining'])

/** Elements per rule id over a list (a collapsed entry counts its `count`). */
export function countByRule(list: readonly IssueRow[]): Record<string, number> {
  const out: Record<string, number> = {}
  for (const i of list) {
    const k = String(i.type ?? i.id ?? '?')
    out[k] = (out[k] ?? 0) + (i.count ?? 1)
  }
  return out
}

/**
 * The findings block of a scan response.
 *  - format "json" (explicit) → the full JSON payload, any size.
 *  - format "compact" (explicit) → the compact listing.
 *  - no format → the JSON payload when it fits INLINE_BUDGET; otherwise the
 *    compact listing plus a JSON summary block (every count, per-rule counts
 *    over the full filtered lists) and one line saying how to get the JSON.
 */
/**
 * A compact-listing section with its counts. `total` (elements) leads, so the
 * heading never shows an entry count where a reader expects the issue count
 * (persona round 4: "## Issues (34)" under "Found 67 issues").
 */
export type CompactList = { title: string; items: readonly IssueRow[]; total?: number; entries?: number; noun?: [string, string] }

export function compactHeading(l: CompactList): string {
  const shown = l.items.length
  if (l.total === undefined) return `## ${l.title} (${shown})`
  const entries = l.entries ?? shown
  const [one, many] = l.noun ?? ['issue', 'issues']
  const parts: string[] = []
  if (entries < l.total) parts.push(`grouped into ${entries} entries`)
  if (shown < entries) parts.push(`${shown} shown`)
  if (parts.length === 0) return `## ${l.title} (${l.total})`
  return `## ${l.title} (${l.total} ${l.total === 1 ? one : many}, ${parts.join('; ')})`
}

export function renderFindingsBlock(
  controls: OutputControls,
  payload: Record<string, unknown>,
  compactLists: CompactList[],
  fullLists?: { issues: readonly IssueRow[]; incomplete?: readonly IssueRow[] },
): { type: 'text'; text: string } {
  const sections = () => compactLists.map((l) => `${compactHeading(l)}\n${compactText(l.items)}`).join('\n\n')
  if (controls.format === 'compact') return { type: 'text', text: sections() }
  const json = '```json\n' + JSON.stringify(payload, null, 2) + '\n```'
  if (controls.formatExplicit || json.length <= INLINE_BUDGET) return { type: 'text', text: json }

  const summary: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(payload)) if (!LIST_KEYS.has(k)) summary[k] = v
  if (fullLists) {
    summary.byRule = countByRule(fullLists.issues)
    if (fullLists.incomplete) summary.incompleteByRule = countByRule(fullLists.incomplete)
  }
  const head =
    `Output: compact — the full JSON is ${json.length.toLocaleString('en-US')} chars, over the inline budget of ${INLINE_BUDGET.toLocaleString('en-US')}. ` +
    'Pass format: "json" for every field (html, fix values, source pointers), or narrow with rules / wcag / minImpact / rootSelector. Counts below cover every finding.'
  const summaryBlock = '```json\n' + JSON.stringify(summary, null, 2) + '\n```'
  let body = sections()
  // Hard ceiling: never let the compact listing itself overflow the budget.
  const room = INLINE_BUDGET - head.length - summaryBlock.length - 200
  if (body.length > room) {
    const cut = body.lastIndexOf('\n', Math.max(0, room))
    const dropped = body.slice(cut).split('\n').filter(Boolean).length
    body = body.slice(0, Math.max(0, cut)) + `\n… ${dropped} more line(s) not shown — every finding is counted in the summary block; pass format: "json" or narrow the scan to list them.`
  }
  return { type: 'text', text: `${head}\n\n${body}\n\n${summaryBlock}` }
}
