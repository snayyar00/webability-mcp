/**
 * Response shaping for scan_page / flow_scan / diff_scan (wave 4).
 *
 * 1. mergeSameElement — three engines (WebAbility, axe-core, HTML_CodeSniffer)
 *    report the same "no accessible name" problem on one element under
 *    different rule ids and criteria. demo.vercel.store's search input came
 *    back as wa-missing_label (1.3.1 serious, add aria-label) AND
 *    h91_inputtext_name (4.1.2 moderate, suggest): one fix, two issues. The
 *    merge keeps the richest fix and the higher severity, unions the criteria,
 *    and lists every rule id in `rules[]` and the folded finding ids in
 *    `alsoReportedAs[]`. Idempotent, so it can run on archived scans too.
 *
 * 2. collapseRepeats — vite.dev/guide/ returned 36 new_window_link entries
 *    with the same fix out of 64, and the 50 cap cut the list. A rule that
 *    repeats >= 4 times with the same fix op + attribute becomes one entry
 *    with `count`, up to 10 example selectors, and a hint to list them all.
 *
 * 3. truncationNote — the hosted server keeps no scan history, so its note
 *    must point at the narrowing controls, never at scan_history.
 */
import type { IssueRow, OutputControls } from './outputControls.js'

const RANK: Record<string, number> = { critical: 4, serious: 3, moderate: 2, minor: 1 }

/** Rule ids that all mean "this element has no accessible name", across engines. */
const NAME_RULES = new Set([
  // form controls
  'missing_label', 'label', 'select-name', 'aria-input-field-name',
  // links
  'empty_link', 'link-name',
  // images
  'missing_alt', 'image-alt', 'h37',
  // buttons and named graphics — svg_missing_name reports the enclosing
  // control's selector when the svg sits in one, so an icon button came back
  // as svg_missing_name AND unlabeled_button (allbirds.com, MCP dogfood
  // 2026-10-03): one missing name, one fix.
  'unlabeled_button', 'button-name', 'input-button-name', 'svg_missing_name', 'svg-img-alt', 'role-img-alt',
])
const isNameRule = (type: string | undefined) => !!type && (NAME_RULES.has(type) || /^h91_[a-z0-9]+_name$/.test(type))

/**
 * Match key for a finding in the accessible-name family: one key per element,
 * whichever engine reported it and whether or not it was merged. diff_scan
 * uses it so a merged baseline and a partly fixed current scan line up.
 */
export function nameFamilyKey(i: { type?: string; rules?: string[]; selector?: string }): string | undefined {
  if (!i.selector) return undefined
  if (!isNameRule(i.type) && !(i.rules ?? []).some(isNameRule)) return undefined
  return `name|${i.selector}`
}

export type Shaped = IssueRow & {
  rules?: string[]
  alsoReportedAs?: string[]
  count?: number
  examples?: string[]
  expand?: string
}

/** 0 no fix, 1 suggest only, 2 a concrete op, +1 when the value is known. */
function fixRichness(i: IssueRow): number {
  const op = i.fix?.op
  if (!op) return 0
  const base = op === 'suggest' ? 1 : 2
  const v = i.fix?.value
  return base + (v !== undefined && v !== null && String(v) !== '' ? 1 : 0)
}

function compareCriteria(a: string, b: string): number {
  const pa = a.split('.').map(Number)
  const pb = b.split('.').map(Number)
  for (let k = 0; k < Math.max(pa.length, pb.length); k++) {
    const d = (pa[k] ?? 0) - (pb[k] ?? 0)
    if (d !== 0 && !Number.isNaN(d)) return d
  }
  return a.localeCompare(b)
}

const unique = <T>(xs: T[]) => [...new Set(xs)]

/**
 * Merge findings on the same element that are the same accessible-name
 * problem. Findings outside the family, and family members alone on their
 * element, pass through unchanged. Order follows each group's first member.
 */
export function mergeSameElement<T extends Shaped>(list: readonly T[]): T[] {
  const groups = new Map<string, T[]>()
  for (const i of list) {
    if (!isNameRule(i.type) || !i.selector) continue
    const g = groups.get(i.selector)
    if (g) g.push(i)
    else groups.set(i.selector, [i])
  }
  const out: T[] = []
  const emitted = new Set<string>()
  for (const i of list) {
    const g = isNameRule(i.type) && i.selector ? groups.get(i.selector) : undefined
    // Two findings of ONE rule on a shared (non-unique) selector are two
    // elements, not one problem — merge only when every rule id in the group
    // appears exactly once.
    if (!g || g.length < 2 || new Set(g.map((x) => x.type)).size !== g.length) {
      out.push(i)
      continue
    }
    if (emitted.has(i.selector!)) continue
    emitted.add(i.selector!)
    // Richest fix first; on a tie the higher severity; then input order.
    const primary = [...g].sort((a, b) => fixRichness(b) - fixRichness(a) || (RANK[b.impact ?? ''] ?? 0) - (RANK[a.impact ?? ''] ?? 0))[0]!
    const others = g.filter((x) => x !== primary)
    const impact = g.reduce((best, x) => ((RANK[x.impact ?? ''] ?? 0) > (RANK[best] ?? 0) ? x.impact! : best), primary.impact ?? '')
    const wcag = unique(g.flatMap((x) => String(x.wcag ?? '').split(/[,\s]+/).filter(Boolean))).sort(compareCriteria).join(',')
    const rules = unique([...(primary.rules ?? [String(primary.type)]), ...others.flatMap((x) => x.rules ?? [String(x.type)])])
    const alsoReportedAs = unique([...(primary.alsoReportedAs ?? []), ...others.flatMap((x) => [...(x.id ? [x.id] : []), ...(x.alsoReportedAs ?? [])])])
    const foundOn = g.some((x) => x.foundOn) ? unique(g.flatMap((x) => x.foundOn ?? [])) : undefined
    out.push({ ...primary, impact, wcag, rules, alsoReportedAs, ...(foundOn ? { foundOn } : {}) })
  }
  return out
}

/** Severity counts for a (merged) result — the summary must match the list. */
export function recountSummary(issues: readonly Shaped[], incomplete: readonly Shaped[]) {
  const s = { total: 0, critical: 0, serious: 0, moderate: 0, minor: 0, incomplete: 0 }
  for (const i of issues) {
    const n = i.count ?? 1
    s.total += n
    if (i.impact === 'critical' || i.impact === 'serious' || i.impact === 'moderate' || i.impact === 'minor') s[i.impact] += n
  }
  for (const i of incomplete) s.incomplete += i.count ?? 1
  return s
}

const COLLAPSE_MIN = 4
const COLLAPSE_EXAMPLES = 10

/**
 * Collapse a rule that repeats >= COLLAPSE_MIN times with the same fix op +
 * attribute into one entry. Skipped for a rule the caller named in rules[] —
 * that is how the caller asks for every instance.
 */
export function collapseRepeats<T extends Shaped>(list: readonly T[], controls: OutputControls): { list: T[]; collapsedGroups: number } {
  const keyOf = (i: T) => `${i.type ?? ''}\u0000${i.fix?.op ?? ''}\u0000${i.fix?.attribute ?? ''}`
  const members = new Map<string, T[]>()
  for (const i of list) {
    const k = keyOf(i)
    const m = members.get(k)
    if (m) m.push(i)
    else members.set(k, [i])
  }
  const out: T[] = []
  const done = new Set<string>()
  let collapsedGroups = 0
  for (const i of list) {
    const k = keyOf(i)
    const m = members.get(k)!
    const type = String(i.type ?? '')
    // Never collapse: a rule the caller named (directly or through a merged
    // rules[] entry), or a visual-tier finding — each carries its own
    // measured value (contrast ratio, colours) that a summary entry would hide.
    const named = controls.rules && (controls.rules.has(type) || (i.rules ?? []).some((r) => controls.rules!.has(r)))
    if (m.length < COLLAPSE_MIN || !type || named || i.fixability === 'visual') {
      out.push(i)
      continue
    }
    if (done.has(k)) continue
    done.add(k)
    collapsedGroups++
    const count = m.reduce((n, x) => n + (x.count ?? 1), 0)
    const examples = unique(m.flatMap((x) => x.examples ?? (x.selector ? [x.selector] : []))).slice(0, COLLAPSE_EXAMPLES)
    const foundOn = m.some((x) => x.foundOn) ? unique(m.flatMap((x) => x.foundOn ?? [])) : undefined
    // One entry speaks for every member, so it may only carry a value and a
    // tier they all share. Per-element values (labels, alt text) differ.
    const values = new Set(m.map((x) => String(x.fix?.value ?? '')))
    const tiers = new Set(m.map((x) => x.fixability))
    const sameValue = values.size === 1
    const fix = i.fix && !sameValue ? (({ value: _v, ...rest }) => rest)(i.fix) : i.fix
    const fixability = sameValue && tiers.size === 1 ? i.fixability : i.fixability === undefined ? undefined : 'contextual'
    out.push({
      ...i,
      count,
      examples,
      ...(fix ? { fix } : {}),
      ...(fixability !== undefined ? { fixability } : {}),
      expand: sameValue
        ? `${count} elements share this rule and fix; ${examples.length} shown. Pass rules: ["${type}"] to list every one.`
        : `${count} elements share this rule and fix op, but the value differs per element; ${examples.length} shown. Pass rules: ["${type}"] to get each element's own value.`,
      ...(foundOn ? { foundOn } : {}),
    })
  }
  return { list: out, collapsedGroups }
}

export function truncationNote(o: { remote: boolean; cap: number; returned: number; total: number; incompleteReturned: number; incompleteTotal: number; stratified: boolean }): string {
  const head =
    ` NOTE: each list is capped at ${o.cap} entries, highest severity first (criticals are never dropped${o.stratified ? '; every issue type keeps at least one entry' : ''})` +
    ` — showing ${o.returned}/${o.total} issue entries and ${o.incompleteReturned}/${o.incompleteTotal} needs-review entries.`
  return o.remote
    ? head + ' To see the rest, narrow the scan: minImpact (e.g. "serious"), rules [...] or wcag [...], rootSelector for one region of the page, and format: "compact" for fewer tokens per finding. For a full report of the whole site, use start_audit.'
    : head + ' Retrieve the FULL untruncated set via `scan_history` (pass this scan\'s id), or narrow with minImpact / rules / wcag / rootSelector, or use format: "compact".'
}

export const OBSOLETE_PARSING_REASON =
  'WCAG 4.1.1 Parsing is obsolete in WCAG 2.2 and always satisfied for HTML, so this is not a conformance failure. A duplicate id only harms users when a label for= / aria-labelledby / aria-describedby reference resolves to the wrong element — those cases are reported under 1.3.1 / 4.1.2. Rename the id if a reference points at it; otherwise this is cleanup.'

const onlyParsing = (wcag: string | undefined) => {
  const c = String(wcag ?? '').split(/[,\s]+/).filter(Boolean)
  return c.length > 0 && c.every((x) => x === '4.1.1')
}

/**
 * Move findings whose only criterion is 4.1.1 (duplicate_id, HTML_CodeSniffer
 * f77, axe duplicate-id / duplicate-id-active) from issues to needs-review,
 * with the reason. axe duplicate-id-aria is tagged 4.1.2 and stays an issue.
 */
export function demoteObsoleteParsing<T extends Shaped & { confidence?: string; reviewReason?: string }>(issues: readonly T[], incomplete: readonly T[]): { issues: T[]; incomplete: T[]; demoted: number } {
  const keep: T[] = []
  const moved: T[] = []
  for (const i of issues) (onlyParsing(i.wcag) ? moved : keep).push(i)
  const tag = (i: T): T => ({ ...i, confidence: 'needs_review', reviewReason: OBSOLETE_PARSING_REASON })
  return {
    issues: keep,
    incomplete: [...incomplete.map((i) => (onlyParsing(i.wcag) ? tag(i) : i)), ...moved.map(tag)],
    demoted: moved.length,
  }
}

export type SeveritySummary = ReturnType<typeof recountSummary>

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`

/**
 * The lead sentence of a scan_page response. Persona round 4: 24/80 runs read
 * "Found 67 issue(s) … issues[] has 34 entries for 67 issue(s)" as two
 * competing counts, and 21/80 saw a page-wide "Found 67" above a filtered
 * list of 1. One number is the issue count (one per affected element and
 * problem); entries are only how the list groups them. With filters active
 * (`page` set) the filtered set leads and the page-wide total is a secondary
 * clause.
 */
export function scanHeadline(o: {
  url: string
  /** Severity counts of the set being returned (the filtered set when filters are on). */
  shown: SeveritySummary
  /** Page-wide counts — set only when filters narrowed the result. */
  page?: SeveritySummary
  /** Filter description, e.g. "rules=[missing_alt]". */
  filters?: string
  issueEntries: number
  incompleteEntries: number
  collapsedGroups: number
}): string {
  const s = o.shown
  const matching = o.page ? ` matching the filters${o.filters ? ` (${o.filters})` : ''}` : ''
  let text =
    `Found ${plural(s.total, 'high-confidence issue', 'high-confidence issues')}${matching} on ${o.url}: ` +
    `${s.critical} critical, ${s.serious} serious, ${s.moderate} moderate, ${s.minor} minor.`
  if (s.incomplete > 0) {
    text += ` ${s.incomplete} additional finding(s)${o.page ? ' matching the filters' : ''} need human review (gradient backgrounds, marketing imagery, etc.) — see \`incomplete[]\`. Do NOT auto-fix these.`
  }
  if (o.page) {
    text +=
      ` Whole page, before filters: ${plural(o.page.total, 'issue', 'issues')} and ${o.page.incomplete} needing review — that is the total to report.` +
      ' `summary` counts the filtered set; `pageSummary` counts the whole page.'
  } else {
    text += ` Total to report: ${plural(s.total, 'issue', 'issues')} (one per affected element and problem).`
  }
  const issuesGrouped = o.issueEntries < s.total
  const reviewGrouped = o.incompleteEntries < s.incomplete
  if (o.collapsedGroups > 0 && (issuesGrouped || reviewGrouped)) {
    const parts: string[] = []
    if (issuesGrouped) parts.push(`the ${plural(s.total, 'issue is', 'issues are')} grouped into ${o.issueEntries} entries in issues[]`)
    if (reviewGrouped) parts.push(`the ${s.incomplete} needs-review finding(s) into ${o.incompleteEntries} entries in incomplete[]`)
    const joined = parts.join('; ')
    text +=
      ` Listing: ${joined} — ${o.collapsedGroups} rule(s) repeat with the same fix and are listed once with \`count\`.` +
      ' Pass rules: ["<rule id>"] to list every element of a rule.'
  }
  return text
}
