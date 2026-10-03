/**
 * Type-stratified cap for MCP tool responses (scan_page / flow_scan).
 *
 * BUG EVIDENCE (round-3 persona P007, squarespace.com, scan
 * 2026-09-18T08-24-25Z): the page produced 155 issues — 22 serious, 83
 * moderate, 50 minor — including 26 `keyboard_trap` (2.1.1) issues on the
 * carousel controls. The severity-sorted cap returned 22 serious + the first
 * 28 moderates in detector order; `contrast_insufficient` (25) and
 * `missing_audio_description` (8) occupied those slots, so the default
 * response carried ZERO 2.1.1 findings on a page full of keyboard-inoperable
 * controls. The persona's keyboard-only pass flagged exactly this absence:
 * "the accessible-name issue is moot until focus is [there]" — the report
 * hid the entire `keyboard_trap` type behind the cap.
 *
 * Fix: stratify the cap. Phase 1 keeps the highest-severity issue of EACH
 * distinct `type` (severity order), so every type present on the page gets at
 * least one representative in the default view. Phase 2 fills the remaining
 * slots in the same severity order as before — majority types still dominate
 * the tail, and the cap stays exactly `cap`. Nothing is dropped from
 * scan_history: the archived copy stores the full pre-cap list either way.
 *
 * Deterministic and stable: input order only changes which member of a type
 * is picked (first per type wins), never which types survive.
 */

type ImpactRanked = { impact?: string; type?: string }

/** Stratified severity cap. Returns [kept list, anyTypeRescued] (a type the plain first-cap cut would have hidden). */
export function stratifiedCap<T extends { impact?: string; type?: string }>(
  severitySorted: readonly T[],
  cap: number,
): [T[], boolean] {
  if (severitySorted.length <= cap) return [[...severitySorted], false]
  const kept: T[] = []
  const seen = new Set<string>()
  // Phase 1: one representative per type, in the given (severity) order.
  for (const issue of severitySorted) {
    if (kept.length >= cap) break
    const t = issue.type ?? ''
    if (seen.has(t)) continue
    seen.add(t)
    kept.push(issue)
  }
  // Phase 2: fill remaining slots from the survivors, preserving order.
  if (kept.length < cap) {
    const keptSet = new Set(kept)
    for (const issue of severitySorted) {
      if (kept.length >= cap) break
      if (keptSet.has(issue)) continue
      kept.push(issue)
      keptSet.add(issue)
    }
  }
  // A type was rescued when the plain cut (first `cap` by severity) would have
  // returned ZERO of it but the stratified list includes one.
  const keptTypes = new Set(kept.map((i) => i.type ?? ''))
  const plainTypes = new Set(severitySorted.slice(0, cap).map((i) => i.type ?? ''))
  let rescued = false
  for (const t of keptTypes) {
    if (!plainTypes.has(t)) {
      rescued = true
      break
    }
  }
  return [kept, rescued]
}
