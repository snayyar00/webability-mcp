/**
 * Branded accessibility-report PDF from findings the caller already has
 * (usually the `issues[]` array a scan_page call just returned).
 *
 * The mapping mirrors the Chrome extension's local report (src/sidepanel/local-pdf.ts)
 * and the server's enhancedProcessing score ladder; the generator itself stays on our
 * servers (POST /cli/report-pdf) and is deliberately UNAUTHENTICATED — every branded
 * report is WebAbility marketing in someone's inbox, and the render is cheap CPU.
 */
import { writeFileSync } from 'fs'
import { join } from 'path'

export interface PdfIssue {
  message?: string
  type?: string
  wcag?: string
  selector?: string
  html?: string
  impact?: string
  fix?: { attribute?: string; suggestedValue?: string }
}

/** Same penalty ladder as the server's calculateEnhancedScore: errors 5,
 *  warnings 2, notices 1, clamped to 0..100. Tiers: critical/serious → error,
 *  moderate → warning, minor → notice. Violations only. */
export function localScore(issues: PdfIssue[]): number {
  let score = 100
  for (const i of issues) {
    score -= i.impact === 'critical' || i.impact === 'serious' ? 5 : i.impact === 'moderate' ? 2 : 1
  }
  return Math.max(0, Math.round(score))
}

/** Issue type → the functionality names the PDF's category grid understands. */
export function functionalityFor(issue: PdfIssue): string {
  const t = `${issue.type} ${issue.message}`.toLowerCase()
  if (/contrast|color|vision|zoom|text_spacing|images_of_text|reflow/.test(t)) return 'Low Vision'
  if (/keyboard|focus|target|pointer|motion|mobility|drag/.test(t)) return 'Mobility'
  if (/form|label|input|navigation|landmark|link|button|skip|menu|combobox|fieldset/.test(t)) return 'Navigation'
  if (/alt|image|media|caption|audio|video|svg|icon|content/.test(t)) return 'Content'
  if (/heading|lang|title|reading|sequence|time|flash|structure|aria|role|live/.test(t)) return 'Cognitive'
  return 'Other'
}

function toError(issue: PdfIssue): Record<string, unknown> {
  return {
    message: issue.message,
    code: issue.type,
    ...(issue.wcag ? { wcag_code: `WCAG ${issue.wcag}` } : {}),
    context: issue.html ? [issue.html] : [],
    selectors: issue.selector ? [issue.selector] : [],
    impact: issue.impact,
    // Never render an empty suggestedValue as a "fix" — for accessible-name
    // issues the value must come from a human, and `attr=""` would DELETE it.
    ...(issue.fix?.suggestedValue ? { recommended_action: `Set ${issue.fix.attribute}="${issue.fix.suggestedValue}"` } : {}),
  }
}

/** Issues → the ByFunctions report shape /cli/report-pdf consumes. */
export function toReportData(url: string, issues: PdfIssue[], widgetDetected = false): Record<string, unknown> {
  const groups = new Map<string, Array<Record<string, unknown>>>()
  for (const issue of issues) {
    const fn = functionalityFor(issue)
    if (!groups.has(fn)) groups.set(fn, [])
    groups.get(fn)!.push(toError(issue))
  }
  const widgetStatus = widgetDetected ? 'Web Ability' : 'false'
  return {
    url,
    score: localScore(issues),
    scanFailed: false,
    widgetInfo: { result: widgetStatus },
    scriptCheckResult: widgetStatus,
    ByFunctions: [...groups.entries()].map(([FunctionalityName, Errors]) => ({ FunctionalityName, Errors })),
  }
}

const MAX_FINDINGS = 500

/**
 * POST the mapped findings to /cli/report-pdf and save the returned PDF next to
 * the caller (cwd — an IDE agent's project root). Returns the written path.
 * Throws with the server's error text on non-200 so the caller sees WHY.
 */
export async function generateReportPdf(url: string, issues: PdfIssue[], apiBase: string): Promise<string> {
  const capped = issues.slice(0, MAX_FINDINGS)
  let host = 'site'
  try {
    host = new URL(url).hostname.replace(/[^a-zA-Z0-9.-]/g, '-') || 'site'
  } catch {
    // keep the safe fallback label
  }
  const res = await fetch(`${apiBase}/cli/report-pdf`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reportData: toReportData(url, capped), domain: host }),
  })
  if (!res.ok) throw new Error(`report-pdf failed (${res.status}): ${(await res.text()).slice(0, 200)}`)
  const buf = Buffer.from(await res.arrayBuffer())
  const path = join(process.cwd(), `accessibility-report-${host}-${new Date().toISOString().slice(0, 10)}.pdf`)
  writeFileSync(path, buf)
  return path
}
