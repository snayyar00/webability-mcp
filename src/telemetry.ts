/**
 * Usage telemetry → platform API (the admin scan feed at
 * app.webability.io/admin/scans).
 *
 * One small event per tool call (EVERY tool, not just the scan-shaped ones):
 * tool, target label, ok/failed, duration, summary counts, and at most one
 * tiny `meta` string (detected framework / fix-returned / AA pass-fail).
 * Full scan results, HTML, and fix code NEVER leave the machine via
 * telemetry — they live in the local scan log (see scanLog.ts). Disclosed in
 * README + PRIVACY.md; disable with WEBABILITY_SCAN_TELEMETRY=off.
 *
 * Fire-and-forget with a hard timeout: telemetry must never slow a tool call
 * down or break it.
 */
import { randomBytes } from 'crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'fs'
import { homedir } from 'os'
import { dirname, join } from 'path'
import { describeScanTarget } from './scanLog.js'

const API_URL = process.env.WEBABILITY_API_URL || process.env.ABILYO_API_URL || 'https://api.webability.io'

export function telemetryEnabled(): boolean {
  return process.env.WEBABILITY_SCAN_TELEMETRY !== 'off'
}

/** Random anonymous installation id, persisted next to the scan log. */
let cachedClientId: string | null = null
function clientId(): string | null {
  if (cachedClientId) return cachedClientId
  try {
    const path = join(homedir(), '.webability', 'client-id')
    try {
      cachedClientId = readFileSync(path, 'utf8').trim() || null
    } catch {
      cachedClientId = randomBytes(16).toString('hex')
      mkdirSync(dirname(path), { recursive: true })
      writeFileSync(path, cachedClientId)
    }
    return cachedClientId
  } catch {
    return null // read-only FS (containers) — events just go unattributed
  }
}

export interface ScanEventSummary {
  total?: number
  critical?: number
  serious?: number
  moderate?: number
  minor?: number
  incomplete?: number
}

/**
 * Telemetry label for what a tool call was pointed at. URL-shaped tools reuse
 * the scan-log target (URL / startUrl / "inline-html (N KB)"); the rest get a
 * small non-content label (issue type + WCAG SC, CSS selector, tag filter) so
 * per-tool usage is visible without shipping page content or HTML.
 */
export function describeTelemetryTarget(tool: string, args: Record<string, unknown> | undefined): string {
  const label = (() => {
    if (!args) return tool
    switch (tool) {
      case 'generate_ai_fix': {
        const issue = args.issue as Record<string, unknown> | undefined
        const type = typeof issue?.type === 'string' && issue.type ? issue.type : ''
        const wcag = typeof issue?.wcag === 'string' && issue.wcag ? `wcag:${issue.wcag}` : ''
        const issueLabel = [type, wcag].filter(Boolean).join(' ')
        if (issueLabel) return issueLabel
        return typeof args.url === 'string' && args.url ? args.url : tool
      }
      case 'find_source':
        return typeof args.selector === 'string' && args.selector ? args.selector : tool
      case 'get_rules': {
        const tags = Array.isArray(args.tags) ? (args.tags as unknown[]).filter((t): t is string => typeof t === 'string') : []
        return tags.length > 0 ? `tags:${tags.join(',')}` : 'all'
      }
      case 'check_color_contrast':
        if (typeof args.url === 'string' && args.url) return args.url
        return `${typeof args.foreground === 'string' ? args.foreground : '?'} on ${typeof args.background === 'string' ? args.background : '?'}`
      case 'scan_history':
        if (typeof args.id === 'string' && args.id) return `id:${args.id}`
        if (typeof args.filter === 'string' && args.filter) return `filter:${args.filter}`
        return 'list'
      default:
        return describeScanTarget(tool, args)
    }
  })()
  return label.slice(0, 300)
}

/** Pull summary counts out of a tool response (the ```json block). Best-effort. */
export function extractSummary(response: unknown): ScanEventSummary | null {
  try {
    const content = (response as any)?.content
    if (!Array.isArray(content)) return null
    for (const c of content) {
      if (c?.type !== 'text' || typeof c.text !== 'string') continue
      const m = c.text.match(/```json\n([\s\S]*?)\n```/)
      if (!m) continue
      const parsed = JSON.parse(m[1])
      if (parsed && typeof parsed.summary === 'object' && parsed.summary !== null) return parsed.summary
      if (Array.isArray(parsed)) return { total: parsed.length } // check_aria / scan_html violation arrays
      if (Array.isArray(parsed.violations)) return { total: parsed.violations.length }
    }
    return null
  } catch {
    return null
  }
}

/**
 * Small per-tool enrichment parsed best-effort from the response text (same
 * spirit as extractSummary). Returns counts that fit the existing summary
 * columns plus at most one short `meta` string. Never throws.
 */
export function extractToolTelemetry(tool: string, response: unknown): { summary: ScanEventSummary | null; meta: string | null } {
  try {
    const content = (response as any)?.content
    const firstText: string = Array.isArray(content) ? (content.find((c: any) => c?.type === 'text')?.text ?? '') : ''
    switch (tool) {
      case 'generate_ai_fix': {
        // The valuable signal: did fix generation actually return something?
        const alternatives = (firstText.match(/^### Option \d+/gm) || []).length
        return { summary: { total: alternatives }, meta: alternatives > 0 ? 'fix:yes' : 'fix:no' }
      }
      case 'detect_framework': {
        const m = firstText.match(/^Framework: (.+)$/m)
        return { summary: null, meta: m ? `framework:${m[1].trim().slice(0, 100)}` : null }
      }
      case 'check_color_contrast': {
        const m = firstText.match(/WCAG AA\s+\(≥ [\d.]+\): (PASS|FAIL)/)
        return { summary: null, meta: m ? `aa:${m[1].toLowerCase()}` : null }
      }
      case 'get_rules': {
        const m = firstText.match(/^(\d+) rules?/)
        return { summary: m ? { total: parseInt(m[1], 10) } : null, meta: null }
      }
      case 'find_source': {
        if (/^No source files matched/.test(firstText)) return { summary: { total: 0 }, meta: null }
        const matches = (firstText.match(/^- /gm) || []).length
        return { summary: matches > 0 ? { total: matches } : null, meta: null }
      }
      case 'scan_history': {
        const m = firstText.match(/^(\d+) scan\(s\)/)
        return { summary: m ? { total: parseInt(m[1], 10) } : null, meta: null }
      }
      default:
        // Scan-shaped tools: unchanged — counts from the ```json block.
        return { summary: extractSummary(response), meta: null }
    }
  } catch {
    return { summary: null, meta: null }
  }
}

export function reportScanEvent(event: {
  tool: string
  target: string
  source: 'hosted' | 'local'
  ok: boolean
  durationMs: number
  summary: ScanEventSummary | null
  /** Optional short enrichment, e.g. "framework:tailwind", "fix:yes", "aa:fail". */
  meta?: string | null
}): void {
  if (!telemetryEnabled()) return
  try {
    void fetch(`${API_URL}/mcp/scan-events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: event.tool,
        target: event.target,
        source: event.source,
        ok: event.ok,
        durationMs: event.durationMs,
        summary: event.summary ?? undefined,
        ...(event.meta ? { meta: event.meta.slice(0, 120) } : {}),
        clientId: event.source === 'local' ? clientId() : null,
      }),
      signal: AbortSignal.timeout(3000),
    }).catch(() => {})
  } catch {
    // fetch unavailable (very old node) — telemetry silently off
  }
}
