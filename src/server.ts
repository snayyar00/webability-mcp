// Side-effect-free server module: builds a configured MCP Server with all tools.
// Both entry points (index.ts = stdio, http.ts = Streamable HTTP) import createServer from here.
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolRequest } from '@modelcontextprotocol/sdk/types.js'
import { scan, detectFramework, getContrastRatio, extractSiteTheme } from '@webability/core'
import { execFile } from 'child_process'
import { promisify } from 'util'
import { readFileSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'
import dnsPromises from 'dns/promises'
import { isIP } from 'net'
import type { BrowserContext } from 'playwright'
import { newScanId, readScanHistory, readScanResult, recordScan, scanLogDir, scanLogEnabled } from './scanLog.js'
import { describeTelemetryTarget, extractToolTelemetry, reportScanEvent } from './telemetry.js'

const execFileAsync = promisify(execFile)
const API_URL = process.env.WEBABILITY_API_URL || process.env.ABILYO_API_URL || 'https://api.webability.io'

/**
 * Severity ordering for the axe-style impact taxonomy (`critical > serious >
 * moderate > minor`, matching `IssueImpact` in @webability/core). Used to sort
 * issue lists by severity BEFORE they are capped to RESULT_CAP — otherwise a
 * page with more findings than the cap can silently drop every critical issue
 * just because lower-severity findings happened to come first in the unsorted
 * detector output.
 */
const IMPACT_RANK: Record<string, number> = { critical: 4, serious: 3, moderate: 2, minor: 1 }

/** Descending severity sort (highest-impact first). Stable, non-mutating. */
function bySeverityDesc<T extends { impact?: string }>(list: readonly T[]): T[] {
  return [...list].sort((a, b) => (IMPACT_RANK[b.impact ?? ''] ?? 0) - (IMPACT_RANK[a.impact ?? ''] ?? 0))
}

/**
 * Associates a returned tool response with the FULL, pre-truncation scan result
 * so scan_history can persist the complete finding set even when the response
 * sent to the caller is capped to RESULT_CAP. Keyed by the response object so
 * nothing extra is ever serialized into the client-facing payload.
 */
const fullScanResultByResponse = new WeakMap<object, unknown>()

/**
 * Resolve a WebAbility auth token for backend endpoints gated behind device-flow login.
 * `/cli/visual-audit` calls paid Claude vision, so PR #124 requires a JWT — the MCP tool
 * has to present the same token the CLI obtains via `login`, or it always 401s.
 *
 * Lookup order: explicit env var (the natural channel for an MCP server config) → the
 * token the `webability` CLI persisted after login. The CLI stores it with the `conf`
 * package (projectName "webability"); we read that JSON directly rather than depend on
 * the CLI package. Returns '' when nothing is found so callers can emit an actionable
 * "authenticate first" message instead of leaking a bare 401.
 */
function resolveAuthToken(): string {
  const fromEnv = process.env.WEBABILITY_API_KEY || process.env.ABILYO_API_KEY || ''
  if (fromEnv) return fromEnv
  const home = homedir()
  const candidates: string[] = []
  if (process.platform === 'darwin') {
    candidates.push(join(home, 'Library', 'Preferences', 'webability-nodejs', 'config.json'))
  } else if (process.platform === 'win32') {
    const appData = process.env.APPDATA || join(home, 'AppData', 'Roaming')
    candidates.push(join(appData, 'webability-nodejs', 'Config', 'config.json'))
  }
  const xdg = process.env.XDG_CONFIG_HOME || join(home, '.config')
  candidates.push(join(xdg, 'webability-nodejs', 'config.json'))
  for (const p of candidates) {
    try {
      const parsed = JSON.parse(readFileSync(p, 'utf8'))
      if (parsed && typeof parsed.apiKey === 'string' && parsed.apiKey) return parsed.apiKey
    } catch {
      // file absent or unreadable — try the next candidate
    }
  }
  return ''
}

export interface ServerOptions {
  /** Remote/hosted mode (HTTP transport reachable from the internet): enables the SSRF
   *  URL allowlist and disables local-filesystem tools (find_source). Off for local stdio. */
  remote?: boolean
}

/** True if an IP literal is loopback / private / link-local / cloud-metadata / CGNAT. */
function isBlockedAddress(addr: string): boolean {
  const a = addr.toLowerCase()
  if (a === '::1' || a === '::' || a.startsWith('fe80') || a.startsWith('fc') || a.startsWith('fd')) return true
  const mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
  const ipv4 = mapped ? mapped[1] : a
  const m = ipv4.match(/^(\d+)\.(\d+)\.\d+\.\d+$/)
  if (m) {
    const o1 = parseInt(m[1], 10)
    const o2 = parseInt(m[2], 10)
    if (o1 === 0 || o1 === 127 || o1 === 10) return true          // this-host / loopback / private
    if (o1 === 169 && o2 === 254) return true                     // link-local + cloud metadata (169.254.169.254)
    if (o1 === 172 && o2 >= 16 && o2 <= 31) return true           // private
    if (o1 === 192 && o2 === 168) return true                     // private
    if (o1 === 100 && o2 >= 64 && o2 <= 127) return true          // CGNAT (often internal)
  }
  return false
}

/** SSRF guard: only http(s) to public, externally-resolvable addresses.
 *  NOTE residual risk: Chromium follows redirects, so a 302 to a metadata IP can re-introduce
 *  SSRF after this check. Pair with an egress proxy/allowlist in production for full coverage. */
async function assertSafeUrl(raw: string): Promise<void> {
  let u: URL
  try {
    u = new URL(raw)
  } catch {
    throw new Error(`invalid URL "${raw}"`)
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error(`scheme "${u.protocol}" not allowed`)
  let addrs: string[]
  if (isIP(u.hostname)) {
    addrs = [u.hostname]
  } else {
    try {
      addrs = (await dnsPromises.lookup(u.hostname, { all: true })).map((r) => r.address)
    } catch {
      throw new Error(`cannot resolve host "${u.hostname}"`)
    }
  }
  if (addrs.length === 0) throw new Error(`no addresses for "${u.hostname}"`)
  for (const a of addrs) if (isBlockedAddress(a)) throw new Error(`"${u.hostname}" resolves to blocked internal address ${a}`)
}

/** Install an SSRF guard on a Playwright context: every request — top-level navigations,
 *  redirect targets, AND sub-resources (e.g. <img>/<script> in attacker-supplied HTML) — is
 *  validated; anything resolving to an internal/private address is aborted. Used in remote mode. */
async function installSsrfRoute(context: BrowserContext): Promise<void> {
  await context.route('**/*', async (route) => {
    try {
      await assertSafeUrl(route.request().url())
      await route.continue()
    } catch {
      await route.abort()
    }
  })
}

function rgbStringToHex(c: string): string | null {
  if (c.startsWith('#') && c.length === 7) return c.toLowerCase()
  const m = c.match(/rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/)
  if (!m) return null
  const [r, g, b] = [m[1], m[2], m[3]].map((n) => parseInt(n, 10))
  return '#' + [r, g, b].map((n) => n.toString(16).padStart(2, '0')).join('').toLowerCase()
}

async function extractBrandPaletteFromUrl(url: string): Promise<string[]> {
  const pw = await import('playwright')
  const browser = await pw.chromium.launch({ headless: true })
  try {
    const page = await (await browser.newContext()).newPage()
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 })
    const theme = await extractSiteTheme(page)
    const raw = [
      ...Object.values(theme.cssVars),
      ...theme.topBgColors.map((c) => c.color),
      ...theme.topTextColors.map((c) => c.color),
    ]
    const hexes = raw.map(rgbStringToHex).filter((h): h is string => !!h)
    return Array.from(new Set(hexes))
  } finally {
    await browser.close().catch(() => {})
  }
}

const INSTRUCTIONS = `WebAbility is a web accessibility platform — AI-powered widget, scanner, and agents for WCAG 2.2 / ADA / Section 508 / EAA compliance. https://webability.io

This MCP exposes the same scanning engine that powers the WebAbility widget and dashboard, so you can audit and fix accessibility issues from your IDE while you build.

## Engines used by scan_page
- WebAbility detectors (60+ rules — gradient-aware contrast, weak names, decorative-icon detection, etc.)
- axe-core (104 rules)
- HTML_CodeSniffer (200+ rules)
Results from all three are deduplicated into one issue list.

## Three-tier output (since v1.2.1, mirrors axe-core)
\`scan_page\` and \`flow_scan\` return (\`scan_html\` is axe-only and returns raw violations):
- **issues**: high-confidence violations — safe to act on
- **incomplete**: needs human review — DO NOT auto-fix these. Common causes: contrast against gradient/image backgrounds, marketing-image alt text, framer-motion pre-animation states.
- **summary**: counts by severity + an \`incomplete\` count
When proposing fixes to the user, treat \`incomplete\` items as questions, not bugs.

## Tool routing
- "Scan this page / URL / localhost" → \`scan_page\`
- "Walk through login → checkout" → \`flow_scan\` with \`autoNavigate\`
- "What does this WCAG rule check" → \`get_rules\`
- "Suggest a fix for this issue" → \`detect_framework\` then \`generate_ai_fix\`
- "Did my fix work?" → \`verify_fix\` (after you edit the code AND serve the change — closes scan → fix → verify)
- "Check this contrast pair" → \`check_color_contrast\` (pass \`url\` to get brand-aligned suggestions)
- "Find where this selector lives in code" → \`find_source\`
- "Validate this HTML snippet" → \`scan_html\` or \`check_aria\`
- "Catch issues axe misses (icon contrast, focus visibility, look-but-not-button)" → \`visual_audit\` (account required)
- "I need a report to hand to a compliance officer / legal" → \`start_audit\`, then poll \`get_audit\` (account required)
- "What did we scan before / show me that earlier scan" → \`scan_history\` (local installs only — the hosted server keeps no history)

## Important
- The core loop: \`scan_page\` → \`detect_framework\` → \`generate_ai_fix\` → edit source → \`verify_fix\`.
- Generated fix code edits the user's source — confirm before applying.
- Paid, account-gated tools: \`visual_audit\`, \`start_audit\`/\`get_audit\` (they run server-side browser/AI work). Everything else runs free and local.
- The widget runtime applies its own client-side patches at runtime; do not duplicate those edits in source code.`

const handleListTools = async () => ({
  tools: [
    {
      name: 'scan_page',
      description: 'Scan a web page for WCAG accessibility issues. Works on any URL — deployed sites, localhost, staging. Returns the three-tier shape: `issues` (high-confidence violations safe to fix), `incomplete` (needs human review — gradient backgrounds, marketing imagery, axe-incomplete results, framer-motion pre-animation states), and a `summary`. Treat `incomplete` as questions, never auto-fix them.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          url: { type: 'string', description: 'URL to scan (e.g. https://example.com or http://localhost:3000)' },
          rootSelector: { type: 'string', description: 'CSS selector to limit scan scope (optional)' },
          viewport: { type: 'string', enum: ['desktop', 'tablet', 'mobile'], description: 'Viewport size (default: desktop)' },
        },
        required: ['url'],
      },
    },
    {
      name: 'verify_fix',
      description: 'Re-scan a specific element after applying an accessibility fix and confirm the violation is gone — closes the loop that find-only tools leave open. After you edit the code and serve it (deployed, staging, or http://localhost:3000), call this with the URL and the selector you fixed to get a machine-checked verified: true|false (DOM engines only — visual_audit findings and needs-review items are out of scope). Pass the WCAG criterion (e.g. "1.1.1") or axe rule id (e.g. "color-contrast") to check just that criterion; omit it to require the element be clean of ALL violations. A blocked page (bot-challenge / HTTP error) is reported as unverified, never a pass — verification fails closed. IMPORTANT: if your fix changed the element\'s class or id, the original selector may no longer match anything, which reads as verified — re-run scan_page or pass the updated selector to be sure. Pair with scan_page → generate_ai_fix → verify_fix for a full find-fix-verify cycle.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          url: { type: 'string', description: 'URL now serving the fix (deployed, staging, or http://localhost:3000)' },
          selector: { type: 'string', description: 'CSS selector of the element you fixed — use the `selector` from the original scan_page issue' },
          wcag: { type: 'string', description: 'Optional: WCAG criterion (e.g. "1.1.1", "1.4.3") or axe rule id (e.g. "color-contrast") to verify specifically. Omit to require the element be free of ALL violations.' },
          viewport: { type: 'string', enum: ['desktop', 'tablet', 'mobile'], description: 'Viewport size (default: desktop). Use the same viewport the issue was found at.' },
        },
        required: ['url', 'selector'],
      },
    },
    {
      name: 'start_audit',
      description: 'Kick off a FULL accessibility audit deliverable for a URL — a persistent, timestamped artifact, not an inline scan. Runs the server-side pipeline (axe + advanced checks + mobile viewports + annotated screenshots + optional agent spot-check) and produces a downloadable report and a formatted Excel workbook (Cover / Status / Barriers / ADA context sheets) stored durably. Returns immediately with an audit `id`; poll `get_audit` for progress and, when complete, download URLs. Use this when someone needs a durable artifact to attach as evidence of testing effort for a compliance officer or legal response — for iterating on code, use scan_page + verify_fix instead. REQUIRES A WEBABILITY ACCOUNT (runs paid server-side browser/AI work): authenticate via `webability login` or set WEBABILITY_API_KEY. Set includeAgent:true to add the (slower, paid) agentic manual-audit pass.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          url: { type: 'string', description: 'URL to audit (a public/staging URL the server can reach — not localhost)' },
          includeAgent: { type: 'boolean', description: 'Also run the agentic manual-audit pass (keyboard/focus/modal exploration). Slower and paid. Default false.' },
        },
        required: ['url'],
      },
    },
    {
      name: 'get_audit',
      description: 'Check an audit started with start_audit: returns overall status, per-step progress (scan → viewports → screenshots → agent → excel → publish), and — once complete — a severity summary plus short-lived download URLs for the report (JSON) and the Excel workbook. Poll every ~15s while status is pending/running. Only the account that started an audit can read it.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          id: { type: 'number', description: 'The audit id returned by start_audit' },
        },
        required: ['id'],
      },
    },
    {
      name: 'flow_scan',
      description: 'Scan a multi-page user journey. Walks startUrl plus the required `autoNavigate` URLs sequentially (deterministic — one page fully rendered and scanned before the next), then returns ONE consolidated report with issues deduplicated across pages, each carrying the same fix payload / confidence / review flags as scan_page. Every requested URL gets an explicit outcome in `pages[]` (scanned / nav_failed / scan_failed / redirected_duplicate / duplicate_request / skipped_cap / blocked — bot-challenge, not a clean page) — a page is never silently dropped. Better than per-page scans for journeys (login → checkout etc). For a single page, use scan_page.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          startUrl: { type: 'string', description: 'Starting URL of the journey' },
          maxPages: { type: 'number', description: 'Max pages to scan (default 10)' },
          autoNavigate: { type: 'array', items: { type: 'string' }, description: 'REQUIRED — the URLs to walk after startUrl (the MCP server is headless and cannot discover a journey interactively). For a single page, use scan_page instead.' },
        },
        required: ['startUrl', 'autoNavigate'],
      },
    },
    {
      name: 'detect_framework',
      description: 'Detect which framework/stack a page uses (Tailwind, MUI, Bootstrap, WordPress, Next.js, plain CSS). Use before generate_ai_fix to get framework-appropriate code.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          url: { type: 'string', description: 'URL to inspect' },
        },
        required: ['url'],
      },
    },
    {
      name: 'generate_ai_fix',
      description: 'Generate framework-aware fix alternatives for a specific accessibility issue. For color contrast issues, returns 3 alternatives (minimal, brand-aligned, high contrast); brand palette is auto-extracted from the live URL using our scanner if `brandColors` is omitted. For label/ARIA issues, returns 1-2 alternatives. Each alternative includes ready-to-paste code for the detected framework.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          issue: { type: 'object', description: 'Issue object from scan_page (with selector, wcag, impact, message, fix.currentValue)' },
          html: { type: 'string', description: 'The element\'s outerHTML — send at most ~600 chars' },
          context: { type: 'string', description: 'Parent element outerHTML for context (~400 chars)' },
          url: { type: 'string', description: 'Page URL — also used to auto-extract brand palette for contrast issues if `brandColors` is not provided.' },
          framework: { type: 'string', enum: ['tailwind', 'bootstrap', 'mui', 'wordpress', 'nextjs', 'plain-css'], description: 'CSS framework — use detect_framework first' },
          brandColors: { type: 'array', items: { type: 'string' }, description: 'Brand palette for brand-aligned suggestions. If omitted on a contrast issue with a `url`, auto-extracted via the scanner.' },
        },
        required: ['issue', 'html', 'framework'],
      },
    },
    {
      name: 'visual_audit',
      description: 'Pixel-level accessibility audit using Claude vision. Catches issues that DOM scanners miss: icon contrast (1.4.11), focus visibility (2.4.7), "looks like a button but isn\'t" (4.1.2), text rendered as images (1.4.5), visual hierarchy mismatches. Takes a URL, opens it in a headless browser, screenshots, and runs vision-based detection. Complements scan_page — run both for full coverage. REQUIRES A WEBABILITY ACCOUNT (like start_audit — these are the paid, server-side tools; the DOM-based tools run free and local): authenticate via `webability login` or set WEBABILITY_API_KEY in your MCP server env before calling.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          url: { type: 'string', description: 'URL to audit visually' },
          viewport: { type: 'string', enum: ['desktop', 'tablet', 'mobile'], description: 'Viewport size (default: desktop)' },
          fullPage: { type: 'boolean', description: 'Capture full scrolled page instead of just viewport (default: false)' },
          brandColors: { type: 'array', items: { type: 'string' }, description: 'Brand hex colors for context-aware filtering' },
        },
        required: ['url'],
      },
    },
    {
      name: 'find_source',
      description: 'Find source files in the local project that contain a given CSS selector. Maps DOM selectors back to source code so you can edit the right file. Searches React/Vue/Svelte/HTML/PHP/Astro files.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          selector: { type: 'string', description: 'CSS selector from a scan issue' },
          rootDir: { type: 'string', description: 'Project root to search (defaults to cwd)' },
        },
        required: ['selector'],
      },
    },
    {
      name: 'scan_html',
      description: 'Scan a raw HTML snippet for accessibility issues without serving it. Useful for code review, component snippets, or content from docs. Spins up a headless page, sets the HTML, and runs axe-core ONLY — lighter and faster than scan_page, but it skips the WebAbility detectors and HTML_CodeSniffer, and returns axe `violations` (with an `incomplete` count), not scan_page\'s three-tier issues/incomplete/summary shape.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          html: { type: 'string', description: 'HTML content to test' },
          tags: { type: 'array', items: { type: 'string' }, description: 'WCAG tags to check (default ["wcag2a","wcag2aa","wcag21aa","wcag22aa"])' },
          width: { type: 'number', description: 'Viewport width (default 1280)' },
          height: { type: 'number', description: 'Viewport height (default 800)' },
        },
        required: ['html'],
      },
    },
    {
      name: 'get_rules',
      description: 'List axe-core accessibility rules with optional tag filtering. Returns ruleId, description, help text, helpUrl, and tags for each rule. Useful for understanding what a WCAG criterion checks.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          tags: { type: 'array', items: { type: 'string' }, description: 'Filter by tags (e.g. ["wcag21aa"], ["best-practice"], ["cat.aria"])' },
        },
      },
    },
    {
      name: 'check_color_contrast',
      description: 'Check a foreground/background color pair against WCAG contrast thresholds. When it fails, suggests BRAND-aligned replacements — extracts the actual brand palette from a live URL using our scanner (CSS vars + most-used colors), or use a provided `brandColors` array. No `url` and no `brandColors` = ratio + pass/fail only.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          foreground: { type: 'string', description: 'Foreground color (hex or rgb)' },
          background: { type: 'string', description: 'Background color (hex or rgb)' },
          fontSize: { type: 'number', description: 'Font size in px (default 16)' },
          isBold: { type: 'boolean', description: 'Whether text is bold (default false)' },
          url: { type: 'string', description: 'Live URL to extract brand palette from (uses our scanner — CSS vars + dominant colors).' },
          brandColors: { type: 'array', items: { type: 'string' }, description: 'Pre-supplied brand palette. Skips URL extraction if provided.' },
        },
        required: ['foreground', 'background'],
      },
    },
    {
      name: 'check_aria',
      description: 'Validate ARIA attribute + accessible name/role/value usage in an HTML snippet. Runs axe-core `cat.aria` and `cat.name-role-value` rules (aria-* attribute correctness, role validity, required parents/children, aria-hidden-focus, accessible names). Returns `violations` (high-confidence) and `incomplete` (needs human review, e.g. dangling ARIA references — do NOT auto-fix).',
      inputSchema: {
        type: 'object' as const,
        properties: {
          html: { type: 'string', description: 'HTML to test for ARIA correctness' },
        },
        required: ['html'],
      },
    },
    {
      name: 'scan_history',
      description: 'Browse past scans run through this MCP server. Every scan_page / flow_scan / scan_html / visual_audit / check_aria / verify_fix call is logged locally (~/.webability/scans; local installs only — the hosted server keeps no history). Without arguments, lists recent scans (when, what target, result summary). Pass `id` to retrieve the FULL stored result of one past scan, or `filter` to match a URL/tool substring.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          limit: { type: 'number', description: 'Max history entries to return (default 20)' },
          filter: { type: 'string', description: 'Substring match on target URL or tool name (e.g. "abilyo.com" or "scan_page")' },
          id: { type: 'string', description: 'A scan id from the history list — returns that scan\'s full stored response' },
        },
      },
    },
  ],
})

/** Tools whose calls are recorded in the local scan history. */
const LOGGED_SCAN_TOOLS = new Set(['scan_page', 'flow_scan', 'scan_html', 'visual_audit', 'check_aria', 'verify_fix'])

/**
 * First-line failure sniff across every tool's error shapes. Superset of the
 * old scan-only pattern (`Scan failed:` / `Error:` / `Blocked URL:` /
 * `… failed:`), extended for the non-scan tools: "Detection failed:",
 * "AI fix failed:", "AI service unavailable (503)…", "Visual audit error:",
 * "Visual audit failed (500):", "Could not parse colors.", "Unknown tool: x".
 */
const looksFailed = (text: string): boolean =>
  /^(Scan failed|Error|Blocked URL|.*failed):/i.test(text) ||
  /^(Unknown tool|Could not parse|AI service unavailable)\b/i.test(text) ||
  /^.*(?:failed|error) \(\d+\):/i.test(text) ||
  /^.*error:/i.test(text)

const handleCallTool = async (request: CallToolRequest, opts: ServerOptions = {}) => {
  // EVERY tool call is wrapped here, including failures:
  //  - telemetry event (tool, small target label, ok, duration, counts, tiny
  //    meta — never page content) → platform API, ALL tools, both modes;
  //    opt-out via WEBABILITY_SCAN_TELEMETRY=off
  //  - local file log + scan_history: scan-shaped tools on local installs
  //    only (the hosted server is multi-tenant and must not accumulate other
  //    users' full results)
  //  - structured stdout line: hosted mode, for live tailing in Dozzle
  const toolName = request.params.name
  const started = Date.now()
  const target = describeTelemetryTarget(toolName, request.params.arguments as Record<string, unknown> | undefined)
  const response = await dispatchTool(request, opts)
  const durationMs = Date.now() - started
  const firstText = Array.isArray((response as any)?.content)
    ? ((response as any).content.find((c: any) => c?.type === 'text')?.text ?? '')
    : ''
  const ok = !looksFailed(firstText)
  const { summary, meta } = extractToolTelemetry(toolName, response)

  if (LOGGED_SCAN_TOOLS.has(toolName) && !opts.remote && scanLogEnabled()) {
    // Persist the FULL (pre-truncation) result when the handler recorded one,
    // so scan_history can recover findings that were clipped from the capped
    // response the caller received. Falls back to the response itself for
    // tools that don't truncate.
    const archived =
      response && typeof response === 'object'
        ? fullScanResultByResponse.get(response as object)
        : undefined
    recordScan(
      {
        id: newScanId(toolName),
        timestamp: new Date(started).toISOString(),
        tool: toolName,
        target,
        durationMs,
        ok,
        summary: String(firstText).slice(0, 300),
      },
      archived ?? response,
    )
  }

  if (opts.remote) {
    // One structured line per tool call on stdout — `docker logs` / Dozzle-
    // friendly. Scan-shaped tools keep the original `scan` type for existing
    // log consumers; everything else is a `tool` line.
    const type = LOGGED_SCAN_TOOLS.has(toolName) ? 'scan' : 'tool'
    console.error(JSON.stringify({ type, ts: new Date(started).toISOString(), tool: toolName, target, ok, durationMs, summary, ...(meta ? { meta } : {}) }))
  }

  reportScanEvent({ tool: toolName, target, source: opts.remote ? 'hosted' : 'local', ok, durationMs, summary, meta })

  return response
}

const dispatchTool = async (request: CallToolRequest, opts: ServerOptions = {}) => {
  const { name, arguments: args } = request.params

  if (name === 'scan_history') {
    if (opts.remote) return { content: [{ type: 'text', text: 'scan_history is not available in remote mode.' }] }
    const id = args?.id as string | undefined
    if (id) {
      const stored = readScanResult(id)
      if (!stored) return { content: [{ type: 'text', text: `No stored scan with id "${id}" (it may have been pruned — the last 500 full results are kept).` }] }
      return { content: [{ type: 'text', text: '```json\n' + JSON.stringify(stored, null, 2) + '\n```' }] }
    }
    const entries = readScanHistory((args?.limit as number) || 20, args?.filter as string | undefined)
    if (entries.length === 0) {
      return { content: [{ type: 'text', text: `No scans logged yet${args?.filter ? ` matching "${args.filter}"` : ''}. History is written to ${scanLogDir()} (set WEBABILITY_SCAN_LOG=off to disable).` }] }
    }
    const lines = entries.map((e) => `${e.timestamp}  [${e.tool}] ${e.target} — ${e.ok ? 'ok' : 'FAILED'} (${e.durationMs}ms)  id=${e.id}\n    ${e.summary.split('\n')[0]}`)
    return {
      content: [
        { type: 'text', text: `${entries.length} scan(s), newest first (full result: call scan_history with the id):\n\n${lines.join('\n')}` },
      ],
    }
  }

  // Hardening for the hosted/remote (HTTP) transport: the server is internet-reachable,
  // so block local-filesystem tools and validate every outbound URL (SSRF) before any fetch.
  if (opts.remote) {
    if (name === 'find_source') {
      return { content: [{ type: 'text', text: 'find_source is disabled on the hosted MCP server — it searches a local project, which does not exist server-side.' }] }
    }
    const candidateUrls = [
      args?.url,
      args?.startUrl,
      ...(Array.isArray(args?.autoNavigate) ? (args!.autoNavigate as unknown[]) : []),
    ].filter((v): v is string => typeof v === 'string' && v.length > 0)
    for (const candidate of candidateUrls) {
      try {
        await assertSafeUrl(candidate)
      } catch (e) {
        return { content: [{ type: 'text', text: `Blocked URL: ${(e as Error).message}` }] }
      }
    }
  }

  if (name === 'scan_page') {
    const url = args?.url as string
    if (!url) return { content: [{ type: 'text', text: 'Error: url is required' }] }

    try {
      const result = await scan(url, {
        rootSelector: args?.rootSelector as string | undefined,
        viewport: (args?.viewport as any) || 'desktop',
        dismissModals: true,
        browser: { headless: true, timeout: 30000 },
      })

      // Blocked / bot-challenge guard — the target served a Cloudflare/Akamai/
      // PerimeterX interstitial or an HTTP error instead of the real page, so
      // `issues` is EMPTY not because the page is clean but because nothing real
      // was scanned. Surface an explicit signal so the caller (or a CI pipeline)
      // never reads this as a passing scan.
      if (result.blocked) {
        const b = result.blocked
        const blockedPayload = {
          url,
          blocked: true,
          reason: b.reason,
          ...(b.vendor ? { vendor: b.vendor } : {}),
          ...(typeof b.status === 'number' ? { status: b.status } : {}),
          ...(b.signal ? { signal: b.signal } : {}),
          summary: result.summary,
          issues: [],
          incomplete: [],
        }
        return {
          content: [
            {
              type: 'text',
              text:
                `BLOCKED: ${url} was not actually scanned. ${b.reason}` +
                ` This is NOT a clean result — do not report the page as accessible or issue-free.` +
                (b.vendor ? ` Detected vendor: ${b.vendor}.` : '') +
                (typeof b.status === 'number' ? ` HTTP ${b.status}.` : ''),
            },
            { type: 'text', text: '```json\n' + JSON.stringify(blockedPayload, null, 2) + '\n```' },
          ],
        }
      }

      const projectIssue = (i: typeof result.issues[number]) => ({
        id: i.id,
        impact: i.impact,
        wcag: i.wcag,
        type: i.type,
        message: i.message,
        selector: i.selector,
        html: i.html?.slice(0, 400),
        fix: i.fix,
        ...(i.confidence ? { confidence: i.confidence } : {}),
        ...(i.reviewReason ? { reviewReason: i.reviewReason } : {}),
      })

      // The payload arrays are capped so a huge scan doesn't blow the tool-result
      // token budget. Surface the cap explicitly (bug: a 261-issue page silently
      // returned only 50 with no signal the list was clipped).
      //
      // Sort by severity (critical → minor) BEFORE capping: otherwise the cap is
      // applied to the raw detector order and can drop every critical issue while
      // keeping low-severity ones (observed on a page with 9 critical / 17 serious
      // / 132 moderate — the 50 returned were 0 critical because moderates sorted
      // first). Sorting guarantees the most important findings always survive the
      // cap.
      const RESULT_CAP = 50
      const sortedIssues = bySeverityDesc(result.issues)
      const sortedIncomplete = bySeverityDesc(result.incomplete)
      const issuesTotal = sortedIssues.length
      const incompleteTotal = sortedIncomplete.length
      const issuesTruncated = issuesTotal > RESULT_CAP
      const incompleteTruncated = incompleteTotal > RESULT_CAP

      const payload = {
        url,
        summary: result.summary,
        framework: (result as any).framework || 'plain-css',
        truncated: issuesTruncated || incompleteTruncated,
        issues: sortedIssues.slice(0, RESULT_CAP).map(projectIssue),
        issuesReturned: Math.min(issuesTotal, RESULT_CAP),
        issuesTotal,
        incomplete: sortedIncomplete.slice(0, RESULT_CAP).map(projectIssue),
        incompleteReturned: Math.min(incompleteTotal, RESULT_CAP),
        incompleteTotal,
      }

      const incompleteCount = result.summary.incomplete ?? 0
      const truncationNote =
        issuesTruncated || incompleteTruncated
          ? ` NOTE: results truncated to the ${RESULT_CAP} highest-severity of each list (sorted critical→minor, so criticals are never dropped) — showing ${payload.issuesReturned}/${issuesTotal} issue(s) and ${payload.incompleteReturned}/${incompleteTotal} incomplete finding(s). Retrieve the FULL untruncated set via \`scan_history\` (pass this scan's id), or narrow \`rootSelector\` to shrink the page.`
          : ''
      const summary =
        `Found ${result.summary.total} high-confidence issue(s) on ${url}: ` +
        `${result.summary.critical} critical, ${result.summary.serious} serious, ` +
        `${result.summary.moderate} moderate, ${result.summary.minor} minor.` +
        (incompleteCount > 0
          ? ` ${incompleteCount} additional finding(s) need human review (gradient backgrounds, marketing imagery, etc.) — see \`incomplete[]\`. Do NOT auto-fix these.`
          : '') +
        truncationNote

      const response = {
        content: [
          { type: 'text', text: summary },
          { type: 'text', text: '```json\n' + JSON.stringify(payload, null, 2) + '\n```' },
        ],
      }

      // Register the FULL, untruncated finding set (severity-sorted, same per-issue
      // projection) so scan_history persists every finding — including any clipped
      // from the capped response — rather than the already-truncated payload.
      if (issuesTruncated || incompleteTruncated) {
        fullScanResultByResponse.set(response, {
          content: [
            { type: 'text', text: summary },
            {
              type: 'text',
              text:
                '```json\n' +
                JSON.stringify(
                  {
                    ...payload,
                    truncated: false,
                    issues: sortedIssues.map(projectIssue),
                    issuesReturned: issuesTotal,
                    incomplete: sortedIncomplete.map(projectIssue),
                    incompleteReturned: incompleteTotal,
                  },
                  null,
                  2,
                ) +
                '\n```',
            },
          ],
        })
      }

      return response
    } catch (err) {
      return { content: [{ type: 'text', text: `Scan failed: ${(err as Error).message}` }] }
    }
  }

  if (name === 'verify_fix') {
    const url = args?.url as string
    const selector = args?.selector as string
    const wcag = (args?.wcag as string | undefined)?.trim() || undefined
    if (!url || !selector) return { content: [{ type: 'text', text: 'Error: url and selector are required' }] }

    try {
      // Re-scan scoped to the fixed element only — a focused, fast check rather
      // than a whole-page scan. Same engine and options as scan_page.
      const result = await scan(url, {
        rootSelector: selector,
        viewport: (args?.viewport as any) || 'desktop',
        dismissModals: true,
        browser: { headless: true, timeout: 30000 },
      })

      // A blocked page was NOT scanned — reporting it as "fixed" would be a lie
      // that ships a regression to production. Verification must fail closed.
      if (result.blocked) {
        const b = result.blocked
        return {
          content: [
            {
              type: 'text',
              text:
                `UNVERIFIED: ${url} was not actually scanned (${b.reason}${b.vendor ? `, ${b.vendor}` : ''}${typeof b.status === 'number' ? `, HTTP ${b.status}` : ''}). ` +
                `A blocked page is NOT proof the fix worked — re-run against a reachable URL (e.g. localhost or a staging URL).`,
            },
            { type: 'text', text: '```json\n' + JSON.stringify({ url, selector, ...(wcag ? { wcag } : {}), verified: false, reason: 'blocked', blocked: b }, null, 2) + '\n```' },
          ],
        }
      }

      // When a WCAG criterion / axe rule id is given, only that criterion counts;
      // otherwise ANY remaining violation on the element means "not fixed".
      const matchesWcag = (i: any) => !wcag || (typeof i.wcag === 'string' && i.wcag.includes(wcag)) || i.type === wcag || i.id === wcag
      const remaining = result.issues.filter(matchesWcag)
      const needsReview = result.incomplete.filter(matchesWcag)
      const resolved = remaining.length === 0

      const evidence = remaining.slice(0, 10).map((i: any) => ({
        id: i.id,
        wcag: i.wcag,
        type: i.type,
        impact: i.impact,
        message: i.message,
        selector: i.selector,
        html: i.html?.slice(0, 300),
      }))

      const payload = {
        url,
        selector,
        ...(wcag ? { wcag } : {}),
        verified: resolved,
        remainingCount: remaining.length,
        remainingIssues: evidence,
        needsReview: needsReview.length,
      }

      const text = resolved
        ? `VERIFIED: no ${wcag ? `${wcag} ` : ''}violation remains on \`${selector}\` at ${url}.` +
          (needsReview.length ? ` (${needsReview.length} finding(s) on this element still need human review — see needsReview; verification does not cover those.)` : '') +
          ` Note: an empty result also happens when the selector no longer matches — expected if you removed the element, but if your fix changed its class/id, re-run scan_page to confirm the fix rather than a selector miss.`
        : `NOT RESOLVED: ${remaining.length} ${wcag ? `${wcag} ` : ''}violation(s) still present on \`${selector}\` at ${url}. The fix did not clear them — see remainingIssues[] for what remains.`

      return {
        content: [
          { type: 'text', text },
          { type: 'text', text: '```json\n' + JSON.stringify(payload, null, 2) + '\n```' },
        ],
      }
    } catch (err) {
      return { content: [{ type: 'text', text: `verify_fix failed: ${(err as Error).message}` }] }
    }
  }

  if (name === 'start_audit') {
    const url = args?.url as string
    if (!url) return { content: [{ type: 'text', text: 'Error: url is required' }] }
    if (/^https?:\/\/(localhost|127\.|\[::1\])/i.test(url)) {
      // The pipeline runs on our servers in every mode (even a local stdio MCP),
      // so it can never reach the developer's localhost.
      return { content: [{ type: 'text', text: 'start_audit runs server-side, so it cannot reach a localhost URL. Use a public or staging URL.' }] }
    }
    const token = resolveAuthToken()
    if (!token) {
      return { content: [{ type: 'text', text: 'start_audit requires a WebAbility account (it runs paid server-side browser/AI work). Log in with `webability login` or set WEBABILITY_API_KEY in your MCP server config, then retry. (scan_page and the other DOM-based tools need no account.)' }] }
    }

    try {
      const res = await fetch(`${API_URL}/cli/audit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ url, includeAgent: Boolean(args?.includeAgent) }),
      })
      if (res.status === 401 || res.status === 403) {
        return { content: [{ type: 'text', text: `start_audit could not authenticate (${res.status}). Your WebAbility token is missing, expired, or lacks access. Re-run \`webability login\` (or refresh WEBABILITY_API_KEY) and retry.` }] }
      }
      if (res.status === 429) {
        return { content: [{ type: 'text', text: 'start_audit is rate-limited (too many audits queued). Wait and retry.' }] }
      }
      if (!res.ok) {
        return { content: [{ type: 'text', text: `start_audit failed (${res.status}): ${await res.text()}` }] }
      }
      const data = (await res.json()) as { id: number; status: string; includeAgent?: boolean }
      return {
        content: [
          {
            type: 'text',
            text: `Audit #${data.id} queued for ${url}${data.includeAgent ? ' (with agent pass)' : ''}. The pipeline runs server-side — poll \`get_audit\` with id ${data.id} every ~15s for progress and download URLs.`,
          },
          { type: 'text', text: '```json\n' + JSON.stringify(data, null, 2) + '\n```' },
        ],
      }
    } catch (err) {
      return { content: [{ type: 'text', text: `start_audit error: ${(err as Error).message}` }] }
    }
  }

  if (name === 'get_audit') {
    const id = args?.id as number
    if (!id && id !== 0) return { content: [{ type: 'text', text: 'Error: id is required (from start_audit)' }] }
    const token = resolveAuthToken()
    if (!token) {
      return { content: [{ type: 'text', text: 'get_audit requires the same WebAbility account that started the audit. Log in with `webability login` or set WEBABILITY_API_KEY, then retry.' }] }
    }

    try {
      const res = await fetch(`${API_URL}/cli/audit/${encodeURIComponent(String(id))}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (res.status === 401 || res.status === 403) {
        return { content: [{ type: 'text', text: `get_audit could not authenticate (${res.status}). Re-run \`webability login\` (or refresh WEBABILITY_API_KEY) and retry.` }] }
      }
      if (res.status === 404) {
        return { content: [{ type: 'text', text: `No audit #${id} for this account. Check the id, and that you are the account that started it.` }] }
      }
      if (!res.ok) {
        return { content: [{ type: 'text', text: `get_audit failed (${res.status}): ${await res.text()}` }] }
      }
      const data = (await res.json()) as any
      const steps = Array.isArray(data.steps) ? data.steps.map((s: any) => `${s.step}:${s.status}`).join('  ') : ''
      let text: string
      if (data.status === 'complete') {
        const sum = data.summary ? `${data.summary.total} finding(s) (${data.summary.critical ?? 0} critical, ${data.summary.serious ?? 0} serious).` : 'complete.'
        const dl = data.downloads
          ? `\n\nDownloads (expire ~1h):\n- report: ${data.downloads.report}` + (data.downloads.workbook ? `\n- workbook (.xlsx): ${data.downloads.workbook}` : '\n- workbook: not built for this audit')
          : ''
        text = `Audit #${data.id} for ${data.url} — COMPLETE. ${sum}${dl}`
      } else if (data.status === 'failed') {
        text = `Audit #${data.id} for ${data.url} — FAILED${data.error ? `: ${data.error}` : ''}. Steps: ${steps}`
      } else {
        text = `Audit #${data.id} for ${data.url} — ${data.status}${data.currentStep ? ` (at ${data.currentStep})` : ''}. Steps: ${steps}. Poll again in ~15s.`
      }
      return { content: [{ type: 'text', text }, { type: 'text', text: '```json\n' + JSON.stringify(data, null, 2) + '\n```' }] }
    } catch (err) {
      return { content: [{ type: 'text', text: `get_audit error: ${(err as Error).message}` }] }
    }
  }

  if (name === 'flow_scan') {
    const startUrl = args?.startUrl as string
    if (!startUrl) return { content: [{ type: 'text', text: 'Error: startUrl is required' }] }
    const maxPages = (args?.maxPages as number) || 10
    const autoNav = (args?.autoNavigate as string[]) || []

    if (autoNav.length === 0) {
      return { content: [{ type: 'text', text: 'Error: flow_scan requires autoNavigate — the list of URLs in the journey to walk after startUrl. The MCP server is headless and cannot discover a journey interactively, so pass the steps explicitly. For a single page, use scan_page instead.' }] }
    }

    // Deterministic, sequential walk. The previous model raced a tight
    // `page.goto` loop against `framenavigated`-triggered, 600ms-debounced
    // scans keyed on `page.url()` at fire-time. Two bugs fell out of that:
    //  (1) an intermediate page's scheduled scan fired AFTER the loop had
    //      already navigated on, so it scanned the wrong (later) URL — the
    //      intermediate page was silently dropped with no signal (asked for
    //      3 gov.uk pages, got 2, no reason given).
    //  (2) scans landed mid-navigation on a half-parsed DOM, producing
    //      "missing skip link" / "missing landmark" findings that a direct
    //      scan_page of the same URL does NOT report.
    // flow_scan is non-interactive (it walks an explicit URL list), so there
    // is no reason to be event-driven. Visit one URL at a time, let the same
    // scan() pipeline scan_page uses handle render-settle, and record an
    // explicit per-page outcome so a skipped page always carries a reason.
    type PageOutcome = {
      requested: string
      status: 'scanned' | 'nav_failed' | 'scan_failed' | 'redirected_duplicate' | 'duplicate_request' | 'skipped_cap' | 'blocked'
      finalUrl?: string
      reason?: string
      issues?: any[]
      incomplete?: any[]
    }

    const normalize = (u: string) => (u.startsWith('http') ? u : `https://${u}`)
    const requested = [startUrl, ...autoNav].map(normalize)
    const outcomes: PageOutcome[] = []

    try {
      const pw = await import('playwright')
      const browser = await pw.chromium.launch({ headless: true })
      const context = await browser.newContext({ viewport: { width: 1280, height: 720 } })
      if (opts.remote) await installSsrfRoute(context)
      const page = await context.newPage()

      const requestedSeen = new Set<string>()
      const scannedFinalUrls = new Set<string>()
      let scannedCount = 0

      try {
        for (const target of requested) {
          if (scannedCount >= maxPages) {
            outcomes.push({ requested: target, status: 'skipped_cap', reason: `page limit reached (maxPages=${maxPages})` })
            continue
          }
          if (requestedSeen.has(target)) {
            outcomes.push({ requested: target, status: 'duplicate_request', reason: 'same URL requested earlier in the journey' })
            continue
          }
          requestedSeen.add(target)

          // Match scan_page's URL path exactly: goto domcontentloaded, then
          // let scan()'s waitForRenderSettle wait for `load` + animation
          // settle before any engine runs.
          let mainStatus: number | undefined
          try {
            const response = await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 30000 })
            // Capture the main-document HTTP status. scan_page's URL path reads
            // this from its own goto; here the caller navigates, so we thread it
            // into scan() below — otherwise a plain 4xx/5xx error page with no
            // challenge DOM markers would be scanned as a clean page.
            mainStatus = typeof response?.status === 'function' ? response.status() : undefined
          } catch (err) {
            outcomes.push({ requested: target, status: 'nav_failed', reason: `navigation failed: ${(err as Error).message}` })
            continue
          }

          const finalUrl = page.url()
          if (scannedFinalUrls.has(finalUrl)) {
            outcomes.push({ requested: target, status: 'redirected_duplicate', finalUrl, reason: `resolved to ${finalUrl}, which was already scanned` })
            continue
          }
          scannedFinalUrls.add(finalUrl)

          try {
            const r = await scan(page, { includeAxe: true, dismissModals: true, mainStatus })
            // Bot-challenge / interstitial guard — scan() sets `blocked` when the
            // DOM is a Cloudflare/PerimeterX/error page, not the real site. Record
            // it as NOT scanned (with the reason) so its empty issue list never
            // gets counted as a clean page.
            if (r.blocked) {
              outcomes.push({ requested: target, status: 'blocked', finalUrl, reason: r.blocked.reason })
            } else {
              outcomes.push({ requested: target, status: 'scanned', finalUrl, issues: r.issues, incomplete: r.incomplete })
              scannedCount++
            }
          } catch (err) {
            outcomes.push({ requested: target, status: 'scan_failed', finalUrl, reason: `scan failed: ${(err as Error).message}` })
          }
        }
      } finally {
        await browser.close().catch(() => {})
      }

      // Same per-issue projection scan_page returns, so a finding in a
      // multi-page flow is exactly as actionable as a single-page scan
      // (carries fix payload, confidence, reviewReason — previously dropped).
      const projectIssue = (i: any) => ({
        id: i.id,
        impact: i.impact,
        wcag: i.wcag,
        type: i.type,
        message: i.message,
        selector: i.selector,
        html: i.html?.slice(0, 400),
        fix: i.fix,
        ...(i.confidence ? { confidence: i.confidence } : {}),
        ...(i.reviewReason ? { reviewReason: i.reviewReason } : {}),
      })

      const scannedPages = outcomes.filter((o) => o.status === 'scanned')
      const droppedPages = outcomes.filter((o) => o.status !== 'scanned')

      // Dedupe across pages — same type+selector+wcag = one finding, tracking
      // which pages it appeared on. Keep `issues` / `incomplete` separate.
      const dedupAcrossPages = (source: 'issues' | 'incomplete') => {
        const map = new Map<string, any & { foundOn: string[] }>()
        for (const pr of scannedPages) {
          for (const issue of ((pr as any)[source] as any[]) || []) {
            const k = `${issue.type}::${issue.selector}::${issue.wcag}`
            const existing = map.get(k)
            if (existing) {
              if (!existing.foundOn.includes(pr.finalUrl!)) existing.foundOn.push(pr.finalUrl!)
            } else {
              map.set(k, { ...projectIssue(issue), foundOn: [pr.finalUrl!] })
            }
          }
        }
        return Array.from(map.values())
      }

      // Sort by severity (critical → minor) before capping — same guarantee as
      // scan_page: the RESULT_CAP must never drop a critical finding in favour of
      // a lower-severity one that happened to be deduped first.
      const unique = bySeverityDesc(dedupAcrossPages('issues'))
      const uniqueIncomplete = bySeverityDesc(dedupAcrossPages('incomplete'))

      const RESULT_CAP = 50
      const issuesTruncated = unique.length > RESULT_CAP
      const incompleteTruncated = uniqueIncomplete.length > RESULT_CAP

      const payload = {
        startUrl,
        pagesRequested: requested.length,
        pagesScanned: scannedPages.length,
        pages: outcomes.map((o) => ({
          requested: o.requested,
          status: o.status,
          ...(o.finalUrl ? { finalUrl: o.finalUrl } : {}),
          ...(o.reason ? { reason: o.reason } : {}),
          ...(o.status === 'scanned'
            ? { issueCount: o.issues?.length ?? 0, incompleteCount: o.incomplete?.length ?? 0 }
            : {}),
        })),
        summary: {
          uniqueIssues: unique.length,
          needsReview: uniqueIncomplete.length,
          pagesDropped: droppedPages.length,
        },
        truncated: issuesTruncated || incompleteTruncated,
        issues: unique.slice(0, RESULT_CAP),
        issuesTotal: unique.length,
        incomplete: uniqueIncomplete.slice(0, RESULT_CAP),
        incompleteTotal: uniqueIncomplete.length,
      }

      // Human-readable summary. Surface dropped pages EXPLICITLY — never
      // return fewer pages than requested without saying why.
      const droppedNote = droppedPages.length > 0
        ? `\n\n## Pages not scanned (${droppedPages.length})\n\n` +
          droppedPages.map((o) => `- ${o.requested} — ${o.status}: ${o.reason ?? 'no detail'}`).join('\n')
        : ''

      const renderLine = (i: any) =>
        `[${i.impact}] WCAG ${i.wcag} — ${i.message}\n  Selector: ${i.selector}\n  Found on: ${i.foundOn.join(', ')}` +
        (i.reviewReason ? `\n  ⚠ Review: ${i.reviewReason}` : '')

      const incompleteSection = uniqueIncomplete.length > 0
        ? `\n\n## Needs Review (${uniqueIncomplete.length}) — do NOT auto-fix\n\n` +
          uniqueIncomplete.slice(0, 20).map(renderLine).join('\n\n')
        : ''

      const response = {
        content: [
          {
            type: 'text',
            text:
              `# Flow Scan Report\n\n` +
              `Pages requested: ${requested.length}\n` +
              `Pages scanned: ${scannedPages.length}\n` +
              (droppedPages.length > 0 ? `Pages dropped: ${droppedPages.length} (see below)\n` : '') +
              `Unique high-confidence issues: ${unique.length}\n` +
              `Needs review: ${uniqueIncomplete.length}\n\n` +
              unique.slice(0, 30).map(renderLine).join('\n\n') +
              incompleteSection +
              droppedNote,
          },
          { type: 'text', text: '```json\n' + JSON.stringify(payload, null, 2) + '\n```' },
        ],
      }

      // Persist every unique finding (severity-sorted) to scan_history, not just
      // the capped set, so criticals clipped from the response stay recoverable.
      if (issuesTruncated || incompleteTruncated) {
        fullScanResultByResponse.set(response, {
          content: [
            response.content[0]!,
            {
              type: 'text',
              text:
                '```json\n' +
                JSON.stringify(
                  { ...payload, truncated: false, issues: unique, incomplete: uniqueIncomplete },
                  null,
                  2,
                ) +
                '\n```',
            },
          ],
        })
      }

      return response
    } catch (err) {
      return { content: [{ type: 'text', text: `Flow scan failed: ${(err as Error).message}` }] }
    }
  }

  if (name === 'detect_framework') {
    const url = args?.url as string
    if (!url) return { content: [{ type: 'text', text: 'Error: url is required' }] }

    try {
      const pw = await import('playwright')
      const browser = await pw.chromium.launch({ headless: true })
      const context = await browser.newContext()
      if (opts.remote) await installSsrfRoute(context)
      const page = await context.newPage()
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 })
      const fw = await detectFramework(page)
      await browser.close()
      return { content: [{ type: 'text', text: `Framework: ${fw.framework}` }] }
    } catch (err) {
      return { content: [{ type: 'text', text: `Detection failed: ${(err as Error).message}` }] }
    }
  }

  if (name === 'generate_ai_fix') {
    const issue = args?.issue as any
    const html = args?.html as string
    if (!issue || !html) return { content: [{ type: 'text', text: 'Error: issue and html required' }] }

    let brandColors = (args?.brandColors as string[] | undefined) || []
    let brandSource = brandColors.length > 0 ? 'arg' : 'none'
    const url = (args?.url as string | undefined) || ''

    // Auto-extract brand palette via scanner — only for contrast issues, where the platform prompt actually consumes it.
    const issueType = (issue.type || '') as string
    const isContrast = issueType.includes('contrast') || issue.wcag === '1.4.3' || issue.wcag === '1.4.11'
    if (brandColors.length === 0 && url && isContrast) {
      try {
        brandColors = await extractBrandPaletteFromUrl(url)
        brandSource = `scanner: ${url}`
      } catch (err) {
        // Soft failure — fall through with empty palette; server still generates the other 2 alternatives.
        brandSource = `extraction failed (${(err as Error).message.slice(0, 60)})`
      }
    }

    const framework = (args?.framework as string) || 'plain-css'

    try {
      const res = await fetch(`${API_URL}/cli/ai-fix`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          issue, html,
          context: args?.context || '',
          url,
          framework,
          brandColors,
        }),
      })

      if (!res.ok) {
        const attr = issue.fix?.attribute as string | undefined
        const suggested = (issue.fix?.suggestedValue as string | undefined) || ''
        // Only surface a deterministic fallback when the detector actually carries a
        // concrete value. For accessible-name issues (aria-label/alt/title) the
        // detector deliberately leaves the value empty and sets needsManualReview —
        // the name must come from the AI or a human. Emitting `aria-label=""` here
        // would DELETE the accessible name, which is strictly worse than doing
        // nothing. So never render an empty-valued attribute as a "fix".
        if (attr && suggested.trim()) {
          return { content: [{ type: 'text', text: `AI service unavailable (${res.status}). Deterministic fallback from the scanner: \`${attr}="${suggested}"\`` }] }
        }
        return { content: [{ type: 'text', text: `AI service unavailable (${res.status}) and no safe deterministic fallback exists for this "${issue.type || issue.wcag || 'accessibility'}" issue — it needs a real accessible name, which can't be inferred reliably. Mark it for manual review. Do NOT set ${attr ? `\`${attr}\`` : 'the attribute'} to an empty string; that would remove the accessible name and make the element worse than it is now. Retry generate_ai_fix once the AI service is back, or write a descriptive value by hand.` }] }
      }

      const data = await res.json() as { alternatives: any[] }

      // Choose the code-snippet shape by FIX TYPE, not just "print frameworkCode if present".
      // An attribute-level fix (aria-label, alt, role, tabindex, lang, title, aria-hidden, …)
      // is an HTML/JSX attribute change — on the web it's written the same way regardless of
      // CSS framework. The AI's `frameworkCode` is only meaningful for (a) styling fixes where
      // the attribute is `style`/`class`/`className` (contrast, focus ring, target size), or
      // (b) native mobile frameworks, where it carries native accessibility modifiers
      // (e.g. `.accessibilityLabel("…")`). Rendering `frameworkCode` for a web attribute fix
      // is how an aria-label fix ended up shaped like a CSS rule — `.x[aria-label='…'] {}` —
      // which is not something a developer can apply. So for web attribute fixes we
      // deterministically render `attribute="value"` and ignore the CSS-shaped snippet.
      const WEB_FRAMEWORKS = new Set(['tailwind', 'bootstrap', 'mui', 'wordpress', 'nextjs', 'plain-css'])
      const isStylingAttribute = (attr: string) => attr === 'style' || attr === 'class' || attr === 'className'
      const renderFixCode = (a: any) => {
        const attributeHtml = `${a.attribute}="${a.value}"`
        const isWebAttributeFix = WEB_FRAMEWORKS.has(framework) && a.attribute && !isStylingAttribute(a.attribute)
        // Web attribute fix → always the HTML attribute. Styling / native fixes → keep the
        // framework snippet, falling back to the attribute form when the AI omitted it.
        return isWebAttributeFix ? attributeHtml : (a.frameworkCode || attributeHtml)
      }
      const lines = (data.alternatives || []).map((a, i) =>
        `### Option ${i + 1}: ${a.label}\n**${a.attribute}** = \`${a.value}\`\n\n${a.explanation}\n\n\`\`\`\n${renderFixCode(a)}\n\`\`\``,
      ).join('\n\n---\n\n')

      const header = isContrast
        ? `# AI Fix Alternatives\n\n_Brand palette: ${brandColors.length} color${brandColors.length === 1 ? '' : 's'} (${brandSource})_\n\n`
        : `# AI Fix Alternatives\n\n`
      return {
        content: [{ type: 'text', text: `${header}${lines || 'No alternatives generated.'}` }],
      }
    } catch (err) {
      return { content: [{ type: 'text', text: `AI fix failed: ${(err as Error).message}` }] }
    }
  }

  if (name === 'visual_audit') {
    const url = args?.url as string
    if (!url) return { content: [{ type: 'text', text: 'Error: url is required' }] }
    const viewport = (args?.viewport as 'desktop' | 'tablet' | 'mobile') || 'desktop'
    const fullPage = args?.fullPage === true

    try {
      const pw = await import('playwright')
      const browser = await pw.chromium.launch({ headless: true })
      const sizes = { desktop: { width: 1280, height: 720 }, tablet: { width: 768, height: 1024 }, mobile: { width: 375, height: 667 } }
      const context = await browser.newContext({ viewport: sizes[viewport] })
      if (opts.remote) await installSsrfRoute(context)
      const page = await context.newPage()
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 })
      await page.waitForTimeout(800) // let JS-driven UI settle
      const buf = await page.screenshot({ fullPage, type: 'png' })
      await browser.close()
      const screenshot = buf.toString('base64')

      // visual_audit runs paid Claude vision, so the backend requires a device-flow JWT (#124).
      const token = resolveAuthToken()
      if (!token) {
        return { content: [{ type: 'text', text: 'visual_audit requires a WebAbility account. It runs a paid Claude-vision pass, so the backend is authenticated. Log in with the CLI (`webability login`) or set the WEBABILITY_API_KEY environment variable in your MCP server config, then retry. (scan_page, check_color_contrast and the other DOM-based tools need no account.)' }] }
      }

      const res = await fetch(`${API_URL}/cli/visual-audit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          screenshot, platform: 'web',
          screenName: url,
          brandColors: Array.isArray(args?.brandColors) ? args?.brandColors : [],
        }),
      })
      if (res.status === 401 || res.status === 403) {
        return { content: [{ type: 'text', text: `visual_audit could not authenticate (${res.status}). Your WebAbility token is missing, expired, or lacks access. Re-run \`webability login\` (or refresh WEBABILITY_API_KEY) and retry.` }] }
      }
      if (!res.ok) {
        return { content: [{ type: 'text', text: `Visual audit failed (${res.status}): ${await res.text()}` }] }
      }
      const data = await res.json() as { issues: any[]; count: number }
      const lines = data.issues.map((i, idx) =>
        `${idx + 1}. [${(i.severity as string).toUpperCase()}] WCAG ${i.wcag} — ${i.message}` +
        (i.region ? `\n   region: ${i.region.x},${i.region.y} ${i.region.width}x${i.region.height}px` : '') +
        (i.fix?.suggestedValue ? `\n   fix: ${i.fix.attribute} = ${i.fix.suggestedValue}` : '')
      ).join('\n\n')
      return { content: [{ type: 'text', text: `# Visual Audit: ${url}\n\nFound ${data.count} pixel-level issues.\n\n${lines || 'No visual issues detected.'}` }] }
    } catch (err) {
      return { content: [{ type: 'text', text: `Visual audit error: ${(err as Error).message}` }] }
    }
  }

  if (name === 'find_source') {
    const selector = args?.selector as string
    if (!selector) return { content: [{ type: 'text', text: 'Error: selector is required' }] }

    try {
      const rootDir = (args?.rootDir as string) || process.cwd()

      // Extract identifying tokens
      const tokens: string[] = []
      const idMatch = selector.match(/#([\w-]+)/)
      if (idMatch) tokens.push(idMatch[1])
      const classMatches = selector.match(/\.[\w\\/-]+/g)
      if (classMatches) classMatches.forEach((c) => {
        const cleaned = c.replace(/^\./, '').replace(/\\/g, '')
        if (cleaned.length > 3) tokens.push(cleaned)
      })
      // Attribute selectors carry the most stable, human-authored, verbatim-searchable
      // tokens (e.g. [data-testid="foo"], [aria-label="Some Label"], [name="bar"]).
      // Extract the VALUE portion for common operators (=, ~=, *=, ^=, $=, |=),
      // supporting both "double" and 'single' quoting plus unquoted values.
      const attrRegex = /\[\s*[\w:-]+\s*(?:[~^$*|]?=)\s*(?:"([^"]*)"|'([^']*)'|([^\]\s]+))\s*(?:[iIsS]\s*)?\]/g
      let attrMatch: RegExpExecArray | null
      while ((attrMatch = attrRegex.exec(selector)) !== null) {
        const value = attrMatch[1] ?? attrMatch[2] ?? attrMatch[3] ?? ''
        // Split multi-word values (e.g. an aria-label like "Some Label") into words,
        // mirroring how a hyphenated class/id stays a single searchable token.
        value.split(/\s+/).forEach((word) => {
          const cleaned = word.trim()
          if (cleaned.length > 3 && !tokens.includes(cleaned)) tokens.push(cleaned)
        })
      }

      if (tokens.length === 0) {
        return { content: [{ type: 'text', text: `No identifying tokens in selector "${selector}". Try a more specific selector.` }] }
      }

      const matches = new Set<string>()
      for (const token of tokens.slice(0, 5)) {
        // Never let a token be parsed as a flag (argument injection); `--` stops rg flag parsing.
        if (token.startsWith('-')) continue
        try {
          const { stdout } = await execFileAsync('rg', [
            '-l',
            '--type-add', 'web:*.{tsx,jsx,ts,js,vue,svelte,html,php,astro}',
            '-t', 'web',
            '--max-count', '10',
            '--',
            token,
            rootDir,
          ], { timeout: 5000 })
          stdout.split('\n').filter(Boolean).forEach((f) => matches.add(f))
        } catch {
          // No matches for this token, continue
        }
      }

      if (matches.size === 0) {
        return { content: [{ type: 'text', text: `No source files matched tokens: ${tokens.join(', ')}` }] }
      }

      const list = Array.from(matches).slice(0, 10).map((f) => `- ${f}`).join('\n')
      return {
        content: [{ type: 'text', text: `Source candidates for \`${selector}\`:\n\n${list}\n\nUse Read on the most likely file, then apply the fix.` }],
      }
    } catch (err) {
      return { content: [{ type: 'text', text: `Source lookup failed: ${(err as Error).message}` }] }
    }
  }

  if (name === 'scan_html') {
    const html = args?.html as string
    if (!html) return { content: [{ type: 'text', text: 'Error: html is required' }] }
    const tags = (args?.tags as string[]) || ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']
    const width = (args?.width as number) || 1280
    const height = (args?.height as number) || 800

    try {
      const pw = await import('playwright')
      const browser = await pw.chromium.launch({ headless: true })
      const context = await browser.newContext({ viewport: { width, height } })
      if (opts.remote) await installSsrfRoute(context)
      const page = await context.newPage()
      await page.setContent(html, { waitUntil: 'domcontentloaded' })
      const { runAxe } = await import('@webability/core')
      const result = await runAxe(page, tags)
      await browser.close()

      const violations = result.violations.map((v) => ({
        id: v.id,
        impact: v.impact,
        help: v.help,
        helpUrl: v.helpUrl,
        wcagTags: v.tags.filter((t) => t.startsWith('wcag')),
        nodes: v.nodes.slice(0, 5).map((n) => ({
          html: n.html.slice(0, 300),
          target: n.target,
          failureSummary: n.failureSummary,
        })),
      }))

      return {
        content: [
          { type: 'text', text: `${violations.length} violation${violations.length === 1 ? '' : 's'} found in HTML snippet (tags: ${tags.join(', ')}).` },
          { type: 'text', text: '```json\n' + JSON.stringify({ violations, passes: result.passes.length, incomplete: result.incomplete.length }, null, 2) + '\n```' },
        ],
      }
    } catch (err) {
      return { content: [{ type: 'text', text: `scan_html failed: ${(err as Error).message}` }] }
    }
  }

  if (name === 'get_rules') {
    const tags = args?.tags as string[] | undefined

    try {
      const axe = (await import('axe-core')).default as any
      const rules = axe.getRules(tags && tags.length > 0 ? tags : undefined) as Array<{
        ruleId: string
        description: string
        help: string
        helpUrl: string
        tags: string[]
      }>
      return {
        content: [
          { type: 'text', text: `${rules.length} rule${rules.length === 1 ? '' : 's'}${tags?.length ? ` matching [${tags.join(', ')}]` : ''}.` },
          { type: 'text', text: '```json\n' + JSON.stringify(rules, null, 2) + '\n```' },
        ],
      }
    } catch (err) {
      return { content: [{ type: 'text', text: `get_rules failed: ${(err as Error).message}` }] }
    }
  }

  if (name === 'check_color_contrast') {
    const fg = args?.foreground as string
    const bg = args?.background as string
    if (!fg || !bg) return { content: [{ type: 'text', text: 'Error: foreground and background are required' }] }
    const fontSize = (args?.fontSize as number) || 16
    const isBold = args?.isBold === true

    const ratio = getContrastRatio(fg, bg)
    if (ratio === 0) {
      return { content: [{ type: 'text', text: `Could not parse colors. Use hex (#RRGGBB) or rgb(r,g,b).` }] }
    }
    // WCAG large text: ≥18pt (≈24px) regular, or ≥14pt (≈18.66px) bold
    const isLarge = fontSize >= 24 || (isBold && fontSize >= 18.66)
    const aaThreshold = isLarge ? 3.0 : 4.5
    const aaaThreshold = isLarge ? 4.5 : 7.0
    const aaPass = ratio >= aaThreshold
    const aaaPass = ratio >= aaaThreshold

    const lines = [
      `Contrast ratio: ${ratio.toFixed(2)}:1 (${fg} on ${bg}, ${fontSize}px${isBold ? ' bold' : ''}, ${isLarge ? 'large' : 'normal'} text)`,
      `WCAG AA  (≥ ${aaThreshold}): ${aaPass ? 'PASS' : 'FAIL'}`,
      `WCAG AAA (≥ ${aaaThreshold}): ${aaaPass ? 'PASS' : 'FAIL'}`,
    ]

    if (!aaPass) {
      let palette = (args?.brandColors as string[] | undefined) || []
      let paletteSource = 'arg'
      const url = args?.url as string | undefined

      if (palette.length === 0 && url) {
        try {
          palette = await extractBrandPaletteFromUrl(url)
          paletteSource = `scanner: ${url}`
        } catch (err) {
          lines.push('', `Brand extraction failed: ${(err as Error).message}`)
        }
      }

      if (palette.length === 0) {
        lines.push('', 'No brand palette to suggest from. Pass `brandColors` or `url` (we extract the palette from the live page using our scanner).')
      } else {
        const candidates = palette
          .map((c) => ({ color: c, ratio: getContrastRatio(c, bg) }))
          .filter((c) => c.ratio > 0)
          .sort((a, b) => b.ratio - a.ratio)
        const aaCandidates = candidates.filter((c) => c.ratio >= aaThreshold)
        const aaaCandidates = candidates.filter((c) => c.ratio >= aaaThreshold)

        lines.push('', `Brand palette (${palette.length} colors, source: ${paletteSource}):`)
        if (aaCandidates.length === 0) {
          lines.push(`  No brand color passes AA on ${bg}. Best available: ${candidates[0]?.color || 'n/a'} (${candidates[0]?.ratio.toFixed(2) || '0'}:1)`)
        } else {
          lines.push(`  Brand colors passing AA  (≥ ${aaThreshold}): ${aaCandidates.slice(0, 3).map((c) => `${c.color} (${c.ratio.toFixed(2)}:1)`).join(', ')}`)
        }
        if (!aaaPass) {
          if (aaaCandidates.length === 0) {
            lines.push(`  No brand color passes AAA on ${bg}.`)
          } else {
            lines.push(`  Brand colors passing AAA (≥ ${aaaThreshold}): ${aaaCandidates.slice(0, 3).map((c) => `${c.color} (${c.ratio.toFixed(2)}:1)`).join(', ')}`)
          }
        }
      }
    }

    return { content: [{ type: 'text', text: lines.join('\n') }] }
  }

  if (name === 'check_aria') {
    const html = args?.html as string
    if (!html) return { content: [{ type: 'text', text: 'Error: html is required' }] }

    try {
      const pw = await import('playwright')
      const browser = await pw.chromium.launch({ headless: true })
      const context = await browser.newContext()
      if (opts.remote) await installSsrfRoute(context)
      const page = await context.newPage()
      await page.setContent(html, { waitUntil: 'domcontentloaded' })
      const { runAxe } = await import('@webability/core')
      // `cat.aria` alone MISSES `aria-hidden-focus` — axe tags that rule
      // `cat.name-role-value` (WCAG 4.1.2), not `cat.aria`. Without it a
      // focusable-yet-`aria-hidden` control (a serious, common real bug) slips
      // through as "no violations". Adding the name-role-value category also
      // pulls in the sibling accessible-name rules (button-name, link-name,
      // input-button-name, …) — all squarely ARIA/name-role-value concerns.
      const result = await runAxe(page, ['cat.aria', 'cat.name-role-value'])
      await browser.close()

      // Shared projection so `violations` and `incomplete` have identical shape.
      const projectAxe = (v: {
        id: string; impact: string; help: string; helpUrl: string
        nodes: Array<{ html: string; target: string[]; failureSummary?: string }>
      }) => ({
        id: v.id,
        impact: v.impact,
        help: v.help,
        helpUrl: v.helpUrl,
        nodes: v.nodes.slice(0, 5).map((n) => ({
          html: n.html.slice(0, 300),
          target: n.target,
          failureSummary: n.failureSummary,
        })),
      })

      const violations = result.violations.map(projectAxe)
      // Surface axe's `incomplete` bucket (mirrors scan_page). Dangling ARIA
      // references (e.g. `aria-labelledby="missing-id"`) land here, NOT in
      // `violations`, so dropping it silently hid real ARIA defects. These need
      // human review — do NOT auto-fix.
      const incomplete = result.incomplete.map(projectAxe)

      const summaryLine = violations.length === 0
        ? 'No ARIA violations found.'
        : `${violations.length} ARIA violation${violations.length === 1 ? '' : 's'} found.`
      const incompleteNote = incomplete.length > 0
        ? ` ${incomplete.length} finding(s) need human review (e.g. dangling ARIA references) — see \`incomplete[]\`. Do NOT auto-fix these.`
        : ''

      return {
        content: [
          { type: 'text', text: summaryLine + incompleteNote },
          { type: 'text', text: '```json\n' + JSON.stringify({ violations, incomplete }, null, 2) + '\n```' },
        ],
      }
    } catch (err) {
      return { content: [{ type: 'text', text: `check_aria failed: ${(err as Error).message}` }] }
    }
  }

  return { content: [{ type: 'text', text: `Unknown tool: ${name}` }] }
}

export function createServer(opts: ServerOptions = {}) {
  const server = new Server(
    { name: 'webability', version: '1.3.0' },
    { capabilities: { tools: {} }, instructions: INSTRUCTIONS },
  )
  server.setRequestHandler(ListToolsRequestSchema, handleListTools)
  server.setRequestHandler(CallToolRequestSchema, (req) => handleCallTool(req, opts))
  return server
}
