// Side-effect-free server module: builds a configured MCP Server with all tools.
// Both entry points (index.ts = stdio, http.ts = Streamable HTTP) import createServer from here.
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolRequest } from '@modelcontextprotocol/sdk/types.js'
import { aiFixFramework, detectPageStack, type PageStack } from './siteFramework.js'
import { resolveVerifyFixArgs, verifyFixTargetUrl, VERIFY_FIX_URL_KEYS } from './verifyFixArgs.js'
import { resolveGetRulesArgs, ruleIdMatches } from './getRulesArgs.js'
import { scan, getContrastRatio, extractSiteTheme, VIEWPORT_SIZES } from '@webability/core'
import { contrastLaunchesBrowser, contrastPalette } from './contrastPalette.js'

import { isTunnelUrl, parseTunnelTarget, type TunnelTarget, tunnelHeadersFor } from './tunnelAuth'
import { DeadlineError, withDeadline } from './deadline'
import { stratifiedCap } from './capStratified'
import { execFile } from 'child_process'
import { promisify } from 'util'
import { readFileSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'
import dnsPromises from 'dns/promises'
import { isIP } from 'net'
import type { BrowserContext } from 'playwright'
import { blockedUrlMessage, resolvedAddressFrom } from './blockedUrlMessage.js'
import { describeScanTarget, newScanId, readScanHistory, readScanResult, recordScan, scanLogDir, scanLogEnabled } from './scanLog.js'
import { describeTelemetryTarget, extractToolTelemetry, reportScanEvent } from './telemetry.js'
import { enablePostHogMcpAnalytics } from './posthog.js'
import { MCP_VERSION } from './version.js'
import { generateReportPdf, type PdfIssue } from './reportPdf.js'
import { axeRuleFixMeta, enrichIssue, webabilityRuleFixMeta, FIXABILITY_TIERS, type Fixability } from './fixOps.js'
import { INLINE_BUDGET, OUTPUT_CONTROL_PROPERTIES, controlsList, describeControls, filterIssues, isFiltered, parseOutputControls, renderFindingsBlock, scanLevel, type OutputControls } from './outputControls.js'
import { collectSourcePointers, findSourceCandidates, type SourcePointer } from './sourcePointers.js'
import { collapseRepeats, dropObsoleteParsing, mergeSameElement, nameFamilyKey, recountSummary, scanHeadline, truncationNote } from './scanShaping.js'
import { fastScanHtml } from './fastScan.js'
import { openSession } from './browser.js'
import { AccountError, addSite, createUpgradeLink, describeSite, findSite, INSTALL_SNIPPET, listSites } from './account.js'
import { ACCOUNT_TOOLS, signInRequired } from './signIn.js'
import { ToolRefusal, assertSelectorMatches, readElementColors, scopeAxeRules } from './pageChecks.js'

/** Every arg that can carry a URL the server will navigate to; the hosted SSRF guard checks all of them. */
export const HOSTED_URL_ARG_KEYS: string[] = [...new Set(['url', 'startUrl', 'baselineUrl', ...VERIFY_FIX_URL_KEYS])]

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
 * A refused or failed tool call. `isError: true` is how an MCP client tells a
 * refusal from a result; without it an agent reads the error text as success.
 */
function toolError(text: string): { content: Array<{ type: 'text'; text: string }>; isError: true } {
  return { content: [{ type: 'text', text }], isError: true }
}

/**
 * Associates a returned tool response with the FULL, pre-truncation scan result
 * so scan_history can persist the complete finding set even when the response
 * sent to the caller is capped to RESULT_CAP. Keyed by the response object so
 * nothing extra is ever serialized into the client-facing payload.
 */
const fullScanResultByResponse = new WeakMap<object, unknown>()

/**
 * Resolve a WebAbility auth token for Full tools that need a JWT (`visual_audit`, `start_audit`).
 * Free for the customer with a WebAbility account — the token identifies the account.
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
  /** Per-request WebAbility token for Full tools (visual_audit / start_audit). On the hosted
   *  HTTP endpoint this is the CALLER's own key (from their Authorization header). Free
   *  with a WebAbility account; the token identifies the account.
   *  When unset, tools fall back to resolveAuthToken() (stdio env/CLI). */
  authToken?: string
  /** Hosted request with NO credentials (partial-auth mode). The account tools
   *  (visual_audit / start_audit / get_audit) must refuse — never fall back to
   *  resolveAuthToken(), which on the hosted deploy is the operator's own key
   *  and would run anonymous traffic on the operator's account. */
  anonymous?: boolean
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
async function installSsrfRoute(context: BrowserContext, tunnel: TunnelTarget | null = null): Promise<void> {
  await context.route('**/*', async (route) => {
    try {
      const requestUrl = route.request().url()
      await assertSafeUrl(requestUrl)
      // Per-request, deliberately. setExtraHTTPHeaders is context-wide and has
      // already leaked a per-site token to every third-party script on a
      // scanned page in this codebase. tunnelHeadersFor returns {} unless this
      // exact request is going to this exact tunnel.
      const extra = tunnelHeadersFor(requestUrl, tunnel)
      if (Object.keys(extra).length > 0) {
        await route.continue({ headers: { ...route.request().headers(), ...extra } })
        return
      }
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

/**
 * Open a page THIS process controls, with the tunnel header installed.
 *
 * `scan()` accepts a URL or a page. Given a URL it launches its own browser
 * with no route hook, so the tunnel header is never attached and the relay
 * refuses every request — the tools this whole feature is for (scan_page,
 * verify_fix) silently could not use it. Given a page, it scans what we hand
 * it, so the header rides along.
 *
 * Only used when a tunnel target exists. Ordinary scans keep the existing path
 * untouched, which is the one with all the production mileage on it.
 */
/** Viewport for a tunnelled scan. scan() resolves presets itself for the URL
 *  path; when we open the page we have to resolve it here instead. */
function VIEWPORT_FOR_TUNNEL(preset: unknown): { width: number; height: number } {
  if (preset === 'mobile') return { width: 390, height: 844 }
  if (preset === 'tablet') return { width: 820, height: 1180 }
  return { width: 1280, height: 800 }
}

async function withTunnelPage<T>(url: string, tunnel: TunnelTarget | null, viewport: { width: number; height: number }, fn: (page: any, status?: number) => Promise<T>, remote: boolean): Promise<T> {
  const session = await openSession({
    remote,
    contextOptions: { viewport },
    // A tunnel always installs the relay guard; with no tunnel the guard is
    // the hosted SSRF block, so a local run must not install it (localhost).
    setupContext: (context) => (tunnel || remote ? installSsrfRoute(context, tunnel) : undefined),
  })
  try {
    const response = await session.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 })
    return await fn(session.page, typeof response?.status === 'function' ? response.status() : undefined)
  } finally {
    await session.close()
  }
}

/**
 * scan_page / diff_scan page driver. Navigates the page HERE (instead of
 * handing core a URL) so the live DOM is still open after the engines run —
 * that is where React/Vue dev builds keep the component tree, and one
 * `collectSourcePointers` evaluate turns every finding into `file:line
 * (Component)`. Mirrors core's URL path: same goto, same viewport presets,
 * main-document status threaded into scan() for error-page detection.
 */
async function scanWithSourcePointers(
  rawUrl: string,
  tunnel: TunnelTarget | null,
  viewportPreset: unknown,
  scanOptions: Record<string, unknown>,
  remote: boolean,
): Promise<{ result: Awaited<ReturnType<typeof scan>>; pointers: Record<string, SourcePointer>; framework?: PageStack }> {
  const url = rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`
  const scanOpenPage = async (page: any, mainStatus?: number) => {
    const result = await scan(page, { ...scanOptions, mainStatus } as any)
    if (result.blocked) return { result, pointers: {} }
    const pointers = await collectSourcePointers(page, result.issues.map((i) => i.selector))
    // The SAME function detect_framework calls, read from the page the scan
    // just used, so the two tools cannot disagree.
    let framework: PageStack | undefined
    try {
      framework = await detectPageStack(page)
    } catch {
      framework = undefined
    }
    return { result, pointers, framework }
  }
  // Tunnelled: the existing driver already installs the relay route before
  // the first navigation — reuse it rather than duplicate that invariant.
  if (tunnel) return withTunnelPage(url, tunnel, VIEWPORT_FOR_TUNNEL(viewportPreset), (page) => scanOpenPage(page), remote)

  const viewport = (VIEWPORT_SIZES as Record<string, { width: number; height: number }>)[String(viewportPreset || 'desktop')] ?? VIEWPORT_SIZES.desktop
  const session = await openSession({
    remote,
    contextOptions: { viewport },
    setupContext: (context) => (remote ? installSsrfRoute(context, null) : undefined),
  })
  try {
    const response = await session.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 })
    return await scanOpenPage(session.page, typeof response?.status === 'function' ? response.status() : undefined)
  } finally {
    await session.close()
  }
}

/**
 * Lite-only fallback for production builds (no fibers): grep `sourceRoot`
 * for the selector's tokens. Capped so a 200-issue page costs at most ten
 * rg runs; issues that already carry a framework pointer are skipped.
 */
async function attachSourceCandidates<T extends { selector: string; source?: SourcePointer; sourceCandidates?: string[] }>(issues: T[], sourceRoot: string | undefined, remote: boolean): Promise<void> {
  if (!sourceRoot || remote) return
  const cache = new Map<string, string[]>()
  let lookups = 0
  for (const i of issues) {
    if (i.source?.file) continue
    if (!cache.has(i.selector)) {
      if (lookups >= 10) continue
      lookups++
      cache.set(i.selector, await findSourceCandidates(i.selector, sourceRoot))
    }
    const files = cache.get(i.selector)!
    if (files.length) i.sourceCandidates = files
  }
}

/** The findings block: JSON, compact, or compact + JSON summary when the JSON overflows the inline budget (see renderFindingsBlock). */
const renderFindings = renderFindingsBlock

/** The tunnel a tool call targets, paired with its secret. verify_fix reads the
 *  same resolved URL its handler loads (empty `url` falls through to `page` /
 *  `pageUrl`), so an aliased tunnel URL still carries its secret header. */
export function tunnelTargetForCall(name: string, args: Record<string, unknown> | undefined): TunnelTarget | null {
  const a = (args ?? {}) as any
  const raw = name !== 'verify_fix' ? a.url ?? a.startUrl ?? '' : verifyFixTargetUrl(args) ?? ''
  return parseTunnelTarget(String(raw), String(a.tunnel_secret ?? ''))
}

/** Exported for palette-ssrf.e2e.ts: the guard's BEHAVIOUR needs a real
 *  browser and a real loopback listener, not a regex over this file. */
export async function extractBrandPaletteFromUrl(url: string, remote: boolean, tunnel: TunnelTarget | null = null): Promise<string[]> {
  // SSRF guard rationale below. The guard is installed by setupContext so the
  // HTTP/2 fallback context gets it too.
  const session = await openSession({
    remote,
    setupContext: (context) => (remote || tunnel ? installSsrfRoute(context, tunnel) : undefined),
  })
  try {
    // `remote`, exactly like every other browser context in this file — NOT
    // `tunnel`. Gating on the tunnel left the ordinary hosted palette fetch
    // with no SSRF guard at all, so a caller could point generate_ai_fix or
    // check_color_contrast at 169.254.169.254 and have our own cloud fetch it.
    // That is what DEV-1050 was fixing; a tunnel-only condition silently
    // undid it. The tunnel target still rides along so a tunnelled URL keeps
    // working, but it is not what decides whether the guard is installed.
    await session.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 })
    return await brandPaletteFromPage(session.page)
  } finally {
    await session.close()
  }
}

/** Brand palette (CSS vars + most-used colors, as hex) of an open page. */
async function brandPaletteFromPage(page: any): Promise<string[]> {
  const theme = await extractSiteTheme(page)
  const raw = [
    ...Object.values(theme.cssVars),
    ...theme.topBgColors.map((c) => c.color),
    ...theme.topTextColors.map((c) => c.color),
  ]
  const hexes = raw.map(rgbStringToHex).filter((h): h is string => !!h)
  return Array.from(new Set(hexes))
}

/** Server-side Full tools — runnable on hosted Full MCP only. Lite lists them as free upsell stubs. */
// MCP clients give up on a tool call at ~120s (hosted log: failures cluster at
// 126-137s). The whole call must end first, so the caller gets a reason
// instead of a bare client timeout. Capture is ~2s in practice; the vision
// call gets whatever the capture left.
const VISUAL_AUDIT_TOTAL_MS = 115_000
const VISUAL_AUDIT_CAPTURE_MS = 25_000

const FULL_ONLY_TOOLS = new Set(['visual_audit', 'start_audit', 'get_audit'])

const HOSTED_MCP_URL = 'https://mcp.webability.io/mcp'
const SMITHERY_INSTALL = 'webability/accessibility'

/** Prefix shown on Full tools in Lite tools/list so agents discover the free upgrade path. */
function fullToolLiteStubPrefix(toolName: string): string {
  return (
    `[Full — FREE with a WebAbility account. Not runnable in Lite. ` +
    `Connect hosted MCP at ${HOSTED_MCP_URL} (dashboard or Smithery: ${SMITHERY_INSTALL}), ` +
    `authenticate, then call \`${toolName}\`.] `
  )
}

function liteFullUpgradeMessage(toolName: string): string {
  return (
    `\`${toolName}\` runs on **WebAbility MCP Full** (hosted) — free with a WebAbility account. ` +
    `Connect ${HOSTED_MCP_URL}/auth, which asks you to sign in when you connect (or ${HOSTED_MCP_URL} via the dashboard or Smithery: ${SMITHERY_INSTALL}), then retry. ` +
    `Lite keeps scan / fix / verify free with no account.`
  )
}

function buildInstructions(isLite: boolean): string {
  const edition = isLite
    ? `This is **WebAbility MCP Lite** (local, free, no account). Scan / fix / verify / report-PDF run on this machine.
\`visual_audit\`, \`start_audit\`, and \`get_audit\` are listed so you know they exist — they are **free with a WebAbility account** on hosted Full at ${HOSTED_MCP_URL} (dashboard / Smithery: ${SMITHERY_INSTALL}). When the user needs vision or a compliance report, tell them to connect Full (still free; a free account is all it needs). To sign in from this machine, run \`webability login\` (from \`@webability/cli\`).`
    : `This is **WebAbility MCP** (hosted Full). Free for everyone. Scan and check tools work with no account or key, under fair-use limits per IP. A free WebAbility account unlocks \`visual_audit\`, \`start_audit\` and \`get_audit\`; called without one, they return the sign-in steps for each client. An AI agent with its own AgentMail inbox can sign itself up: choose "Sign in with AgentID" on the WebAbility sign-in page. A signed-in agent can then set up a site with no human: \`add_site\`, \`get_install_snippet\`, and \`create_upgrade_link\` (a payment link it gives to its owner); \`list_sites\` shows each plan.`

  const routingExtra = isLite
    ? `- Vision / compliance report → \`visual_audit\` / \`start_audit\` (listed as Full stubs here; free with account on hosted Full at ${HOSTED_MCP_URL})
- "Turn these findings into a shareable PDF" → \`generate_report_pdf\` (local; pass the issues[] from scan_page)
- "What did we scan before" → \`scan_history\` (local only)`
    : `- "Catch issues axe misses (icon contrast, focus visibility, look-but-not-button)" → \`visual_audit\` (free with account)
- "I need a report to hand to a compliance officer / legal" → \`start_audit\`, then poll \`get_audit\` (free with account)
- \`find_source\` / \`scan_history\` / \`generate_report_pdf\` are not available on the hosted server`

  return `WebAbility is a web accessibility platform — AI-powered widget, scanner, and agents for WCAG 2.2 / ADA / Section 508 / EAA compliance. https://webability.io

${edition}

## Engines used by scan_page
- WebAbility detectors (60+ rules — gradient-aware contrast, weak names, decorative-icon detection, etc.)
- axe-core (104 rules)
- HTML_CodeSniffer (200+ rules)
Results from all three are deduplicated into one issue list.

## Output (the scanner judges uncertain findings itself)
\`scan_page\` and \`flow_scan\` return:
- **issues**: violations the scanner stands behind. A finding it cannot judge is resolved to a verdict (e.g. contrast on a gradient is measured from rendered pixels) or dropped.
- **summary**: counts by severity

## Structured fixes (since v1.6.0)
Every issue carries \`fix.op\` from a closed set — \`add-attribute\`, \`set-attribute\`, \`remove-attribute\`, \`add-element\`, \`remove-element\`, \`add-text-content\`, \`suggest\` — plus \`fix.attribute\` / \`fix.value\` when known, and a top-level \`fixability\`:
- **mechanical**: the value is known — apply it as given
- **contextual**: the op is known, the VALUE needs judgment (alt text, a label) — read \`html\` and \`message\`, then write it
- **visual**: needs rendered output (contrast, focus ring, target size) — propose, never auto-apply
On React ≤18 / Vue dev builds each issue also carries \`source\` (\`{file, line, column, component}\`) read from the live component tree — open that file directly instead of calling find_source. Pass \`sourceRoot\` (local only) to get \`sourceCandidates[]\` for production builds.

## Output controls (every scan tool)
\`minImpact\`, \`rules[]\`, \`wcag[]\` narrow the result; \`format: "compact"\` prints one line per element with rule metadata once — use it by default in a coding loop, it is a fraction of the tokens.

## Tool routing
- "Scan this page / URL / localhost" → \`scan_page\`
- "Walk through login → checkout" → \`flow_scan\` with \`autoNavigate\`
- "What does this WCAG rule check" → \`get_rules\`
- "Suggest a fix for this issue" → \`detect_framework\` then \`generate_ai_fix\`
- "Did my fix work?" → \`verify_fix\` (after you edit the code AND serve the change — closes scan → fix → verify)
- "What changed since the last scan / did I introduce regressions?" → \`diff_scan\` (baseline vs current → fixed / new / remaining)
- "Check this contrast pair" / "is this element's contrast OK" → \`check_color_contrast\` (a color pair, or \`url\` + \`selector\` to read the element's colors from the page; \`url\` also gives brand-aligned suggestions)
- "Check the ARIA on this page / this component" → \`check_aria\` with \`url\` (+ \`selector\` for one element) or \`html\`
- "Find where this selector lives in code" → \`find_source\` (Lite / local only)
- "Validate this HTML snippet / a component's markup" → \`scan_html\` (in-process, milliseconds, no browser — structural rules only; \`engine: "browser"\` for contrast) or \`check_aria\`
- "Give me a shareable report of these findings" → \`generate_report_pdf\` (Lite / local only)
${routingExtra}

## Important
- The core loop: \`scan_page\` → \`detect_framework\` → \`generate_ai_fix\` → edit source → \`verify_fix\`.
- Generated fix code edits the user's source — confirm before applying.
- The widget runtime applies its own client-side patches at runtime; do not duplicate those edits in source code.`
}

/**
 * Tools whose description promises localhost — true on stdio, FALSE on hosted.
 *
 * These take a URL and browse it, and the hosted server's SSRF guard refuses
 * loopback/RFC1918 before any fetch. Shipping one description for both
 * transports meant the hosted server advertised a capability it then refused
 * (DEV-1049). start_audit is absent on purpose: its description already says
 * "not localhost", because its pipeline is server-side in EVERY transport.
 */
const LOCALHOST_CAPABLE_TOOLS = new Set(['scan_page', 'flow_scan', 'verify_fix', 'diff_scan', 'detect_framework', 'generate_ai_fix', 'visual_audit', 'check_color_contrast', 'check_aria'])

/** Appended on the hosted transport so the calling model does not retry a refused localhost URL in a loop. */
const REMOTE_LOCALHOST_CAVEAT =
  ' NOTE: on this HOSTED server, localhost and private addresses are refused — it runs in our cloud and cannot reach your machine. Two ways to scan a local dev server: run the MCP locally (`npx -y @webability/mcp`, simplest — nothing leaves the machine), or open a tunnel (`webability-tunnel --port 3000`) and pass its URL as `url` together with the printed secret as `tunnel_secret`.'

const ALL_TOOLS = [
    {
      name: 'scan_page',
      description: 'Scan a web page for WCAG accessibility issues. Works on any URL — deployed sites, localhost, staging. Returns `issues` (violations the scanner stands behind; uncertain findings are judged or dropped, never listed for review) and a `summary`. On React ≤18 / Vue dev builds each issue carries `source` ({file, line, column, component}) read from the live component tree. Every issue carries a structured `fix.op` (add-attribute | set-attribute | remove-attribute | add-element | remove-element | add-text-content | suggest) with `fix.attribute` / `fix.value` when known, and a `fixability` tier (mechanical = apply as given; contextual = op known, value needs judgment; visual = needs rendered output, propose only).',
      inputSchema: {
        type: 'object' as const,
        properties: {
          url: { type: 'string', description: 'URL to scan (e.g. https://webability.io or http://localhost:3000)' },
          rootSelector: { type: 'string', description: 'CSS selector to limit scan scope (optional)' },
          viewport: { type: 'string', enum: ['desktop', 'tablet', 'mobile'], description: 'Viewport size (default: desktop)' },
          sourceRoot: { type: 'string', description: 'Local project root (local installs only). Issues without a framework `source` pointer get `sourceCandidates[]` — files whose contents match the selector\'s id/class/attribute tokens.' },
          ...OUTPUT_CONTROL_PROPERTIES,
        },
        required: ['url'],
      },
    },
    {
      name: 'verify_fix',
      description: 'Re-scan a specific element after applying an accessibility fix and confirm the violation is gone — closes the loop that find-only tools leave open. After you edit the code and serve it (deployed, staging, or http://localhost:3000), call this with the URL and the selector you fixed to get a machine-checked verified: true|false (DOM engines only — visual_audit findings are out of scope). Pass the WCAG criterion (e.g. "1.1.1") or axe rule id (e.g. "color-contrast") to check just that criterion; omit it to require the element be clean of ALL violations. A blocked page (bot-challenge / HTTP error) is reported as unverified, never a pass — verification fails closed. If the selector matches no element, the result is verified: false with reason "not-found" — pass the element\'s current selector, or re-run scan_page if your fix removed the element. Pair with scan_page → generate_ai_fix → verify_fix for a full find-fix-verify cycle.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          url: { type: 'string', description: 'URL now serving the fix (deployed, staging, or http://localhost:3000). Also accepted as `page` or `pageUrl`.' },
          selector: { type: 'string', description: 'CSS selector of the element you fixed — use the `selector` from the original scan_page issue' },
          wcag: { type: 'string', description: 'Optional: WCAG criterion (e.g. "1.1.1", "1.4.3") or axe rule id (e.g. "color-contrast") to verify specifically. Omit to require the element be free of ALL violations.' },
          viewport: { type: 'string', enum: ['desktop', 'tablet', 'mobile'], description: 'Viewport size (default: desktop). Use the same viewport the issue was found at.' },
        },
        required: ['url', 'selector'],
      },
    },
    {
      name: 'diff_scan',
      description: 'Compare two scans of the same page and report what changed: `fixed[]` (in the baseline, gone now), `new[]` (regressions — not in the baseline, present now), `remaining[]` (still there). Page-level complement to verify_fix (one element). Baseline is a scan_history id (`baselineId`, local installs) or a live scan of `baselineUrl`; current is `url` (scanned live now) or another history id (`currentId`). Findings are matched by issue id (rule + element), so a changed class/id on a fixed element reads as fixed AND new — check `new[]` before calling it a regression. Typical loop: scan_page → edit → diff_scan(baselineId=<that scan id>, url=<same url>) → confirm new[] is empty.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          url: { type: 'string', description: 'URL to scan now as the CURRENT side (deployed, staging, or http://localhost:3000). Omit when passing currentId.' },
          baselineId: { type: 'string', description: 'scan_history id of the BASELINE scan (local installs only)' },
          baselineUrl: { type: 'string', description: 'Scan this URL live as the baseline (e.g. production) — use when there is no stored baseline' },
          currentId: { type: 'string', description: 'scan_history id to use as the CURRENT side instead of scanning `url`' },
          rootSelector: { type: 'string', description: 'CSS selector to limit live scans to (optional)' },
          viewport: { type: 'string', enum: ['desktop', 'tablet', 'mobile'], description: 'Viewport for live scans (default: desktop). Use the same viewport the baseline used.' },
          ...OUTPUT_CONTROL_PROPERTIES,
        },
      },
    },
    {
      name: 'start_audit',
      description: 'Kick off a FULL accessibility audit deliverable for a URL — a persistent, timestamped artifact, not an inline scan. Runs the server-side pipeline (axe + advanced checks + mobile viewports + annotated screenshots + optional agent spot-check) and produces a downloadable report and a formatted Excel workbook (Cover / Status / Barriers / ADA context sheets) stored durably. Returns immediately with an audit `id`; poll `get_audit` for progress and, when complete, download URLs. Use this when someone needs a durable artifact to attach as evidence of testing effort for a compliance officer or legal response — for iterating on code, use scan_page + verify_fix instead. Free for everyone; needs a free WebAbility account (sign in by connecting https://mcp.webability.io/mcp/auth, or run `webability login`). Set includeAgent:true to add the slower agentic manual-audit pass. To audit a local dev server, open a tunnel (`webability-tunnel --port 3000`) and pass its URL as `url` with the printed secret as `tunnel_secret`; keep the tunnel open until get_audit reports complete (about 5 minutes) — the pipeline loads the page several times.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          url: { type: 'string', description: 'URL to audit (a public/staging URL the server can reach, or a webability-tunnel URL — not localhost)' },
          includeAgent: { type: 'boolean', description: 'Also run the agentic manual-audit pass (keyboard/focus/modal exploration). Slower. Default false.' },
          tunnel_secret: {
            type: 'string',
            description: 'Secret printed by `webability-tunnel`. Required when `url` is a tunnel URL; the URL alone will be refused by the relay. Ignored otherwise.',
          },
        },
        required: ['url'],
      },
    },
    {
      name: 'add_site',
      description: 'Add a website to the signed-in WebAbility account. The site gets the full widget for its first 30 days and a first scan. Returns the site id and plan tier. Next: put the get_install_snippet tag on the site, and use create_upgrade_link to get a payment link for the WebAbility Pro plan. Needs a free WebAbility account (an AI agent can sign itself up with "Sign in with AgentID").',
      inputSchema: {
        type: 'object' as const,
        properties: {
          url: { type: 'string', description: 'The site to add, for example https://shop.example.com. One domain per site.' },
        },
        required: ['url'],
      },
    },
    {
      name: 'list_sites',
      description: 'List the sites on the signed-in WebAbility account with each site id, plan tier and the date the current plan ends. Use it to check that a payment activated WebAbility Pro on a site. Needs a free WebAbility account.',
      inputSchema: { type: 'object' as const, properties: {} },
    },
    {
      name: 'get_install_snippet',
      description: 'Get the one-line script tag that installs the WebAbility accessibility widget. Put it in the <head> or before </body> of every page of a site added with add_site. The widget finds the site by its domain, so the same tag works on every site. No account needed.',
      inputSchema: { type: 'object' as const, properties: {} },
    },
    {
      name: 'create_upgrade_link',
      description: 'Get a Stripe Checkout link that puts one site on the WebAbility Pro plan (the widget subscription). Give the link to the human who pays (your owner). When they pay, the plan activates on that site automatically; check with list_sites. You never handle card details. The site must be on the account (add_site first). Needs a free WebAbility account.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          domain: { type: 'string', description: 'The site to upgrade, as added with add_site (for example shop.example.com)' },
          billing_interval: { type: 'string', enum: ['monthly', 'yearly'], description: 'Billing period. Default monthly.' },
        },
        required: ['domain'],
      },
    },
    {
      name: 'get_audit',
      description: 'Check an audit started with start_audit: returns overall status, per-step progress (scan → viewports → screenshots → agent → excel → publish), and — once complete — a severity summary plus short-lived download URLs for the report (JSON) and the Excel workbook. Poll every ~15s while status is pending/running. Only the account that started an audit can read it. Free with a WebAbility account.',
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
      description: 'Scan a multi-page user journey. Walks startUrl plus the required `autoNavigate` URLs sequentially (deterministic — one page fully rendered and scanned before the next), then returns ONE consolidated report with issues deduplicated across pages, each carrying the same fix payload as scan_page. Every requested URL gets an explicit outcome in `pages[]` (scanned / nav_failed / scan_failed / redirected_duplicate / duplicate_request / skipped_cap / blocked — bot-challenge, not a clean page) — a page is never silently dropped. Better than per-page scans for journeys (login → checkout etc). For a single page, use scan_page.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          startUrl: { type: 'string', description: 'Starting URL of the journey' },
          maxPages: { type: 'number', description: 'Max pages to scan (default 10)' },
          autoNavigate: { type: 'array', items: { type: 'string' }, description: 'REQUIRED — the URLs to walk after startUrl (the MCP server is headless and cannot discover a journey interactively). For a single page, use scan_page instead.' },
          sourceRoot: { type: 'string', description: 'Local project root (local installs only) for `sourceCandidates[]` on issues without a framework `source` pointer.' },
          ...OUTPUT_CONTROL_PROPERTIES,
        },
        required: ['startUrl', 'autoNavigate'],
      },
    },
    {
      name: 'detect_framework',
      description: 'Detect a page\'s stack as two separate fields: `framework` — the application framework, CMS or site builder (e.g. nextjs, nuxt, sveltekit, vitepress, astro, gatsby, wordpress, shopify, mediawiki, vue, react; "unknown" when no signal) — and `cssToolkit` (tailwind, bootstrap, mui, plain-css). Lists the evidence it used and the value to pass as generate_ai_fix `framework`. scan_page reports the same two fields from the same detection.',
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
          issue: { type: ['object', 'string'], description: 'Issue object from scan_page (with selector, wcag, impact, message, fix.currentValue), or a plain-text issue description' },
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
      description: 'Pixel-level accessibility audit using Claude vision. Catches issues that DOM scanners miss: icon contrast (1.4.11), focus visibility (2.4.7), "looks like a button but isn\'t" (4.1.2), text rendered as images (1.4.5), visual hierarchy mismatches. Takes a URL, opens it in a headless browser, screenshots, and runs vision-based detection. Complements scan_page — run both for full coverage. Free for everyone; sign in with a free WebAbility account for vision and full audits (sign in by connecting https://mcp.webability.io/mcp/auth, or run `webability login`). Fair-use rate limits apply.',
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
      description: 'Scan a raw HTML snippet or component markup without serving it — IN-PROCESS by default (jsdom + WebAbility detectors + axe-core): milliseconds, no browser, no network, so it fits inside a tight edit loop. Fragments are auto-wrapped into a document. Returns scan_page\'s shape (issues / summary) with `fix.op` + `fixability` on every finding. jsdom has no layout, so visual-tier rules (contrast, target size, focus ring) are NOT evaluated — the dropped count is reported as `skippedVisual`; pass `engine: "browser"` to run the axe-core headless-browser path for those (slower, axe rules only, returns axe `violations`).',
      inputSchema: {
        type: 'object' as const,
        properties: {
          html: { type: 'string', description: 'HTML content to test — a full document or a fragment' },
          engine: { type: 'string', enum: ['in-process', 'browser'], description: '"in-process" (default): jsdom, ms, structural rules. "browser": headless Chromium + axe-core, includes contrast.' },
          tags: { type: 'array', items: { type: 'string' }, description: 'WCAG tags to check (default ["wcag2a","wcag2aa","wcag21aa","wcag22aa"])' },
          width: { type: 'number', description: 'Viewport width (browser engine only, default 1280)' },
          height: { type: 'number', description: 'Viewport height (browser engine only, default 800)' },
          ...OUTPUT_CONTROL_PROPERTIES,
        },
        required: ['html'],
      },
    },
    {
      name: 'get_rules',
      description: 'List accessibility rules from both engines — axe-core (104) and the WebAbility detectors (90+) — with optional filters. Every rule carries `fixability` (mechanical | contextual | visual) and a `fix` op template, so you can pick the rules worth auto-fixing before scanning. Returns ruleId, engine, description, help, helpUrl, tags/wcag, fixability, fix.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          tags: { type: 'array', items: { type: 'string' }, description: 'axe tag filter (e.g. ["wcag2aa"], ["best-practice"], ["cat.aria"]; a category also works without "cat."). WebAbility rules match on their WCAG criterion tag (e.g. "wcag143"). An unknown tag or category is an error that lists the valid ones.' },
          rule: { type: 'string', description: 'Only rules whose id contains these whole words (e.g. "link" → link-name, skip-link, not blink; "color-contrast"; case and -/_ insensitive). Also accepted: ruleId, id, query.' },
          fixability: { type: 'string', enum: ['mechanical', 'contextual', 'visual'], description: 'Only rules of this fixability tier' },
          engine: { type: 'string', enum: ['all', 'axe', 'webability'], description: 'Which engine\'s rules to list (default all)' },
        },
      },
    },
    {
      name: 'check_color_contrast',
      description: 'Check text contrast against the WCAG AA threshold (4.5:1, or 3:1 for large text); the AAA verdict is shown only when you pass level: "AAA". Either pass a `foreground` / `background` color pair, or pass `url` + `selector` to read the element\'s own text color, background (composited from the nearest painted ancestors), font size and weight from the live page; explicit colors win over the page. A gradient or image background is reported as an error, never a guessed ratio. When it fails, suggests BRAND-aligned replacements — extracts the actual brand palette from the `url` page using our scanner (CSS vars + most-used colors), or use a provided `brandColors` array. No `url` and no `brandColors` = ratio + pass/fail only.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          foreground: { type: 'string', description: 'Foreground color (hex or rgb). Optional with url + selector.' },
          background: { type: 'string', description: 'Background color (hex or rgb). Optional with url + selector.' },
          fontSize: { type: 'number', description: 'Font size in px (default 16, or the element\'s computed size with url + selector)' },
          isBold: { type: 'boolean', description: 'Whether text is bold (default false, or the element\'s computed weight with url + selector)' },
          url: { type: 'string', description: 'Live page: with `selector`, the colors are read from that element; on a failing pair, the brand palette is extracted from it (uses our scanner — CSS vars + dominant colors).' },
          selector: { type: 'string', description: 'CSS selector of the text element on `url` (e.g. the `selector` from a scan_page issue)' },
          brandColors: { type: 'array', items: { type: 'string' }, description: 'Pre-supplied brand palette. Skips URL extraction if provided.' },
          level: { type: 'string', enum: ['AA', 'AAA'], description: 'Conformance level to judge. Default "AA". "AAA" adds the enhanced-contrast (1.4.6) verdict and AAA palette suggestions.' },
        },
      },
    },
    {
      name: 'check_aria',
      description: 'Validate ARIA attribute + accessible name/role/value usage — in an HTML snippet (`html`) or on a live page (`url`), optionally limited to one element and its descendants (`selector`). Runs axe-core `cat.aria` and `cat.name-role-value` rules (aria-* attribute correctness, role validity, required parents/children, aria-hidden-focus, accessible names). Returns `violations`. A selector that matches nothing, or a page that answers an HTTP error, is an error — never "no violations". Nodes cap at 5 per rule by default — every rule reports nodesTotal + truncated; raise nodeLimit (max 50) or use scan_history(id) for the full set.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          html: { type: 'string', description: 'HTML to test for ARIA correctness (pass this or `url`)' },
          url: { type: 'string', description: 'Live page to check (pass this or `html`)' },
          selector: { type: 'string', description: 'Only report findings on this element and its descendants (e.g. the `selector` from a scan_page issue). ARIA references outside it still resolve.' },
          nodeLimit: { type: 'number', description: 'Max nodes returned per rule (default 5, max 50)' },
        },
      },
    },
    {
      name: 'scan_history',
      description: 'Browse past scans run through this MCP server. Every scan_page / flow_scan / scan_html / visual_audit / check_aria / verify_fix call is logged locally (~/.webability/scans; local installs only — the hosted server keeps no history). Without arguments, lists recent scans (when, what target, result summary). Pass `id` to retrieve the FULL stored result of one past scan, or `filter` to match a URL/tool substring.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          limit: { type: 'number', description: 'Max history entries to return (default 20)' },
          filter: { type: 'string', description: 'Substring match on target URL or tool name (e.g. "webability.io" or "scan_page")' },
          id: { type: 'string', description: 'A scan id from the history list — returns that scan\'s full stored response' },
        },
      },
    },
    {
      name: 'generate_report_pdf',
      description: 'Turn scan findings into a branded WebAbility accessibility-report PDF, saved next to the project (local installs only). Pass the `issues[]` array a scan_page call returned plus the page `url`; the tool groups findings by functionality (Low Vision / Mobility / Navigation / Content / Cognitive), computes the WCAG score with the same penalty ladder as the platform, and renders a shareable PDF — free, no account. Use it when the user wants a deliverable to attach to an email, ticket, or compliance thread. Capped at 500 findings. For the full audit deliverable (Excel workbook + evidence screenshots), use start_audit instead.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          url: { type: 'string', description: 'The scanned page URL (used for the report header and file name)' },
          issues: {
            type: 'array',
            description: 'Findings to include — pass the `issues[]` array from scan_page (message/type/wcag/selector/html/impact/fix).',
            items: {
              type: 'object',
              properties: {
                message: { type: 'string' },
                type: { type: 'string' },
                wcag: { type: 'string' },
                selector: { type: 'string' },
                html: { type: 'string' },
                impact: { type: 'string', enum: ['critical', 'serious', 'moderate', 'minor'] },
                fix: { type: 'object', properties: { attribute: { type: 'string' }, suggestedValue: { type: 'string' } } },
              },
            },
          },
          widgetDetected: { type: 'boolean', description: 'Whether the WebAbility widget was detected on the page (shown in the report\'s widget status).' },
        },
        required: ['url', 'issues'],
      },
    },
  ]


/**
 * Behaviour hints every directory review checks (Claude connectors directory,
 * ChatGPT plugin directory): a human title plus EXPLICIT readOnly /
 * destructive / idempotent / openWorld booleans. "Read-only" means the tool
 * changes nothing in the user's environment; it may still fetch a page.
 * openWorld = it reaches a URL or a third-party service.
 */
type Hints = { title: string; readOnlyHint: boolean; destructiveHint: boolean; idempotentHint: boolean; openWorldHint: boolean }
const read = (title: string, openWorldHint: boolean): Hints => ({ title, readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint })
const TOOL_ANNOTATIONS: Record<string, Hints> = {
  scan_page: read('Scan a page for accessibility issues', true),
  verify_fix: read('Verify an accessibility fix', true),
  diff_scan: read('Compare two accessibility scans', true),
  start_audit: { title: 'Start a full accessibility audit', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  get_audit: read('Get audit status and report', true),
  add_site: { title: 'Add a site to the account', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  list_sites: read('List the account sites and plans', false),
  get_install_snippet: read('Get the widget install tag', false),
  create_upgrade_link: { title: 'Get a WebAbility Pro payment link', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  flow_scan: read('Scan a multi-page user flow', true),
  detect_framework: read('Detect the site framework', true),
  // Not read-only: both send page content (an HTML snippet / a screenshot) to
  // the WebAbility API and a third-party model, and visual_audit runs a
  // server-side vision pass. Clients must not auto-approve them as harmless reads. Not
  // idempotent either: model output varies between calls.
  generate_ai_fix: { title: 'Suggest a framework-aware fix', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  visual_audit: { title: 'Visual accessibility audit', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  find_source: read('Find the source file for a selector', false),
  scan_html: read('Scan an HTML snippet', false),
  get_rules: read('List accessibility rules', false),
  check_color_contrast: read('Check color contrast', true),
  check_aria: read('Validate ARIA in HTML or on a page', true),
  scan_history: read('List past scans', false),
  generate_report_pdf: { title: 'Create an accessibility report PDF', readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
}

function withAnnotations<T extends { name: string }>(tool: T): T & { title?: string; annotations?: Hints } {
  const annotations = TOOL_ANNOTATIONS[tool.name]
  return annotations ? { ...tool, title: annotations.title, annotations } : tool
}

/** Local-only recovery hint inside a tool description; stripped on hosted. */
const SCAN_HISTORY_HINT = ' or use scan_history(id) for the full set'

function handleListTools(opts: ServerOptions = {}) {
  const isLite = !opts.remote
  const tools = ALL_TOOLS
    .filter((tool) => {
      // Hosted Full: no local-filesystem / local-history tools
      if (!isLite && (tool.name === 'find_source' || tool.name === 'scan_history' || tool.name === 'generate_report_pdf')) return false
      return true
    })
    .map((tool) => {
      // Lite: keep Full tools visible as free-with-account stubs (stronger upgrade discovery)
      if (isLite && FULL_ONLY_TOOLS.has(tool.name)) {
        return { ...tool, description: fullToolLiteStubPrefix(tool.name) + tool.description }
      }
      // Hosted: correct the localhost promise rather than letting a tool
      // advertise something the SSRF guard will then refuse.
      if (!isLite && LOCALHOST_CAPABLE_TOOLS.has(tool.name)) {
        // The tunnel param is added HERE rather than in each tool definition:
        // it only means anything on the hosted transport, and advertising it
        // on the local MCP would invite people to stand up a relay they do not
        // need — locally, localhost is just localhost.
        return {
          ...tool,
          description: tool.description.replace(SCAN_HISTORY_HINT, '') + REMOTE_LOCALHOST_CAVEAT,
          inputSchema: {
            ...tool.inputSchema,
            properties: {
              ...(tool.inputSchema as any).properties,
              tunnel_secret: {
                type: 'string',
                description: 'Secret printed by `webability-tunnel`. Required when `url` is a tunnel URL; the URL alone will be refused by the relay. Ignored otherwise.',
              },
            },
          },
        }
      }
      // Hosted keeps no scan history, so no description may point there
      // (check_aria's node-cap hint did).
      if (!isLite && tool.description.includes(SCAN_HISTORY_HINT)) {
        return { ...tool, description: tool.description.replace(SCAN_HISTORY_HINT, '') }
      }
      return tool
    })
    .map(withAnnotations)
  return { tools }
}

/** Tools whose calls are recorded in the local scan history. */
const LOGGED_SCAN_TOOLS = new Set(['scan_page', 'flow_scan', 'scan_html', 'visual_audit', 'check_aria', 'verify_fix', 'diff_scan'])

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
  // isError is the tool's own verdict; the text match stays for older
  // handlers that return a failure without setting it.
  const ok = !(response as any)?.isError && !looksFailed(firstText)
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
    // Local history keeps the FULL target (query strings included): it never
    // leaves the machine, and scans of query- or fragment-distinct URLs must
    // stay distinguishable here. Only the telemetry/stdout `target` above is
    // scrubbed.
    recordScan(
      {
        id: newScanId(toolName),
        timestamp: new Date(started).toISOString(),
        tool: toolName,
        target: describeScanTarget(toolName, request.params.arguments as Record<string, unknown> | undefined),
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
  const name = request.params.name
  const args = stripAnalyticsArgs(name, request.params.arguments as Record<string, unknown> | undefined)

  // A tunnel target, derived once per call from the url + tunnel_secret the
  // caller supplied. Null for every ordinary scan, which is almost all of them
  // — and null means no header is ever attached to anything.
  // `url` for most tools, `startUrl` for flow_scan. Reading only `url` made
  // every tunnelled flow scan fail with a null target and no explanation.
  const tunnel: TunnelTarget | null = tunnelTargetForCall(name, args)

  // Lite (local stdio): Full tools are advertised as free stubs but not runnable here.
  if (!opts.remote && FULL_ONLY_TOOLS.has(name)) {
    return toolError(liteFullUpgradeMessage(name))
  }

  if (name === 'generate_report_pdf') {
    // Local-only like find_source: the PDF is written to the caller's project
    // directory, which does not exist server-side.
    if (opts.remote) return toolError('generate_report_pdf is not available on the hosted MCP server — it saves a file to your machine. Run the local MCP (`npx -y @webability/mcp`) to use it.')
    const url = args?.url as string
    const issues = args?.issues as PdfIssue[] | undefined
    if (!url || !Array.isArray(issues) || issues.length === 0) {
      return toolError('Error: url and a non-empty issues array are required — pass the `issues[]` from scan_page.')
    }
    try {
      const path = await generateReportPdf(url, issues, API_URL)
      const capped = issues.length > 500 ? ` (${issues.length} findings passed, first 500 included)` : ''
      return { content: [{ type: 'text', text: `Branded accessibility report written to ${path}${capped}. Attach it to an email, ticket, or compliance thread.` }] }
    } catch (err) {
      return toolError(`generate_report_pdf failed: ${(err as Error).message}`)
    }
  }

  if (name === 'scan_history') {
    if (opts.remote) return toolError('scan_history is not available in remote mode.')
    const id = args?.id as string | undefined
    if (id) {
      const stored = readScanResult(id)
      if (!stored) return toolError(`No stored scan with id "${id}" (it may have been pruned — the last 500 full results are kept).`)
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

  // Hosted anonymous call to an account tool: refuse as a tool result (never an
  // HTTP 401 — see signIn.ts), before the URL guard's DNS lookup and before any
  // browser or API work. These calls are in no rate-limit class.
  if (opts.anonymous && ACCOUNT_TOOLS.has(name)) return toolError(signInRequired(name))

  // Account tools call only our own API with the caller's token, so they run
  // before the hosted URL guard (which would DNS-check a site the agent has
  // not deployed yet).
  if (name === 'get_install_snippet') {
    return {
      content: [
        {
          type: 'text',
          text: `Put this tag in the <head> (or before </body>) of every page of the site:\n\n${INSTALL_SNIPPET}\n\nThe widget finds the site by its domain, so the site must be on the account (add_site).`,
        },
      ],
    }
  }
  if (name === 'add_site' || name === 'list_sites' || name === 'create_upgrade_link') {
    const token = opts.anonymous ? '' : (opts.authToken || resolveAuthToken())
    if (!token) return toolError(signInRequired(name))
    try {
      if (name === 'list_sites') {
        const sites = await listSites(API_URL, token)
        if (!sites.length) return { content: [{ type: 'text', text: 'No sites on this account yet. Add one with add_site.' }] }
        return { content: [{ type: 'text', text: `${sites.length} site(s):\n${sites.map(describeSite).join('\n')}` }] }
      }
      if (name === 'add_site') {
        const url = typeof args?.url === 'string' ? args.url : ''
        if (!url.trim()) return toolError('add_site needs a url, for example https://shop.example.com')
        const site = await addSite(API_URL, token, url)
        if (!site) return toolError(`WebAbility accepted ${url}, but it is not in the site list yet. Call list_sites in a minute.`)
        return {
          content: [
            {
              type: 'text',
              text: `Added ${site.url}.\n${describeSite(site)}\n\nNext:\n1. Install the widget: call get_install_snippet and put the tag on every page.\n2. For WebAbility Pro: call create_upgrade_link with domain ${site.url} and give the link to the person who pays.`,
            },
          ],
        }
      }
      const domain = typeof args?.domain === 'string' ? args.domain : ''
      if (!domain.trim()) return toolError('create_upgrade_link needs a domain, for example shop.example.com')
      const interval = String(args?.billing_interval || 'monthly').toLowerCase() === 'yearly' ? 'YEARLY' : 'MONTHLY'
      const site = findSite(await listSites(API_URL, token), domain)
      if (!site) return toolError(`${domain} is not on this account. Add it with add_site first, then call create_upgrade_link again.`)
      const link = await createUpgradeLink(API_URL, token, site, interval)
      return {
        content: [
          {
            type: 'text',
            text: `Payment link for the WebAbility Pro plan on ${site.url} (${interval.toLowerCase()} billing):\n\n${link}\n\nGive this link to your owner, the person who pays. The price shows on the page. When they pay, the plan activates on ${site.url} automatically; check with list_sites. The link expires in 24 hours.`,
          },
        ],
      }
    } catch (err) {
      if (err instanceof AccountError) return toolError(`${name}: ${err.message}`)
      return toolError(`${name} error: ${(err as Error).message}`)
    }
  }

  // Hardening for the hosted/remote (HTTP) transport: the server is internet-reachable,
  // so block local-filesystem tools and validate every outbound URL (SSRF) before any fetch.
  if (opts.remote) {
    if (name === 'find_source') {
      return toolError('find_source is disabled on the hosted MCP server — it searches a local project, which does not exist server-side.')
    }
    const candidateUrls = [
      ...HOSTED_URL_ARG_KEYS.map((k) => (args as Record<string, unknown> | undefined)?.[k]),
      ...(Array.isArray(args?.autoNavigate) ? (args!.autoNavigate as unknown[]) : []),
    ].filter((v): v is string => typeof v === 'string' && v.length > 0)
    for (const candidate of candidateUrls) {
      try {
        await assertSafeUrl(candidate)
      } catch (e) {
        // The guard is right to refuse; the old bare message read as a broken
        // product on the most obvious first thing a developer tries. Point
        // localhost/LAN attempts at the stdio server, which runs on THEIR
        // machine and scans localhost fine. Cloud-metadata and CGNAT stay
        // generic — see blockedUrlMessage.ts.
        const detail = (e as Error).message
        return toolError(blockedUrlMessage(detail, resolvedAddressFrom(detail)))
      }
    }
  }

  if (name === 'scan_page') {
    const url = args?.url as string
    if (!url) return toolError('Error: url is required')
    let controls: OutputControls
    try { controls = parseOutputControls(args as Record<string, unknown>) } catch (e) { return toolError(`Error: ${(e as Error).message}`) }

    try {
      const scanOptions = {
        rootSelector: args?.rootSelector as string | undefined,
        viewport: (args?.viewport as any) || 'desktop',
        dismissModals: true,
        browser: { headless: true, timeout: 30000 },
        level: scanLevel(controls),
      }
      const { result, pointers, framework } = await scanWithSourcePointers(url, tunnel, args?.viewport, scanOptions, Boolean(opts.remote))

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
          isError: true,
        }
      }

      const projectIssue = (i: typeof result.issues[number]) => enrichIssue({
        id: i.id,
        impact: i.impact,
        wcag: i.wcag,
        type: i.type,
        message: i.message,
        selector: i.selector,
        html: i.html?.slice(0, 400),
        fix: i.fix,
        ...(pointers[i.selector] ? { source: pointers[i.selector] } : {}),
      })
      type ProjectedIssue = ReturnType<typeof projectIssue> & { sourceCandidates?: string[] }

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
      // Output controls narrow BEFORE the cap, so `minImpact: "serious"` on a
      // 300-issue page returns every serious issue, not the serious subset of
      // the first 50. The archived scan_history copy stays unfiltered.
      //
      // Same-element findings that are one problem across engines are merged
      // first (scanShaping.mergeSameElement); the summary is recounted from
      // the merged lists, and the archive keeps them merged but not collapsed.
      // 4.1.1 Parsing is obsolete in WCAG 2.2 — those findings are dropped
      // (scanShaping.dropObsoleteParsing).
      const parsing = dropObsoleteParsing(result.issues.map(projectIssue) as ProjectedIssue[])
      const projectedIssues: ProjectedIssue[] = bySeverityDesc(mergeSameElement(parsing.issues))
      const mergedSummary = recountSummary(projectedIssues)
      await attachSourceCandidates(projectedIssues, args?.sourceRoot as string | undefined, Boolean(opts.remote))
      const filteredIssues = filterIssues(projectedIssues, controls)
      // With filters on, `summary` and the headline describe the FILTERED set
      // (persona round 4: "Found 67 … Returning 1"); the page-wide counts move
      // to `pageSummary`.
      const filtered = isFiltered(controls)
      const shownSummary = filtered ? recountSummary(filteredIssues) : mergedSummary
      // Repeats of one rule with one fix → one entry with `count` (after the
      // filters, so a caller who names the rule in rules[] sees every one).
      const collapsedIssues = collapseRepeats(filteredIssues, controls)
      const sortedIssues = collapsedIssues.list
      // Instance counts (every element) vs entry counts (after collapsing).
      const issuesTotal = filteredIssues.length
      const issueEntries = sortedIssues.length
      const issuesTruncated = issueEntries > RESULT_CAP
      // Stratify the cap: one representative per issue TYPE first, then fill by
      // severity. Without this, a majority type (e.g. 25 contrast_insufficient
      // moderates) can fill the entire moderate band and hide a whole type —
      // observed on squarespace.com (155 issues incl. 26 keyboard_trap; the
      // default response returned 0 of them, persona P007 round 3).
      const [capIssues, typesRescued] = stratifiedCap(sortedIssues, RESULT_CAP)
      const typeStratified = typesRescued

      const collapsedGroups = collapsedIssues.collapsedGroups
      const payload = {
        url,
        summary: shownSummary,
        ...(filtered ? { pageSummary: mergedSummary, filters: controlsList(controls) } : {}),
        // App framework (nextjs, sveltekit, wordpress… or "unknown") and the
        // CSS toolkit, from the same detectPageStack detect_framework runs.
        framework: framework?.framework ?? 'unknown',
        cssToolkit: framework?.cssToolkit ?? 'unknown',
        /** @deprecated Alias of cssToolkit, kept for JSON consumers of <= 1.6.4. Remove in a major release. */
        cssFramework: framework?.cssToolkit ?? 'unknown',
        ...(framework?.builder ? { builder: framework.builder } : {}),
        truncated: issuesTruncated,
        issues: capIssues,
        issuesReturned: capIssues.length,
        issueEntries,
        issuesTotal,
        ...(collapsedGroups > 0
          ? { counts: 'summary.* and issuesTotal count every element. issues[] holds issueEntries entries: an entry with `count` stands for that many elements of one rule with one fix (see `examples`, `expand`). issuesReturned counts entries.' }
          : {}),
      }

      const note = issuesTruncated
        ? truncationNote({ remote: Boolean(opts.remote), cap: RESULT_CAP, returned: payload.issuesReturned, total: issueEntries, stratified: typeStratified })
        : ''
      const summary =
        scanHeadline({ url, shown: shownSummary, ...(filtered ? { page: mergedSummary, filters: controlsList(controls) } : {}), issueEntries, collapsedGroups }) +
        note

      const response = {
        content: [
          { type: 'text', text: summary },
          renderFindings(
            controls,
            payload,
            [
              { title: 'Issues', items: payload.issues, total: issuesTotal, entries: issueEntries },
            ],
            { issues: sortedIssues },
          ),
        ],
      }

      // Always register the canonical archive: the FULL, unfiltered, untruncated
      // finding set as JSON. The caller's response may be capped, narrowed by
      // output controls, or rendered compact — none of those may reach
      // scan_history, or diff_scan cannot read the scan back as a baseline.
      {
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
                    // The archive is the whole page, whatever the caller filtered.
                    summary: mergedSummary,
                    pageSummary: undefined,
                    filters: undefined,
                    truncated: false,
                    counts: undefined,
                    issues: projectedIssues,
                    issuesReturned: projectedIssues.length,
                    issueEntries: projectedIssues.length,
                    issuesTotal: projectedIssues.length,
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
      return toolError(`Scan failed: ${(err as Error).message}`)
    }
  }

  if (name === 'verify_fix') {
    const resolvedVf = resolveVerifyFixArgs(args as Record<string, unknown> | undefined)
    if (resolvedVf.error) return toolError(resolvedVf.error)
    const url = resolvedVf.url as string
    const selector = resolvedVf.selector as string
    const wcag = resolvedVf.wcag
    if (!url || !selector) return toolError('Error: url and selector are required')

    // An unrecognized rule id matches NOTHING, so the old filter returned an
    // empty list and reported VERIFIED on an UNFIXED element — fail-closed
    // broken in the dangerous direction (persona P058 F5: wcag:"label" on a
    // still-labelled-less input verified true; the same after reverting a real
    // fix). Validate non-criterion ids against the real rule registries BEFORE
    // scanning and refuse to certify anything we cannot check.
    const isCriterion = (s: string) => /^\d+(\.\d+)*$/.test(s.trim())
    const normRule = (s: string) => s.trim().toLowerCase().replace(/-/g, '_')
    if (wcag && !isCriterion(wcag)) {
      const known = new Set<string>()
      try {
        const { WCAG_BY_ISSUE } = await import('@webability/core')
        for (const ruleId of Object.keys(WCAG_BY_ISSUE)) known.add(normRule(ruleId))
      } catch { /* registry unavailable — axe list below still applies */ }
      try {
        const axe = (await import('axe-core')).default as any
        for (const r of axe.getRules() as Array<{ ruleId: string }>) known.add(normRule(r.ruleId))
      } catch { /* axe unavailable — webability ids above still apply */ }
      if (known.size > 0 && !known.has(normRule(wcag))) {
        return {
          content: [
            {
              type: 'text',
              text:
                `UNVERIFIED: "${wcag}" is not a known rule id, so nothing was checked. ` +
                `Pass a WCAG criterion (e.g. "1.1.1", "1.4.3") or a rule id from get_rules (e.g. "image-alt", "missing_alt", "color-contrast").`,
            },
            { type: 'text', text: '```json\n' + JSON.stringify({ url, selector, wcag, verified: false, reason: 'unknown_rule' }, null, 2) + '\n```' },
          ],
          isError: true,
        }
      }
    }

    try {
      // Re-scan scoped to the fixed element only — a focused, fast check rather
      // than a whole-page scan. Same engine and options as scan_page.
      const verifyOptions = {
        // The caller named one rule/criterion; check it whatever its level
        // (an AAA criterion would otherwise be gated out and read as fixed).
        level: 'AAA' as const,
        rootSelector: selector,
        viewport: (args?.viewport as any) || 'desktop',
        dismissModals: true,
        browser: { headless: true, timeout: 30000 },
      }
      const result = tunnel
        ? await withTunnelPage(url, tunnel, VIEWPORT_FOR_TUNNEL(args?.viewport as any), (page) => scan(page, verifyOptions), !!opts.remote)
        : await withTunnelPage(url, null, VIEWPORT_SIZES[(args?.viewport as keyof typeof VIEWPORT_SIZES) || 'desktop'] ?? VIEWPORT_SIZES.desktop, (page, status) => scan(page, { ...verifyOptions, mainStatus: status } as any), !!opts.remote)

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
          isError: true,
        }
      }

      // A selector that matches nothing (or cannot be parsed) verified
      // NOTHING. The old verdict was `verified: true` with a hedge sentence
      // (persona round 4, docs.python.org `a.skip-link`), and agents read the
      // boolean. Fail closed with a reason the caller can act on.
      const scopeWarning = (result.engineWarnings ?? []).find((w: string) => w.startsWith('scope:root-miss') || w.startsWith('scope:invalid-selector'))
      if (scopeWarning) {
        const reason = scopeWarning.startsWith('scope:root-miss') ? 'not-found' : 'invalid-selector'
        const text =
          reason === 'not-found'
            ? `UNVERIFIED: \`${selector}\` matches no element at ${url}, so nothing was checked. If your fix changed the element's class/id, pass its current selector. If the fix removed the element, a selector cannot verify it — re-run scan_page and confirm the issue is no longer listed.`
            : `UNVERIFIED: \`${selector}\` is not a valid CSS selector, so the check could not be scoped to an element. Pass a valid selector (scan_page returns one per issue).`
        return {
          content: [
            { type: 'text', text },
            { type: 'text', text: '```json\n' + JSON.stringify({ url, selector, ...(wcag ? { wcag } : {}), verified: false, reason, remainingCount: null, remainingIssues: [] }, null, 2) + '\n```' },
          ],
        }
      }

      // When a WCAG criterion / rule id is given, only that criterion counts;
      // otherwise ANY remaining violation on the element means "not fixed".
      // Rule ids are compared with '-'/'_' equivalence: axe ids are hyphenated
      // ('image-alt') while WebAbility types are underscored ('missing_alt'),
      // and an exact-string compare silently never matched the other family.
      const matchesWcag = (i: any) => {
        if (!wcag) return true
        if (isCriterion(wcag)) return typeof i.wcag === 'string' && i.wcag.includes(wcag)
        return normRule(i.type || '') === normRule(wcag) || normRule(i.id || '') === normRule(wcag)
      }
      const remaining = result.issues.filter(matchesWcag)
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
      }

      const text = resolved
        ? `VERIFIED: no ${wcag ? `${wcag} ` : ''}violation remains on \`${selector}\` at ${url}.`
        : `NOT RESOLVED: ${remaining.length} ${wcag ? `${wcag} ` : ''}violation(s) still present on \`${selector}\` at ${url}. The fix did not clear them — see remainingIssues[] for what remains.`

      return {
        content: [
          { type: 'text', text },
          { type: 'text', text: '```json\n' + JSON.stringify(payload, null, 2) + '\n```' },
        ],
      }
    } catch (err) {
      return toolError(`verify_fix failed: ${(err as Error).message}`)
    }
  }

  if (name === 'diff_scan') {
    const url = (args?.url as string | undefined)?.trim() || undefined
    const baselineId = (args?.baselineId as string | undefined)?.trim() || undefined
    const baselineUrl = (args?.baselineUrl as string | undefined)?.trim() || undefined
    const currentId = (args?.currentId as string | undefined)?.trim() || undefined
    if (!baselineId && !baselineUrl) return toolError('Error: pass baselineId (a scan_history id) or baselineUrl (scan live as the baseline).')
    if (!url && !currentId) return toolError('Error: pass url (scan now as the current side) or currentId (a scan_history id).')
    if (opts.remote && (baselineId || currentId)) {
      return toolError('diff_scan by history id is not available on the hosted MCP server — it keeps no scan history. Run the local MCP (`npx -y @webability/mcp`) to diff against a stored scan, or pass baselineUrl + url to diff two live pages here.')
    }
    let diffControls: OutputControls
    try { diffControls = parseOutputControls(args as Record<string, unknown>) } catch (e) { return toolError(`Error: ${(e as Error).message}`) }

    type Projected = ReturnType<typeof enrichIssue> & { id: string; impact?: string }
    const live = async (target: string): Promise<{ issues: Projected[]; blocked?: unknown }> => {
      const scanOptions = {
        rootSelector: args?.rootSelector as string | undefined,
        viewport: (args?.viewport as any) || 'desktop',
        dismissModals: true,
        browser: { headless: true, timeout: 30000 },
        level: scanLevel(diffControls),
      }
      const t = parseTunnelTarget(target, String((args as any)?.tunnel_secret ?? ''))
      const { result, pointers } = await scanWithSourcePointers(target, t, args?.viewport, scanOptions, Boolean(opts.remote))
      if (result.blocked) return { issues: [], blocked: result.blocked }
      const project = (i: any): Projected => enrichIssue({ id: i.id, impact: i.impact, wcag: i.wcag, type: i.type, message: i.message, selector: i.selector, html: i.html?.slice(0, 400), fix: i.fix, ...(pointers[i.selector] ? { source: pointers[i.selector] } : {}) })
      return { issues: mergeSameElement(result.issues.map(project)) }
    }
    const stored = (id: string): { issues: Projected[] } => {
      const rec = readScanResult(id) as any
      if (!rec) throw new Error(`no stored scan with id "${id}" (pruned, or never logged — see scan_history)`)
      const blocks: any[] = rec?.response?.content ?? []
      const json = blocks.map((c) => String(c?.text ?? '')).find((t) => t.startsWith('```json'))
      if (!json) throw new Error(`stored scan "${id}" has no JSON payload to diff (tool: ${rec.tool})`)
      const payload = JSON.parse(json.replace(/^```json\n|\n```$/g, ''))
      if (payload.blocked) throw new Error(`stored scan "${id}" was BLOCKED (${payload.reason}) — nothing real was scanned, so it cannot be a baseline`)
      if (!Array.isArray(payload.issues)) throw new Error(`stored scan "${id}" is not a page scan (tool: ${rec.tool}) — pass a scan_page id`)
      const project = (i: any): Projected => enrichIssue(i)
      // Merge here too: archives written before same-element merging still
      // hold both engine findings, and diffing them against a merged live
      // scan would report the folded one as fixed.
      return { issues: mergeSameElement(payload.issues.map(project)) }
    }

    try {
      const baseline = baselineId ? stored(baselineId) : await live(baselineUrl!)
      if ((baseline as any).blocked) throw new Error(`baseline ${baselineUrl} was BLOCKED (${(baseline as any).blocked.reason}) — not scanned, cannot diff`)
      const current = currentId ? stored(currentId) : await live(url!)
      if ((current as any).blocked) throw new Error(`current ${url} was BLOCKED (${(current as any).blocked.reason}) — not scanned, cannot diff`)

      // Match key. WebAbility/axe ids are `<engine>-<rule>-<selector hash>` and
      // stable across scans. HTML_CodeSniffer / deep ids embed the result INDEX
      // (`htmlcs-3-<hash>`), which shifts whenever any earlier finding changes
      // — keyed by id they would read as one fixed + one new. Key those by
      // rule + criterion + selector instead.
      // Two things make an id useless as a diff key: HTML_CodeSniffer / deep
      // ids carry the result INDEX, and any engine's hash covers the selector —
      // which changes every load when a framework mints the element id
      // (Google Sign-In `gsi_<n>_<n>`, Radix / Headless UI / MUI counters,
      // React `:r1:`). Both fall back to engine|rule|criterion|selector, with
      // the generated token wildcarded, so the same element on two loads
      // lands in remaining[] instead of fixed[] + new[].
      const GENERATED_ID = /(#|\bid=["']?)(?:gsi|radix|headlessui|mui|react-aria|rc|chakra|mantine|downshift|floating-ui)[_-][^\s.>#\[\]:"']*|#[^\s.>#\[]*\d{3,}[^\s.>#\[]*|:r[0-9a-z]+:/g
      const stableSelector = (sel: string) => sel.replace(GENERATED_ID, '#*')
      const keyOf = (i: Projected & { type?: string; wcag?: string; selector?: string; rules?: string[] }) => {
        // Accessible-name findings are merged across engines; the merged id is
        // whichever engine had the richest fix, so it can change between two
        // scans of one element. Key them by element instead.
        const nameKey = nameFamilyKey(i)
        if (nameKey) return `${nameKey.replace(GENERATED_ID, '#*')}`
        const sel = String(i.selector ?? '')
        const unstable = /^(htmlcs|deep)-\d+-/.test(i.id) || GENERATED_ID.test(sel)
        GENERATED_ID.lastIndex = 0
        return unstable ? `${i.id.split('-')[0]}|${i.type}|${i.wcag}|${stableSelector(sel)}` : i.id
      }
      const diff = (a: Projected[], b: Projected[]) => {
        // Multiset match: each baseline finding absorbs at most ONE current
        // finding with the same key, so a second equivalent element (two Radix
        // popovers where there was one) is reported as new, not swallowed.
        const counts = (list: Projected[]) => {
          const m = new Map<string, number>()
          for (const i of list) { const k = keyOf(i); m.set(k, (m.get(k) ?? 0) + 1) }
          return m
        }
        const take = (m: Map<string, number>, k: string) => { const n = m.get(k) ?? 0; if (n > 0) m.set(k, n - 1); return n > 0 }
        const A = counts(a), B = counts(b)
        const kept: Projected[] = [], added: Projected[] = [], gone: Projected[] = []
        for (const i of b) (take(A, keyOf(i)) ? kept : added).push(i)
        for (const i of a) if (!take(B, keyOf(i))) gone.push(i)
        return { gone: bySeverityDesc(gone), added: bySeverityDesc(added), kept: bySeverityDesc(kept) }
      }
      const issues = diff(filterIssues(baseline.issues as any[], diffControls), filterIssues(current.issues as any[], diffControls))
      const CAP = 50
      const payload = {
        baseline: baselineId ?? baselineUrl,
        current: currentId ?? url,
        summary: { baseline: baseline.issues.length, current: current.issues.length, fixed: issues.gone.length, new: issues.added.length, remaining: issues.kept.length },
        fixed: issues.gone.slice(0, CAP),
        new: issues.added.slice(0, CAP),
        remaining: issues.kept.slice(0, CAP),
        truncated: [issues.gone, issues.added, issues.kept].some((l) => l.length > CAP),
      }
      const verdict = issues.added.length === 0
        ? `No regressions: ${issues.gone.length} fixed, 0 new, ${issues.kept.length} remaining (${baseline.issues.length} → ${current.issues.length}).`
        : `REGRESSIONS: ${issues.added.length} new issue(s) not in the baseline — see new[]. Also ${issues.gone.length} fixed, ${issues.kept.length} remaining (${baseline.issues.length} → ${current.issues.length}).`
      const idNote = issues.added.length && issues.gone.length ? ' If you changed a fixed element\'s class/id, it appears in BOTH fixed[] and new[] — compare selectors before calling it a regression.' : ''
      return {
        content: [
          { type: 'text', text: verdict + idNote + (isFiltered(diffControls) ? describeControls(diffControls) : '') + (payload.truncated ? ` Lists capped at ${CAP} (severity-sorted).` : '') },
          renderFindings(diffControls, payload, [{ title: 'New (regressions)', items: payload.new }, { title: 'Fixed', items: payload.fixed }, { title: 'Remaining', items: payload.remaining }]),
        ],
      }
    } catch (err) {
      return toolError(`diff_scan failed: ${(err as Error).message}`)
    }
  }

  if (name === 'start_audit') {
    const url = args?.url as string
    if (!url) return toolError('Error: url is required')
    if (/^https?:\/\/(localhost|127\.|\[::1\])/i.test(url)) {
      // The pipeline runs on our servers in every mode (even a local stdio MCP),
      // so it can never reach the developer's localhost.
      return toolError('start_audit runs server-side, so it cannot reach a localhost URL. Use a public or staging URL, or open a tunnel (`webability-tunnel --port 3000`) and pass its URL with `tunnel_secret`.')
    }
    // Without the secret the relay answers 401 on every fetch, and the audit
    // would publish a report on that refusal page.
    if (isTunnelUrl(url) && !tunnel) {
      return toolError('start_audit: this is a webability-tunnel URL but no `tunnel_secret` was passed. Pass the secret `webability-tunnel` printed — without it the relay refuses every request and there is nothing to audit.')
    }
    const token = opts.anonymous ? '' : (opts.authToken || resolveAuthToken())
    if (!token) {
      return toolError('start_audit needs a free WebAbility account. Run `webability login` (or connect to the hosted server and sign in), then retry.')
    }

    try {
      const res = await fetch(`${API_URL}/cli/audit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        // `tunnel` is non-null only for a URL on the pinned relay origin, so the
        // secret can never ride along to any other host.
        body: JSON.stringify({ url, includeAgent: Boolean(args?.includeAgent), ...(tunnel ? { tunnelSecret: tunnel.secret } : {}) }),
      })
      if (res.status === 429) {
        return toolError('start_audit is rate-limited (too many audits queued). Wait and retry.')
      }
      if (res.status === 401 || res.status === 403) {
        return toolError(`start_audit could not authenticate (${res.status}). Your WebAbility token is missing, expired, or lacks access. Re-run \`webability login\` (or refresh WEBABILITY_API_KEY) and retry.`)
      }
      if (!res.ok) {
        return toolError(`start_audit failed (${res.status}): ${await res.text()}`)
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
      return toolError(`start_audit error: ${(err as Error).message}`)
    }
  }

  if (name === 'get_audit') {
    const id = args?.id as number
    if (!id && id !== 0) return toolError('Error: id is required (from start_audit)')
    const token = opts.anonymous ? '' : (opts.authToken || resolveAuthToken())
    if (!token) {
      return toolError('get_audit needs a free WebAbility account. Run `webability login` (or connect to the hosted server and sign in), then retry.')
    }

    try {
      const res = await fetch(`${API_URL}/cli/audit/${encodeURIComponent(String(id))}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (res.status === 429) {
        return toolError('get_audit is rate-limited. Wait and retry.')
      }
      if (res.status === 401 || res.status === 403) {
        return toolError(`get_audit could not authenticate (${res.status}). Re-run \`webability login\` (or refresh WEBABILITY_API_KEY) and retry.`)
      }
      if (res.status === 404) {
        return toolError(`No audit #${id} for this account. Check the id, and that you are the account that started it.`)
      }
      if (!res.ok) {
        return toolError(`get_audit failed (${res.status}): ${await res.text()}`)
      }
      const data = (await res.json()) as any
      const steps = Array.isArray(data.steps) ? data.steps.map((s: any) => `${s.step}:${s.status}`).join('  ') : ''
      let text: string
      if (data.status === 'complete') {
        // The pipeline's summary keys are Capitalized severities (Critical/High/
        // Medium/Low + total) — see auditPipeline.service summarize(). The old
        // lowercase reads always printed 0.
        const sum = data.summary ? `${data.summary.total} finding(s) (${data.summary.Critical ?? 0} critical, ${data.summary.High ?? 0} high).` : 'complete.'
        const dl = data.downloads
          ? `\n\nDownloads (expire ~1h):\n- report: ${data.downloads.report}` + (data.downloads.workbook ? `\n- workbook (.xlsx): ${data.downloads.workbook}` : '\n- workbook: not built for this audit')
          : ''
        text = `Audit #${data.id} for ${data.url} — COMPLETE. ${sum}${dl}`
      } else if (data.status === 'failed') {
        // The pipeline's reason usually ends in its own full stop; drop it so the line gets exactly one.
        const reason = typeof data.error === 'string' ? data.error.replace(/[.\s]+$/, '') : ''
        text = `Audit #${data.id} for ${data.url} — FAILED${reason ? `: ${reason}` : ''}. Steps: ${steps}`
      } else {
        text = `Audit #${data.id} for ${data.url} — ${data.status}${data.currentStep ? ` (at ${data.currentStep})` : ''}. Steps: ${steps}. Poll again in ~15s.`
      }
      return { content: [{ type: 'text', text }, { type: 'text', text: '```json\n' + JSON.stringify(data, null, 2) + '\n```' }] }
    } catch (err) {
      return toolError(`get_audit error: ${(err as Error).message}`)
    }
  }

  if (name === 'flow_scan') {
    const startUrl = args?.startUrl as string
    let flowControls: OutputControls
    try { flowControls = parseOutputControls(args as Record<string, unknown>) } catch (e) { return toolError(`Error: ${(e as Error).message}`) }
    if (!startUrl) return toolError('Error: startUrl is required')
    const maxPages = (args?.maxPages as number) || 10
    const autoNav = (args?.autoNavigate as string[]) || []

    if (autoNav.length === 0) {
      return toolError('Error: flow_scan requires autoNavigate — the list of URLs in the journey to walk after startUrl. The MCP server is headless and cannot discover a journey interactively, so pass the steps explicitly. For a single page, use scan_page instead.')
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
    }

    const normalize = (u: string) => (u.startsWith('http') ? u : `https://${u}`)
    const requested = [startUrl, ...autoNav].map(normalize)
    const outcomes: PageOutcome[] = []

    try {
      const session = await openSession({
        remote: opts.remote,
        contextOptions: { viewport: { width: 1280, height: 720 } },
        setupContext: (context) => (opts.remote ? installSsrfRoute(context, tunnel) : undefined),
      })
      // goto() may swap in a fresh page (HTTP/2 fallback), so re-read after it.
      let page = session.page

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
            const response = await session.goto(target, { waitUntil: 'domcontentloaded', timeout: 30000 })
            page = session.page
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
            const r = await scan(page, { includeAxe: true, dismissModals: true, mainStatus, level: scanLevel(flowControls) })
            // Bot-challenge / interstitial guard — scan() sets `blocked` when the
            // DOM is a Cloudflare/PerimeterX/error page, not the real site. Record
            // it as NOT scanned (with the reason) so its empty issue list never
            // gets counted as a clean page.
            if (r.blocked) {
              outcomes.push({ requested: target, status: 'blocked', finalUrl, reason: r.blocked.reason })
            } else {
              // Framework source pointers, read while this page's DOM is still open.
              const pointers = await collectSourcePointers(page, r.issues.map((i) => i.selector))
              const withSource = (list: typeof r.issues) => list.map((i) => (pointers[i.selector] ? { ...i, source: pointers[i.selector] } : i))
              outcomes.push({ requested: target, status: 'scanned', finalUrl, issues: withSource(r.issues) })
              scannedCount++
            }
          } catch (err) {
            outcomes.push({ requested: target, status: 'scan_failed', finalUrl, reason: `scan failed: ${(err as Error).message}` })
          }
        }
      } finally {
        await session.close()
      }

      // Same per-issue projection scan_page returns, so a finding in a
      // multi-page flow is exactly as actionable as a single-page scan
      // (carries the fix payload).
      const projectIssue = (i: any) => enrichIssue({
        id: i.id,
        impact: i.impact,
        wcag: i.wcag,
        type: i.type,
        message: i.message,
        selector: i.selector,
        html: i.html?.slice(0, 400),
        fix: i.fix,
        // core's `source` is the ENGINE name ('webability' | 'axe' | 'htmlcs');
        // only the pointer object attached above is a source pointer.
        ...(i.source && typeof i.source === 'object' ? { source: i.source } : {}),
      })

      const scannedPages = outcomes.filter((o) => o.status === 'scanned')
      const droppedPages = outcomes.filter((o) => o.status !== 'scanned')

      // Dedupe across pages — same type+selector+wcag = one finding, tracking
      // which pages it appeared on. 
      const dedupAcrossPages = () => {
        const map = new Map<string, any & { foundOn: string[] }>()
        for (const pr of scannedPages) {
          for (const issue of ((pr as any).issues as any[]) || []) {
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
      // Same-element findings that are one problem across engines merge
      // first (foundOn is unioned), as in scan_page.
      const parsing = dropObsoleteParsing(dedupAcrossPages())
      const allUnique = bySeverityDesc(mergeSameElement(parsing.issues))
      await attachSourceCandidates(allUnique as any[], args?.sourceRoot as string | undefined, Boolean(opts.remote))
      const unique = filterIssues(allUnique as any[], flowControls)
      // Repeats of one rule with one fix → one entry with `count`.
      const collapsedIssues = collapseRepeats(unique, flowControls)
      const collapsedGroups = collapsedIssues.collapsedGroups

      const RESULT_CAP = 50
      // Stratified cap — same rationale as scan_page: a majority type must not
      // fill the list and hide other types across a multi-page journey.
      const [capIssues, typesRescued] = stratifiedCap(collapsedIssues.list, RESULT_CAP)
      const issuesTruncated = collapsedIssues.list.length > RESULT_CAP

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
            ? { issueCount: mergeSameElement((o.issues ?? []).map(projectIssue)).length }
            : {}),
        })),
        summary: {
          uniqueIssues: unique.length,
          pagesDropped: droppedPages.length,
        },
        ...(isFiltered(flowControls)
          ? { pageSummary: { uniqueIssues: allUnique.length, pagesDropped: droppedPages.length }, filters: controlsList(flowControls) }
          : {}),
        truncated: issuesTruncated,
        issues: capIssues,
        issueEntries: collapsedIssues.list.length,
        issuesTotal: unique.length,
        ...(collapsedGroups > 0
          ? { counts: 'summary.uniqueIssues and issuesTotal count every element. issues[] holds issueEntries entries: an entry with `count` stands for that many elements of one rule with one fix (see `examples`, `expand`).' }
          : {}),
      }
      const flowNote =
        (collapsedGroups > 0
          ? `${isFiltered(flowControls) ? '' : `Total to report: ${unique.length} unique issue(s). `}Listing: the ${unique.length} unique issue(s) are grouped into ${collapsedIssues.list.length} entries in issues[] — ${collapsedGroups} rule(s) repeat with the same fix and are listed once with \`count\`. Pass rules: ["<rule id>"] to list every element of a rule.\n`
          : '') +
        (issuesTruncated
          ? truncationNote({ remote: Boolean(opts.remote), cap: RESULT_CAP, returned: capIssues.length, total: collapsedIssues.list.length, stratified: typesRescued }).trim() + '\n'
          : '')

      // Human-readable summary. Surface dropped pages EXPLICITLY — never
      // return fewer pages than requested without saying why.
      const droppedNote = droppedPages.length > 0
        ? `\n\n## Pages not scanned (${droppedPages.length})\n\n` +
          droppedPages.map((o) => `- ${o.requested} — ${o.status}: ${o.reason ?? 'no detail'}`).join('\n')
        : ''

      const renderLine = (i: any) =>
        (i.count
          ? `[${i.impact}] WCAG ${i.wcag} — ${i.message} (×${i.count} elements)\n  Examples: ${(i.examples ?? []).join(' | ')}\n  ${i.expand ?? ''}`
          : `[${i.impact}] WCAG ${i.wcag} — ${i.message}\n  Selector: ${i.selector}`) +
        `\n  Found on: ${(i.foundOn ?? []).join(', ')}`

      const findingsBlock = renderFindings(
        flowControls,
        payload,
        [
          { title: 'Issues', items: payload.issues, total: unique.length, entries: collapsedIssues.list.length },
        ],
        { issues: collapsedIssues.list },
      )
      // The readable list repeats the JSON. Print it only beside a JSON block,
      // and only when both still fit inline (or the caller asked for JSON).
      const readableList = collapsedIssues.list.slice(0, 30).map(renderLine).join('\n\n')
      const showReadable =
        findingsBlock.text.startsWith('```json') && (flowControls.formatExplicit || findingsBlock.text.length + readableList.length <= INLINE_BUDGET)
      const response = {
        content: [
          {
            type: 'text',
            text:
              `# Flow Scan Report\n\n` +
              `Pages requested: ${requested.length}\n` +
              `Pages scanned: ${scannedPages.length}\n` +
              (droppedPages.length > 0 ? `Pages dropped: ${droppedPages.length} (see below)\n` : '') +
              `Unique high-confidence issues: ${unique.length}${isFiltered(flowControls) ? describeControls(flowControls) : ''}\n` +
              (isFiltered(flowControls)
                ? `Whole flow, before filters: ${allUnique.length} unique issue(s), that is the total to report (\`summary\` counts the filtered set, \`pageSummary\` the whole flow).\n`
                : '') +
              `\n` +
              flowNote +
              (showReadable ? readableList : '') +
              droppedNote,
          },
          findingsBlock,
        ],
      }

      // Always persist the canonical archive (every unique finding, unfiltered,
      // as JSON) — the response may be capped, filtered, or compact.
      {
        fullScanResultByResponse.set(response, {
          content: [
            response.content[0]!,
            {
              type: 'text',
              text:
                '```json\n' +
                JSON.stringify(
                  { ...payload, summary: { uniqueIssues: allUnique.length, pagesDropped: droppedPages.length }, pageSummary: undefined, filters: undefined, truncated: false, counts: undefined, issues: allUnique, issueEntries: allUnique.length, issuesTotal: allUnique.length },
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
      return toolError(`Flow scan failed: ${(err as Error).message}`)
    }
  }

  if (name === 'detect_framework') {
    const url = args?.url as string
    if (!url) return toolError('Error: url is required')

    try {
      const session = await openSession({
        remote: opts.remote,
        setupContext: (context) => (opts.remote ? installSsrfRoute(context, tunnel) : undefined),
      })
      let stack: PageStack
      try {
        await session.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 })
        stack = await detectPageStack(session.page as any)
      } finally {
        await session.close()
      }
      const forAiFix = aiFixFramework(stack)
      const lines = [`Framework: ${stack.framework}`, `CSS toolkit: ${stack.cssToolkit}`]
      if (stack.builder) lines.push(`Page builder: ${stack.builder}`)
      lines.push(`Evidence: ${stack.evidence.length ? stack.evidence.join('; ') : 'no application-framework signal on the page'}`)
      lines.push(`For generate_ai_fix, pass framework: "${forAiFix}". scan_page reports the same framework / cssToolkit fields.`)
      return {
        content: [
          { type: 'text', text: lines.join('\n') },
          { type: 'text', text: '```json\n' + JSON.stringify({ url, ...stack, aiFixFramework: forAiFix }, null, 2) + '\n```' },
        ],
      }
    } catch (err) {
      return toolError(`Detection failed: ${(err as Error).message}`)
    }
  }

  if (name === 'generate_ai_fix') {
    // Clients (and Claude, prompted casually) often pass the issue as prose.
    // The platform endpoint 500s on a string issue, so normalize to the
    // object shape it expects.
    const issue = (typeof args?.issue === 'string' ? { message: args.issue } : args?.issue) as any
    const html = args?.html as string
    if (!issue || !html) return toolError('Error: issue and html required')

    let brandColors = (args?.brandColors as string[] | undefined) || []
    let brandSource = brandColors.length > 0 ? 'arg' : 'none'
    const url = (args?.url as string | undefined) || ''

    // Auto-extract brand palette via scanner — only for contrast issues, where the platform prompt actually consumes it.
    const issueType = (issue.type || '') as string
    // A prose issue ("Text has insufficient color contrast…") carries the signal
    // in message, not type/wcag — check it too so palette extraction still fires.
    const isContrast =
      issueType.includes('contrast') ||
      issue.wcag === '1.4.3' ||
      issue.wcag === '1.4.11' ||
      /contrast/i.test((issue.message as string) || '') ||
      /contrast/i.test((issue.rule as string) || '')
    if (brandColors.length === 0 && url && isContrast) {
      try {
        brandColors = await extractBrandPaletteFromUrl(url, !!opts.remote, tunnel)
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
        return toolError(`AI service unavailable (${res.status}) and no safe deterministic fallback exists for this "${issue.type || issue.wcag || 'accessibility'}" issue — it needs a real accessible name, which can't be inferred reliably. Mark it for manual review. Do NOT set ${attr ? `\`${attr}\`` : 'the attribute'} to an empty string; that would remove the accessible name and make the element worse than it is now. Retry generate_ai_fix once the AI service is back, or write a descriptive value by hand.`)
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
      return toolError(`AI fix failed: ${(err as Error).message}`)
    }
  }

  if (name === 'visual_audit') {
    const url = args?.url as string
    if (!url) return toolError('Error: url is required')
    const viewport = (args?.viewport as 'desktop' | 'tablet' | 'mobile') || 'desktop'
    const fullPage = args?.fullPage === true
    if (isTunnelUrl(url) && !tunnel) {
      return toolError('Visual audit error: this is a webability-tunnel URL but no `tunnel_secret` was passed. Pass the secret `webability-tunnel` printed — without it the relay serves its refusal page, not your app.')
    }

    const started = Date.now()
    try {
      let phase = 'browser launch'
      let httpStatus = 0
      let screenshot: string
      try {
        screenshot = await withDeadline(async (signal) => {
          const sizes = { desktop: { width: 1280, height: 720 }, tablet: { width: 768, height: 1024 }, mobile: { width: 375, height: 667 } }
          const session = await openSession({
            remote: opts.remote,
            contextOptions: { viewport: sizes[viewport] },
            setupContext: (context) => (opts.remote ? installSsrfRoute(context, tunnel) : undefined),
          })
          // The race has already rejected if the deadline fired during launch;
          // stop here rather than load a page nobody is waiting for.
          if (signal.aborted) {
            await session.close()
            return ''
          }
          signal.addEventListener('abort', () => void session.close())
          try {
            phase = 'page load'
            const response = await session.goto(url, { waitUntil: 'domcontentloaded', timeout: VISUAL_AUDIT_CAPTURE_MS })
            const page = session.page
            // An error page is not the target: a closed tunnel serves the
            // relay's 404, a missing secret its 401. Auditing it would report
            // "no issues" on a page the caller never asked about.
            if (response && response.status() >= 400) {
              httpStatus = response.status()
              return ''
            }
            await page.waitForTimeout(800) // let JS-driven UI settle
            phase = 'screenshot'
            const buf = await page.screenshot({ fullPage, type: 'png' })
            return buf.toString('base64')
          } finally {
            await session.close()
          }
        }, VISUAL_AUDIT_CAPTURE_MS, 'capture')
      } catch (err) {
        if (err instanceof DeadlineError) {
          return toolError(`Visual audit error: the ${phase} step did not finish within ${VISUAL_AUDIT_CAPTURE_MS / 1000}s, so no screenshot was taken. Check the page loads for a normal browser${tunnel ? ' and that the tunnel is still open' : ''}, then retry.`)
        }
        throw err
      }
      if (httpStatus) {
        return toolError(`Visual audit error: ${url} returned HTTP ${httpStatus}, so there is no page to audit.${tunnel ? ' The tunnel may have closed — open a new one with `webability-tunnel` and retry with its new URL and secret.' : ''}`)
      }

      // visual_audit needs a (free) account token so the backend can run
      // vision on the caller's account (#124).
      const token = opts.anonymous ? '' : (opts.authToken || resolveAuthToken())
      if (!token) {
        return toolError('visual_audit needs a free WebAbility account. Run `webability login` (or connect to the hosted server and sign in), then retry.')
      }

      let res: Response
      try {
        res = await fetch(`${API_URL}/cli/visual-audit`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify({
            screenshot, platform: 'web',
            screenName: url,
            brandColors: Array.isArray(args?.brandColors) ? args?.brandColors : [],
          }),
          signal: AbortSignal.timeout(VISUAL_AUDIT_TOTAL_MS - (Date.now() - started)),
        })
      } catch (err) {
        if ((err as Error)?.name === 'TimeoutError') {
          return toolError(`Visual audit error: the page was captured, but WebAbility's vision analysis did not finish within ${Math.round(VISUAL_AUDIT_TOTAL_MS / 1000)}s. The delay is on WebAbility's side, not your page. Use scan_page for DOM-level results in the meantime.`)
        }
        throw err
      }
      if (res.status === 429) {
        return toolError('visual_audit is rate-limited. Wait and retry.')
      }
      if (res.status === 401 || res.status === 403) {
        return toolError(`visual_audit could not authenticate (${res.status}). Your WebAbility token is missing, expired, or lacks access. Re-run \`webability login\` (or refresh WEBABILITY_API_KEY) and retry.`)
      }
      if (!res.ok) {
        return toolError(`Visual audit failed (${res.status}): ${await res.text()}`)
      }
      const data = await res.json() as { issues: any[]; count: number }
      const lines = data.issues.map((i, idx) =>
        `${idx + 1}. [${(i.severity as string).toUpperCase()}] WCAG ${i.wcag} — ${i.message}` +
        (i.region ? `\n   region: ${i.region.x},${i.region.y} ${i.region.width}x${i.region.height}px` : '') +
        (i.fix?.suggestedValue ? `\n   fix: ${i.fix.attribute} = ${i.fix.suggestedValue}` : '')
      ).join('\n\n')
      return { content: [{ type: 'text', text: `# Visual Audit: ${url}\n\nFound ${data.count} pixel-level issues.\n\n${lines || 'No visual issues detected.'}` }] }
    } catch (err) {
      return toolError(`Visual audit error: ${(err as Error).message}`)
    }
  }

  if (name === 'find_source') {
    const selector = args?.selector as string
    if (!selector) return toolError('Error: selector is required')

    try {
      const rootDir = (args?.rootDir as string) || process.cwd()
      const files = await findSourceCandidates(selector, rootDir)
      if (files.length === 0) {
        return { content: [{ type: 'text', text: `No source files under ${rootDir} matched the id/class/attribute tokens of "${selector}". Try a more specific selector, or scan a dev build — scan_page reads \`source\` pointers straight from React/Vue dev builds.` }] }
      }
      const list = files.map((f) => `- ${f}`).join('\n')
      return {
        content: [{ type: 'text', text: `Source candidates for \`${selector}\`:\n\n${list}\n\nUse Read on the most likely file, then apply the fix.` }],
      }
    } catch (err) {
      return toolError(`Source lookup failed: ${(err as Error).message}`)
    }
  }

  if (name === 'scan_html') {
    const html = args?.html as string
    if (!html) return toolError('Error: html is required')
    const tags = (args?.tags as string[]) || ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']
    const width = (args?.width as number) || 1280
    const height = (args?.height as number) || 800
    const engine = (args?.engine as string | undefined) || 'in-process'
    if (engine !== 'in-process' && engine !== 'browser') return toolError('Error: engine must be "in-process" or "browser"')
    let htmlControls: OutputControls
    try { htmlControls = parseOutputControls(args as Record<string, unknown>) } catch (e) { return toolError(`Error: ${(e as Error).message}`) }
    // An explicit axe wcag2aaa tag is an AAA request (the level gate would drop it otherwise).
    if (tags.includes('wcag2aaa') && !htmlControls.level) htmlControls = { ...htmlControls, level: 'AAA' }

    if (engine === 'in-process') {
      try {
        const r = await fastScanHtml(html, { wcagTags: tags, level: scanLevel(htmlControls, tags) })
        const issues = filterIssues(r.issues, htmlControls)
        const htmlFiltered = isFiltered(htmlControls)
        const shown = htmlFiltered ? recountSummary(issues) : r.summary
        const payload = {
          engine: r.engine,
          fragment: r.fragment,
          durationMs: r.durationMs,
          summary: shown,
          ...(htmlFiltered ? { pageSummary: r.summary, filters: controlsList(htmlControls) } : {}),
          skippedVisual: r.skippedVisual,
          ...(r.engineWarnings ? { engineWarnings: r.engineWarnings } : {}),
          issues,
        }
        const text =
          `Found ${shown.total} issue(s)${htmlFiltered ? ` matching the filters (${controlsList(htmlControls)})` : ''} in the HTML ${r.fragment ? 'fragment' : 'document'} in ${r.durationMs}ms (in-process: WebAbility detectors + axe-core, no browser): ` +
          `${shown.critical} critical, ${shown.serious} serious, ${shown.moderate} moderate, ${shown.minor} minor.` +
          (htmlFiltered ? ` Whole snippet, before filters: ${r.summary.total} issue(s) (\`pageSummary\`).` : '') +
          (r.skippedVisual ? ` ${r.skippedVisual} visual-tier finding(s) (contrast / target size / focus) were NOT evaluated — jsdom has no layout; use engine:"browser" or scan_page for those.` : ' Visual-tier rules (contrast / target size / focus) are not evaluated in-process.')
        return {
          content: [
            { type: 'text', text },
            renderFindings(htmlControls, payload, [{ title: 'Issues', items: issues }]),
          ],
        }
      } catch (err) {
        return toolError(`scan_html failed: ${(err as Error).message}`)
      }
    }

    try {
      const session = await openSession({
        remote: opts.remote,
        contextOptions: { viewport: { width, height } },
        setupContext: (context) => (opts.remote ? installSsrfRoute(context, tunnel) : undefined),
      })
      let result: Awaited<ReturnType<typeof import('@webability/core').runAxe>>
      try {
        await session.page.setContent(html, { waitUntil: 'domcontentloaded' })
        const { runAxe } = await import('@webability/core')
        // level:"AAA" must run the axe AAA rules in the browser engine too, as the in-process path does.
        const axeTags = htmlControls.level === 'AAA' && !tags.includes('wcag2aaa') ? [...tags, 'wcag2aaa'] : tags
        result = await runAxe(session.page, axeTags)
      } finally {
        await session.close()
      }

      const violations = result.violations.filter((v) => filterIssues([{ type: v.id, impact: v.impact ?? undefined, wcag: v.tags.filter((t) => /^wcag\d{3,4}$/.test(t)).map((t) => t.replace(/^wcag(\d)(\d)(\d+)$/, '$1.$2.$3')).join(',') }], htmlControls).length > 0).map((v) => ({
        id: v.id,
        impact: v.impact,
        help: v.help,
        helpUrl: v.helpUrl,
        wcagTags: v.tags.filter((t) => t.startsWith('wcag')),
        // Same closed-set op / tier scan_page carries, as a per-rule template
        // (axe reports the failure, not a value — the value is the agent's job).
        fix: { op: axeRuleFixMeta(v.id).op, ...(axeRuleFixMeta(v.id).attribute ? { attribute: axeRuleFixMeta(v.id).attribute } : {}) },
        fixability: axeRuleFixMeta(v.id).fixability,
        nodes: v.nodes.slice(0, 5).map((n) => ({
          html: n.html.slice(0, 300),
          target: n.target,
          failureSummary: n.failureSummary,
        })),
      }))

      return {
        content: [
          { type: 'text', text: `${violations.length} violation${violations.length === 1 ? '' : 's'} found in HTML snippet (browser engine, axe-core only; tags: ${tags.join(', ')})${isFiltered(htmlControls) ? describeControls(htmlControls) : ''}.` },
          { type: 'text', text: '```json\n' + JSON.stringify({ violations, passes: result.passes.length }, null, 2) + '\n```' },
        ],
      }
    } catch (err) {
      return toolError(`scan_html failed: ${(err as Error).message}`)
    }
  }

  if (name === 'get_rules') {
    // Systematic arg validation: every key checked, before any engine runs.
    // A bogus engine used to silently return ALL rules (neither `!==` guard
    // matched), and unknown keys (e.g. `tag` for `tags`) were swallowed.
    const resolved = resolveGetRulesArgs(args as Record<string, unknown> | undefined)
    if (resolved.error) return toolError(resolved.error)
    let tags = resolved.tags
    const ruleQuery = resolved.rule
    const fixability = args?.fixability as Fixability | undefined
    const engine = (args?.engine as string | undefined) || 'all'
    if (engine !== 'all' && engine !== 'axe' && engine !== 'webability') {
      return toolError('Error: engine must be one of all | axe | webability')
    }
    if (args?.tags !== undefined && (!Array.isArray(args.tags) || !(args.tags as unknown[]).every((t) => typeof t === 'string'))) {
      return toolError('Error: tags must be an array of strings')
    }
    if (fixability && !FIXABILITY_TIERS.has(fixability)) {
      return toolError(`Error: fixability must be one of ${[...FIXABILITY_TIERS].join(' | ')}`)
    }

    try {
      // Every tag must exist in some engine. An unknown tag matched nothing and
      // answered a silent "0 rules" (persona round 4: category "landmarks").
      // The valid set is read from axe and the WebAbility registry at runtime.
      if (tags && tags.length > 0) {
        const axeAll = ((await import('axe-core')).default as any).getRules() as Array<{ tags: string[] }>
        const { WCAG_BY_ISSUE: registry } = await import('@webability/core')
        const known = new Map<string, string>()
        for (const r of axeAll) for (const t of r.tags) known.set(t.toLowerCase(), t)
        for (const wcag of Object.values(registry)) known.set('wcag' + String(wcag).replace(/\./g, ''), 'wcag' + String(wcag).replace(/\./g, ''))
        const categories = [...known.values()].filter((t) => t.startsWith('cat.')).sort()
        const out: string[] = []
        for (const raw of tags) {
          const t = raw.trim().toLowerCase()
          const hit = known.get(t) ?? known.get(`cat.${t}`)
          if (hit) { out.push(hit); continue }
          // Tags expanded from level / wcag / criterion (level "A" also yields
          // wcag22a, which no axe rule carries) are dropped, not refused.
          if (resolved.expanded) continue
          const looksCategory = t.startsWith('cat.') || args?.category !== undefined
          return toolError(
            `Error: unknown ${looksCategory ? 'category' : 'tag'} "${raw}" — no rule carries it. ` +
              `Valid categories: ${categories.join(', ')}. ` +
              'Other tags: WCAG levels (wcag2a, wcag2aa, wcag21aa, wcag22aa — wcag21aa / wcag22aa hold only the criteria NEW in that version), ' +
              'single criteria (wcag143), best-practice, section508, EN-301-549. Or pass level: "AA" / wcag: "1.4.3".',
          )
        }
        if (out.length === 0) {
          const criterion = tags.map((t) => t.match(/^wcag(\d)(\d)(\d+)$/)).find(Boolean)
          const label = criterion ? `WCAG ${criterion[1]}.${criterion[2]}.${criterion[3]}` : tags.join(', ')
          return { content: [{ type: 'text', text: `0 rules: no rule covers ${label}. It is checked by people, not by an automated rule — call get_rules with no arguments for every automated rule.` }, { type: 'text', text: '```json\n[]\n```' }] }
        }
        tags = out
      }
      const rules: Array<Record<string, unknown>> = []
      if (engine !== 'webability') {
        const axe = (await import('axe-core')).default as any
        const axeRules = axe.getRules(tags && tags.length > 0 ? tags : undefined) as Array<{ ruleId: string; description: string; help: string; helpUrl: string; tags: string[] }>
        for (const r of axeRules) {
          const meta = axeRuleFixMeta(r.ruleId)
          rules.push({ ...r, engine: 'axe-core', fixability: meta.fixability, fix: { op: meta.op, ...(meta.attribute ? { attribute: meta.attribute } : {}) } })
        }
      }
      if (engine !== 'axe') {
        const { WCAG_BY_ISSUE } = await import('@webability/core')
        const wanted = tags && tags.length > 0 ? new Set(tags.map((t) => t.toLowerCase())) : null
        for (const [ruleId, wcag] of Object.entries(WCAG_BY_ISSUE)) {
          const wcagTag = 'wcag' + wcag.replace(/\./g, '')
          if (wanted && !wanted.has(wcagTag)) continue
          const meta = webabilityRuleFixMeta(ruleId)
          rules.push({
            ruleId,
            engine: 'webability',
            description: ruleId.replace(/_/g, ' '),
            wcag,
            tags: [wcagTag],
            fixability: meta.fixability,
            fix: { op: meta.op, ...(meta.attribute ? { attribute: meta.attribute } : {}) },
          })
        }
      }
      const byFix = fixability ? rules.filter((r) => r.fixability === fixability) : rules
      const filtered = ruleQuery ? byFix.filter((r) => ruleIdMatches(String(r.ruleId), ruleQuery)) : byFix
      const filters = [ruleQuery ? `rule "${ruleQuery}"` : '', tags?.length ? `tags [${tags.join(', ')}]` : '', fixability ? `fixability ${fixability}` : '', engine !== 'all' ? `engine ${engine}` : ''].filter(Boolean)
      return {
        content: [
          {
            type: 'text',
            text:
              `${filtered.length} rule${filtered.length === 1 ? '' : 's'}${filters.length ? ` matching ${filters.join(', ')}` : ''}.` +
              (filtered.length === 0 && ruleQuery ? ` no rule id contains the word(s) "${ruleQuery.replace(/_/g, '-')}" — try one shorter word (e.g. "contrast", "label", "aria"), or call get_rules with no arguments for every rule.` : ''),
          },
          { type: 'text', text: '```json\n' + JSON.stringify(filtered, null, 2) + '\n```' },
        ],
      }
    } catch (err) {
      return toolError(`get_rules failed: ${(err as Error).message}`)
    }
  }

  if (name === 'check_color_contrast') {
    const str = (v: unknown) => (typeof v === 'string' ? v.trim() : '')
    let fg = str(args?.foreground)
    let bg = str(args?.background)
    const url = str(args?.url)
    const selector = str(args?.selector)
    if ((!fg || !bg) && !(url && selector)) {
      return toolError('Error: pass foreground and background colors, or `url` + `selector` to read them from an element on the live page.')
    }
    const contrastLevel = args?.level === undefined || args?.level === null ? 'AA' : String(args.level)
    if (contrastLevel !== 'AA' && contrastLevel !== 'AAA') return toolError('Error: level must be "AA" or "AAA"')
    const showAaa = contrastLevel === 'AAA'
    let fontSize = typeof args?.fontSize === 'number' && args.fontSize > 0 ? args.fontSize : undefined
    let isBold = typeof args?.isBold === 'boolean' ? args.isBold : undefined
    let palette = contrastPalette(args?.brandColors)
    let paletteSource = 'arg'
    let readNote = ''

    // url + selector with a color missing: read the element's own colors from
    // the live page (same page-open path as the other url tools). The brand
    // palette, when needed, comes from the same page — one browser, not two.
    if ((!fg || !bg) && url && selector) {
      try {
        const readFromPage = async (page: any, status?: number) => {
          if (typeof status === 'number' && status >= 400) throw new ToolRefusal(`check_color_contrast failed: ${url} answered HTTP ${status} — no colors were read.`)
          await page.waitForLoadState('load', { timeout: 8000 }).catch(() => {})
          const el = await readElementColors(page, selector)
          if ('error' in el) {
            if (el.error === 'invalid') throw new ToolRefusal(`Error: selector "${selector}" is not a valid CSS selector.`)
            if (el.error === 'nomatch') throw new ToolRefusal(`Error: selector "${selector}" matches no element on ${url} — nothing was checked.`)
            throw new ToolRefusal(`Error: could not parse the computed color "${'value' in el ? el.value : ''}" of ${selector} — pass foreground and background explicitly.`)
          }
          const needPalette = palette.length === 0
          return { el, pagePalette: needPalette ? await brandPaletteFromPage(page).catch(() => [] as string[]) : [] }
        }
        const read = await withTunnelPage(url, tunnel, VIEWPORT_FOR_TUNNEL('desktop'), readFromPage, !!opts.remote)
        const el = read.el
        if (!bg && !el.background) {
          return toolError(
            `Error: the background behind ${selector} on ${url} is a gradient or image (background-image on ${el.backgroundImageOn}) — there is no single color to measure. ` +
              'pass `background` with the color the text actually sits on, or check it with visual_audit.',
          )
        }
        fg ||= el.color
        bg ||= el.background as string
        fontSize ??= el.fontSize
        isBold ??= el.bold
        readNote = `Colors read from ${selector} on ${url} (computed style; background composited from the nearest painted ancestors).`
        if (palette.length === 0 && read.pagePalette.length > 0) {
          palette = read.pagePalette
          paletteSource = `scanner: ${url}`
        }
      } catch (err) {
        if (err instanceof ToolRefusal) return toolError(err.message)
        return toolError(`check_color_contrast failed: ${(err as Error).message}`)
      }
    }
    const size = fontSize ?? 16
    const bold = isBold ?? false

    const ratio = getContrastRatio(fg, bg)
    if (ratio === 0) {
      return toolError(`Could not parse colors. Use hex (#RRGGBB) or rgb(r,g,b).`)
    }
    // WCAG large text: ≥18pt (≈24px) regular, or ≥14pt (≈18.66px) bold
    const isLarge = size >= 24 || (bold && size >= 18.66)
    const aaThreshold = isLarge ? 3.0 : 4.5
    const aaaThreshold = isLarge ? 4.5 : 7.0
    const aaPass = ratio >= aaThreshold
    const aaaPass = ratio >= aaaThreshold

    const lines = [
      `Contrast ratio: ${ratio.toFixed(2)}:1 (${fg} on ${bg}, ${size}px${bold ? ' bold' : ''}, ${isLarge ? 'large' : 'normal'} text)`,
      `WCAG AA  (≥ ${aaThreshold}): ${aaPass ? 'PASS' : 'FAIL'}`,
      // AA is the default and only verdict; AAA only on request (owner: "always AA").
      ...(showAaa ? [`WCAG AAA (≥ ${aaaThreshold}): ${aaaPass ? 'PASS' : 'FAIL'}`] : []),
      ...(readNote ? [readNote] : []),
    ]

    if (!aaPass) {
      // Same test the hosted anonymous gate uses to count this call as heavy.
      if (palette.length === 0 && paletteSource === 'arg' && contrastLaunchesBrowser(args) && url && !readNote) {
        try {
          palette = await extractBrandPaletteFromUrl(url, !!opts.remote, tunnel)
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
        if (showAaa && !aaaPass) {
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
    const ariaArgError = checkAriaArgError(args)
    if (ariaArgError) return toolError(ariaArgError)
    const html = typeof args?.html === 'string' && args.html.trim() ? args.html : undefined
    const url = typeof args?.url === 'string' && args.url.trim() ? args.url.trim() : undefined
    const selector = typeof args?.selector === 'string' && args.selector.trim() ? args.selector.trim() : undefined
    if (!html && !url) return toolError('Error: pass `html` (a markup snippet) or `url` (a live page to check).')
    if (html && url) return toolError('Error: pass `html` or `url`, not both.')
    const nodeLimitRaw = args?.nodeLimit as number | undefined
    if (nodeLimitRaw !== undefined && (!Number.isInteger(nodeLimitRaw) || nodeLimitRaw < 1 || nodeLimitRaw > 50)) {
      return toolError('Error: nodeLimit must be an integer between 1 and 50')
    }
    const nodeLimit = nodeLimitRaw ?? 5
    const where = url ?? 'the HTML snippet'

    try {
      // `cat.aria` alone MISSES `aria-hidden-focus` — axe tags that rule
      // `cat.name-role-value` (WCAG 4.1.2), not `cat.aria`. Without it a
      // focusable-yet-`aria-hidden` control (a serious, common real bug) slips
      // through as "no violations". Adding the name-role-value category also
      // pulls in the sibling accessible-name rules (button-name, link-name,
      // input-button-name, …) — all squarely ARIA/name-role-value concerns.
      // axe runs on the whole document; `selector` then keeps the nodes inside
      // that element, so ARIA references that point outside it still resolve.
      const check = async (page: any, status?: number) => {
        if (url && typeof status === 'number' && status >= 400) throw new ToolRefusal(`check_aria failed: ${url} answered HTTP ${status} — nothing was checked. This is NOT a clean result.`)
        // A client-rendered page is an empty shell at domcontentloaded; wait
        // (bounded) for load so "no violations" is never about the shell.
        if (url) await page.waitForLoadState('load', { timeout: 8000 }).catch(() => {})
        if (selector) await assertSelectorMatches(page, selector, where)
        const { runAxe } = await import('@webability/core')
        const r = await runAxe(page, ['cat.aria', 'cat.name-role-value'])
        if (!selector) return r
        return { ...r, violations: await scopeAxeRules(page, r.violations as any[], selector) }
      }
      let result: Awaited<ReturnType<typeof import('@webability/core').runAxe>>
      if (url) {
        result = await withTunnelPage(url, tunnel, VIEWPORT_FOR_TUNNEL('desktop'), check, !!opts.remote)
      } else {
        const session = await openSession({
          remote: opts.remote,
          setupContext: (context) => (opts.remote ? installSsrfRoute(context, tunnel) : undefined),
        })
        try {
          await session.page.setContent(html!, { waitUntil: 'domcontentloaded' })
          result = await check(session.page)
        } finally {
          await session.close()
        }
      }

      // Shared projection so violations have a stable shape.
      // Nodes cap at nodeLimit per rule (default 5) — every rule discloses
      // nodesTotal + truncated in the scan_page vocabulary, and the FULL set
      // is archived for scan_history(id) recovery (previously the cap was
      // silent AND history stored the truncated response: unrecoverable).
      const projectAxe = (limit: number) => (v: {
        id: string; impact: string; help: string; helpUrl: string
        nodes: Array<{ html: string; target: string[]; failureSummary?: string }>
      }) => ({
        id: v.id,
        impact: v.impact,
        help: v.help,
        helpUrl: v.helpUrl,
        nodes: v.nodes.slice(0, limit).map((n) => ({
          html: n.html.slice(0, 300),
          target: n.target,
          failureSummary: n.failureSummary,
        })),
        nodesTotal: v.nodes.length,
        truncated: v.nodes.length > limit,
      })

      const violations = result.violations.map(projectAxe(nodeLimit))
      // axe incomplete results (dangling ARIA references etc.) are not
      // reported: the scanner judges or drops what axe could not decide.
      const truncatedRules = violations.filter((r) => r.truncated).length
      const scope = (url ? ` on ${url}` : '') + (selector ? ` within ${selector}` : '')
      const summaryLine = violations.length === 0
        ? `No ARIA violations found${scope}.`
        : `${violations.length} ARIA violation${violations.length === 1 ? '' : 's'} found${scope}.`
      const truncationNote = truncatedRules > 0
        ? ` NOTE: ${truncatedRules} rule(s) truncated to ${nodeLimit} nodes each (see truncated/nodesTotal per rule) — pass nodeLimit (max 50)${opts.remote ? '' : ' or retrieve the FULL untruncated set via `scan_history` with this scan\'s id'}.`
        : ''

      const response = {
        content: [
          { type: 'text', text: summaryLine + truncationNote },
          { type: 'text', text: '```json\n' + JSON.stringify({ violations }, null, 2) + '\n```' },
        ],
      }
      // Archive the FULL untruncated set so scan_history(id) recovers nodes
      // clipped from this response (same pattern as scan_page).
      {
        const fullViolations = result.violations.map(projectAxe(Number.MAX_SAFE_INTEGER))
        fullScanResultByResponse.set(response, {
          content: [
            response.content[0]!,
            { type: 'text', text: '```json\n' + JSON.stringify({ violations: fullViolations }, null, 2) + '\n```' },
          ],
        })
      }
      return response
    } catch (err) {
      if (err instanceof ToolRefusal) return toolError(err.message)
      return toolError(`check_aria failed: ${(err as Error).message}`)
    }
  }

  return toolError(`Unknown tool: ${name}`)
}

/**
 * Analytics args @posthog/mcp injects into every advertised tool schema
 * (`enablePostHogMcpAnalytics`). PostHog strips them from a call only when the
 * same server instance served tools/list first; the hosted transport builds a
 * server per request, so they reached the strict validators and check_aria /
 * verify_fix / get_rules answered `unknown argument 'context'` (MCP dogfood
 * 2026-10-03). We drop them ourselves, except where a tool declares the key as
 * its own argument (generate_ai_fix's `context` is real input).
 */
export const ANALYTICS_ARG_KEYS = ['context', 'llm_model', 'conversation_id'] as const

const OWN_ARG_KEYS = new Map<string, Set<string>>(ALL_TOOLS.map((t) => [t.name, new Set(Object.keys((t.inputSchema as any)?.properties ?? {}))]))

export function stripAnalyticsArgs(name: string, args: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!args || typeof args !== 'object') return args
  const own = OWN_ARG_KEYS.get(name)
  let out: Record<string, unknown> | undefined
  for (const k of ANALYTICS_ARG_KEYS) {
    if (!(k in args) || own?.has(k)) continue
    out ??= { ...args }
    delete out[k]
  }
  return out ?? args
}

const CHECK_ARIA_KEYS = ['html', 'url', 'selector', 'nodeLimit', 'tunnel_secret']
function checkAriaArgError(args: Record<string, unknown> | undefined): string | null {
  const unknown = Object.keys(args ?? {}).filter((k) => !CHECK_ARIA_KEYS.includes(k))
  return unknown.length > 0 ? `Error: unknown argument '${unknown[0]}' — valid keys: ${CHECK_ARIA_KEYS.join(', ')}` : null
}

/**
 * The unknown-key gate of the tools that refuse unknown args (get_rules,
 * verify_fix, check_aria), applied after the analytics strip exactly as a
 * real call is. Null when every key is accepted. Other tools ignore unknown
 * keys, so they always pass.
 */
export function strictArgError(name: string, rawArgs: Record<string, unknown> | undefined): string | null {
  const args = stripAnalyticsArgs(name, rawArgs)
  const unknownOnly = (e: string | undefined) => (e && /unknown argument/.test(e) ? e : null)
  if (name === 'get_rules') return unknownOnly(resolveGetRulesArgs(args).error)
  if (name === 'verify_fix') return unknownOnly(resolveVerifyFixArgs(args).error)
  if (name === 'check_aria') return checkAriaArgError(args)
  return null
}

/**
 * @posthog/mcp 0.17 pushes every injected analytics arg into the schema's
 * `required` list (no option to make it optional), so models treated
 * `context` / `llm_model` as mandatory. Re-wrap tools/list after PostHog
 * instruments the server and drop them from `required`; `context` and
 * `llm_model` stay advertised, as optional.
 *
 * `conversation_id` is removed outright: its injected description tells the
 * model to "echo the conversation_id from the server's previous response",
 * and no response of ours carries one (persona round 4, 18/80 runs). A call
 * that still sends it is accepted — stripAnalyticsArgs drops it.
 */
const UNADVERTISED_ANALYTICS_ARGS = ['conversation_id']

function keepAnalyticsArgsOptional(server: Server): void {
  const handlers = (server as any)._requestHandlers as Map<string, (req: any, extra: any) => Promise<any>> | undefined
  const inner = handlers?.get('tools/list')
  if (!handlers || !inner) return
  handlers.set('tools/list', async (req, extra) => {
    const res = await inner(req, extra)
    for (const t of res?.tools ?? []) {
      const own = OWN_ARG_KEYS.get(t.name)
      const req2 = t?.inputSchema?.required
      if (Array.isArray(req2)) t.inputSchema.required = req2.filter((k: string) => !(ANALYTICS_ARG_KEYS as readonly string[]).includes(k) || own?.has(k))
      const props = t?.inputSchema?.properties
      if (props) for (const k of UNADVERTISED_ANALYTICS_ARGS) if (!own?.has(k)) delete props[k]
    }
    return res
  })
}

export function createServer(opts: ServerOptions = {}) {
  const isLite = !opts.remote
  const server = new Server(
    { name: isLite ? 'webability-lite' : 'webability', version: MCP_VERSION },
    { capabilities: { tools: {} }, instructions: buildInstructions(isLite) },
  )
  server.setRequestHandler(ListToolsRequestSchema, () => handleListTools(opts))
  server.setRequestHandler(CallToolRequestSchema, (req) => handleCallTool(req, opts))
  enablePostHogMcpAnalytics(server, opts)
  keepAnalyticsArgsOptional(server)
  return server
}
