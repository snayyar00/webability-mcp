import type { BrowserContext, Page, Request } from 'playwright'
import { openSession, type OpenSessionOptions } from './browser.js'
import { isInstallScript, type InstallObservation } from './installCheck.js'

// Runs before page scripts. DOM types are deliberately confined to browser code.
const INIT = `(() => {
  const observations = { policyViolations: [], runtimeErrors: [] };
  window.__webabilityInstallObservation = observations;
  addEventListener('securitypolicyviolation', e => observations.policyViolations.push({
    blockedUrl: e.blockedURI, directive: e.effectiveDirective,
    policy: e.originalPolicy, disposition: e.disposition
  }));
  addEventListener('error', e => {
    if (e.filename) observations.runtimeErrors.push({ scriptUrl: e.filename, message: e.message });
  });
})()`

/**
 * A V8 stack frame line: `    at fn (URL:line:col)` or `    at URL:line:col`.
 * Scoped to the line so a URL inside the error message never counts as a frame.
 */
const STACK_FRAME_URL = /^\s+at\s+(.+):(\d+):(\d+)\)?\s*$/

/**
 * The URL a frame names, or undefined for a frame that names no file.
 * A parenthesised URL keeps its own parentheses, so the tail is matched
 * greedily and the column pair taken from the end.
 */
export function scriptUrlFromStack(stack: string | undefined): string | undefined {
  for (const line of stack?.split('\n') ?? []) {
    const prefix = line.match(STACK_FRAME_URL)?.[1]
    if (!prefix) continue
    const candidate = /^https?:\/\//.test(prefix) ? prefix : prefix.slice(prefix.lastIndexOf(' (') + 2)
    // A frame URL names a file: a bare host with a port is not one.
    if (!/^https?:\/\/[^/]+\/./.test(candidate)) continue
    try { return new URL(candidate).href } catch { /* Malformed frame; try the next. */ }
  }
  return undefined
}

/**
 * URLs a redirecting script is evidence under. A script that executes at a
 * recognized embed URL is that embed, so the classifier has to see the terminal
 * URL; a hop to any other host is a different script.
 */
export function recordedScriptUrls(requestUrl: string, originalUrl: string): string[] {
  return requestUrl !== originalUrl && isInstallScript(requestUrl) ? [originalUrl, requestUrl] : [originalUrl]
}

/** Overridable so tests can prove the deadline without waiting out the default. */
const DEFAULT_OBSERVATION_DEADLINE_MS = 30000

export interface ObserveInstallOptions extends OpenSessionOptions {
  /** Overall cap on the observation. Exceeding it rejects and always closes the session. */
  deadlineMs?: number
}

/** Top-level document only. No consent interaction or policy bypass. */
export async function observeInstall(url: string, options: ObserveInstallOptions = {}): Promise<InstallObservation> {
  const { deadlineMs = DEFAULT_OBSERVATION_DEADLINE_MS, ...sessionOptions } = options
  let requests: InstallObservation['requests'] = []
  let uncaught: InstallObservation['runtimeErrors'] = []
  // Terminal URL of a redirect chain -> the URL the page asked for. A script that
  // redirects to another embed host still executes at its terminal URL, so the
  // exception names that one and has to map back to the recorded request.
  let chainOriginals = new Map<string, string>()
  const session = await openSession({
    ...sessionOptions,
    setupContext: async (context: BrowserContext) => {
      await sessionOptions.setupContext?.(context)
      // Reset when the shared opener retries in a fresh context.
      requests = []
      uncaught = []
      chainOriginals = new Map()
      // Listeners are context-wide, so a popup the page opens reports too.
      // Only the session's own page is evidence about this page.
      let inspected: Page | undefined
      const isInspectedScript = (request: Request): boolean => {
        try {
          const frame = request.frame()
          return request.resourceType() === 'script' && frame.page() === inspected && !frame.parentFrame()
        } catch { return false } // Service-worker requests have no frame.
      }
      await context.addInitScript(INIT)
      context.on('request', (request) => {
        if (!isInspectedScript(request)) return
        let original = request
        while (original.redirectedFrom()) original = original.redirectedFrom()!
        // A recognized terminal URL is evidence under itself; a hop to any other
        // host only says which page request the chain started from.
        chainOriginals.set(request.url(), isInstallScript(request.url()) ? request.url() : original.url())
        for (const url of recordedScriptUrls(request.url(), original.url())) {
          if (!requests.some((r) => r.url === url)) requests.push({ url })
        }
      })
      const record = async (request: Request, failed: boolean) => {
        try {
          if (!isInspectedScript(request)) return
          let original = request
          while (original.redirectedFrom()) original = original.redirectedFrom()!
          const response = await request.response()
          // Only terminal requests: a 200 response alone is not a completed download.
          if (request.redirectedTo()) return
          const outcome = { ...(response ? { status: response.status() } : {}),
            ...(failed ? { failure: request.failure()?.errorText ?? 'Script request failed' } : {}) }
          for (const url of recordedScriptUrls(request.url(), original.url())) {
            const entry = requests.find((r) => r.url === url && r.status === undefined && !r.failure)
            if (entry) Object.assign(entry, outcome)
          }
        } catch { /* Context closure cannot supply usable evidence. */ }
      }
      context.on('requestfinished', (r) => { void record(r, false) })
      // window 'error' is muted for cross-origin scripts without CORS ("Script error."),
      // so the page-level exception is the only record of a broken install.
      context.on('page', (page: Page) => {
        if (inspected) return
        inspected = page
        page.on('pageerror', (error: Error) => {
          const frameUrl = scriptUrlFromStack(error.stack)
          // Child-frame exceptions surface on the Page too. Only a script the
          // inspected document itself requested is evidence about this page.
          const scriptUrl = frameUrl && chainOriginals.get(frameUrl)
          if (scriptUrl) uncaught.push({ scriptUrl, message: error.message })
        })
      })
      context.on('requestfailed', (r) => { void record(r, true) })
    },
  })
  let deadlineTimer: NodeJS.Timeout | undefined
  const deadline = new Promise<never>((_, reject) => {
    deadlineTimer = setTimeout(() => reject(new Error(`Install observation exceeded the ${deadlineMs}ms deadline`)), deadlineMs)
  })
  // A client-side redirect replaces the document during the wait, and the init
  // script reruns in the new one, so its own guard cannot see the swap. The
  // page's main-frame DOMContentLoaded is one new-document signal per document;
  // same-document history changes do not fire it.
  let documentLoads = 0
  let countedPage: Page = session.page
  const countDocument = () => { documentLoads++ }
  countedPage.on('domcontentloaded', countDocument)
  try {
    // A page can block the event loop after load, so the DOM read would never
    // settle. The deadline bounds the whole observation, not just navigation.
    return await Promise.race([inspect(), deadline])
  } finally {
    clearTimeout(deadlineTimer)
    await session.close()
  }

  async function inspect(): Promise<InstallObservation> {
    const started = Date.now()
    const response = await session.goto(url, { waitUntil: 'load', timeout: 20000 })
    if (!response || response.status() >= 400) throw new Error(`Page navigation failed: HTTP ${response?.status() ?? 'unknown'}`)
    // The shared opener retries in a fresh browser: the first load is that page's.
    if (session.page !== countedPage) {
      countedPage.off('domcontentloaded', countDocument)
      countedPage = session.page
      documentLoads = 1
      countedPage.on('domcontentloaded', countDocument)
    }
    // Bounded window for dynamically inserted embeds; not a site-wide absence claim.
    await session.page.waitForTimeout(1000)
    if (documentLoads > 1) throw new Error('Install observation was interrupted by navigation')
    const dom = await session.page.evaluate(`(() => {
      const o = window.__webabilityInstallObservation;
      if (!o) throw new Error('Install observation was interrupted by navigation');
      return { ...o, scriptElements: Array.from(document.querySelectorAll('script[src], script[data-src]')).flatMap(s => {
        const type = s.getAttribute('type') || '';
        const attributes = Object.fromEntries(['data-cookieconsent', 'data-cookiecategory', 'data-consent'].filter(k => s.hasAttribute(k)).map(k => [k, s.getAttribute(k)]));
        // src and data-src are separate candidates (consent managers keep a
        // placeholder in src). One malformed URL skips that candidate only.
        return ['src', 'data-src'].flatMap(name => {
          const raw = s.getAttribute(name);
          if (!raw) return [];
          try { return [{ src: new URL(raw, document.baseURI).href, type, attributes }] } catch { return [] }
        });
      }) };
    })()`)
    // A redirected script reports its terminal URL (module scripts do even for
    // window 'error'), so both sources map back to the recorded request. An
    // unmapped URL is not a script this page requested: not evidence here.
    const runtimeErrors = [...dom.runtimeErrors, ...uncaught].flatMap((e) => {
      const scriptUrl = chainOriginals.get(e.scriptUrl)
      return scriptUrl ? [{ scriptUrl, message: e.message }] : []
    }).filter((e, index, all) => all.findIndex((o) => o.scriptUrl === e.scriptUrl &&
      (o.message.includes(e.message) || e.message.includes(o.message))) === index)
    return { ...dom, runtimeErrors, finalUrl: session.page.url(), requests, observationDurationMs: Date.now() - started }
  }
}
