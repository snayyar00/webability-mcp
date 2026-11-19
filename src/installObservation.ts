import type { BrowserContext, Request } from 'playwright'
import { openSession, type OpenSessionOptions } from './browser.js'
import type { InstallObservation } from './installCheck.js'

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

/** Top-level document only. No consent interaction or policy bypass. */
export async function observeInstall(url: string, options: OpenSessionOptions = {}): Promise<InstallObservation> {
  let requests: InstallObservation['requests'] = []
  const session = await openSession({
    ...options,
    setupContext: async (context: BrowserContext) => {
      await options.setupContext?.(context)
      // Reset when the shared opener retries in a fresh context.
      requests = []
      await context.addInitScript(INIT)
      context.on('request', (request) => {
        try {
          if (request.resourceType() === 'script' && !request.frame().parentFrame() && !request.redirectedFrom()) {
            requests.push({ url: request.url() })
          }
        } catch { /* Service-worker requests have no frame. */ }
      })
      const record = async (request: Request, failed: boolean) => {
        try {
          if (request.resourceType() !== 'script' || request.frame().parentFrame()) return
          let original = request
          while (original.redirectedFrom()) original = original.redirectedFrom()!
          const response = await request.response()
          // Only terminal requests: a 200 response alone is not a completed download.
          if (request.redirectedTo()) return
          const entry = requests.find((r) => r.url === original.url() && r.status === undefined && !r.failure)
          if (entry) Object.assign(entry, { ...(response ? { status: response.status() } : {}),
            ...(failed ? { failure: request.failure()?.errorText ?? 'Script request failed' } : {}) })
        } catch { /* Context closure cannot supply usable evidence. */ }
      }
      context.on('requestfinished', (r) => { void record(r, false) })
      context.on('requestfailed', (r) => { void record(r, true) })
    },
  })
  const started = Date.now()
  try {
    const response = await session.goto(url, { waitUntil: 'load', timeout: 20000 })
    if (!response || response.status() >= 400) throw new Error(`Page navigation failed: HTTP ${response?.status() ?? 'unknown'}`)
    // Bounded window for dynamically inserted embeds; not a site-wide absence claim.
    await session.page.waitForTimeout(1000)
    const dom = await session.page.evaluate(`(() => {
      const o = window.__webabilityInstallObservation;
      if (!o) throw new Error('Install observation was interrupted by navigation');
      return { ...o, scriptElements: Array.from(document.querySelectorAll('script[src], script[data-src]')).map(s => ({
        src: new URL(s.getAttribute('src') || s.getAttribute('data-src'), document.baseURI).href,
        type: s.getAttribute('type') || '',
        attributes: Object.fromEntries(['data-cookieconsent', 'data-cookiecategory', 'data-consent'].filter(k => s.hasAttribute(k)).map(k => [k, s.getAttribute(k)]))
      })) };
    })()`)
    return { ...dom, finalUrl: session.page.url(), requests, observationDurationMs: Date.now() - started }
  } finally {
    await session.close()
  }
}
