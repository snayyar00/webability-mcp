/**
 * The engine's Page for scan_page / diff_scan (DESIGN M-1 cutover step 2).
 *
 * A browser session from openSession (local Chromium on stdio, the hosted
 * browser on the HTTP server). Every call reads `session.page` when it runs,
 * because the HTTP/2 retry in session.goto swaps the page for one in a fresh
 * browser; navigation goes through session.goto for that retry. Routes (SSRF
 * guard, tunnel header) live on the session's context, so the engine's own
 * goto carries them.
 */
import { fromPlaywright, type Page } from '@webability/core/engine'
import type { BrowserSession } from './browser.js'

export function sessionPage(session: BrowserSession): Page {
  const p = () => session.page
  const page = fromPlaywright({
    goto: (url, o) => session.goto(url, o),
    evaluate: (fn, arg) => p().evaluate(fn, arg),
    screenshot: (o) => p().screenshot(o),
    keyboard: { press: (k) => p().keyboard.press(k) },
    waitForLoadState: (s, o) => p().waitForLoadState(s, o),
    url: () => p().url(),
    addScriptTag: (o) => p().addScriptTag(o),
  })
  // axe scans iframes through the live page (read per call: the retry swaps it).
  return { ...page, playwrightPage: () => p() }
}
