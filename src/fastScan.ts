/**
 * In-process scan_html (DEV-1089 item 6): jsdom + the WebAbility detectors +
 * axe-core, no browser, no network. A component-sized snippet audits in
 * milliseconds instead of the ~1.5 s a headless Chromium launch costs.
 *
 * jsdom has no layout engine, so two shims stand in for it:
 *   - client rects: every element that is not display:none reports one rect.
 *     Without this, visibility gates (`getClientRects().length === 0`) hide
 *     the whole page and `missing_h1` fires on a page WITH an h1.
 *   - media readyState: axe's preload waits for `loadedmetadata` on every
 *     <video>/<audio>, which never fires in jsdom — 10 s stall per page.
 *
 * What layout cannot fake, we do not report: every finding whose rule is in
 * the `visual` fixability tier (contrast, target size, focus ring, reflow…)
 * is dropped and counted in `skippedVisual`. Use engine:"browser" for those.
 */
import { createRequire } from 'module'
import { enrichIssue, type Fixability } from './fixOps.js'

const require = createRequire(import.meta.url)

export interface FastScanIssue {
  id: string
  type: string
  wcag: string
  level?: string
  impact: string
  message: string
  selector: string
  html?: string
  fixability: Fixability
  fix: { op: string; attribute?: string; value?: string; currentValue?: string; suggestedValue?: string; needsManualReview?: boolean }
}

export interface FastScanResult {
  engine: 'in-process'
  fragment: boolean
  issues: FastScanIssue[]
  summary: { total: number; critical: number; serious: number; moderate: number; minor: number }
  skippedVisual: number
  engineWarnings?: string[]
  durationMs: number
}

const looksLikeDocument = (html: string) => /<html[\s>]|<!doctype/i.test(html)

function installLayoutShims(win: any) {
  const Element = win.Element
  const rect = (el: any) => {
    const style = win.getComputedStyle(el)
    if (style && style.display === 'none') return null
    let p = el.parentElement
    while (p) {
      if (win.getComputedStyle(p).display === 'none') return null
      p = p.parentElement
    }
    return { x: 0, y: 0, top: 0, left: 0, right: 100, bottom: 20, width: 100, height: 20, toJSON() { return this } }
  }
  Element.prototype.getBoundingClientRect = function () {
    return rect(this) ?? { x: 0, y: 0, top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0, toJSON() { return this } }
  }
  Element.prototype.getClientRects = function () {
    const r = rect(this)
    const list: any = r ? [r] : []
    list.item = (i: number) => list[i] ?? null
    return list
  }
  if (win.HTMLMediaElement) {
    Object.defineProperty(win.HTMLMediaElement.prototype, 'readyState', { configurable: true, get: () => 4 })
  }
  // Canvas is used only by the colour kernel (contrast) — visual tier, dropped anyway.
  if (win.HTMLCanvasElement) {
    win.HTMLCanvasElement.prototype.getContext = () => null
  }
}

let scanning: Promise<unknown> = Promise.resolve()

/**
 * ONE jsdom window for the life of the process. axe-core (and the detector
 * kernel) bind to the ambient `window`/`document` when first loaded, so a
 * fresh JSDOM per call scans the FIRST document forever — the second call
 * returned nothing. Instead the document is rewritten in place per scan
 * (`document.open/write/close`), which keeps every engine pointed at the
 * live content.
 */
let shared: { dom: import('jsdom').JSDOM; win: any } | null = null

function sharedWindow() {
  if (shared) return shared
  const { JSDOM, VirtualConsole } = require('jsdom') as typeof import('jsdom')
  // jsdom logs "Not implemented" (canvas etc.) to the console by default — keep stderr clean.
  const virtualConsole = new VirtualConsole()
  const dom = new JSDOM('<!doctype html><html><head><title></title></head><body></body></html>', { pretendToBeVisual: true, virtualConsole })
  const win = dom.window as any
  installLayoutShims(win)
  const g = globalThis as any
  g.window = win; g.document = win.document; g.Node = win.Node; g.Element = win.Element; g.HTMLElement = win.HTMLElement; g.getComputedStyle = win.getComputedStyle
  shared = { dom, win }
  return shared
}

export async function fastScanHtml(html: string, opts: { wcagTags?: string[]; level?: 'A' | 'AA' | 'AAA' } = {}): Promise<FastScanResult> {
  // The detector kernel and axe read the ambient `window`/`document`; scans
  // must not interleave. Serialise on a module-level chain.
  const run = scanning.then(() => fastScanHtmlSerial(html, opts))
  scanning = run.catch(() => undefined)
  return run
}

async function fastScanHtmlSerial(html: string, opts: { wcagTags?: string[]; level?: 'A' | 'AA' | 'AAA' }): Promise<FastScanResult> {
  const started = Date.now()
  const fragment = !looksLikeDocument(html)
  const doc = fragment ? `<!doctype html><html lang="en"><head><title>snippet</title></head><body><main><h1>Snippet</h1>${html}</main></body></html>` : html
  const { win } = sharedWindow()
  win.document.open()
  win.document.write(doc)
  win.document.close()

  const { scanDocument } = await import('@webability/core/dom')
  const result = await scanDocument({ window: win, includeAxe: true, wcagTags: opts.wcagTags, level: opts.level })
  let skippedVisual = 0
  const project = (list: any[]) => {
    const out: FastScanIssue[] = []
    for (const i of list) {
      const e = enrichIssue({ id: i.id, type: i.type, wcag: i.wcag, level: i.level, impact: i.impact, message: i.message, selector: i.selector, html: i.html?.slice(0, 400), fix: i.fix }) as any
      if (e.fixability === 'visual') { skippedVisual++; continue }
      out.push(e)
    }
    return out
  }
  const issues = project(result.issues)
  const count = (lvl: string) => issues.filter((i) => i.impact === lvl).length
  const warnings = (result.engineWarnings ?? []).filter((w) => !w.startsWith('focus:'))
  return {
    engine: 'in-process',
    fragment,
    issues,
    summary: { total: issues.length, critical: count('critical'), serious: count('serious'), moderate: count('moderate'), minor: count('minor') },
    skippedVisual,
    ...(warnings.length ? { engineWarnings: warnings } : {}),
    durationMs: Date.now() - started,
  }
}
