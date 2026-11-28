/**
 * The scan_html engine, in its own thread.
 *
 * jsdom + the WebAbility detectors + axe-core are one synchronous block on
 * whatever thread runs them: measured on origin/main, 12 KB of markup blocked
 * the loop 5.9 s, 24 KB 33 s. On the main thread that block is the whole
 * process — /health, OAuth and every other tenant's tool call wait behind it,
 * and a deadline cannot preempt it (a timer only fires when the loop yields).
 *
 * In a worker the block costs one thread: the parent keeps answering, and a
 * scan that blows its budget is stopped with `terminate()` — real preemption,
 * not a rejected promise racing a block that runs on regardless. `terminate()`
 * also discards the thread's half-written jsdom document, so the next call
 * starts from a clean one.
 *
 * The caps and the queue stay in the parent (fastScan.ts): they refuse work
 * before it costs a thread.
 */
import { createRequire } from 'node:module'
import { parentPort } from 'node:worker_threads'

import type { ScanIssue } from '@webability/core'
import type { scanDocument as scanDocumentFn } from '@webability/core/dom'
import type { DOMWindow } from 'jsdom'

import { judgeWithin } from './deadline.js'
import type { FastScanIssue, ScanWorkerJob, ScanWorkerResult } from './fastScan.js'
import { enrichIssue } from './fixOps.js'

const require = createRequire(import.meta.url)

/** CSS.escape per CSSOM §2.1.1 (serialize an identifier). */
function cssEscape(value: unknown): string {
  const s = String(value)
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c === 0) out += '\uFFFD'
    else if ((c >= 0x1 && c <= 0x1f) || c === 0x7f || (i === 0 && c >= 0x30 && c <= 0x39) || (i === 1 && c >= 0x30 && c <= 0x39 && s.charCodeAt(0) === 0x2d)) out += '\\' + c.toString(16) + ' '
    else if (i === 0 && c === 0x2d && s.length === 1) out += '\\' + s[i]
    else if (c >= 0x80 || c === 0x2d || c === 0x5f || (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a)) out += s[i]
    else out += '\\' + s[i]
  }
  return out
}

/**
 * jsdom has no layout, so every geometry read is answered here instead of
 * returning zeros (a zero-size element reads as hidden and hides findings).
 */
function installLayoutShims(win: DOMWindow) {
  const Element = win.Element
  // jsdom's getComputedStyle reads the element's inline style and throws on
  // elements that have none (a MathML root: <math lang="en">). Such an element
  // gets an empty declaration, as an unstyled element would.
  const computed = win.getComputedStyle.bind(win)
  win.getComputedStyle = ((el: Element | null, pseudo?: string | null) =>
    el && (el as Element & { style?: unknown }).style === undefined
      ? win.document.createElement('div').style
      : computed(el as Element, pseudo ?? undefined)) as typeof win.getComputedStyle
  const rect = (el: Element): DOMRect | null => {
    const style = win.getComputedStyle(el)
    if (style && style.display === 'none') return null
    let p = el.parentElement
    while (p) {
      if (win.getComputedStyle(p).display === 'none') return null
      p = p.parentElement
    }
    return { x: 0, y: 0, top: 0, left: 0, right: 100, bottom: 20, width: 100, height: 20, toJSON() { return this } } as DOMRect
  }
  Element.prototype.getBoundingClientRect = function () {
    return rect(this) ?? ({ x: 0, y: 0, top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0, toJSON() { return this } } as DOMRect)
  }
  Element.prototype.getClientRects = function () {
    const r = rect(this)
    const list = (r ? [r] : []) as unknown as DOMRectList & Array<DOMRect>
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
  // No layout means no hit testing: nothing is at any point.
  win.Document.prototype.elementFromPoint = () => null
  win.Document.prototype.elementsFromPoint = () => []
  // jsdom has no CSS namespace; the kernel builds selectors with CSS.escape.
  if (!win.CSS) win.CSS = { escape: cssEscape } as unknown as typeof win.CSS
}

type Engine = { win: DOMWindow; scanDocument: typeof scanDocumentFn }

/**
 * ONE jsdom window for the life of the thread. axe-core (and the detector
 * kernel) bind to the ambient `window`/`document` when first loaded, so a fresh
 * JSDOM per call scans the FIRST document forever — the second call returned
 * nothing. Instead the document is rewritten in place per scan
 * (`document.open/write/close`), which keeps every engine pointed at the live
 * content. Cold cost is 1-4 s, so the thread is kept warm and only replaced
 * when a deadline forces `terminate()`.
 *
 * Memoised as the PROMISE, not the built engine: the parent starts the warm-up
 * at module load and posts jobs immediately, so a second `engineReady()` call
 * arrives while the first is still awaiting jsdom and must not build a second
 * window. A rejected warm-up stays rejected — the parent kills this thread.
 */
let warming: Promise<Engine> | null = null

async function engineReady(): Promise<Engine> {
  warming ??= warmEngine()
  return warming
}

async function warmEngine(): Promise<Engine> {
  const { JSDOM, VirtualConsole } = require('jsdom') as typeof import('jsdom')
  // jsdom logs "Not implemented" (canvas etc.) to the console by default — keep stderr clean.
  const dom = new JSDOM('<!doctype html><html><head><title></title></head><body></body></html>', { pretendToBeVisual: true, virtualConsole: new VirtualConsole() })
  const win = dom.window
  installLayoutShims(win)
  const g = globalThis as unknown as Record<string, unknown>
  // Detectors run in Node's realm and read DOM globals (NodeFilter, CSS,
  // HTMLInputElement...) as free identifiers: expose every jsdom global this
  // realm lacks. Node's own (navigator, crypto, fetch, performance) win — the
  // `k in g` check keeps them. Lazy getters, so a throwing accessor
  // (localStorage on an opaque origin) throws only if a detector reads it.
  for (const k of Object.getOwnPropertyNames(win)) {
    if (k in g) continue
    Object.defineProperty(g, k, { configurable: true, get: () => win[k] })
  }
  // Detector functions run in this realm and read the kernel helpers
  // (isVisible, uniqueSel, isHiddenFromAT...) as free identifiers: install them
  // on this globalThis too (scanDocument installs them on the jsdom window
  // only), or every detector throws and scan_html runs axe alone. Idempotent.
  const { installDomKernel, scanDocument } = await import('@webability/core/dom')
  installDomKernel(g)
  return { win, scanDocument }
}

async function scan(job: ScanWorkerJob): Promise<ScanWorkerResult> {
  const { win, scanDocument } = await engineReady()
  // Measured from here, not from spawn: a cold thread costs seconds and is not
  // the scan's duration.
  const started = Date.now()
  win.document.open()
  win.document.write(job.doc)
  win.document.close()

  // `judgeWithin` must be applied HERE, not in the parent: it caps the judge
  // with a getter on `timeoutMs`, and structured clone evaluates a getter at
  // postMessage time — the judge would then be frozen at the budget it had when
  // the job was dispatched, ignoring the scan it waited behind.
  const judge = job.judgeEndsAt === undefined ? job.judge : judgeWithin(job.judge, job.judgeEndsAt)
  const result = await scanDocument({
    // jsdom's DOMWindow is the same object core takes; the DOM lib's global
    // statics (AnalyserNode, …) are absent from its type only because @types/jsdom
    // models the instance, not the realm's constructor table.
    window: win as unknown as Window & typeof globalThis,
    includeAxe: true,
    wcagTags: job.wcagTags,
    level: job.level,
    judge,
  })

  let skippedVisual = 0
  const project = (list: ScanIssue[]) => {
    const out: FastScanIssue[] = []
    for (const i of list) {
      // Explicit field list, not a spread: `ScanIssue` carries engine-internal
      // context (`source`, `confidence`, `reviewReason`, `evidence`) that the
      // tool payload has never exposed and that must not start leaking now.
      const e = enrichIssue({
        id: i.id,
        type: i.type,
        wcag: i.wcag,
        level: i.level,
        impact: i.impact,
        message: i.message,
        selector: i.selector,
        html: i.html?.slice(0, 400),
        fix: i.fix,
      })
      if (e.fixability === 'visual') { skippedVisual++; continue }
      out.push(e)
    }
    return out
  }
  const issues = project(result.issues ?? [])
  const count = (lvl: string) => issues.filter((i) => i.impact === lvl).length
  const warnings = (result.engineWarnings ?? []).filter((w) => !w.startsWith('focus:'))
  return {
    engine: 'in-process',
    issues,
    summary: { total: issues.length, critical: count('critical'), serious: count('serious'), moderate: count('moderate'), minor: count('minor') },
    skippedVisual,
    ...(result.judged?.length ? { judged: result.judged as ScanWorkerResult['judged'] } : {}),
    ...(warnings.length ? { engineWarnings: warnings } : {}),
    internal_bugs: (result.internal_bugs ?? []) as ScanWorkerResult['internal_bugs'],
    durationMs: Date.now() - started,
  }
}

/**
 * Messages run one at a time: the window is shared, so a second scan starting
 * mid-`await` of the first would rewrite the document under it. The parent
 * already serialises, which makes this a cheap second lock, not the plan.
 */
let chain: Promise<void> = Promise.resolve()

function post(message: unknown) {
  // Never bare `postMessage`: jsdom installs its own `window.postMessage` on
  // the bridged globals.
  parentPort!.postMessage(message)
}

parentPort!.on('message', (job: ScanWorkerJob) => {
  chain = chain.then(async () => {
    try {
      post({ id: job.id, ok: true, result: await scan(job) })
    } catch (err) {
      const e = err as Error
      post({ id: job.id, ok: false, error: { name: e?.name ?? 'Error', message: e?.message ?? String(err), stack: e?.stack } })
    }
  })
})

/**
 * Ready protocol. The parent may only `terminate()` a thread that is warm and
 * running the job whose deadline fired; a thread still paying the 1-4 s
 * cold start is kept, because killing it throws away the warm-up and the next
 * caller pays it again — the wedge this signal exists to end. Posted from the
 * module top level so the warm-up runs while the thread is idle, and jobs
 * posted before the listener below is attached are buffered on the port.
 */
engineReady().then(
  () => post({ ready: true }),
  (err: unknown) => {
    const e = err as Error | undefined
    post({ ready: false, error: { name: e?.name ?? 'Error', message: e?.message ?? String(err), stack: e?.stack } })
  },
)
