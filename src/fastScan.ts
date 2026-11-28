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
 *
 * The engine runs in a worker thread (scanWorker.ts), never on this one: a
 * scan is one synchronous block of 0.7-33 s, and on the main thread that block
 * is the whole process — /health, OAuth and every other tenant's tool call wait
 * behind it, and a deadline cannot preempt it (a timer only fires when the loop
 * yields). Four guards keep it from becoming a freeze, in this order: a
 * pre-scan cap on bytes / element count / nesting depth, a bounded queue that
 * answers "busy, retry in Ns" instead of chaining callers, a wall-clock
 * deadline per call (withDeadline), and terminate() on the thread when that
 * deadline passes — which is what makes the deadline real.
 *
 * This module owns the policy (caps, queue, deadline, thread lifecycle) and
 * the document decision; the worker owns jsdom and the scan itself.
 */
import { Worker } from 'node:worker_threads'

import { defaultTreeAdapter, parse as parse5Parse } from 'parse5'
import type { InternalBug, JudgeOptions, JudgedEntry } from '@webability/core'
import { DeadlineError, withDeadline } from './deadline.js'
import type { Fixability } from './fixOps.js'

/**
 * Caps, deadline and queue for the in-process engine.
 *
 * ONE jsdom document per worker thread, one scan at a time, started on demand.
 * Measured on origin/main: 12 KB of markup cost 5.9 s, 24 KB 33 s, a
 * depth-800 nest 10 s. The cost is superlinear in element count and nesting
 * depth, not in bytes, so the snippet gets a ceiling in all three dimensions.
 * A 33 s scan no longer freezes the server, but it still burns a thread and a
 * caller's 24 s budget: anything bigger belongs on scan_page or on
 * engine:"browser", where each scan is its own page.
 */
export const SCAN_HTML_MAX_BYTES = 256 * 1024
/** Measured: 300 flat elements ≈ 9 s worst case, 500 ≈ 38 s. A component snippet, not a page. */
export const SCAN_HTML_MAX_ELEMENTS = 300
/** Real markup nests well under 30. The 800-deep shape takes 10 s. */
export const SCAN_HTML_MAX_DEPTH = 100
/**
 * In-flight + queued scan_html calls allowed on one process. Past this the
 * caller is told the server is busy instead of joining a chain of unknown
 * length — unbounded queueing is what turned one slow scan into a total stall.
 */
export const DEFAULT_SCAN_HTML_QUEUE = 8
/**
 * One scan_html call may not outlive this. scan_page's hosted budget is 25 s;
 * the snippet engine gets the same idea one second under it.
 */
export const SCAN_HTML_DEADLINE_MS = 24_000

export type ScanHtmlLimitKind = 'bytes' | 'elements' | 'depth'

/** The snippet is past an engine cap. The message always names the way out. */
export class ScanHtmlLimitError extends Error {
  constructor(
    readonly kind: ScanHtmlLimitKind,
    message: string,
  ) {
    super(message)
    this.name = 'ScanHtmlLimitError'
  }
}

/** Every scan slot is taken: answer with retry guidance, never queue forever. */
export class ScanHtmlBusyError extends Error {
  readonly retryAfterSeconds: number
  constructor(
    readonly queueDepth: number,
    retryAfterSeconds: number,
  ) {
    super(
      `scan_html is at capacity: ${queueDepth} in-process scan(s) already running or queued on this server (the jsdom engine scans one document at a time). ` +
        `Server busy — retry in ${retryAfterSeconds}s. A snippet this slow belongs on scan_page, or on scan_html with engine:"browser".`,
    )
    this.name = 'ScanHtmlBusyError'
    this.retryAfterSeconds = retryAfterSeconds
  }
}

/**
 * Elements and nesting depth of the tree the HTML parser builds from this
 * markup, counted on parse5 (the parser jsdom uses) before the engine sees it.
 * A hand-written tokenizer here kept under-counting: a stray `<`, an `=` outside
 * a value, an end tag whose name differs by one character, `</p>` and `</br>`
 * that build elements (a seeded fuzz against parse5 found thousands). Counting
 * the parser's own tree cannot be bypassed that way. parse5 is a linear state
 * machine, so a 256 KB unterminated tag costs one pass; building a bare tree is
 * cheap next to the detectors, which are what the caps protect.
 *
 * The walk stops as soon as a cap is passed. The implied html, head and body
 * do not count; `<template>` content does (over-counting only refuses a rare
 * safe snippet).
 */
/** The document the engine writes for this input: a snippet goes inside a fixed page, a whole document as is. */
export function engineDocument(html: string): { doc: string; fragment: boolean } {
  const fragment = !looksLikeDocument(html)
  return { doc: fragment ? `<!doctype html><html lang="en"><head><title>snippet</title></head><body><main><h1>Snippet</h1>${html}</main></body></html>` : html, fragment }
}
/** Elements and depth the fixed snippet page adds by itself: title, main, h1; main is one level. */
const WRAPPER_ELEMENTS = 3
const WRAPPER_DEPTH = 1
const HTML_NS = 'http://www.w3.org/1999/xhtml'
/**
 * The document's own html/head/body, which every page has and the caps ignore.
 * Inside <svg>/<math> the same tag names are foreign elements the parser really
 * builds, so the skip is keyed on the HTML namespace, not the name alone.
 */
const isImpliedRoot = (tagName: string, namespaceURI: unknown) =>
  namespaceURI === HTML_NS && (tagName === 'html' || tagName === 'head' || tagName === 'body')
/** Thrown out of the parse5 tree adapter to stop a parse past the element cap. */
const OVER_ELEMENTS = new Error('scan_html element cap')
const OVER_DEPTH = new Error('scan_html depth cap')

export function estimateMarkupSize(html: string): { elements: number; depth: number; over?: ScanHtmlLimitKind } {
  // Parse what the engine will write: a `</p>` inside the snippet page builds
  // a <p>, while the same `</p>` at the top of a bare document is dropped.
  const { doc, fragment } = engineDocument(html)
  // parse5's tree builder slows down sharply with depth (52k nested divs: 9 s),
  // so the parse itself must stop at the cap: count every element as the
  // builder creates it and abort past the cap. Created >= built (the adoption
  // agency clones), so stopping early only ever refuses, never under-counts.
  let created = fragment ? -WRAPPER_ELEMENTS : 0
  const depthOf = new WeakMap<object, number>()
  const track = (parent: any, node: any) => {
    if (typeof node.tagName !== 'string') return
    const implied = isImpliedRoot(node.tagName, node.namespaceURI)
    const d = (depthOf.get(parent) ?? 0) + (implied ? 0 : 1)
    depthOf.set(node, d)
    if (d - (fragment ? WRAPPER_DEPTH : 0) > SCAN_HTML_MAX_DEPTH) throw OVER_DEPTH
  }
  const capped = {
    ...defaultTreeAdapter,
    createElement(tagName: string, namespaceURI: any, attrs: any) {
      if (!isImpliedRoot(tagName, namespaceURI)) {
        created += 1
        if (created > SCAN_HTML_MAX_ELEMENTS) throw OVER_ELEMENTS
      }
      return defaultTreeAdapter.createElement(tagName, namespaceURI, attrs)
    },
    // Depth as nodes are attached, so a deep nest is refused as too deep, not
    // as too many elements. A node the adoption agency moves keeps a stale depth
    // on its children; that can only miss here, and the exact walk below
    // still measures the (now small) tree.
    appendChild(parent: any, node: any) {
      track(parent, node)
      defaultTreeAdapter.appendChild(parent, node)
    },
    insertBefore(parent: any, node: any, ref: any) {
      track(parent, node)
      defaultTreeAdapter.insertBefore(parent, node, ref)
    },
  }
  let root: any
  try {
    root = parse5Parse(doc, { treeAdapter: capped as typeof defaultTreeAdapter })
  } catch (err) {
    if (err === OVER_ELEMENTS) return { elements: created, depth: 0, over: 'elements' }
    if (err === OVER_DEPTH) return { elements: created, depth: SCAN_HTML_MAX_DEPTH + 1, over: 'depth' }
    throw err
  }
  let elements = fragment ? -WRAPPER_ELEMENTS : 0
  let maxDepth = 0
  const depthOffset = fragment ? WRAPPER_DEPTH : 0
  const stack: Array<[any, number]> = [[root, 0]]
  while (stack.length) {
    const [node, depth] = stack.pop()!
    let childDepth = depth
    if (typeof node.tagName === 'string') {
      if (!isImpliedRoot(node.tagName, node.namespaceURI)) {
        elements += 1
        if (elements > SCAN_HTML_MAX_ELEMENTS) return { elements, depth: maxDepth, over: 'elements' }
        childDepth = depth + 1
        if (childDepth - depthOffset > maxDepth) {
          maxDepth = childDepth - depthOffset
          if (maxDepth > SCAN_HTML_MAX_DEPTH) return { elements, depth: maxDepth, over: 'depth' }
        }
      }
    }
    const kids = node.childNodes as any[] | undefined
    if (kids) for (let k = kids.length - 1; k >= 0; k--) stack.push([kids[k], childDepth])
    if (node.content?.childNodes) stack.push([node.content, childDepth])
  }
  return { elements, depth: maxDepth }
}

/**
 * Refuse a snippet the shared in-process engine cannot scan inside its budget,
 * BEFORE a byte of it reaches jsdom. Every message names the alternative —
 * a refusal with no way forward is just retried by the agent.
 */
export function assertScanHtmlWithinCaps(html: string): void {
  const bytes = Buffer.byteLength(html, 'utf8')
  if (bytes > SCAN_HTML_MAX_BYTES) {
    throw new ScanHtmlLimitError(
      'bytes',
      `scan_html html is ${kb(bytes)} KB; the in-process engine caps a snippet at ${kb(SCAN_HTML_MAX_BYTES)} KB. ` +
        'Split it into smaller snippets, or use scan_page on the URL (or scan_html with engine:"browser") to scan a whole page.',
    )
  }
  const { elements, depth, over } = estimateMarkupSize(html)
  if (over === 'elements') {
    throw new ScanHtmlLimitError(
      'elements',
      `scan_html html has ~${elements} elements; the in-process engine caps a snippet at ${SCAN_HTML_MAX_ELEMENTS} (its cost grows superlinearly with element count). ` +
        'Split it into smaller snippets, or use scan_page on the URL (or scan_html with engine:"browser") to scan a whole page.',
    )
  }
  if (over === 'depth') {
    throw new ScanHtmlLimitError(
      'depth',
      `scan_html html nests ${depth} levels deep; the in-process engine caps nesting at ${SCAN_HTML_MAX_DEPTH} levels. ` +
        'Flatten the markup, or use scan_page on the URL (or scan_html with engine:"browser") to scan the page as built.',
    )
  }
}

const kb = (bytes: number) => `${Math.round(bytes / 1024).toLocaleString('en-US')}`

function scanQueueLimit(): number {
  const raw = Number(process.env.MCP_SCAN_HTML_MAX_QUEUE)
  return Number.isInteger(raw) && raw > 0 ? raw : DEFAULT_SCAN_HTML_QUEUE
}

/** How long a caller at the back of the queue should wait: the scans ahead of it, at the recent measured pace. */
function retryAfterSeconds(depth: number): number {
  return Math.min(30, Math.max(1, Math.ceil((depth * recentScanMs) / 1000)))
}

/** Scans in flight + waiting. */
let queueDepth = 0
/** EWMA of completed in-process scans, the basis of the "retry in Ns" hint. */
let recentScanMs = 750

/**
 * Queue state as seen from outside the engine, for the two places that answer
 * a caller before a scan could start: the hosted edge (503 + `Retry-After`
 * when `full`) and the handler (the header on a scan that timed out, where the
 * honest wait is the pace of the scans ahead).
 */
export function scanHtmlQueue(): { depth: number; limit: number; full: boolean; retryAfterSeconds: number } {
  const limit = scanQueueLimit()
  const depth = queueDepth
  return { depth, limit, full: depth >= limit, retryAfterSeconds: retryAfterSeconds(Math.max(1, depth)) }
}

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
  /** AI-judge verdicts on findings the engines could not decide (text-only here). */
  judged?: JudgedEntry[]
  skippedVisual: number
  engineWarnings?: string[]
  internal_bugs?: InternalBug[]
  durationMs: number
}

const looksLikeDocument = (html: string) => /<html[\s>]|<!doctype/i.test(html)

/**
 * The scan result without the two fields the parent owns: the worker never
 * learns whether its document came from a snippet, and `durationMs` is the
 * scan's own time on its own thread.
 */
export type ScanWorkerResult = Omit<FastScanResult, 'fragment'>

/** One unit of work for the worker. Plain JSON — structured clone, no functions. */
export interface ScanWorkerJob {
  id: number
  /** The finished document to write: the snippet wrapper is already applied. */
  doc: string
  wcagTags?: string[]
  level?: 'A' | 'AA' | 'AAA'
  judge?: Omit<JudgeOptions, 'transport'>
  /** Absolute epoch ms the judge must end by; the worker caps its own judge with it. */
  judgeEndsAt?: number
}

/** What a worker posts back: the result, or the error with its name restored. */
type ScanWorkerReply = { id: number; ok: true; result: ScanWorkerResult } | { id: number; ok: false; error: { name: string; message: string; stack?: string } }

/**
 * The warm-up signal. A thread posts `ready` once jsdom, axe and the detector
 * kernel are loaded, i.e. once a job posted to it can be scanned at all; before
 * that a job sits in the thread's port queue while the cold start runs. A
 * failed warm-up is final — that thread can never scan, so the parent kills it.
 */
type ScanWorkerReady = { ready: true } | { ready: false; error: { name: string; message: string; stack?: string } }
type ScanWorkerMessage = ScanWorkerReply | ScanWorkerReady

let scanning: Promise<void> = Promise.resolve()

/**
 * ONE warm engine thread, spawned on the first scan and reused. Two reasons,
 * both measured: a cold thread costs 1-4 s before jsdom is even loaded, and
 * axe-core plus the detector kernel bind to the ambient `window`/`document`
 * when first loaded — which is why the worker rewrites one document in place
 * instead of building a fresh JSDOM per call.
 *
 * `ready` and `running` are the deadline's two questions: a deadline may kill a
 * thread only when it is warm AND the job that blew its budget is the one it is
 * working on. Killing a warming thread throws away the 1-4 s it already paid, so
 * the replacement pays it again, and a loaded machine can lose that race every
 * call — the thread never finishes warming and the engine never recovers.
 */
interface EngineThread {
  readonly worker: Worker
  /** Warm-up finished: a job posted now is scanned, not queued behind imports. */
  ready: boolean
  /** The job posted to this thread whose reply has not been seen yet, if any. */
  running: number | null
}

let engineThread: EngineThread | null = null
let nextJobId = 1
const pending = new Map<number, { resolve: (r: ScanWorkerResult) => void; reject: (e: Error) => void }>()

/**
 * The thread's loader. tsx registers its module hooks on the MAIN thread only
 * (its preflight and ESM entry both check `isMainThread`), so a worker started
 * from source resolves none of this package's relative `.js` specifiers and
 * dies with ERR_MODULE_NOT_FOUND. `workerTsx.mjs` registers the same hooks in
 * the thread before the entry module loads. In dist the worker is emitted
 * beside its imports, so it needs no loader and inherits this process's argv.
 */
function workerExecArgv(): string[] | undefined {
  if (!import.meta.url.endsWith('.ts')) return undefined
  return ['--import', new URL('./workerTsx.mjs', import.meta.url).href]
}

function spawnEngineThread(): EngineThread {
  // By extension, not by module resolution: under `tsx` the source is what must
  // run, in dist it is the emitted sibling.
  const url = new URL(import.meta.url.endsWith('.ts') ? './scanWorker.ts' : './scanWorker.js', import.meta.url)
  const thread: EngineThread = { worker: new Worker(url, { execArgv: workerExecArgv() }), ready: false, running: null }
  const { worker: w } = thread
  // Listeners first, then unref: attaching a `message` listener re-refs the
  // thread's port (node:internal/worker/io), so unref-ing before the `on` calls
  // is silently undone and an idle warm thread pins the event loop forever. An
  // idle warm thread must not keep the process alive (tests, the CLI); a thread
  // with a job in flight is ref'd in dispatch, and its reply unrefs again.
  w.on('message', (msg: ScanWorkerMessage) => {
    // Only the current thread's readiness matters: a terminated thread can still
    // deliver a message in the tick before `exit`.
    if ('ready' in msg) {
      if (engineThread !== thread) return
      if (msg.ready) {
        thread.ready = true
        return
      }
      // A thread whose warm-up threw can never scan. Its jobs (and the callers
      // waiting on them) are failed here rather than at each deadline.
      const err = new Error(msg.error.message)
      err.name = msg.error.name
      if (msg.error.stack) err.stack = msg.error.stack
      killEngineThread(err)
      return
    }
    const entry = pending.get(msg.id)
    if (!entry) return
    pending.delete(msg.id)
    if (thread.running === msg.id) thread.running = null
    if (pending.size === 0) w.unref()
    if (msg.ok) {
      entry.resolve(msg.result)
      return
    }
    // Rebuild the error the worker threw, name and stack intact: callers branch
    // on `instanceof`/`name` (the handler maps DeadlineError, ScanHtmlLimitError
    // and friends), and a bare Error would hide which one happened.
    const err = new Error(msg.error.message)
    err.name = msg.error.name
    if (msg.error.stack) err.stack = msg.error.stack
    entry.reject(err)
  })
  const died = (err: Error) => {
    // A terminate() we caused fires 'exit' after the replacement may exist:
    // only the CURRENT thread's death may clear the handle and its jobs.
    if (engineThread !== thread) return
    killEngineThread(err)
  }
  w.on('error', died)
  w.on('exit', (code) => died(new Error(`scan_html engine thread exited with code ${code}`)))
  w.unref()
  return thread
}

/**
 * Stop the thread and fail everything it owed. Jobs are rejected BEFORE the
 * handle is cleared and the thread terminated: a cleared map with an unsettled
 * job would leave `work` pending forever, and the serial chain releases only
 * when `work` settles.
 */
function killEngineThread(reason: Error) {
  const thread = engineThread
  engineThread = null
  for (const [id, entry] of pending) {
    pending.delete(id)
    entry.reject(reason)
  }
  thread?.worker.terminate().catch(() => {})
}

export interface FastScanOptions {
  wcagTags?: string[]
  level?: 'A' | 'AA' | 'AAA'
  judge?: JudgeOptions
  /**
   * Absolute epoch ms the judge must end by (the call's own deadline, minus a
   * margin to build the reply). Applied in the worker, not here: capping it
   * here would freeze the budget at dispatch time and give the judge the whole
   * scan's duration on top.
   */
  judgeEndsAt?: number
  /** Hard budget for one scan. Defaults to SCAN_HTML_DEADLINE_MS. */
  deadlineMs?: number
}

export async function fastScanHtml(html: string, opts: FastScanOptions = {}): Promise<FastScanResult> {
  // The caps run here as well as in the handler: this is a public entry point
  // (tests, the CLI), and a cap the caller can forget is not a cap.
  assertScanHtmlWithinCaps(html)
  // A judge transport is a function; structured clone refuses it, and the
  // refusal would arrive as a DataCloneError after the caller spent a queue
  // slot. Refuse it here, before either.
  if (opts.judge && typeof (opts.judge as { transport?: unknown }).transport === 'function') {
    throw new Error(
      'scan_html judge options carry a `transport` function, which cannot cross to the worker thread that runs the scan. ' +
        'Call scanDocument from @webability/core/dom directly to supply a transport.',
    )
  }

  const limit = scanQueueLimit()
  if (queueDepth >= limit) throw new ScanHtmlBusyError(queueDepth, retryAfterSeconds(queueDepth))
  queueDepth += 1

  // Serialise on a module-level chain: the thread has ONE document, so scans
  // must not interleave. The chain is released by the WORK, never by the
  // caller's deadline — see fastScanHtmlSerial.
  const previous = scanning
  let releaseChain!: () => void
  scanning = new Promise<void>((resolve) => (releaseChain = resolve))

  let settled = false
  // `scanMs` is the scan's OWN duration, absent when the scan never ran (its
  // caller gave up while it was queued) — the average is the pace of one scan,
  // so neither queue wait nor a skipped waiter moves it.
  const onSettled = (scanMs?: number) => {
    if (settled) return
    settled = true
    queueDepth -= 1
    if (scanMs !== undefined) recentScanMs = Math.round(recentScanMs * 0.7 + scanMs * 0.3)
    releaseChain()
  }

  return fastScanHtmlSerial(html, opts, previous, onSettled)
}

/**
 * One call, inside the serial chain, under a hard deadline.
 *
 * The deadline covers the QUEUE WAIT as well as the scan (it starts at call
 * entry, in fastScanHtml), so a call cannot outlive its budget however long the
 * queue is. What it now also does is stop the WORK: the scan is a synchronous
 * block on another thread, so `terminate()` is real preemption — the reply is
 * no longer bounded by how long the block runs, and the thread's half-written
 * document dies with it.
 *
 * Only a deadline kills the thread, and only one that is warm AND working on
 * this job. A job still queued never touched the document; an error the worker
 * reported is that scan's problem, not the thread's; and a thread still paying
 * its 1-4 s cold start is the one case where killing makes the next call pay it
 * again. On a loaded machine that next call loses the same race to its own
 * deadline, the replacement never finishes warming, and the engine never
 * recovers — so a warming thread is kept: this caller is answered at its
 * deadline (the work continues abandoned), and the next one inherits the
 * warm-up instead of restarting it.
 */
function fastScanHtmlSerial(html: string, opts: FastScanOptions, previous: Promise<void>, onSettled: (scanMs?: number) => void): Promise<FastScanResult> {
  const abort = new AbortController()
  const { doc, fragment } = engineDocument(html)
  const job: ScanWorkerJob = { id: nextJobId++, doc, wcagTags: opts.wcagTags, level: opts.level, judge: opts.judge, judgeEndsAt: opts.judgeEndsAt }
  const work: Promise<FastScanResult> = previous.then(() => {
    // A caller who gave up while queued must not reach the thread at all.
    abort.signal.throwIfAborted()
    return dispatchToEngine(job)
  }).then((r) => ({ ...r, fragment }))
  // `work` is async from the start, so it cannot throw before returning a
  // promise: the slot and the chain are always released exactly once.
  work.then(
    (r) => onSettled(r.durationMs),
    () => onSettled(undefined),
  )
  return withDeadline(() => work, opts.deadlineMs ?? SCAN_HTML_DEADLINE_MS, 'scan_html').catch((err) => {
    abort.abort()
    if (err instanceof DeadlineError) {
      const thread = engineThread
      if (thread?.ready && thread.running === job.id) {
        killEngineThread(new DeadlineError('scan_html', err.ms))
        // The replacement costs a cold start, so the next caller's "retry in Ns"
        // hint must not be the warm pace. Spawned here, synchronously, and not
        // on the next dispatch: the warm-up is the cost, so it must start now,
        // while this caller waits out Retry-After anyway.
        engineThread = spawnEngineThread()
        recentScanMs = Math.max(recentScanMs, 3_000)
      } else if (thread && !thread.ready && thread.running === job.id) {
        // This job is on a thread still paying its cold start. The work is
        // abandoned but owns the thread, the queue slot and the serial chain:
        // release them now so the next caller can queue, and let the abandoned
        // job land on a thread nothing else waits for. `onSettled` is
        // idempotent, so its eventual reply finds the entry already released.
        onSettled(undefined)
      }
      // Still queued: leave the chain alone. Once `previous` settles,
      // `throwIfAborted` rejects `work` and its own handler releases it, with
      // `thread.running` still naming the job the thread is really running. An
      // early release here would let a later dispatch shadow that job, and its
      // deadline would then kill a scan still inside its own budget.
    }
    throw err
  })
}

function dispatchToEngine(job: ScanWorkerJob): Promise<ScanWorkerResult> {
  const thread = (engineThread ??= spawnEngineThread())
  const w = thread.worker
  return new Promise<ScanWorkerResult>((resolve, reject) => {
    pending.set(job.id, { resolve, reject })
    // Set before the post, in the same synchronous block: no timer can fire
    // between the two, so a deadline never sees `running` pointing at a job
    // whose message the thread has not received.
    thread.running = job.id
    // A job in flight must hold the loop open; the reply unrefs again.
    w.ref()
    try {
      w.postMessage(job)
    } catch (err) {
      // A structured-clone refusal throws here, after the promise was already
      // given a resolver. Without this the entry is never claimed and the ref
      // is never dropped: the map leaks and the process can never exit.
      pending.delete(job.id)
      if (thread.running === job.id) thread.running = null
      if (pending.size === 0) w.unref()
      reject(err instanceof Error ? err : new Error(String(err)))
    }
  })
}
