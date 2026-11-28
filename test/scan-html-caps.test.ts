/**
 * scan_html is a process-wide, single-document engine: one module-level jsdom
 * window, one scan at a time, no AbortSignal, no deadline and no per-call cap
 * (the only limit was the 5 MiB HTTP body). Phase-3 measured the consequences
 * on origin/main: a 12 KB snippet blocked the event loop for 5.9 s, 24 KB for
 * 33 s, a depth-800 nest for 10 s — /health and every other tool share that
 * loop, so the container HEALTHCHECK failed during any such scan, and any
 * caller holding a valid account token was unmetered.
 *
 * These tests pin the three guards:
 *   1. cheap pre-scan caps (bytes / elements / nesting depth) with a tool-level
 *      error that points at engine:"browser" / scan_page;
 *   2. a hard deadline (withDeadline) so one call cannot outlive 24 s;
 *   3. a bounded queue — past the cap the caller is told the server is busy
 *      instead of chaining onto the shared promise forever.
 *
 * Payload shapes are the measured ones: span soup (element count), deep nests
 * (depth), and a normal component snippet that must keep working.
 */
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { createRequire } from 'node:module'
import { createServer as createNetServer } from 'node:net'
import { test } from 'node:test'
import { Worker } from 'node:worker_threads'


import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import {
  DEFAULT_SCAN_HTML_QUEUE,
  ScanHtmlBusyError,
  ScanHtmlLimitError,
  SCAN_HTML_DEADLINE_MS,
  SCAN_HTML_MAX_BYTES,
  SCAN_HTML_MAX_DEPTH,
  SCAN_HTML_MAX_ELEMENTS,
  assertScanHtmlWithinCaps,
  engineDocument,
  estimateMarkupSize,
  fastScanHtml,
  scanHtmlQueue,
} from '../src/fastScan.ts'
import { scanHtmlBusyRefusal } from '../src/scanHtmlGate.ts'
import { HOSTED_CALL_DEADLINE_MS, createServer } from '../src/server.ts'

const require = createRequire(import.meta.url)

const SMALL = '<main><h1>T</h1><img src="a.png"><button></button></main>'
/** Flat element soup: the 12 KB → 5.9 s shape (cost is superlinear in element count).
 *  The image without alt is a known positive, so "the scan completed" is checked
 *  by a finding, not by an empty list. */
const spans = (n: number) => '<main><h1>T</h1><img src="a.png">' + '<span>text</span>'.repeat(n) + '</main>'
/** The depth-800 → 10 s shape. */
const nest = (n: number) => '<main><h1>T</h1>' + '<div>'.repeat(n) + 'x' + '</div>'.repeat(n) + '</main>'

const isLimit = (kind: string) => (err: unknown) => {
  assert.ok(err instanceof ScanHtmlLimitError, `expected ScanHtmlLimitError, got ${(err as Error)?.name}: ${(err as Error)?.message}`)
  assert.equal(err.kind, kind)
  // Every cap error must name the way out, not just refuse.
  assert.match(err.message, /scan_page/)
  assert.match(err.message, /engine:"browser"/)
  return true
}

async function connect(srv = createServer({ remote: true })) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([srv.connect(serverTransport), client.connect(clientTransport)])
  return client
}

const text = (res: any) => res.content.map((c: any) => String(c.text ?? '')).join('\n')

test('caps: 256 KB of html is refused before jsdom is even loaded', async () => {
  const html = '<div>' + 'x'.repeat(SCAN_HTML_MAX_BYTES) + '</div>'
  const t0 = Date.now()
  assert.throws(() => assertScanHtmlWithinCaps(html), isLimit('bytes'))
  const ms = Date.now() - t0
  // A length check, not a scan: a 300 KB scan takes minutes, so anything in
  // the low hundreds of ms (under the parallel suite's load) is proof enough.
  assert.ok(ms < 500, `byte cap should be a length check, took ${ms}ms`)

  // Through the tool: a tool-level error naming the alternatives, still no jsdom.
  const jsdom = require.resolve('jsdom')
  assert.equal(require.cache[jsdom], undefined, 'premise: jsdom is not loaded yet in this process')
  const client = await connect()
  const res = await client.callTool({ name: 'scan_html', arguments: { html } })
  assert.equal((res as any).isError, true)
  assert.match(text(res), /scan_page/)
  assert.match(text(res), /engine:"browser"/)
  assert.equal(require.cache[jsdom], undefined, 'an over-cap snippet must not reach the jsdom engine')
  await client.close()
})

test('caps: the element-count cap refuses span soup before any scan runs', () => {
  const html = spans(SCAN_HTML_MAX_ELEMENTS + 1)
  assert.throws(() => assertScanHtmlWithinCaps(html), isLimit('elements'))
  // A snippet at the cap is accepted (the cap is a ceiling, not a target).
  // main + h1 + img + spans: exactly the cap.
  assert.doesNotThrow(() => assertScanHtmlWithinCaps(spans(SCAN_HTML_MAX_ELEMENTS - 3)))
  assert.throws(() => assertScanHtmlWithinCaps(spans(SCAN_HTML_MAX_ELEMENTS - 2)), isLimit('elements'))
})

test('caps: the nesting-depth cap refuses the depth-800 shape', () => {
  const html = nest(SCAN_HTML_MAX_DEPTH + 1)
  assert.throws(() => assertScanHtmlWithinCaps(html), isLimit('depth'))
  assert.throws(() => assertScanHtmlWithinCaps(nest(800)), isLimit('depth'))
  assert.doesNotThrow(() => assertScanHtmlWithinCaps(nest(SCAN_HTML_MAX_DEPTH - 1)))
})

test('the pre-scan estimate is cheap and does not over-count void/self-closing tags', () => {
  // 256 KB of prose: no tags, so only the byte/length walk happens.
  const prose = '<main><h1>T</h1><p>' + 'text '.repeat(Math.floor((SCAN_HTML_MAX_BYTES - 100) / 5)) + '</p></main>'
  const t0 = Date.now()
  const est = estimateMarkupSize(prose)
  assert.ok(Date.now() - t0 < 500, 'pre-scan is one pass, not a parse')
  assert.equal(est.elements, 3)

  const voids = estimateMarkupSize('<img src="a"><br><input type="text"><div><span>x</span></div>')
  assert.equal(voids.elements, 5)
  assert.equal(voids.depth, 2, 'void elements close themselves; only div > span nests')

  // A `>` inside a quoted attribute value does not split the tag in two.
  assert.equal(estimateMarkupSize('<a title="a > b">x</a>').elements, 1)
})

test('the pre-scan is linear on hostile markup (the guard must not become the wedge)', () => {
  // Measured on the first version of this guard: a backtracking tag regex took
  // 1.0 s at 32 KB, 4.4 s at 64 KB and 16 s at 128 KB on these shapes — a
  // scanner that a single small request can freeze is worse than no cap.
  const shapes: Array<[string, string]> = [
    ['unterminated tags', '<a '.repeat(85_000)],
    ['unterminated names', '<a'.repeat(128_000)],
    ['one 250 KB name', '<' + 'a'.repeat(250_000)],
    ['unclosed quote', '<div title="' + 'x'.repeat(250_000)],
    ['stray angle brackets', '< '.repeat(125_000)],
    // parse5's tree builder is superlinear in depth: a full parse of this took
    // 9 s. The count must stop the parse at the cap.
    ['52k nested divs', '<div>'.repeat(52_000)],
    ['85k nested formatting tags', '<b>'.repeat(85_000)],
    ['misnested formatting', '<b><i></b></i>'.repeat(18_000)],
    ['nested tables', '<table><tr><td>'.repeat(17_000)],
  ]
  for (const [label, html] of shapes) {
    const t0 = Date.now()
    const est = estimateMarkupSize(html)
    const ms = Date.now() - t0
    assert.ok(ms < 500, `${label}: pre-scan took ${ms}ms on ${Buffer.byteLength(html)} bytes`)
    if (label.startsWith('unterminated') || label === 'one 250 KB name' || label === 'unclosed quote' || label === 'stray angle brackets') {
      // Nothing after an unterminated tag is markup the parser would build.
      assert.ok(est.elements <= SCAN_HTML_MAX_ELEMENTS, `${label}: counted ${est.elements} elements`)
    } else {
      // A real nest or soup past a cap is refused, quickly.
      assert.ok(est.over, `${label}: not refused (${est.elements} elements, depth ${est.depth})`)
    }
  }
})

test('a stray `<` is text, not a tag that swallows the markup after it', () => {
  // Per the tokenizer `<` followed by a space starts no tag; the next character
  // is read again. Jumping to the next `>` here would skip a real <span>.
  assert.equal(estimateMarkupSize('x < y <span>z</span>').elements, 1)
  assert.equal(estimateMarkupSize('< 3 and <b>bold</b>').elements, 1)
})

test('caps cannot be bypassed by closing tags the parser treats differently', () => {
  // `</br>` is a br START tag in the HTML parser: it inserts an element.
  assert.throws(() => assertScanHtmlWithinCaps('</br>'.repeat(SCAN_HTML_MAX_ELEMENTS + 5)), isLimit('elements'))
  // A stray `</p>` inserts a p element too.
  assert.throws(() => assertScanHtmlWithinCaps('</p>'.repeat(SCAN_HTML_MAX_ELEMENTS + 5)), isLimit('elements'))
  // An unmatched `</span>` is ignored by the parser, so it cannot cancel the
  // depth of the divs around it: 50 open divs + 100 stray closers + 60 more is
  // a real depth of 110, past the cap.
  assert.throws(() => assertScanHtmlWithinCaps('<div>'.repeat(50) + '</span>'.repeat(100) + '<div>'.repeat(60)), isLimit('depth'))
})

test('the estimate never counts fewer elements or less depth than jsdom actually builds', async () => {
  // The bypass direction is the dangerous one: a pre-scan that under-counts
  // waves through exactly the payload it exists to stop. Pin it against the
  // parser the engine itself uses.
  const { JSDOM } = await import('jsdom')
  const cases: Array<[string, string]> = [
    ['component', SMALL],
    ['voids', '<img src="a"><br><input type="text"><div><span>x</span></div>'],
    ['self-closing divs', '<div/>'.repeat(50)],
    ['bare quote in a tag', '<x ">' + '<span>x</span>'.repeat(60) + '<x ">'],
    ['quoted angle bracket', '<a title="a > b"><span>x</span></a>'],
    ['40 deep', nest(40)],
    ['table without tbody', '<table><tr><td><span>x</span></td></tr></table>'],
    ['stray br closers', '</br>'.repeat(20)],
    ['stray p closers', '</p>'.repeat(20)],
    ['unmatched closer inside a nest', '<div>'.repeat(10) + '</span>'.repeat(5) + '<div>'.repeat(10)],
    ['stray angle bracket', 'x < y <span>z</span>'],
    // Review shapes (PR 230): each was accepted while jsdom built more.
    ['double angle bracket', '<<span>x</span>'.repeat(20)],
    ['angle bracket then space', '< <span>x</span>'.repeat(20)],
    ['equals at attribute-name start', '<x =">' + '<span>x</span>'.repeat(20)],
    ['double equals', '<x a=="' + '>' + '<span>x</span>'.repeat(20)],
    ['closer that does not match', '<div></span>'.repeat(40)],
    ['empty closer', '<div></>'.repeat(40)],
    ['tag name with a dot', '<br.>'.repeat(40)],
    ['end tag name with a dot', '<div>'.repeat(40) + '</div.x>'.repeat(40) + '<div>'.repeat(20)],
  ]
  for (const [label, html] of cases) {
    const dom = new JSDOM('<!doctype html><html><body></body></html>')
    const doc = dom.window.document as any
    doc.open()
    // The document the engine writes: a snippet inside the fixed page, whose
    // own <main> and <h1> do not count.
    doc.write(engineDocument(html).doc)
    doc.close()
    const main = doc.querySelector('main')
    const actualElements = main.querySelectorAll('*').length - 1
    let actualDepth = 0
    const walk = (el: any, d: number) => {
      actualDepth = Math.max(actualDepth, d)
      for (const child of el.children) walk(child, d + 1)
    }
    walk(main, 0)
    const est = estimateMarkupSize(html)
    // A +2 slack on both counts: the parser inserts a couple of nodes the markup
    // never names (`<tbody>` for a bare `<tr>`, `<head>`/`<body>`). Those are
    // constant, and both caps leave room, so they cannot defeat one.
    assert.ok(est.elements + 2 >= actualElements, `${label}: estimate ${est.elements} < jsdom ${actualElements}`)
    assert.ok(est.depth + 2 >= actualDepth, `${label}: estimate depth ${est.depth} < jsdom ${actualDepth}`)
  }
})

test('caps cannot be bypassed by a quote the tokenizer does not treat as a quote', () => {
  // A bare `"` is an ordinary character in a tag: `<x ">` closes at that `>`.
  // A regex that treats it as a quote reads the whole payload as one element.
  const wrapper = '<x ">'
  const spanSoup = wrapper + '<span>x</span>'.repeat(5000) + wrapper
  assert.throws(() => assertScanHtmlWithinCaps(spanSoup), isLimit('elements'))
  const deep = wrapper + nest(800) + wrapper
  assert.throws(() => assertScanHtmlWithinCaps(deep), isLimit('depth'))
})

test('caps cannot be bypassed by a trailing slash on a non-void element', () => {
  // parse5 ignores `<div/>` outside foreign content: it nests like `<div>`.
  assert.throws(() => assertScanHtmlWithinCaps('<div/>'.repeat(SCAN_HTML_MAX_DEPTH + 5)), isLimit('depth'))
})

test('a normal component snippet still scans', async () => {
  const r = await fastScanHtml(SMALL)
  assert.equal(r.engine, 'in-process')
  assert.ok(r.issues.length >= 2, `expected findings, got ${r.issues.map((i) => i.type).join(',')}`)
})

test('deadline: a call waiting behind a slow scan is answered at its deadline, not at the end of the queue', async () => {
  // The 120-span scan blocks for seconds; the second call's 250 ms budget
  // expires meanwhile. The timer itself can only fire when the block yields, so
  // the assertion is the return type plus the 24 s ceiling — never "at 250 ms".
  const slow = fastScanHtml(spans(120))
  const t0 = Date.now()
  await assert.rejects(fastScanHtml(SMALL, { deadlineMs: 250 }), /did not finish within/)
  const ms = Date.now() - t0
  assert.ok(ms < SCAN_HTML_DEADLINE_MS, `a queued call must not outlive the default budget (took ${ms}ms)`)
  const first = await slow
  assert.ok(first.issues.length >= 1, 'the first scan must still complete normally')
})

test('deadline: a queued call whose caller gave up never reaches the engine thread', async () => {
  // The skip path is `abort.abort()` + `signal.throwIfAborted()` before the job
  // is posted. Without it every expired waiter still occupies the one engine
  // thread for seconds after its caller was answered — the same wedge the cap
  // and the queue exist to prevent, one layer down.
  await fastScanHtml(SMALL) // warms the engine thread
  // The dispatch boundary is the Worker object itself: count posts instead of
  // reaching into the module (there is no shared window to watch any more).
  const original = Worker.prototype.postMessage
  let posts = 0
  const count = function (this: Worker, ...args: Parameters<typeof original>) {
    posts += 1
    return original.apply(this, args)
  }
  Worker.prototype.postMessage = count
  try {
    const slow = fastScanHtml(spans(120))
    await assert.rejects(fastScanHtml(SMALL, { deadlineMs: 100 }), /did not finish within/)
    await slow
    assert.equal(posts, 1, `only the running scan may reach the engine thread, saw ${posts} dispatches`)
  } finally {
    Worker.prototype.postMessage = original
  }
})

test('deadline: a scan that blows its budget returns a DeadlineError, never a result', async () => {
  // A pathological payload under the caps, on a budget it cannot meet. The
  // detector kernel is one synchronous block, so the timer fires at the first
  // yield: the reply is bounded by that block (which the caps bound), not by
  // the deadline alone. Only the 24 s ceiling is asserted here, load-tolerant.
  const t0 = Date.now()
  let finished = false
  let err: unknown
  try {
    await fastScanHtml(spans(200), { deadlineMs: 250 })
    finished = true
  } catch (e) {
    err = e
  }
  const ms = Date.now() - t0
  assert.equal(finished, false, 'a scan past its 250 ms budget must not report findings as if it finished')
  assert.equal((err as Error)?.name, 'DeadlineError')
  assert.match(String((err as Error)?.message), /did not finish within/)
  assert.ok(ms < SCAN_HTML_DEADLINE_MS, `one call must not outlive the default budget (took ${ms}ms)`)
})

test('deadline: an aborted scan leaves the scanning chain healthy', async () => {
  await assert.rejects(fastScanHtml(spans(200), { deadlineMs: 250 }), /did not finish within/)
  // The abandoned scan may still own the shared window until it settles; the
  // next scan must still produce a real result for ITS document (never an empty
  // or clobbered one written mid-abort).
  const r = await fastScanHtml(SMALL, { deadlineMs: 24_000 })
  const ids = r.issues.map((i) => i.type)
  assert.ok(ids.includes('image-alt') || ids.includes('missing_alt'), `post-abort scan missed the img: ${ids}`)
  assert.ok(ids.includes('button-name') || ids.includes('unlabeled_button'), `post-abort scan missed the button: ${ids}`)
  assert.equal(r.fragment, true)
})

test('deadline: 24 s default, one second under scan_page hosted budget', () => {
  assert.equal(SCAN_HTML_DEADLINE_MS, 24_000)
  assert.ok(SCAN_HTML_DEADLINE_MS < HOSTED_CALL_DEADLINE_MS)
})

test('queue: past the cap the caller is told the server is busy, and the slot frees up', async () => {
  const previous = process.env.MCP_SCAN_HTML_MAX_QUEUE
  process.env.MCP_SCAN_HTML_MAX_QUEUE = '1'
  try {
    const slow = fastScanHtml(spans(120))
    await assert.rejects(fastScanHtml(SMALL), (err: unknown) => {
      assert.ok(err instanceof ScanHtmlBusyError, `expected ScanHtmlBusyError, got ${(err as Error)?.name}`)
      assert.match(err.message, /busy/i)
      assert.match(err.message, /retry in \d+s/)
      assert.ok(err.retryAfterSeconds >= 1)
      return true
    })
    const slowResult = await slow
    assert.ok(slowResult.issues.length >= 1, 'the first scan must not be disturbed by the refusal')
    // Slot released: the next call runs.
    const after = await fastScanHtml(SMALL)
    assert.ok(after.issues.length >= 2)
  } finally {
    if (previous === undefined) delete process.env.MCP_SCAN_HTML_MAX_QUEUE
    else process.env.MCP_SCAN_HTML_MAX_QUEUE = previous
  }
})

test('queue: the busy state reaches the caller as a tool result, not a hang', async () => {
  const previous = process.env.MCP_SCAN_HTML_MAX_QUEUE
  process.env.MCP_SCAN_HTML_MAX_QUEUE = '1'
  try {
    const client = await connect()
    const [a, b] = await Promise.allSettled([
      client.callTool({ name: 'scan_html', arguments: { html: spans(120) } }),
      client.callTool({ name: 'scan_html', arguments: { html: SMALL } }),
    ])
    const results = [a, b].filter((r): r is PromiseFulfilledResult<any> => r.status === 'fulfilled').map((r) => r.value)
    assert.equal(results.length, 2, 'both calls must be answered — the queued call must not hang')
    const busy = results.filter((r) => r.isError && /busy|retry in/i.test(text(r)))
    assert.equal(busy.length, 1, `expected exactly one busy result, got: ${results.map((r) => text(r).slice(0, 80)).join(' | ')}`)
    assert.ok(results.some((r) => !r.isError), 'the other call must still scan')
    await client.close()
  } finally {
    if (previous === undefined) delete process.env.MCP_SCAN_HTML_MAX_QUEUE
    else process.env.MCP_SCAN_HTML_MAX_QUEUE = previous
  }
})

test('the scan runs off the main thread: jsdom is never bridged into this realm', async () => {
  // The bug this module exists for: jsdom + the detectors are ONE synchronous
  // block, so on the main thread a 24 KB snippet froze /health for 33 s. The
  // engine now lives on a worker thread.
  //
  // The old in-process engine had to install the jsdom window's globals on
  // `globalThis` (the detectors read `document`, `NodeFilter`, `CSS` as free
  // identifiers), so a scan that ran in this realm leaves `globalThis.document`
  // set. It must now stay absent: a worker's globals are its own. (Responsiveness
  // under a real scan is measured end-to-end over HTTP: /health answered 399
  // times during a 21.9 s scan, worst 26 ms.)
  const r = await fastScanHtml(spans(200), { deadlineMs: 24_000 })
  assert.ok(r.issues.length >= 1, 'the scan must produce findings')
  assert.ok(r.durationMs > 0, 'the worker reports its own scan duration')
  assert.equal((globalThis as { document?: unknown }).document, undefined, 'the engine thread owns the document; this realm must not be given one')
})

test('a job the thread cannot clone fails the call and leaves the engine usable', async () => {
  // Anything non-cloneable that gets past the entry check (a stray function on
  // the judge) throws from postMessage — after the promise already has a
  // resolver and the thread is ref'd. Unhandled, the pending entry is never
  // claimed and the ref never dropped: every later call still works, but the
  // process can never exit.
  await fastScanHtml(SMALL) // warm the thread
  await assert.rejects(
    fastScanHtml(SMALL, { judge: { textModel: 'x', onDone: () => 1 } as never }),
    /could not be cloned/,
  )
  const after = await fastScanHtml(SMALL)
  assert.ok(after.issues.length >= 2, 'the engine must still answer after a clone refusal')
})

test('the default queue is bounded', () => {
  assert.ok(Number.isInteger(DEFAULT_SCAN_HTML_QUEUE) && DEFAULT_SCAN_HTML_QUEUE >= 2 && DEFAULT_SCAN_HTML_QUEUE <= 32)
})

test('a seeded fuzz never finds an estimate below the tree jsdom builds', async () => {
  // Hand-picked shapes miss whole classes (the review's parse5 fuzz found
  // thousands). Random strings from tag and punctuation tokens, judged against
  // the parser the engine uses, with no slack.
  const { JSDOM } = await import('jsdom')
  const tokens = ['<', '>', '/', '=', '"', "'", ' ', '!', '?', '-', '.', 'div', 'span', 'p', 'br', 'b', 'x', 'tr', 'td', 'table', 'a', '</', '<!--', '-->', '<div>', '</div>', '<p>', '</p>', '<br>', '</br>', '<span>', '</span>', '<x ', 'a=', '="', '<<', '<svg>', '</svg>', '<math>', '<html>', '<head>', '<body>', '</body>']
  let seed = 230
  const rand = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff)
  const dom = new JSDOM('<!doctype html><html><body></body></html>')
  const doc = dom.window.document as any
  const misses: string[] = []
  for (let n = 0; n < 2000 && misses.length < 5; n++) {
    let html = ''
    const len = 5 + Math.floor(rand() * 40)
    for (let t = 0; t < len; t++) html += tokens[Math.floor(rand() * tokens.length)]
    const { elements: actualElements, depth: actualDepth } = jsdomSize(doc, html)
    const est = estimateMarkupSize(html)
    if (est.elements < actualElements || est.depth < actualDepth) misses.push(`${JSON.stringify(html)}: estimate ${est.elements}/${est.depth}, jsdom ${actualElements}/${actualDepth}`)
  }
  assert.deepEqual(misses, [])
})

test('foreign-content html/head/body are counted: they are real SVG/MathML elements', () => {
  // Inside <svg>/<math> an <html> tag is not the implied root; parse5 builds it.
  for (const root of ['svg', 'math']) {
    const nest = `<${root}>` + '<html>'.repeat(500)
    const est = estimateMarkupSize(nest)
    assert.ok(est.over, `<${root}><html>x500 must be refused, got ${JSON.stringify(est)}`)
    assert.throws(() => assertScanHtmlWithinCaps(nest), ScanHtmlLimitError)
  }
})

test('foreign-content html/head/body: the estimate matches the tree jsdom builds', async () => {
  const { JSDOM } = await import('jsdom')
  const doc = new JSDOM('<!doctype html><html><body></body></html>').window.document as any
  // <html> stays foreign inside <svg>/<math>; <head>/<body> break out of it.
  const shapes = ['<svg><html><html></html></html></svg>', '<math><html><html>', '<svg><body></body><head></head>', '<svg><g><html><body>', '<p>x</p><body><head><html>', '<svg><foreignObject><html><body><p>x']
  for (const html of shapes) {
    const est = estimateMarkupSize(html)
    const actual = jsdomSize(doc, html)
    assert.ok(est.elements >= actual.elements && est.depth >= actual.depth, `${html}: estimate ${est.elements}/${est.depth}, jsdom ${actual.elements}/${actual.depth}`)
  }
})

/**
 * Elements and depth of the tree jsdom builds for what the engine writes, by the
 * caps' rule: the document's own (HTML-namespace) html/head/body are free, and a
 * snippet's fixed page (title, main, h1; main one level) is not counted.
 */
function jsdomSize(doc: any, html: string): { elements: number; depth: number } {
  const { doc: written, fragment } = engineDocument(html)
  doc.open()
  doc.write(written)
  doc.close()
  const XHTML = 'http://www.w3.org/1999/xhtml'
  let elements = fragment ? -3 : 0
  let depth = 0
  const walk = (el: any, d: number) => {
    const implied = el.namespaceURI === XHTML && ['html', 'head', 'body'].includes(el.localName)
    const here = implied ? d : d + 1
    if (!implied) elements += 1
    depth = Math.max(depth, here - (fragment ? 1 : 0))
    for (const child of el.children) walk(child, here)
    if (el.localName === 'template' && el.content) for (const child of el.content.children) walk(child, here)
  }
  walk(doc.documentElement, 0)
  return { elements, depth }
}

// ---- the hosted edge: 503 + Retry-After, and the header on a timed-out call --

const QUEUE_FULL = { depth: 2, limit: 2, full: true, retryAfterSeconds: 7 }

/** The fields of a JSON-RPC reply these tests read, or a failure naming what was missing. */
function asReply(value: unknown): Record<string, unknown> {
  assert.ok(value && typeof value === 'object', `expected a JSON-RPC reply object, got ${JSON.stringify(value)}`)
  return value as Record<string, unknown>
}

const scanCall = (id: number, args: Record<string, unknown> = { html: SMALL }) => ({
  jsonrpc: '2.0',
  id,
  method: 'tools/call',
  params: { name: 'scan_html', arguments: args },
})

test('edge gate: a full engine answers 503 with the wait, one reply per message', () => {
  const refusal = scanHtmlBusyRefusal(scanCall(1), false, QUEUE_FULL)
  assert.ok(refusal, 'a scan_html call on a full engine must be refused before the SDK sees it')
  assert.equal(refusal.status, 503, '503 is what a client library retries on by itself')
  assert.equal(refusal.retryAfterSeconds, 7, 'the header value is the queue snapshot, not a guess')
  const single = asReply(refusal.body)
  assert.equal(single.id, 1, 'the reply carries the request id')
  const error = asReply(single.error)
  assert.match(String(error.message), /scan_html is at capacity/)
  assert.match(String(error.message), /retry in 7s/)
  assert.match(String(error.message), /engine:"browser"/, 'the refusal names the way out')
  assert.equal(asReply(error.data).retryAfterSeconds, 7)

  // A batch stays a batch: a pipelined pair must not come back half-answered.
  const batch = scanHtmlBusyRefusal([scanCall(1), scanCall(2)], false, QUEUE_FULL)?.body
  assert.ok(Array.isArray(batch), 'a batch body must be answered with a batch')
  assert.deepEqual(batch.map((r) => asReply(r).id), [1, 2])
})

test('edge gate: engine:"browser" and other tools are never refused by it', () => {
  assert.equal(
    scanHtmlBusyRefusal(scanCall(1, { html: SMALL, engine: 'browser' }), false, QUEUE_FULL),
    null,
    'a browser scan runs its own page, not the shared engine',
  )
  const other = { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'scan_page', arguments: { url: 'https://example.com' } } }
  assert.equal(scanHtmlBusyRefusal(other, false, QUEUE_FULL), null)
  assert.equal(
    scanHtmlBusyRefusal(scanCall(3), false, { depth: 1, limit: 8, full: false, retryAfterSeconds: 1 }),
    null,
    'room in the queue means no refusal',
  )
})

test('edge gate: /mcp/apps gets a readable tool result, not a dead connector', () => {
  // The Apps SDK has no retry-on-status behavior: a non-200 is a dead connector.
  const refusal = scanHtmlBusyRefusal(scanCall(9), true, QUEUE_FULL)
  assert.equal(refusal?.status, 200)
  const result = asReply(asReply(refusal?.body).result)
  assert.equal(result.isError, true)
  const content = result.content
  assert.ok(Array.isArray(content) && content.length > 0, 'a tool result carries content')
  assert.match(String(asReply(content[0]).text), /retry in 7s/)
  assert.equal(result._meta, undefined, 'busy is not a sign-in problem: no auth challenge')
})

test('queue: the snapshot the edge reads reports full at the cap, with a bounded wait', async () => {
  const previous = process.env.MCP_SCAN_HTML_MAX_QUEUE
  process.env.MCP_SCAN_HTML_MAX_QUEUE = '1'
  try {
    assert.equal(scanHtmlQueue().full, false, 'an idle engine is not full')
    const slow = fastScanHtml(spans(200))
    try {
      const busy = scanHtmlQueue()
      assert.equal(busy.depth, 1)
      assert.equal(busy.limit, 1)
      assert.equal(busy.full, true)
      assert.ok(busy.retryAfterSeconds >= 1 && busy.retryAfterSeconds <= 30, `bounded wait, got ${busy.retryAfterSeconds}`)
    } finally {
      await slow
    }
    assert.equal(scanHtmlQueue().full, false, 'the slot is released with the work')
  } finally {
    if (previous === undefined) delete process.env.MCP_SCAN_HTML_MAX_QUEUE
    else process.env.MCP_SCAN_HTML_MAX_QUEUE = previous
  }
})

test('retry hint: a busy call and a timed-out call both report when to come back', async () => {
  // The header is the transport's job (http.ts); this pins that the handler
  // hands it a number at all, for the two failures that are worth retrying.
  const previous = process.env.MCP_SCAN_HTML_MAX_QUEUE
  process.env.MCP_SCAN_HTML_MAX_QUEUE = '1'
  const busyWaits: number[] = []
  try {
    const client = await connect(createServer({ remote: true, onScanHtmlRetry: (s) => busyWaits.push(s) }))
    const occupying = fastScanHtml(spans(200))
    const busy = await client.callTool({ name: 'scan_html', arguments: { html: SMALL } })
    assert.equal(asReply(busy).isError, true)
    assert.match(text(busy), /busy/i)
    await occupying
    await client.close()
    assert.equal(busyWaits.length, 1, `one retry hint for one refused call, got ${busyWaits.length}`)
    assert.ok(busyWaits[0] >= 1)
  } finally {
    if (previous === undefined) delete process.env.MCP_SCAN_HTML_MAX_QUEUE
    else process.env.MCP_SCAN_HTML_MAX_QUEUE = previous
  }

  const timeoutWaits: number[] = []
  const client = await connect(createServer({ remote: true, scanHtmlDeadlineMs: 250, onScanHtmlRetry: (s) => timeoutWaits.push(s) }))
  const timedOut = await client.callTool({ name: 'scan_html', arguments: { html: spans(200) } })
  await client.close()
  assert.equal(asReply(timedOut).isError, true, 'a stopped scan is an error, never a partial result')
  assert.match(text(timedOut), /did not finish within/)
  assert.match(text(timedOut), /Retry in \d+s/)
  assert.equal(timeoutWaits.length, 1, 'the deadline reports the same wait the text states')
  assert.ok(timeoutWaits[0] >= 1)
})

/**
 * The two signals only exist on the wire: a status and a header. Everything
 * above pins the body; this pins that a proxy or client library actually sees
 * `Retry-After` — on the 503 for a refused call, and on the 200 that carries a
 * timed-out tool result, where a header is the only transport-level place for it
 * (the SDK owns that response and never clears headers set before it flushes).
 *
 * No timers: readiness is the server's own listen line, and the probe loop ends
 * on a real outcome (a refusal, or the occupying call settling).
 */
test('hosted: Retry-After on the 503 when the engine is full, and on a timed-out scan', async () => {
  const port = await freePort()
  const proc = spawn('./node_modules/.bin/tsx', ['src/http.ts'], {
    env: {
      ...process.env,
      PORT: String(port),
      OAUTH_SIGNING_SECRET: 'scan-html-caps-test-secret-0123456789',
      MCP_SCAN_HTML_MAX_QUEUE: '1',
      // Room for a busy probe loop: the gate under test is depth, not the anon cap.
      ANON_HEAVY_PER_HOUR: '2000',
      MCP_SCAN_HTML_DEADLINE_MS: '1500',
      TRUSTED_PROXY_HOPS: '0',
      WEBABILITY_SCAN_TELEMETRY: 'off',
      POSTHOG_PROJECT_API_KEY: '',
      POSTHOG_API_KEY: '',
    },
    stdio: ['ignore', 'ignore', 'pipe'],
  })
  const base = `http://127.0.0.1:${port}`
  const post = (html: string) =>
    fetch(base + '/mcp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'scan_html', arguments: { html } } }),
    })
  try {
    await waitForListen(proc)

    // ~4 s of work under a 1.5 s deadline: the slot is held, then the call is stopped.
    let settled = false
    const occupying = post(spans(240)).finally(() => { settled = true })
    const refused = await probeUntilRefused(post, () => settled)
    assert.ok(refused, 'a scan_html call on a full engine must be answered 503, not queued behind it')
    assert.equal(refused.status, 503, '503 is the status a client library retries on by itself')
    const wait = Number(refused.headers.get('retry-after'))
    assert.ok(wait >= 1 && wait <= 30, `Retry-After must be a bounded wait, got ${refused.headers.get('retry-after')}`)
    const refusedBody = asReply(await refused.json())
    const refusedError = asReply(refusedBody.error)
    assert.equal(refusedError.code, -32002)
    assert.match(String(refusedError.message), /scan_html is at capacity/)
    assert.equal(asReply(refusedError.data).retryAfterSeconds, wait, 'the body and the header state the same wait')

    // The call that held the slot was stopped, and says when to come back.
    const stopped = await occupying
    assert.equal(stopped.status, 200, 'a tool that failed is not a failed request')
    const stoppedWait = Number(stopped.headers.get('retry-after'))
    assert.ok(stoppedWait >= 1 && stoppedWait <= 30, `the deadline header must be a bounded wait, got ${stopped.headers.get('retry-after')}`)
    const stoppedText = String(asReply(asReply(await stopped.json()).result).content.map((c) => asReply(c).text).join('\n'))
    assert.match(stoppedText, /did not finish within/)
    assert.match(stoppedText, new RegExp(`Retry in ${stoppedWait}s`), 'the text and the header agree')

    // ...and the engine is healthy again, so the refusal was about depth, not damage.
    // The stopped call's engine thread is replaced; on a loaded runner the
    // fresh thread's cold start can eat this test's 1.5 s budget, so allow a
    // few attempts. What must hold is that the engine comes back at all.
    let recovered: Response | undefined
    let lastText = ''
    for (let attempt = 0; attempt < 5; attempt++) {
      recovered = await post(SMALL)
      assert.equal(recovered.status, 200)
      if (recovered.headers.get('retry-after') === null) break
      lastText = JSON.stringify(await recovered.json())
      recovered = undefined
      await new Promise((r) => setTimeout(r, 1000))
    }
    assert.ok(recovered, `a call that finishes has nothing to wait for; last reply: ${lastText.slice(0, 400)}`)
    await recovered.body?.cancel()
  } finally {
    proc.kill()
  }
})

function freePort(): Promise<number> {
  const { promise, resolve } = Promise.withResolvers<number>()
  const s = createNetServer().listen(0, () => {
    const { port } = s.address() as { port: number }
    s.close(() => resolve(port))
  })
  return promise
}

/**
 * Resolves when the server prints its listen line, so no request races the
 * socket. A listener, not `for await`: breaking out of an async iterator
 * destroys the pipe, and the server's later writes then kill it.
 */
async function waitForListen(proc: ChildProcess): Promise<void> {
  const stderr = proc.stderr
  assert.ok(stderr, 'the server must be spawned with a readable stderr')
  const { promise, resolve } = Promise.withResolvers<string>()
  let seen = ''
  stderr.setEncoding('utf8')
  stderr.on('data', (chunk: string) => {
    seen += chunk
    if (seen.includes('listening on')) resolve(seen)
  })
  const exited = Promise.withResolvers<never>()
  proc.once('exit', (code) => exited.reject(new Error(`the server exited with ${code} without listening: ${seen}`)))
  exited.promise.catch(() => { /* failure surfaces through the race below */ })
  await Promise.race([promise, exited.promise])
}

/** The first refusal, or undefined once the call holding the slot has settled. */
async function probeUntilRefused(post: (html: string) => Promise<Response>, settled: () => boolean) {
  for (let i = 0; i < 50 && !settled(); i++) {
    const r = await post(SMALL)
    if (r.status === 503) return r
    await r.body?.cancel()
  }
  return undefined
}
