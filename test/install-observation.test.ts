process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
import assert from 'node:assert/strict'
import { createServer, Server } from 'node:http'
import { AddressInfo } from 'node:net'
import { test } from 'node:test'
import { checkInstall } from '../src/installCheck.ts'
import { observeInstall, recordedScriptUrls, scriptUrlFromStack } from '../src/installObservation.ts'
import type { Route } from 'playwright'

const SITE = 'https://site.example/'
const SCRIPT = 'https://enhancer.webability.io/widget.min.js'

function listen(handler: Parameters<typeof createServer>[1]): Promise<{ server: Server; port: number }> {
  const { promise, resolve } = Promise.withResolvers<{ server: Server; port: number }>()
  const server = createServer(handler)
  server.listen(0, '127.0.0.1', () => resolve({ server, port: (server.address() as AddressInfo).port }))
  return promise
}

for (const scenario of ['present', 'blocked', 'error', 'absent', '404', 'client-block', 'consent', 'data-src-consent', 'navigation-error']) {
  test(`browser install observation: ${scenario}`, async () => {
    let requested = false
    const observe = (url: string) => observeInstall(url, { setupContext: async (context) => {
      await context.route('**/*', async (route: any) => {
        if (route.request().url() === SCRIPT) {
          requested = true
          if (scenario === 'client-block') return route.abort('blockedbyclient')
          return route.fulfill({ status: scenario === '404' ? 404 : 200, contentType: 'application/javascript', headers: { 'access-control-allow-origin': '*' },
            body: scenario === 'error' ? 'throw new Error("widget failure")' : 'window.widgetLoaded = true' })
        }
        const consent = scenario.includes('consent')
        const html = scenario === 'absent' ? '<p>No embed</p>' : `<script ${scenario === 'data-src-consent' ? 'data-src' : 'src'}="${SCRIPT}" crossorigin="anonymous" ${consent ? 'type="text/plain" data-cookieconsent="marketing"' : ''}></script>`
        return route.fulfill({ status: scenario === 'navigation-error' ? 503 : 200, contentType: 'text/html',
          headers: scenario === 'blocked' ? { 'content-security-policy': "script-src 'self'" } : {}, body: html })
      })
    } })
    if (scenario === 'navigation-error') {
      await assert.rejects(checkInstall(SITE, { observe }), /HTTP 503/)
      return
    }
    const result = await checkInstall(SITE, { observe })
    const expected = scenario === 'absent' ? 'not_installed' : scenario.includes('consent') ? 'blocked' : ['404', 'client-block'].includes(scenario) ? 'error' : scenario
    assert.equal(result.state, expected, JSON.stringify(result))
    assert.ok(result.evidence.length)
    const kind = scenario.includes('consent') ? 'consent' : ({ present: 'script', blocked: 'security_policy', error: 'script_error', absent: 'absence', '404': 'script_load', 'client-block': 'script_load' } as Record<string, string>)[scenario]
    assert.equal(result.evidence[0].kind, kind)
    if (scenario.includes('consent')) assert.equal(requested, false)
  })
}

// Real customers paste the tag without crossorigin, and the script host sends
// no CORS header. Chromium mutes window 'error' details for such scripts, so
// the uncaught exception must still reach the observation.
test('browser install observation: error-no-cors', async () => {
  const observe = (url: string) => observeInstall(url, { setupContext: async (context) => {
    await context.route('**/*', async (route: { request(): { url(): string }; fulfill(o: object): Promise<unknown> }) => {
      if (route.request().url() === SCRIPT) {
        return route.fulfill({ status: 200, contentType: 'application/javascript', body: 'throw new Error("widget failure")' })
      }
      return route.fulfill({ status: 200, contentType: 'text/html', body: `<script src="${SCRIPT}"></script>` })
    })
  } })

  const result = await checkInstall(SITE, { observe })

  assert.equal(result.state, 'error', JSON.stringify(result))
  const evidence = result.evidence.find((e) => e.kind === 'script_error')
  assert.equal(evidence?.kind, 'script_error', JSON.stringify(result))
  assert.equal((evidence as { scriptUrl: string }).scriptUrl, SCRIPT)
})

// An exception message can itself carry a URL. Only stack-frame URLs identify
// the script that threw, so a message URL must not win the attribution.
test('browser install observation: URL in the error message is not the script', async () => {
  const observe = (url: string) => observeInstall(url, { setupContext: async (context) => {
    await context.route('**/*', async (route: Route) => {
      if (route.request().url() === SCRIPT) {
        return route.fulfill({ status: 200, contentType: 'application/javascript',
          body: 'throw new Error("Failed to load https://api.example/config")' })
      }
      return route.fulfill({ status: 200, contentType: 'text/html', body: `<script src="${SCRIPT}"></script>` })
    })
  } })

  const result = await checkInstall(SITE, { observe })

  assert.equal(result.state, 'error', JSON.stringify(result))
  const errorUrls = result.evidence.flatMap((e) => e.kind === 'script_error' ? [e.scriptUrl] : [])
  assert.deepEqual(errorUrls, [SCRIPT], JSON.stringify(result))
})

// The embed host redirects to another host. Blink attributes a module script's
// exception to the POST-redirect URL, so the frame URL is not the request the
// page recorded; without the chain mapping the exception is dropped and a
// broken embed reads "present". Playwright does not route redirect hops
// (see ssrf-redirect.test.ts), so this needs two real origins.
test('browser install observation: redirect to another host keeps the exception', async () => {
  const target = await listen((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/javascript', 'access-control-allow-origin': '*' })
    res.end('throw new Error("widget failure")')
  })
  const source = await listen((req, res) => {
    if (req.url === '/widget.min.js') {
      res.writeHead(302, { location: `http://localhost:${target.port}/widget.min.js` })
      res.end()
      return
    }
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end('<script type="module" src="/widget.min.js"></script>')
  })
  try {
    const originalUrl = `http://127.0.0.1:${source.port}/widget.min.js`
    const observation = await observeInstall(`http://127.0.0.1:${source.port}/`)

    // One exception, reported against the URL the page asked for. The message
    // text comes from whichever listener saw it first; the mapping is the point.
    assert.deepEqual(observation.runtimeErrors.map((e) => e.scriptUrl), [originalUrl], JSON.stringify(observation))
    assert.ok(observation.runtimeErrors[0].message.includes('widget failure'))
    assert.deepEqual(observation.requests, [{ url: originalUrl, status: 200 }])
  } finally {
    source.server.close()
    target.server.close()
  }
})

// Context-wide listeners also see popups: an embed loaded only by a popup the
// page opened is not evidence that the inspected page loads it.
test('browser install observation: popup embed is not the inspected page', async () => {
  const POPUP = 'https://site.example/popup'
  let popupRequested = false
  const observe = (url: string) => observeInstall(url, { setupContext: async (context) => {
    await context.route('**/*', async (route: Route) => {
      const requestUrl = route.request().url()
      if (requestUrl === SCRIPT) {
        popupRequested = true
        return route.fulfill({ status: 200, contentType: 'application/javascript', body: 'window.widgetLoaded = true' })
      }
      if (requestUrl === POPUP) {
        return route.fulfill({ status: 200, contentType: 'text/html', body: `<script src="${SCRIPT}"></script>` })
      }
      return route.fulfill({ status: 200, contentType: 'text/html', body: `<p>No embed</p><script>window.open('${POPUP}')</script>` })
    })
  } })

  const result = await checkInstall(SITE, { observe })

  // The popup did load the embed, so an empty result means the filter worked.
  assert.equal(popupRequested, true)
  assert.equal(result.state, 'not_installed', JSON.stringify(result))
  assert.equal(result.evidence[0].kind, 'absence')
})

// A client-side redirect loads a new document during the wait, so the observed
// document is not the one that was navigated to.
test('browser install observation: client redirect during the window interrupts', async () => {
  const OTHER = 'https://site.example/other'
  const observe = (url: string) => observeInstall(url, { setupContext: async (context) => {
    await context.route('**/*', async (route: Route) => {
      const requestUrl = route.request().url()
      if (requestUrl === OTHER) return route.fulfill({ status: 503, contentType: 'text/html', body: '<p>Unavailable</p>' })
      return route.fulfill({ status: 200, contentType: 'text/html',
        body: `<p>No embed</p><script>setTimeout(() => { location.href = '${OTHER}' }, 100)</script>` })
    })
  } })

  await assert.rejects(checkInstall(SITE, { observe }), /interrupted by navigation/)
})

// Same-document history changes are not new documents and must not interrupt.
test('browser install observation: pushState during the window is not a navigation', async () => {
  const observe = (url: string) => observeInstall(url, { setupContext: async (context) => {
    await context.route('**/*', async (route: Route) => route.fulfill({ status: 200, contentType: 'text/html',
      body: `<p>No embed</p><script>setTimeout(() => history.pushState({}, '', '/pushed'), 100)</script>` }))
  } })

  const result = await checkInstall(SITE, { observe })

  assert.equal(result.state, 'not_installed', JSON.stringify(result))
})

// A page that starts an infinite loop after load blocks the DOM read; the
// overall deadline must reject and still free the browser.
test('browser install observation: hung page hits the observation deadline', async () => {
  const observe = (url: string) => observeInstall(url, { deadlineMs: 3000, setupContext: async (context) => {
    await context.route('**/*', async (route: Route) => route.fulfill({ status: 200, contentType: 'text/html',
      body: `<p>No embed</p><script>setTimeout(() => { while (true) {} }, 10)</script>` }))
  } })

  const started = Date.now()
  await assert.rejects(checkInstall(SITE, { observe }), /observation exceeded/i)
  assert.ok(Date.now() - started < 15000, `took ${Date.now() - started}ms`)
})

// Playwright reports child-frame exceptions on the Page too. An iframe that
// loads the embed is not the inspected document loading it.
test('browser install observation: child frame exception is not the inspected document', async () => {
  const FRAME = 'https://site.example/frame'
  const observe = (url: string) => observeInstall(url, { setupContext: async (context) => {
    await context.route('**/*', async (route: Route) => {
      const requestUrl = route.request().url()
      if (requestUrl === SCRIPT) {
        return route.fulfill({ status: 200, contentType: 'application/javascript', body: 'throw new Error("frame failure")' })
      }
      if (requestUrl === FRAME) {
        return route.fulfill({ status: 200, contentType: 'text/html', body: `<script src="${SCRIPT}"></script>` })
      }
      return route.fulfill({ status: 200, contentType: 'text/html', body: `<p>No embed</p><iframe src="${FRAME}"></iframe>` })
    })
  } })

  const result = await checkInstall(SITE, { observe })

  assert.equal(result.state, 'not_installed', JSON.stringify(result))
  assert.equal(result.evidence[0].kind, 'absence')
})

// Real consent managers keep a placeholder in src (about:blank) and hold the
// real embed in data-src. Both are candidates; the consent tag is blocked.
test('browser install observation: consent tag with placeholder src keeps data-src', async () => {
  let requested = false
  const observe = (url: string) => observeInstall(url, { setupContext: async (context) => {
    await context.route('**/*', async (route: Route) => {
      if (route.request().url() === SCRIPT) {
        requested = true
        return route.fulfill({ status: 200, contentType: 'application/javascript', body: 'window.widgetLoaded = true' })
      }
      return route.fulfill({ status: 200, contentType: 'text/html',
        body: `<script type="text/plain" data-cookieconsent="marketing" src="about:blank" data-src="${SCRIPT}"></script>` })
    })
  } })

  const result = await checkInstall(SITE, { observe })

  assert.equal(requested, false)
  assert.equal(result.state, 'blocked', JSON.stringify(result))
  assert.equal(result.evidence[0].kind, 'consent')
})

// One malformed URL must not abort the whole observation.
test('browser install observation: malformed data-src does not abort the observation', async () => {
  const observe = (url: string) => observeInstall(url, { setupContext: async (context) => {
    await context.route('**/*', async (route: Route) => {
      if (route.request().url() === SCRIPT) {
        return route.fulfill({ status: 200, contentType: 'application/javascript', body: 'window.widgetLoaded = true' })
      }
      return route.fulfill({ status: 200, contentType: 'text/html',
        body: `<script src="${SCRIPT}"></script><script data-src="https://"></script>` })
    })
  } })

  const result = await checkInstall(SITE, { observe })

  assert.equal(result.state, 'present', JSON.stringify(result))
})

// A frame URL can carry parentheses, for example a cache-busting `?v=(2)`.
// Dropping them loses the only record of a broken cross-origin install.
test('browser install observation: stack frames keep a URL that contains parentheses', () => {
  const expected = 'https://enhancer.webability.io/widget.min.js?v=(2)'

  for (const stack of [
    `Error: widget failure\n    at ${expected}:1:7`,
    `Error: widget failure\n    at load (${expected}:1:7)`,
  ]) {
    assert.equal(scriptUrlFromStack(stack), expected, stack)
  }
})

// The line has to be a frame, and the URL has to name a file.
test('browser install observation: stack parsing ignores a message URL and a bare host', () => {
  for (const stack of [
    'Error: failed to load https://enhancer.webability.io/widget.min.js:1:7',
    '    at https://enhancer.webability.io:1:7',
  ]) {
    assert.equal(scriptUrlFromStack(stack), undefined, stack)
  }
})

// A first-party loader that redirects to the embed executes at the terminal URL.
// The terminal request is the evidence, so the classifier can see it.
test('browser install observation: a redirect to the embed records both URLs', () => {
  assert.deepEqual(recordedScriptUrls(SCRIPT, 'https://site.example/embed.js'),
    ['https://site.example/embed.js', SCRIPT])
})

// A hop to an unrelated host is a different script, not evidence about this one.
test('browser install observation: a redirect to an unrecognized host records only the original', () => {
  assert.deepEqual(recordedScriptUrls('http://127.0.0.1:9/widget.min.js', 'http://127.0.0.1:8/widget.min.js'),
    ['http://127.0.0.1:8/widget.min.js'])
})
