process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { checkInstall } from '../src/installCheck.ts'
import { observeInstall } from '../src/installObservation.ts'

const SITE = 'https://site.example/'
const SCRIPT = 'https://enhancer.webability.io/widget.min.js'
// Real Chromium, deterministic routed responses: no live CDN or external site.
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
