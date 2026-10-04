/**
 * Friction wave 2 — detect_framework mislabels. 17/24 personas saw `plain-css`
 * for vuejs.org (VitePress), nuxt.com (Nuxt) and vendavo.com (WordPress +
 * Elementor). The core detector only knows CSS frameworks; the tool now adds
 * application-framework signals on top and falls back to the CSS label.
 */
import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'

import { detectSiteFramework } from '../src/siteFramework.ts'

let browser: any
let page: any
before(async () => {
  const pw = await import('playwright')
  browser = await pw.chromium.launch({ headless: true })
  page = await (await browser.newContext()).newPage()
})
after(async () => { await browser?.close() })

const detect = async (body: string, head = '', css = 'plain-css') => {
  await page.setContent(`<!doctype html><html><head>${head}</head><body>${body}</body></html>`)
  return detectSiteFramework(page, css)
}

test('VitePress site (vuejs.org) is vitepress, not plain-css', async () => {
  const r = await detect('<div id="app"><div class="VPDoc"></div></div>', '<meta name="generator" content="VitePress v1.3.4">')
  assert.equal(r.label, 'vitepress')
})

test('Nuxt site (nuxt.com) is nuxt, beating the generic Vue signal', async () => {
  const r = await detect('<div id="__nuxt"><div data-v-app></div></div><script src="/_nuxt/entry.abc.js"></script>')
  assert.equal(r.label, 'nuxt')
})

test('WordPress + Elementor (vendavo.com) is wordpress with builder elementor', async () => {
  const r = await detect('<div class="elementor elementor-123"></div>', '<meta name="generator" content="Elementor 3.21.0"><link rel="stylesheet" href="/wp-content/plugins/elementor/assets/css/frontend.min.css">')
  assert.equal(r.label, 'wordpress')
  assert.equal(r.builder, 'elementor')
})

test('generator meta is case/whitespace tolerant', async () => {
  assert.equal((await detect('<p>x</p>', '<meta name="generator" content="  WORDPRESS 6.5 ">')).label, 'wordpress')
})

test('Next.js is nextjs', async () => {
  const r = await detect('<div id="__next"></div><script id="__NEXT_DATA__" type="application/json">{}</script>')
  assert.equal(r.label, 'nextjs')
})

test('bare Vue 3 app is vue', async () => {
  assert.equal((await detect('<div id="app" data-v-app></div>')).label, 'vue')
})

test('no app signal falls back to the CSS label (plain-css and tailwind)', async () => {
  assert.equal((await detect('<div class="x">hi</div>')).label, 'plain-css')
  assert.equal((await detect('<div class="x">hi</div>', '', 'tailwind')).label, 'tailwind')
})

test('page TEXT mentioning wp-content / nuxt is not a signal; empty generator is safe', async () => {
  const r = await detect('<p>Edit files in wp-content and /_nuxt/ and __next</p>', '<meta name="generator" content="">')
  assert.equal(r.label, 'plain-css')
})

// demo.vercel.store (Next.js App Router, live 2026-10-03): no #__next, no
// __NEXT_DATA__ — the Pages-Router signals all miss. What App Router pages DO
// carry is the route announcer custom element, the RSC flight queue
// (self.__next_f) and data-nextjs-* attributes. scan_page reported
// "plain-css" for this page.
test('Next.js App Router (demo.vercel.store) is nextjs without #__next / __NEXT_DATA__ / /_next/ assets', async () => {
  const r = await detect('<next-route-announcer style="position:absolute"></next-route-announcer><main>x</main><script>(self.__next_f=self.__next_f||[]).push([0])</script>', '', 'tailwind')
  assert.equal(r.label, 'nextjs')
})

test('Next.js data-nextjs-* attribute alone is nextjs', async () => {
  assert.equal((await detect('<div data-nextjs-scroll-focus-boundary="">x</div>')).label, 'nextjs')
})
