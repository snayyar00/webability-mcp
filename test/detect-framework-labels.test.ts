/**
 * Friction wave 2 — detect_framework mislabels. 17/24 personas saw `plain-css`
 * for vuejs.org (VitePress), nuxt.com (Nuxt) and vendavo.com (WordPress +
 * Elementor). The core detector only knows CSS frameworks; the tool adds
 * application-framework signals on top.
 *
 * Persona round 4 (22/80 runs): the app label still FELL BACK to the CSS
 * toolkit — `Framework: tailwind` for svelte.dev, `plain-css` for Wikipedia
 * and Shopify — while scan_page said something else. `framework` and
 * `cssToolkit` are now separate fields from one function (detectPageStack);
 * no app signal is `unknown`, never the toolkit.
 */
import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'

import { detectPageStack } from '../src/siteFramework.ts'

let browser: any
let page: any
before(async () => {
  const pw = await import('playwright')
  browser = await pw.chromium.launch({ headless: true })
  page = await (await browser.newContext()).newPage()
})
after(async () => { await browser?.close() })

const detect = async (body: string, head = '') => {
  // A fresh page per case: setContent keeps window globals (window.Shopify)
  // from the previous case; a real scan always navigates a new page.
  await page.close()
  page = await browser.newPage()
  await page.setContent(`<!doctype html><html><head>${head}</head><body>${body}</body></html>`)
  const r = await detectPageStack(page)
  return { ...r, label: r.framework }
}
const TW = '<div class="flex p-4 m-2 rounded shadow text-gray-700 bg-gray-100 w-4 h-4 grid">x</div>'.repeat(3)

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

test('no app signal is framework "unknown" — never the CSS toolkit', async () => {
  const plain = await detect('<div class="x">hi</div>')
  assert.equal(plain.framework, 'unknown')
  assert.equal(plain.cssToolkit, 'plain-css')
  const tw = await detect(TW)
  assert.equal(tw.framework, 'unknown')
  assert.equal(tw.cssToolkit, 'tailwind')
})

test('svelte.dev shape: SvelteKit attributes + Tailwind classes → framework sveltekit, cssToolkit tailwind', async () => {
  const r = await detect(`<div style="display: contents">${TW}</div>`.replace('<div style', '<div data-sveltekit-preload-data="hover" style'))
  assert.equal(r.framework, 'sveltekit')
  assert.equal(r.cssToolkit, 'tailwind')
  assert.ok(r.evidence.some((e: string) => /sveltekit/i.test(e)), JSON.stringify(r.evidence))
})

test('plain Svelte (scoped svelte-<hash> classes) is svelte', async () => {
  assert.equal((await detect('<h1 class="title svelte-1x2y3z">x</h1><p class="svelte-1x2y3z">y</p>')).framework, 'svelte')
})

test('Wikipedia shape: MediaWiki generator wins over Vue components on the page', async () => {
  const r = await detect('<div id="app" data-v-app><div data-v-1a2b>x</div></div>', '<meta name="generator" content="MediaWiki 1.45.0-wmf.21">')
  assert.equal(r.framework, 'mediawiki')
  assert.ok(r.evidence.some((e: string) => /generator/.test(e)), JSON.stringify(r.evidence))
})

test('Shopify storefront: the Shopify global is shopify, not plain-css', async () => {
  const r = await detect('<div class="shopify-section">x</div><script>window.Shopify = { shop: "x.myshopify.com" }</script>')
  assert.equal(r.framework, 'shopify')
})

test('any generator meta names the framework (derived, not a list)', async () => {
  assert.equal((await detect('<p>x</p>', '<meta name="generator" content="Docusaurus v3.5.2">')).framework, 'docusaurus')
  assert.equal((await detect('<p>x</p>', '<meta name="generator" content="Drupal 10 (https://www.drupal.org)">')).framework, 'drupal')
  assert.equal((await detect('<p>x</p>', '<meta name="generator" content="Wix.com Website Builder">')).framework, 'wix')
})

test('React root without a meta-framework is react', async () => {
  assert.equal((await detect('<div id="root" data-reactroot="">x</div>')).framework, 'react')
})

test('page TEXT mentioning wp-content / nuxt is not a signal; empty generator is safe', async () => {
  const r = await detect('<p>Edit files in wp-content and /_nuxt/ and __next and data-sveltekit and Shopify</p>', '<meta name="generator" content="">')
  assert.equal(r.label, 'unknown')
})

// demo.vercel.store (Next.js App Router, live 2026-10-03): no #__next, no
// __NEXT_DATA__ — the Pages-Router signals all miss. What App Router pages DO
// carry is the route announcer custom element, the RSC flight queue
// (self.__next_f) and data-nextjs-* attributes. scan_page reported
// "plain-css" for this page.
test('Next.js App Router (demo.vercel.store) is nextjs without #__next / __NEXT_DATA__ / /_next/ assets', async () => {
  const r = await detect('<next-route-announcer style="position:absolute"></next-route-announcer><main>x</main><script>(self.__next_f=self.__next_f||[]).push([0])</script>')
  assert.equal(r.label, 'nextjs')
})

test('Next.js data-nextjs-* attribute alone is nextjs', async () => {
  assert.equal((await detect('<div data-nextjs-scroll-focus-boundary="">x</div>')).label, 'nextjs')
})
