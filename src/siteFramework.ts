/// <reference lib="dom" />
/**
 * The one framework answer for a page. scan_page and detect_framework both
 * call detectPageStack, so they cannot disagree.
 *
 * Two separate fields:
 *  - framework: the application framework / CMS / site builder (nextjs,
 *    sveltekit, wordpress, mediawiki, shopify…), or "unknown". Never the CSS
 *    toolkit: persona round 4 (22/80 runs) saw `Framework: tailwind` for
 *    svelte.dev and `plain-css` for Wikipedia, because the label fell back to
 *    the toolkit when no app signal fired.
 *  - cssToolkit: core's CSS detector (tailwind / bootstrap / mui / plain-css).
 *
 * Signals come from attributes, element ids, asset paths, window globals and
 * the generator meta — never page text, so an article about WordPress is not
 * labelled WordPress — and never the hostname.
 */
import { detectFramework } from '@webability/core'

export type SiteFramework = { label: string; builder?: string; evidence: string[] }

export type PageStack = { framework: string; cssToolkit: string; builder?: string; evidence: string[] }

export type PageWithEvaluate = { evaluate: (fn: () => unknown) => Promise<unknown>; waitForLoadState?: (state: 'load', opts: { timeout: number }) => Promise<unknown> }

type Signals = {
  generator: string
  ids: string[]
  assets: string[]
  hasVueAttr: boolean
  hasElementorClass: boolean
  ngVersion: boolean
  vpClass: boolean
  globals: string[]
  nextAppRouter?: boolean
  sveltekitAttr?: boolean
  svelteClass?: boolean
  astroIsland?: boolean
  reactRoot?: boolean
}

// Runs inside the page via evaluate. No named inner functions or consts
// holding functions: tsx/esbuild wraps those in a `__name` helper that does
// not exist in the page, and the whole evaluate throws.
function collectSignals(): Signals {
  const d = document
  const generator = (d.querySelector('meta[name="generator" i]')?.getAttribute('content') || '').toLowerCase()
  const assets = Array.from(d.querySelectorAll('script[src], link[href]')).map((el) => (el.getAttribute('src') || el.getAttribute('href') || '').toLowerCase())
  const ids = ['__nuxt', '__next', 'app', 'VPContent', '__NEXT_DATA__', '___gatsby'].filter((i) => d.getElementById(i))
  const w = window as unknown as Record<string, unknown>
  const globals = ['__NUXT__', '__NEXT_DATA__', '__VP_HASH_MAP__', '__VUE__', 'Shopify'].filter((g) => g in w && w[g] != null)
  // SvelteKit keeps its runtime under window.__sveltekit_<hash>.
  if (Object.keys(w).some((k) => k.startsWith('__sveltekit'))) globals.push('__sveltekit_*')
  let vueAttr = false
  let nextAttr = false
  let kitAttr = false
  let svelteClass = false
  let astroAttr = false
  let reactProp = false
  const all = d.getElementsByTagName('*')
  for (let k = 0; k < all.length && k < 2000; k++) {
    const el = all[k]!
    for (const n of el.getAttributeNames()) {
      if (n.startsWith('data-v-')) vueAttr = true
      else if (n.startsWith('data-nextjs')) nextAttr = true
      else if (n.startsWith('data-sveltekit')) kitAttr = true
      else if (n.startsWith('data-astro-')) astroAttr = true
    }
    // Svelte scopes component CSS with a `svelte-<hash>` class.
    if (!svelteClass && typeof el.className === 'string' && /(^|\s)svelte-[a-z0-9]{4,}(\s|$)/.test(el.className)) svelteClass = true
    // React client roots carry a __reactContainer$<id> / _reactRootContainer
    // property, rendered nodes a __reactFiber$<id> one.
    if (!reactProp && k < 400) {
      for (const key of Object.keys(el)) {
        if (key.startsWith('__reactContainer$') || key.startsWith('__reactFiber$') || key === '_reactRootContainer') { reactProp = true; break }
      }
    }
  }
  return {
    generator,
    ids,
    assets,
    globals,
    hasVueAttr: vueAttr || !!d.querySelector('[data-v-app]'),
    hasElementorClass: !!d.querySelector('[class*="elementor-"], .elementor'),
    ngVersion: !!d.querySelector('[ng-version]'),
    vpClass: !!d.querySelector('.VPDoc, .VPContent, .VPNav'),
    // Next.js App Router pages have no #__next / __NEXT_DATA__. They carry the
    // route announcer element, the RSC flight queue (self.__next_f) and
    // data-nextjs-* attributes instead.
    nextAppRouter: !!d.querySelector('next-route-announcer') || '__next_f' in w || nextAttr,
    sveltekitAttr: kitAttr,
    svelteClass,
    astroIsland: astroAttr || !!d.querySelector('astro-island'),
    reactRoot: reactProp || !!d.querySelector('[data-reactroot]'),
  }
}

/** Product name from a generator meta: "MediaWiki 1.45.0-wmf" → mediawiki, "Wix.com Website Builder" → wix. */
function generatorName(gen: string): string {
  // "Powered by Jekyll" / "Site Kit by Google": the product follows "by".
  const words = gen.trim().split(/[\s/;(,]+/).filter(Boolean)
  const by = words.indexOf('by')
  const first = (by >= 0 && words[by + 1] ? words[by + 1] : words[0]) ?? ''
  return first.replace(/\.(com|org|io|net)$/, '').replace(/[^a-z0-9-]/g, '')
}

export function classifySignals(s: Signals): SiteFramework {
  const gen = s.generator.trim()
  const has = (needle: string) => s.assets.some((a) => a.includes(needle))
  const genEv = gen ? `meta generator "${gen.slice(0, 60)}"` : ''
  const ev = (...items: Array<string | false | undefined>) => items.filter((x): x is string => !!x)

  if (s.ids.includes('__nuxt') || s.globals.includes('__NUXT__') || has('/_nuxt/') || gen.startsWith('nuxt')) {
    return { label: 'nuxt', evidence: ev(s.ids.includes('__nuxt') && '#__nuxt element', s.globals.includes('__NUXT__') && 'window.__NUXT__', has('/_nuxt/') && '/_nuxt/ assets', gen.startsWith('nuxt') && genEv) }
  }
  if (gen.startsWith('vitepress') || s.globals.includes('__VP_HASH_MAP__') || s.vpClass || s.ids.includes('VPContent')) {
    return { label: 'vitepress', evidence: ev(gen.startsWith('vitepress') && genEv, s.globals.includes('__VP_HASH_MAP__') && 'window.__VP_HASH_MAP__', (s.vpClass || s.ids.includes('VPContent')) && 'VitePress VP* layout classes') }
  }
  if (s.ids.includes('__next') || s.globals.includes('__NEXT_DATA__') || has('/_next/') || s.nextAppRouter) {
    return { label: 'nextjs', evidence: ev(s.ids.includes('__next') && '#__next element', s.globals.includes('__NEXT_DATA__') && 'window.__NEXT_DATA__', has('/_next/') && '/_next/ assets', s.nextAppRouter && 'Next.js App Router markers (next-route-announcer / __next_f / data-nextjs-*)') }
  }
  if (s.sveltekitAttr || s.globals.includes('__sveltekit_*') || has('/_app/immutable/')) {
    return { label: 'sveltekit', evidence: ev(s.sveltekitAttr && 'data-sveltekit-* attribute', s.globals.includes('__sveltekit_*') && 'window.__sveltekit_*', has('/_app/immutable/') && '/_app/immutable/ assets') }
  }
  if (s.ids.includes('___gatsby') || gen.startsWith('gatsby')) {
    return { label: 'gatsby', evidence: ev(s.ids.includes('___gatsby') && '#___gatsby element', gen.startsWith('gatsby') && genEv) }
  }
  if (s.astroIsland || gen.startsWith('astro')) {
    return { label: 'astro', evidence: ev(s.astroIsland && 'astro-island / data-astro-* markup', gen.startsWith('astro') && genEv) }
  }
  const elementor = gen.startsWith('elementor') || has('/plugins/elementor') || s.hasElementorClass
  if (gen.startsWith('wordpress') || has('/wp-content/') || has('/wp-includes/') || elementor) {
    return {
      label: 'wordpress',
      ...(elementor ? { builder: 'elementor' } : {}),
      evidence: ev(gen.startsWith('wordpress') && genEv, has('/wp-content/') && '/wp-content/ assets', has('/wp-includes/') && '/wp-includes/ assets', elementor && 'Elementor markup or assets'),
    }
  }
  if (s.globals.includes('Shopify')) return { label: 'shopify', evidence: ['window.Shopify'] }
  // Any other generator names its product (MediaWiki, Drupal, Docusaurus,
  // Hugo, Wix…). Checked before the library signals: Wikipedia ships Vue
  // components, but the site is MediaWiki.
  const named = generatorName(gen)
  if (named && /[a-z]/.test(named)) return { label: named, evidence: [genEv] }
  if (s.hasVueAttr || s.globals.includes('__VUE__')) return { label: 'vue', evidence: ev(s.hasVueAttr && 'data-v-* attributes', s.globals.includes('__VUE__') && 'window.__VUE__') }
  if (s.ngVersion) return { label: 'angular', evidence: ['ng-version attribute'] }
  if (s.svelteClass) return { label: 'svelte', evidence: ['svelte-<hash> scoped classes'] }
  if (s.reactRoot) return { label: 'react', evidence: ['React root (data-reactroot / React container property)'] }
  return { label: 'unknown', evidence: [] }
}

export async function detectSiteFramework(page: PageWithEvaluate): Promise<SiteFramework> {
  try {
    const signals = (await page.evaluate(collectSignals)) as Signals
    return classifySignals(signals)
  } catch {
    return { label: 'unknown', evidence: [] }
  }
}

/**
 * generate_ai_fix's `framework` enum mixes CSS toolkits with two app
 * frameworks. The toolkit decides class names, so it wins unless the page has
 * none and the app framework is one the enum knows.
 */
const AI_FIX_FRAMEWORKS = new Set(['tailwind', 'bootstrap', 'mui', 'wordpress', 'nextjs', 'plain-css'])
export function aiFixFramework(stack: Pick<PageStack, 'framework' | 'cssToolkit'>): string {
  if ((stack.cssToolkit === 'plain-css' || stack.cssToolkit === 'unknown') && AI_FIX_FRAMEWORKS.has(stack.framework)) return stack.framework
  return AI_FIX_FRAMEWORKS.has(stack.cssToolkit) ? stack.cssToolkit : 'plain-css'
}

/**
 * The one detection both tools use. Waits (bounded) for the load event first
 * so a call right after domcontentloaded sees the same late-mounted markers a
 * finished scan sees.
 */
export async function detectPageStack(page: PageWithEvaluate): Promise<PageStack> {
  try {
    await page.waitForLoadState?.('load', { timeout: 8000 })
  } catch {
    /* slow page: detect on what is there */
  }
  let cssToolkit = 'unknown'
  try {
    cssToolkit = (await detectFramework(page as any)).framework
  } catch {
    /* keep unknown */
  }
  const site = await detectSiteFramework(page)
  return { framework: site.label, cssToolkit, ...(site.builder ? { builder: site.builder } : {}), evidence: site.evidence }
}
