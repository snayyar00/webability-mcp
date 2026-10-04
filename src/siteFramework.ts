/**
 * Application-framework detection layered over core's CSS-framework detector.
 * Core only knows tailwind / bootstrap / mui / plain-css, so Vue, Nuxt,
 * VitePress and WordPress/Elementor sites all read "plain-css" (17/24
 * personas). Signals come from attributes and element ids only, never page
 * text, so an article about WordPress is not labelled WordPress.
 */

export type SiteFramework = { label: string; builder?: string }

export type PageWithEvaluate = { evaluate: (fn: () => unknown) => Promise<unknown> }

type Signals = { generator: string; ids: string[]; assets: string[]; hasVueAttr: boolean; hasElementorClass: boolean; ngVersion: boolean; vpClass: boolean; globals: string[]; nextAppRouter?: boolean }

function collectSignals(): Signals {
  const d = document
  const generator = (d.querySelector('meta[name="generator" i]')?.getAttribute('content') || '').toLowerCase()
  const assets = Array.from(d.querySelectorAll('script[src], link[href]')).map((el) => (el.getAttribute('src') || el.getAttribute('href') || '').toLowerCase())
  const ids = ['__nuxt', '__next', 'app', 'VPContent', '__NEXT_DATA__'].filter((i) => d.getElementById(i))
  const w = window as unknown as Record<string, unknown>
  const globals = ['__NUXT__', '__NEXT_DATA__', '__VP_HASH_MAP__', '__VUE__'].filter((g) => g in w)
  return {
    generator,
    ids,
    assets,
    globals,
    hasVueAttr: !!d.querySelector('[data-v-app]') || Array.from(d.querySelectorAll('*')).slice(0, 400).some((el) => el.getAttributeNames().some((n) => n.startsWith('data-v-'))),
    hasElementorClass: !!d.querySelector('[class*="elementor-"], .elementor'),
    ngVersion: !!d.querySelector('[ng-version]'),
    vpClass: !!d.querySelector('.VPDoc, .VPContent, .VPNav'),
    // Next.js App Router pages have no #__next / __NEXT_DATA__. They carry the
    // route announcer element, the RSC flight queue (self.__next_f) and
    // data-nextjs-* attributes instead.
    nextAppRouter:
      !!d.querySelector('next-route-announcer') ||
      '__next_f' in w ||
      (() => {
        const all = d.getElementsByTagName('*')
        for (let k = 0; k < all.length && k < 2000; k++) if (all[k]!.getAttributeNames().some((n) => n.startsWith('data-nextjs'))) return true
        return false
      })(),
  }
}

export function classifySignals(s: Signals, cssFramework: string): SiteFramework {
  const gen = s.generator.trim()
  const has = (needle: string) => s.assets.some((a) => a.includes(needle))
  if (s.ids.includes('__nuxt') || s.globals.includes('__NUXT__') || has('/_nuxt/') || gen.startsWith('nuxt')) return { label: 'nuxt' }
  if (gen.startsWith('vitepress') || s.globals.includes('__VP_HASH_MAP__') || s.vpClass || s.ids.includes('VPContent')) return { label: 'vitepress' }
  if (s.ids.includes('__next') || s.globals.includes('__NEXT_DATA__') || has('/_next/') || s.nextAppRouter) return { label: 'nextjs' }
  const elementor = gen.startsWith('elementor') || has('/plugins/elementor') || s.hasElementorClass
  if (gen.startsWith('wordpress') || has('/wp-content/') || has('/wp-includes/') || elementor) {
    return { label: 'wordpress', ...(elementor ? { builder: 'elementor' } : {}) }
  }
  if (s.hasVueAttr || s.globals.includes('__VUE__')) return { label: 'vue' }
  if (s.ngVersion) return { label: 'angular' }
  return { label: cssFramework }
}

export async function detectSiteFramework(page: PageWithEvaluate, cssFramework: string): Promise<SiteFramework> {
  try {
    const signals = (await page.evaluate(collectSignals)) as Signals
    return classifySignals(signals, cssFramework)
  } catch {
    return { label: cssFramework }
  }
}
