/// <reference lib="dom" />
/**
 * In-page helpers for check_aria / check_color_contrast on a live `url`
 * (persona round 4: both tools took only a snippet or a color pair).
 *
 * Every function passed to page.evaluate below avoids named inner functions
 * and consts that hold functions: tsx/esbuild wraps those in a `__name`
 * helper that does not exist in the page, and the evaluate throws.
 */

type EvalPage = { evaluate: <R, A>(fn: (arg: A) => R, arg: A) => Promise<R> }

/** A refusal whose text is the whole tool answer (no "failed:" wrapper). */
export class ToolRefusal extends Error {}

/** Number of elements `selector` matches, or -1 when it is not a valid selector. */
export async function countMatches(page: EvalPage, selector: string): Promise<number> {
  return page.evaluate((sel: string) => {
    try {
      return document.querySelectorAll(sel).length
    } catch {
      return -1
    }
  }, selector)
}

/** Refuse a selector that is invalid or matches nothing — never report "no violations" on nothing. */
export async function assertSelectorMatches(page: EvalPage, selector: string, where: string): Promise<void> {
  const n = await countMatches(page, selector)
  if (n < 0) throw new ToolRefusal(`Error: selector "${selector}" is not a valid CSS selector.`)
  if (n === 0) throw new ToolRefusal(`Error: selector "${selector}" matches no element on ${where} — nothing was checked. Use a selector from scan_page, or omit selector to check the whole page.`)
}

type AxeNode = { target: unknown[] }
type AxeRule = { nodes: AxeNode[] }

/**
 * Keep only axe nodes inside an element `selector` matches (the element
 * itself or a descendant). axe runs on the whole page first, so ARIA
 * references that point outside the element still resolve.
 */
export async function scopeAxeRules<T extends AxeRule>(page: EvalPage, rules: T[], selector: string): Promise<T[]> {
  const targets = rules.flatMap((r) => r.nodes.map((n) => (Array.isArray(n.target) ? String(Array.isArray(n.target[0]) ? (n.target[0] as unknown[])[0] : n.target[0]) : '')))
  const inside = await page.evaluate(
    (a: { sel: string; targets: string[] }) =>
      a.targets.map((t) => {
        try {
          const el = t ? document.querySelector(t) : null
          return !!el && !!el.closest(a.sel)
        } catch {
          return false
        }
      }),
    { sel: selector, targets },
  )
  let k = 0
  const out: T[] = []
  for (const r of rules) {
    const nodes = r.nodes.filter(() => inside[k++] === true)
    if (nodes.length > 0) out.push({ ...r, nodes })
  }
  return out
}

export type ElementColors =
  | { error: 'invalid' | 'nomatch' }
  | { error: 'unparsed'; value: string }
  | { color: string; background: string | null; backgroundImageOn: string | null; fontSize: number; bold: boolean }

/**
 * The text color of the element `selector` matches and the color it sits on:
 * the element and its ancestors are composited as CSS paints them — each
 * background under its content, each `opacity` scaling the whole group — over
 * a white canvas. A gradient / image showing below the text returns
 * `backgroundImageOn` instead of a guessed color.
 */
export async function readElementColors(page: EvalPage, selector: string): Promise<ElementColors> {
  return page.evaluate((sel: string) => {
    let el: Element | null = null
    try {
      el = document.querySelector(sel)
    } catch {
      return { error: 'invalid' as const }
    }
    if (!el) return { error: 'nomatch' as const }
    // Computed colors can be oklch(...) / color(srgb ...) (Tailwind v4), not
    // only rgb(). Painting one canvas pixel converts any CSS color to RGBA.
    const ctx = document.createElement('canvas').getContext('2d', { willReadFrequently: true })
    if (!ctx) return { error: 'unparsed' as const, value: 'no canvas' }
    const cs = getComputedStyle(el)
    ctx.clearRect(0, 0, 1, 1)
    ctx.fillStyle = 'rgba(0, 0, 0, 0)'
    ctx.fillStyle = cs.color
    ctx.fillRect(0, 0, 1, 1)
    const f = ctx.getImageData(0, 0, 1, 1).data
    if (f[3] === 0 && cs.color !== 'transparent') return { error: 'unparsed' as const, value: cs.color }
    // Two pixels, premultiplied RGBA, built from the element up: one under a
    // glyph (text over the backgrounds) and one beside it (backgrounds only).
    // Each element paints its background under its content, then its
    // `opacity` scales the WHOLE group — text and background together — before
    // it lands on the parent (Codex P1 on #117: fading only the text overstated
    // the ratio). The result is composited over a white canvas.
    const ta = f[3]! / 255
    let txt = [f[0]! * ta, f[1]! * ta, f[2]! * ta, ta]
    let bgp = [0, 0, 0, 0]
    let backgroundImageOn: string | null = null
    let node: Element | null = el
    while (node) {
      const s = getComputedStyle(node)
      ctx.clearRect(0, 0, 1, 1)
      ctx.fillStyle = 'rgba(0, 0, 0, 0)'
      ctx.fillStyle = s.backgroundColor
      ctx.fillRect(0, 0, 1, 1)
      const px = ctx.getImageData(0, 0, 1, 1).data
      const ba = px[3]! / 255
      const b = [px[0]! * ba, px[1]! * ba, px[2]! * ba, ba]
      // A background image paints between this element's color and its
      // children: it shows through unless the children fully cover it.
      if (s.backgroundImage && s.backgroundImage !== 'none' && bgp[3]! < 0.999) {
        backgroundImageOn = node.tagName.toLowerCase() + (node.id ? `#${node.id}` : '')
        break
      }
      const t0 = txt
      const b0 = bgp
      txt = [0, 1, 2, 3].map((c) => t0[c]! + b[c]! * (1 - t0[3]!))
      bgp = [0, 1, 2, 3].map((c) => b0[c]! + b[c]! * (1 - b0[3]!))
      const op = s.opacity === '' ? 1 : Math.min(1, Math.max(0, parseFloat(s.opacity)))
      if (op < 1) {
        txt = txt.map((c) => c * op)
        bgp = bgp.map((c) => c * op)
      }
      node = node.parentElement
    }
    const fg = [0, 1, 2].map((c) => txt[c]! + 255 * (1 - txt[3]!))
    const bg = [0, 1, 2].map((c) => bgp[c]! + 255 * (1 - bgp[3]!))
    return {
      color: '#' + fg.map((c) => Math.round(c).toString(16).padStart(2, '0')).join(''),
      background: backgroundImageOn ? null : '#' + bg.map((c) => Math.round(c).toString(16).padStart(2, '0')).join(''),
      backgroundImageOn,
      fontSize: parseFloat(cs.fontSize) || 16,
      bold: (parseInt(cs.fontWeight, 10) || 400) >= 700,
    }
  }, selector)
}
