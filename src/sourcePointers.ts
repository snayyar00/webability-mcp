/**
 * Source pointers for scan findings (DEV-1089 item 4).
 *
 * Dev builds leave the component tree on the DOM: React ≤18 stores a fiber on
 * every host node (`__reactFiber$…`) whose `_debugSource` is the JSX call
 * site (babel / jsx-dev-runtime) and whose owner chain names the component;
 * Vue 3 stores `__vueParentComponent` with the SFC path in `type.__file`.
 * One page.evaluate reads all of them for every issue selector, so an agent
 * gets `src/Hero.tsx:12:5 (Hero)` without a round-trip through find_source.
 *
 * React 19 dropped `_debugSource`; there we still recover the component name.
 * Production builds carry neither — then `findSourceCandidates` (the
 * find_source token grep over `sourceRoot`) is the fallback.
 */
import { execFile } from 'child_process'
import { promisify } from 'util'

const execFileAsync = promisify(execFile)

export interface SourcePointer {
  file?: string
  line?: number
  column?: number
  component?: string
  framework?: 'react' | 'vue'
}

interface EvaluatePage {
  evaluate<R>(fn: (arg: string[]) => R, arg: string[]): Promise<R>
}

/**
 * Runs in the browser. Kept as a SOURCE STRING, not a TS function: esbuild
 * (tsx / tsup keepNames) decorates inner functions with a `__name(...)` helper
 * that does not exist in the page, so a serialised function threw
 * ReferenceError and every pointer came back empty. `new Function` has no
 * such decoration.
 */
const READ_POINTERS_SOURCE = String.raw`
  const out = {};
  const nameOf = (t) => {
    if (!t) return undefined;
    if (typeof t === 'function') return t.displayName || t.name || undefined;
    if (typeof t === 'object') return t.displayName || t.name || (t.render && (t.render.displayName || t.render.name)) || undefined;
    return undefined;
  };
  for (const sel of selectors) {
    let el = null;
    try { el = document.querySelector(sel); } catch (e) { el = null; }
    if (!el) continue;
    // React 16-18: fiber on the host node; _debugSource from the jsx dev transform; owner chain names the component.
    const fiberKey = Object.keys(el).find((k) => k.startsWith('__reactFiber$') || k.startsWith('__reactInternalInstance$'));
    if (fiberKey) {
      let node = el[fiberKey];
      let src; let component; let hops = 0;
      while (node && hops < 50) {
        if (!src && node._debugSource) src = node._debugSource;
        if (!component && typeof node.type !== 'string') { const n = nameOf(node.type); if (n) component = n; }
        if (src && component) break;
        node = node._debugOwner || node.return;
        hops++;
      }
      if (src || component) {
        const p = { framework: 'react' };
        if (src && src.fileName) p.file = String(src.fileName);
        if (src && typeof src.lineNumber === 'number') p.line = src.lineNumber;
        if (src && typeof src.columnNumber === 'number') p.column = src.columnNumber;
        if (component) p.component = component;
        out[sel] = p;
        continue;
      }
    }
    // Vue 3 dev build: __vueParentComponent with the SFC path in type.__file.
    let vnode = el.__vueParentComponent; let vhops = 0;
    while (vnode && vhops < 50) {
      const t = vnode.type;
      if (t && (t.__file || t.name || t.__name)) {
        const p = { framework: 'vue' };
        if (t.__file) p.file = String(t.__file);
        const n = t.name || t.__name;
        if (n) p.component = String(n);
        out[sel] = p;
        break;
      }
      vnode = vnode.parent; vhops++;
    }
  }
  return out;
`
// eslint-disable-next-line @typescript-eslint/no-implied-eval
const readPointersInPage = new Function('selectors', READ_POINTERS_SOURCE) as (selectors: string[]) => Record<string, SourcePointer>

/**
 * True for component names that tell an agent nothing: minifier output
 * ("c", "Kt", "eB" — any 1-2 char name) and framework
 * internals ("__next_root_layout_boundary__"). Production React builds name
 * every owner like this (demo.vercel.store, 2026-10-03).
 */
export function looksMinified(name: string): boolean {
  if (name.startsWith('__')) return true
  // Terser mangles to mixed case too ("Kt", "eB", "A"); no real component
  // name is two characters or fewer often enough to be worth the noise.
  return name.length <= 2
}

/** Read framework source pointers for the given selectors. Never throws. */
export async function collectSourcePointers(page: EvaluatePage, selectors: string[]): Promise<Record<string, SourcePointer>> {
  const unique = [...new Set(selectors.filter((s) => typeof s === 'string' && s.length > 0))]
  if (unique.length === 0) return {}
  try {
    const raw = await page.evaluate(readPointersInPage, unique)
    const out: Record<string, SourcePointer> = {}
    for (const [sel, p] of Object.entries(raw ?? {})) {
      const clean: SourcePointer = {}
      if (p.file) clean.file = p.file
      if (typeof p.line === 'number') clean.line = p.line
      if (typeof p.column === 'number') clean.column = p.column
      if (p.component && !looksMinified(String(p.component))) clean.component = String(p.component)
      // A pointer with neither a file nor a usable component name is noise.
      if (!clean.file && !clean.component) continue
      if (p.framework) clean.framework = p.framework
      out[sel] = clean
    }
    return out
  } catch {
    return {}
  }
}

/** `src/Hero.tsx:12:5 (Hero)` — the AccessLint/DevTools-style one-liner. */
export function formatSource(p: SourcePointer): string {
  const loc = p.file ? `${p.file}${p.line !== undefined ? `:${p.line}` : ''}${p.line !== undefined && p.column !== undefined ? `:${p.column}` : ''}` : ''
  const comp = p.component ? `(${p.component})` : ''
  return [loc, comp].filter(Boolean).join(' ')
}

/** Identifying tokens in a selector — ids, long class names, attribute values. */
export function selectorTokens(selector: string): string[] {
  const tokens: string[] = []
  const idMatch = selector.match(/#([\w-]+)/)
  if (idMatch) tokens.push(idMatch[1]!)
  const classMatches = selector.match(/\.[\w\\/-]+/g)
  if (classMatches) classMatches.forEach((c) => {
    const cleaned = c.replace(/^\./, '').replace(/\\/g, '')
    if (cleaned.length > 3) tokens.push(cleaned)
  })
  // Attribute selectors carry the most stable, human-authored, verbatim-searchable
  // tokens (e.g. [data-testid="foo"], [aria-label="Some Label"], [name="bar"]).
  const attrRegex = /\[\s*[\w:-]+\s*(?:[~^$*|]?=)\s*(?:"([^"]*)"|'([^']*)'|([^\]\s]+))\s*(?:[iIsS]\s*)?\]/g
  let attrMatch: RegExpExecArray | null
  while ((attrMatch = attrRegex.exec(selector)) !== null) {
    const value = attrMatch[1] ?? attrMatch[2] ?? attrMatch[3] ?? ''
    value.split(/\s+/).forEach((word) => {
      const cleaned = word.trim()
      if (cleaned.length > 3 && !tokens.includes(cleaned)) tokens.push(cleaned)
    })
  }
  return tokens
}

/** Files under rootDir that mention the selector's tokens (the find_source grep). */
export async function findSourceCandidates(selector: string, rootDir: string): Promise<string[]> {
  const tokens = selectorTokens(selector)
  if (tokens.length === 0) return []
  const matches = new Set<string>()
  for (const token of tokens.slice(0, 5)) {
    // Never let a token be parsed as a flag (argument injection); `--` stops rg flag parsing.
    if (token.startsWith('-')) continue
    try {
      const { stdout } = await execFileAsync('rg', [
        '-l',
        '--type-add', 'web:*.{tsx,jsx,ts,js,vue,svelte,html,php,astro}',
        '-t', 'web',
        '--max-count', '10',
        '--',
        token,
        rootDir,
      ], { timeout: 5000 })
      stdout.split('\n').filter(Boolean).forEach((f) => matches.add(f))
    } catch {
      // No matches for this token, continue
    }
  }
  return Array.from(matches).slice(0, 10)
}
