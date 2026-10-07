/**
 * DEV-1089 item 4: `source` pointers on scan_page / flow_scan issues — read
 * from React dev-build fibers (`_debugSource`, owner component name) and Vue
 * dev builds (`__vueParentComponent.type.__file`) in the live DOM, in ONE
 * page.evaluate. Falls back to a token grep of `sourceRoot` (find_source).
 */
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { collectSourcePointers, findSourceCandidates, formatSource, looksMinified } from '../src/sourcePointers.ts'

const FIXTURE = `<!doctype html><html><body>
<img id="hero" src="x.png">
<button id="vbtn"></button>
<a id="plain" href="#"></a>
<input id="minified">
<a id="internal" href="#">x</a>
<span id="named">x</span>
<script>
  // React 16-18 dev build shape: fiber on the DOM node, _debugSource from the
  // jsx dev transform, owner chain for the component name.
  const owner = { type: { name: 'Hero' }, _debugSource: null, return: null }
  document.getElementById('hero')['__reactFiber$abc'] = { _debugSource: { fileName: '/app/src/Hero.tsx', lineNumber: 12, columnNumber: 5 }, _debugOwner: owner, return: owner, type: 'img' }
  // Vue 3 dev build shape.
  // Production React build (demo.vercel.store, live 2026-10-03): the owner
  // chain only names minified components — "c", "u", "j" — or framework
  // internals like __next_root_layout_boundary__. Neither helps an agent.
  document.getElementById('minified')['__reactFiber$abc'] = { type: 'input', return: { type: function c() {}, return: null } }
  document.getElementById('internal')['__reactFiber$abc'] = { type: 'a', return: { type: { displayName: '__next_root_layout_boundary__' }, return: null } }
  document.getElementById('named')['__reactFiber$abc'] = { type: 'span', return: { type: function Nav() {}, return: null } }
  document.getElementById('vbtn').__vueParentComponent = { type: { __file: '/app/src/components/Toolbar.vue', name: 'Toolbar' } }
</script></body></html>`

test('formatSource renders AccessLint-style file:line (Symbol)', () => {
  assert.equal(formatSource({ file: 'src/Hero.tsx', line: 12, column: 5, component: 'Hero' }), 'src/Hero.tsx:12:5 (Hero)')
  assert.equal(formatSource({ file: 'src/Toolbar.vue', component: 'Toolbar' }), 'src/Toolbar.vue (Toolbar)')
  assert.equal(formatSource({ component: 'Hero' }), '(Hero)')
})

test('reads React fiber and Vue component pointers from the live DOM', async () => {
  const pw = await import('playwright')
  const browser = await pw.chromium.launch({ headless: true })
  try {
    const page = await browser.newPage()
    await page.setContent(FIXTURE)
    const out = await collectSourcePointers(page, ['#hero', '#vbtn', '#plain', '#does-not-exist'])
    assert.deepEqual(out['#hero'], { file: '/app/src/Hero.tsx', line: 12, column: 5, component: 'Hero', framework: 'react' })
    assert.deepEqual(out['#vbtn'], { file: '/app/src/components/Toolbar.vue', component: 'Toolbar', framework: 'vue' })
    assert.equal(out['#plain'], undefined)
    assert.equal(out['#does-not-exist'], undefined)
  } finally {
    await browser.close()
  }
})

test('findSourceCandidates greps the project for selector tokens', async () => {
  const root = mkdtempSync(join(tmpdir(), 'wa-src-'))
  mkdirSync(join(root, 'src'))
  writeFileSync(join(root, 'src', 'Hero.tsx'), 'export const Hero = () => <img className="hero-image" src="x.png" />\n')
  writeFileSync(join(root, 'src', 'Other.tsx'), 'export const Other = () => <div className="other" />\n')
  const files = await findSourceCandidates('img.hero-image', root)
  assert.deepEqual(files.map((f) => f.replace(root + '/', '')), ['src/Hero.tsx'])
  assert.deepEqual(await findSourceCandidates('div', root), [])
})

test('findSourceCandidates still works when ripgrep is not installed', async () => {
  const root = mkdtempSync(join(tmpdir(), 'wa-src-norg-'))
  mkdirSync(join(root, 'src'))
  mkdirSync(join(root, 'node_modules', 'lib'), { recursive: true })
  writeFileSync(join(root, 'src', 'Hero.tsx'), 'export const Hero = () => <img className="hero-image" src="x.png" alt="Hero" />\n')
  writeFileSync(join(root, 'src', 'notes.md'), 'hero-image\n')
  writeFileSync(join(root, 'node_modules', 'lib', 'x.js'), 'hero-image\n')
  const savedPath = process.env.PATH
  process.env.PATH = mkdtempSync(join(tmpdir(), 'wa-empty-path-'))
  try {
    const files = await findSourceCandidates('img.hero-image', root)
    assert.deepEqual(files.map((f) => f.replace(root + '/', '')), ['src/Hero.tsx'])
  } finally {
    process.env.PATH = savedPath
  }
})

test('without ripgrep, the project is walked once for all tokens and selectors', async () => {
  const root = mkdtempSync(join(tmpdir(), 'wa-src-walk1-'))
  mkdirSync(join(root, 'src'))
  writeFileSync(join(root, 'src', 'Hero.tsx'), '<img className="hero-image" id="main-banner" alt="Banner" />\n')
  const savedPath = process.env.PATH
  process.env.PATH = mkdtempSync(join(tmpdir(), 'wa-empty-path-'))
  try {
    assert.deepEqual((await findSourceCandidates('img.hero-image#main-banner', root)).length, 1)
    // A file added after the first walk is not seen inside the cache window:
    // proof the second selector reused the walk instead of re-reading the tree.
    writeFileSync(join(root, 'src', 'Late.tsx'), '<p className="late-token" />\n')
    assert.deepEqual(await findSourceCandidates('p.late-token', root), [])
  } finally {
    process.env.PATH = savedPath
  }
})

test('minified or framework-internal component names are omitted; a pointer with nothing left is dropped', async () => {
  const pw = await import('playwright')
  const browser = await pw.chromium.launch({ headless: true })
  try {
    const page = await browser.newPage()
    await page.setContent(FIXTURE)
    const out = await collectSourcePointers(page, ['#minified', '#internal', '#named'])
    assert.equal(out['#minified'], undefined, '"c" is a minifier artifact, not a component name')
    assert.equal(out['#internal'], undefined, '__next_root_layout_boundary__ is a framework internal')
    assert.deepEqual(out['#named'], { component: 'Nav', framework: 'react' }, 'a real 3-letter capitalised name stays')
  } finally {
    await browser.close()
  }
})

test('looksMinified: 1-2 char lowercase names are minified; short capitalised names are not', () => {
  for (const n of ['c', 'u', 'j', 'v', 'ab', 'a1', '_', '$', 'Kt', 'eB', 'Ae', 'A']) assert.equal(looksMinified(n), true, n)
  for (const n of ['Nav', 'Hero', 'App', 'main']) assert.equal(looksMinified(n), false, n)
})
