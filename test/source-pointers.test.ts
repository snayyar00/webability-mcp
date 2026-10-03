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

import { collectSourcePointers, findSourceCandidates, formatSource } from '../src/sourcePointers.ts'

const FIXTURE = `<!doctype html><html><body>
<img id="hero" src="x.png">
<button id="vbtn"></button>
<a id="plain" href="#"></a>
<script>
  // React 16-18 dev build shape: fiber on the DOM node, _debugSource from the
  // jsx dev transform, owner chain for the component name.
  const owner = { type: { name: 'Hero' }, _debugSource: null, return: null }
  document.getElementById('hero')['__reactFiber$abc'] = { _debugSource: { fileName: '/app/src/Hero.tsx', lineNumber: 12, columnNumber: 5 }, _debugOwner: owner, return: owner, type: 'img' }
  // Vue 3 dev build shape.
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
