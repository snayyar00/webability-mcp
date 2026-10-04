// Every anonymous tool that launches a browser or calls the AI endpoint must
// count against a per-IP bucket. check_color_contrast launches Chromium when
// it is given a url, so it is heavy too.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { anonLimitClass } from '../src/anonGate.ts'

test('browser-launching tools are heavy', () => {
  for (const t of ['scan_page', 'flow_scan', 'diff_scan', 'verify_fix', 'detect_framework', 'scan_html', 'check_aria']) {
    assert.equal(anonLimitClass({ name: t }), 'heavy', t)
  }
})

test('check_color_contrast is heavy only when it is given a url', () => {
  assert.equal(anonLimitClass({ name: 'check_color_contrast', args: { foreground: '#000', background: '#fff' } }), null)
  assert.equal(anonLimitClass({ name: 'check_color_contrast' }), null)
  assert.equal(anonLimitClass({ name: 'check_color_contrast', args: { url: 'https://example.com' } }), 'heavy')
})

test('generate_ai_fix is ai', () => {
  assert.equal(anonLimitClass({ name: 'generate_ai_fix' }), 'ai')
})

test('account tools and unknown tools are not limited here', () => {
  for (const t of ['start_audit', 'get_audit', 'visual_audit', 'get_rules', 'nope']) {
    assert.equal(anonLimitClass({ name: t }), null, t)
  }
})

test('check_color_contrast: any truthy url is heavy (the handler launches Chromium on truthiness)', () => {
  for (const url of ['   ', ['https://example.com'], { href: 'https://example.com' }, 1]) {
    assert.equal(anonLimitClass({ name: 'check_color_contrast', args: { url } }), 'heavy', JSON.stringify(url))
  }
})

// The gate and the handler read brandColors through the same parser
// (contrastPalette), so "heavy" is exactly "the handler would launch Chromium".
test('check_color_contrast: valid brandColors + url never reaches Chromium, so it is not heavy', () => {
  assert.equal(anonLimitClass({ name: 'check_color_contrast', args: { url: 'https://example.com', brandColors: ['#0055aa', '#ffffff'] } }), null)
})

test('check_color_contrast: brandColors that parse to an empty palette + url is heavy', () => {
  for (const brandColors of [['garbage'], [], ['notacolor', 42], 'not-an-array', { length: 3 }]) {
    assert.equal(
      anonLimitClass({ name: 'check_color_contrast', args: { url: 'https://example.com', brandColors } }),
      'heavy',
      JSON.stringify(brandColors),
    )
  }
  assert.equal(anonLimitClass({ name: 'check_color_contrast', args: { url: 'https://example.com' } }), 'heavy')
})

test('check_color_contrast: valid brandColors and no url is not heavy', () => {
  assert.equal(anonLimitClass({ name: 'check_color_contrast', args: { brandColors: ['#0055aa'] } }), null)
})

test('check_color_contrast: whitespace url with no usable palette is heavy (the handler launches Chromium before goto fails)', () => {
  assert.equal(anonLimitClass({ name: 'check_color_contrast', args: { url: '   ' } }), 'heavy')
  assert.equal(anonLimitClass({ name: 'check_color_contrast', args: { url: '   ', brandColors: ['garbage'] } }), 'heavy')
})
