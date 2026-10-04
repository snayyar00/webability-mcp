import assert from 'node:assert/strict'
import { test } from 'node:test'
import { contrastPalette, contrastLaunchesBrowser } from '../src/contrastPalette.ts'

test('contrastPalette keeps parseable colors and drops the rest', () => {
  assert.deepEqual(contrastPalette(['#0055aa', 'garbage', 42, 'rgb(0, 0, 0)']), ['#0055aa', 'rgb(0, 0, 0)'])
  assert.deepEqual(contrastPalette(undefined), [])
  assert.deepEqual(contrastPalette('#0055aa'), [])
  assert.deepEqual(contrastPalette({ length: 2 }), [])
})

test('contrastLaunchesBrowser is (empty parsed palette && truthy url)', () => {
  assert.equal(contrastLaunchesBrowser({ url: 'https://example.com', brandColors: ['#000000'] }), false)
  assert.equal(contrastLaunchesBrowser({ url: 'https://example.com', brandColors: ['garbage'] }), true)
  assert.equal(contrastLaunchesBrowser({ url: '   ' }), true)
  assert.equal(contrastLaunchesBrowser({ brandColors: [] }), false)
  assert.equal(contrastLaunchesBrowser(undefined), false)
})
