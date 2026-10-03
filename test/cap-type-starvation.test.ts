/**
 * Red-first test for bug #12 evidence: the RESULT_CAP cap must not hide an
 * entire issue type on busy pages. Reproduces the round-3 P007 distribution:
 * 22 serious, 25 contrast_insufficient moderates, 8 missing_audio_description
 * moderates, 26 keyboard_trap moderates — the plain severity-sorted cut
 * returned 0 keyboard_trap; the stratified cap must return all its types.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { stratifiedCap } from '../src/capStratified.ts'

const SEV: Record<string, number> = { critical: 4, serious: 3, moderate: 2, minor: 1 }
const mk = (id: string, type: string, impact: string, selector = `#${id}`) => ({
  id, type, impact, wcag: '1.1.1', message: id, selector,
})

const bySeverity = (l: { impact: string }[]) => [...l].sort((a, b) => SEV[b.impact] - SEV[a.impact])

test('severity-sorted cut drops every keyboard_trap on a contrast-heavy page (repro shape)', () => {
  const raw = [
    ...Array.from({ length: 22 }, (_, i) => mk(`ser-${i}`, 'label_in_name', 'serious')),
    ...Array.from({ length: 25 }, (_, i) => mk(`con-${i}`, 'contrast_insufficient', 'moderate')),
    ...Array.from({ length: 8 }, (_, i) => mk(`aud-${i}`, 'missing_audio_description', 'moderate')),
    ...Array.from({ length: 26 }, (_, i) => mk(`kt-${i}`, 'keyboard_trap', 'moderate')),
  ]
  const sorted = bySeverity(raw)
  const plain = sorted.slice(0, 50)
  assert.equal(plain.filter((i) => i.type === 'keyboard_trap').length, 0, 'plain cut drops the whole type — the bug')
})

test('stratifiedCap keeps one of every type under the cap and stays at cap', () => {
  const raw = [
    ...Array.from({ length: 22 }, (_, i) => mk(`ser-${i}`, 'label_in_name', 'serious')),
    ...Array.from({ length: 25 }, (_, i) => mk(`con-${i}`, 'contrast_insufficient', 'moderate')),
    ...Array.from({ length: 8 }, (_, i) => mk(`aud-${i}`, 'missing_audio_description', 'moderate')),
    ...Array.from({ length: 26 }, (_, i) => mk(`kt-${i}`, 'keyboard_trap', 'moderate')),
    ...Array.from({ length: 30 }, (_, i) => mk(`min-${i}`, 'target-size', 'minor')),
  ]
  const sorted = bySeverity(raw)
  const [kept, rescued] = stratifiedCap(sorted, 50)
  assert.equal(kept.length, 50)
  const types = new Set(kept.map((i) => i.type))
  for (const t of ['label_in_name', 'contrast_insufficient', 'missing_audio_description', 'keyboard_trap', 'target-size']) {
    assert.ok(types.has(t), `type ${t} must survive the cap`)
  }
  assert.equal(rescued, true, 'keyboard_trap was rescued from beyond the plain cut')
  // Phase 1 picks the highest-severity member of each type: the serious label_in_name wins its tier.
  assert.equal(kept.find((i) => i.type === 'label_in_name')?.impact, 'serious')
})

test('stratifiedCap is a plain copy when the list is under the cap', () => {
  const raw = [mk('a', 'x', 'serious'), mk('b', 'x', 'moderate'), mk('c', 'y', 'minor')]
  const [kept, rescued] = stratifiedCap([...raw], 50)
  assert.deepEqual(kept, raw)
  assert.equal(rescued, false)
})

test('stratifiedCap never returns more than cap and keeps severity order sane', () => {
  const raw = Array.from({ length: 80 }, (_, i) => mk(`k-${i}`, `t${i % 3}`, 'moderate'))
  const [kept] = stratifiedCap([...raw], 50)
  assert.equal(kept.length, 50)
  assert.equal(new Set(kept.map((i) => i.id)).size, 50, 'no duplicates')
})

test('cap==0 edge and single-type lists behave', () => {
  const single = Array.from({ length: 60 }, (_, i) => mk(`s-${i}`, 'x', 'serious'))
  const [keptOne, rOne] = stratifiedCap([...single], 50)
  assert.equal(keptOne.length, 50)
  assert.equal(rOne, false, 'single type: rescue flag stays false (no hidden type)')
  const [empty] = stratifiedCap([], 50)
  assert.deepEqual(empty, [])
})
