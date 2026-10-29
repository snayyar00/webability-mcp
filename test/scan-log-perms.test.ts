/**
 * The local scan log holds full tool responses and target URLs with their
 * query strings (#201). On a shared machine it must be readable by its owner
 * only: directory 0700, files 0600. Recording and reading back still work.
 */
import assert from 'node:assert/strict'
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { newScanId, readScanHistory, readScanResult, recordScan } from '../src/scanLog.ts'

const mode = (p: string) => statSync(p).mode & 0o777

function record(dir: string) {
  process.env.WEBABILITY_SCAN_LOG_DIR = dir
  const id = newScanId('scan_page')
  recordScan({ id, timestamp: new Date().toISOString(), tool: 'scan_page', target: 'https://intranet.corp.test/a?session=s3cr3t', durationMs: 5, ok: true, summary: 'ok' }, { content: [{ type: 'text', text: 'body' }] })
  return id
}

test('a new log directory is 0700 and its files are 0600', { skip: process.platform === 'win32' }, () => {
  const dir = join(mkdtempSync(join(tmpdir(), 'scanlog-')), 'scans')
  const id = record(dir)
  assert.equal(mode(dir), 0o700)
  for (const f of readdirSync(dir)) assert.equal(mode(join(dir, f)), 0o600, f)
  // The owner still reads it back.
  assert.equal(readScanHistory()[0].id, id)
  assert.ok(readScanResult(id))
})

test('an existing world-readable log directory is tightened on the next record', { skip: process.platform === 'win32' }, () => {
  const dir = join(mkdtempSync(join(tmpdir(), 'scanlog-')), 'scans')
  mkdirSync(dir, { recursive: true })
  chmodSync(dir, 0o755)
  record(dir)
  assert.equal(mode(dir), 0o700)
})
