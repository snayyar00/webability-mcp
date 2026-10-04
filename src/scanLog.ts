/**
 * Persistent scan history for the MCP scanner tools.
 *
 * Every scan-shaped tool call (scan_page, flow_scan, scan_html, visual_audit,
 * check_aria) is recorded so you can go back and see what was scanned, when,
 * and what it found:
 *
 *   ~/.webability/scans/index.jsonl       — one line per scan (the ledger)
 *   ~/.webability/scans/<id>.json         — the full tool response
 *
 * Browse it three ways: the `scan_history` MCP tool, `cat`/`jq` on the JSONL,
 * or opening an individual result file.
 *
 * Config:
 *   WEBABILITY_SCAN_LOG_DIR — override the directory
 *   WEBABILITY_SCAN_LOG=off — disable logging entirely
 *
 * Logging is strictly best-effort: a full disk or read-only home dir must
 * never break a scan. In remote/hosted mode the server may handle untrusted
 * multi-tenant traffic — callers decide whether to enable it there.
 */
import { verifyFixTargetUrl } from './verifyFixArgs.js'
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'

export interface ScanLogEntry {
  id: string
  timestamp: string
  tool: string
  /** URL / start URL, or a synthetic label like "inline-html (1.2 KB)". */
  target: string
  durationMs: number
  ok: boolean
  /** First human-readable line of the tool response. */
  summary: string
  /** Result filename inside the log dir (absent if the body could not be written). */
  file?: string
}

const MAX_STORED_RESULTS = 500

export function scanLogDir(): string {
  return process.env.WEBABILITY_SCAN_LOG_DIR || join(homedir(), '.webability', 'scans')
}

export function scanLogEnabled(): boolean {
  return process.env.WEBABILITY_SCAN_LOG !== 'off'
}

let counter = 0

export function newScanId(tool: string): string {
  counter = (counter + 1) % 1000
  return `${new Date().toISOString().replace(/[:.]/g, '-')}-${tool}-${counter}`
}

/** Append one scan to the ledger and store its full response. Never throws. */
export function recordScan(entry: Omit<ScanLogEntry, 'file'>, fullResponse: unknown): void {
  if (!scanLogEnabled()) return
  try {
    const dir = scanLogDir()
    mkdirSync(dir, { recursive: true })

    let file: string | undefined
    try {
      file = `${entry.id}.json`
      writeFileSync(join(dir, file), JSON.stringify({ ...entry, response: fullResponse }, null, 2))
    } catch {
      file = undefined
    }

    appendFileSync(join(dir, 'index.jsonl'), JSON.stringify({ ...entry, ...(file ? { file } : {}) }) + '\n')
    pruneOldResults(dir)
  } catch {
    // Best-effort by contract.
  }
}

/** Newest-first history, optionally filtered by substring match on target/tool. */
export function readScanHistory(limit = 20, filter?: string): ScanLogEntry[] {
  try {
    const indexPath = join(scanLogDir(), 'index.jsonl')
    if (!existsSync(indexPath)) return []
    const lines = readFileSync(indexPath, 'utf8').trim().split('\n')
    const entries: ScanLogEntry[] = []
    for (let i = lines.length - 1; i >= 0 && entries.length < limit; i--) {
      try {
        const e = JSON.parse(lines[i]!) as ScanLogEntry
        if (filter && !`${e.target} ${e.tool}`.toLowerCase().includes(filter.toLowerCase())) continue
        entries.push(e)
      } catch {
        // Skip corrupt lines.
      }
    }
    return entries
  } catch {
    return []
  }
}

/** Full stored response for one scan id (or null if unknown/pruned). */
export function readScanResult(id: string): unknown | null {
  try {
    // Ids are generated from timestamps + tool names; guard against traversal anyway.
    if (!/^[\w.-]+$/.test(id)) return null
    const path = join(scanLogDir(), `${id}.json`)
    if (!existsSync(path)) return null
    return JSON.parse(readFileSync(path, 'utf8'))
  } catch {
    return null
  }
}

/** Keep the ledger forever (it's one line per scan) but cap stored bodies. */
function pruneOldResults(dir: string): void {
  try {
    const files = readdirSync(dir)
      .filter((f) => f.endsWith('.json'))
      .sort() // ids start with an ISO timestamp, so lexicographic = chronological
    for (let i = 0; i < files.length - MAX_STORED_RESULTS; i++) {
      try {
        unlinkSync(join(dir, files[i]!))
      } catch {
        // Best-effort.
      }
    }
  } catch {
    // Best-effort.
  }
}

/** Human-readable label for what a scan tool was pointed at. */
export function describeScanTarget(tool: string, args: Record<string, unknown> | undefined): string {
  if (!args) return tool
  if (tool === 'verify_fix') return verifyFixTargetUrl(args) ?? tool
  if (typeof args.url === 'string') return args.url
  if (typeof args.startUrl === 'string') {
    const extra = Array.isArray(args.autoNavigate) ? ` (+${args.autoNavigate.length} pages)` : ''
    return args.startUrl + extra
  }
  if (typeof args.html === 'string') return `inline-html (${(args.html.length / 1024).toFixed(1)} KB)`
  return tool
}
