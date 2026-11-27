import { normalizeUrlArg } from './publicUrl.js'
import type { InstallEvidence } from './installCheck.js'

export const apiBaseUrl = () => process.env.WEBABILITY_API_URL || process.env.ABILYO_API_URL || 'https://api.webability.io'

export function installUrl(raw: unknown): string {
  if (typeof raw !== 'string' || !raw.trim() || raw.length > 2048) {
    throw new Error('Supply an HTTP or HTTPS URL of at most 2048 characters.')
  }
  const url = new URL(normalizeUrlArg(raw))
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error('Supply an HTTP or HTTPS URL without credentials.')
  }
  url.hash = ''
  return url.href
}

interface Diagnostic {
  url: string
  finalUrl: string
  state: 'installed' | 'blocked' | 'error' | 'not_installed'
  sentence: string
  nextStep: string
  evidence: InstallEvidence[]
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function evidence(value: unknown): boolean {
  if (!record(value)) return false
  switch (value.kind) {
    case 'absence':
      return Array.isArray(value.inspectedScriptUrls) && value.inspectedScriptUrls.every(v => typeof v === 'string') && typeof value.observationDurationMs === 'number'
    case 'security_policy':
      return [value.blockedUrl, value.directive, value.policy].every(v => typeof v === 'string')
    case 'script':
      return typeof value.scriptUrl === 'string' && typeof value.httpStatus === 'number'
    case 'script_error':
      return typeof value.scriptUrl === 'string' && typeof value.message === 'string'
    case 'script_load':
      return typeof value.scriptUrl === 'string' && (typeof value.failure === 'string' || typeof value.httpStatus === 'number')
    case 'consent':
      return typeof value.scriptUrl === 'string' && typeof value.type === 'string' && record(value.attributes) && Object.values(value.attributes).every(v => typeof v === 'string')
    default: return false
  }
}

function diagnostic(body: unknown): body is Diagnostic {
  return record(body) && [body.url, body.finalUrl, body.sentence, body.nextStep].every(v => typeof v === 'string' && v.length > 0) &&
    typeof body.state === 'string' && ['installed', 'blocked', 'error', 'not_installed'].includes(body.state) &&
    Array.isArray(body.evidence) && body.evidence.length > 0 && body.evidence.every(evidence)
}

/** Both callers validate the public target before sending it to this endpoint. */
export async function checkInstallApi(url: string, token?: string): Promise<Diagnostic> {
  const response = await fetch(new URL('/check-install', apiBaseUrl()), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(token && { Authorization: `Bearer ${token}` }) },
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(75_000),
    redirect: 'error',
  })
  const body: unknown = await response.json().catch(() => undefined)
  if (response.status !== 200) {
    const guidance = record(body) ? [body.sentence, body.nextStep].filter(v => typeof v === 'string').join(' ') : ''
    const retry = response.status === 429 ? 'Wait at least one minute before retrying.' : response.status === 502 ? 'Retry the check.' : ''
    throw new Error([`HTTP ${response.status}`, guidance, retry].filter(Boolean).join(' '))
  }
  if (!diagnostic(body)) throw new Error('Invalid check-install response. Retry the check.')
  return body
}
