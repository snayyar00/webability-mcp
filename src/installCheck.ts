/** Evidence-based classification of a completed browser observation. */
export type InstallState = 'present' | 'blocked' | 'error' | 'not_installed'

export type InstallEvidence =
  | { kind: 'script'; scriptUrl: string; httpStatus: number }
  | { kind: 'security_policy'; blockedUrl: string; directive: string; policy: string }
  | { kind: 'script_error'; scriptUrl: string; message: string }
  | { kind: 'script_load'; scriptUrl: string; httpStatus?: number; failure?: string }
  | { kind: 'consent'; scriptUrl: string; type: string; attributes: Record<string, string> }
  | { kind: 'absence'; inspectedScriptUrls: string[]; observationDurationMs: number }

export interface InstallCheckResult {
  url: string
  finalUrl: string
  state: InstallState
  evidence: InstallEvidence[]
}

/** Raw browser observations, not preclassified installation states. */
export interface InstallObservation {
  finalUrl: string
  scriptElements: Array<{ src: string; type?: string; attributes?: Record<string, string> }>
  requests: Array<{ url: string; status?: number; failure?: string }>
  policyViolations: Array<{
    blockedUrl: string
    directive: string
    policy: string
    disposition: 'enforce' | 'report'
  }>
  runtimeErrors: Array<{ scriptUrl: string; message: string }>
  observationDurationMs: number
}

export interface InstallCheckDependencies {
  observe: (url: string) => Promise<InstallObservation>
}

/**
 * Hosts that serve the embed: install snippet, docs, dashboard Install tab
 * (widget.webability.io) and the legacy host. Exact hostnames, never substrings.
 */
const INSTALL_SCRIPT_HOSTS = ['enhancer.webability.io', 'widget-v2.webability.io', 'widget.webability.io', 'widget.access-widget.com']

export function isInstallScript(raw: string): boolean {
  try {
    const u = new URL(raw)
    return u.protocol === 'https:' && !u.port && !u.username && !u.password &&
      INSTALL_SCRIPT_HOSTS.includes(u.hostname) && u.pathname === '/widget.min.js'
  } catch { return false }
}

export async function checkInstall(url: string, deps: InstallCheckDependencies): Promise<InstallCheckResult> {
  const o = await deps.observe(url)
  const result = (state: InstallState, evidence: InstallEvidence[]): InstallCheckResult => ({ url, finalUrl: o.finalUrl, state, evidence })
  const policies: InstallEvidence[] = o.policyViolations
    .filter((p) => p.disposition === 'enforce' && isInstallScript(p.blockedUrl))
    .map(({ blockedUrl, directive, policy }) => ({ kind: 'security_policy', blockedUrl, directive, policy }))
  const consent: InstallEvidence[] = o.scriptElements
    .filter((s) => isInstallScript(s.src) && s.type?.trim().toLowerCase() === 'text/plain' &&
      Object.keys(s.attributes ?? {}).some((k) => ['data-cookieconsent', 'data-cookiecategory', 'data-consent'].includes(k)) &&
      !o.requests.some((r) => r.url === s.src))
    .map((s) => ({ kind: 'consent', scriptUrl: s.src, type: s.type!, attributes: s.attributes! }))
  if (policies.length || consent.length) return result('blocked', [...policies, ...consent])
  const errors: InstallEvidence[] = o.runtimeErrors.filter((e) => isInstallScript(e.scriptUrl))
    .map((e) => ({ kind: 'script_error', ...e }))
  const loads: InstallEvidence[] = o.requests.filter((r) => isInstallScript(r.url) && (r.failure || (r.status !== undefined && r.status >= 400)))
    .map((r) => ({ kind: 'script_load', scriptUrl: r.url, ...(r.status !== undefined ? { httpStatus: r.status } : {}), ...(r.failure ? { failure: r.failure } : {}) }))
  if (errors.length || loads.length) return result('error', [...errors, ...loads])
  const loaded: InstallEvidence[] = o.requests.filter((r) => isInstallScript(r.url) && r.status !== undefined && r.status >= 200 && r.status < 300)
    .map((r) => ({ kind: 'script', scriptUrl: r.url, httpStatus: r.status! }))
  if (loaded.length) return result('present', loaded)
  // An inert tag, unfinished request, or incomplete evidence is not absence.
  if (o.scriptElements.some((s) => isInstallScript(s.src)) || o.requests.some((r) => isInstallScript(r.url))) {
    throw new Error('Recognized script found, but its load outcome could not be established within the observation window')
  }
  return result('not_installed', [{ kind: 'absence', inspectedScriptUrls: o.scriptElements.map((s) => s.src), observationDurationMs: o.observationDurationMs }])
}
