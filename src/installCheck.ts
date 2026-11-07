/** Proposed install-check contract. Detection and browser observation are not implemented yet. */
export type InstallState = 'present' | 'blocked' | 'error' | 'not_installed'

export type InstallEvidence =
  | { kind: 'script'; scriptUrl: string; httpStatus: number }
  | { kind: 'security_policy'; blockedUrl: string; directive: string; policy: string }
  | { kind: 'script_error'; scriptUrl: string; message: string }
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
  scriptElements: Array<{ src: string }>
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

export class InstallCheckNotImplementedError extends Error {
  constructor() {
    super('Install-check detection is not implemented yet; no installation state or evidence is available.')
    this.name = 'InstallCheckNotImplementedError'
  }
}

/**
 * Future implementation will collect observations and classify them here.
 * The injectable observer lets behavior tests use deterministic fixtures.
 * Do not manufacture a state, collect observations, or match scripts in this skeleton.
 */
export async function checkInstall(_url: string, _deps?: InstallCheckDependencies): Promise<InstallCheckResult> {
  throw new InstallCheckNotImplementedError()
}
