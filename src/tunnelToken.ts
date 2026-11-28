import type { Readable } from 'node:stream'
import { resolveAuthToken } from './authToken'

/**
 * Where a `webability-tunnel` token came from. The token is a credential:
 * `--token <t>` puts it in `argv`, which every local process can read out of
 * `ps` and a CI job prints into its log. That still works, but the environment
 * and stdin are the channels a secret belongs in, so `--token` now says so.
 */
export type TunnelTokenSource = 'flag' | 'env' | 'stdin' | 'config'

export interface TunnelToken {
  token: string
  source: TunnelTokenSource
  /** Set when the source is deprecated; the CLI prints it to stderr. */
  warning?: string
}

export interface TunnelTokenInput {
  argv: readonly string[]
  env?: NodeJS.ProcessEnv
  /** Reads the token from stdin. Resolve '' when nothing is piped in. */
  readStdin?: () => Promise<string>
  /** The token `webability login` persisted. Defaults to resolveAuthToken. */
  readConfig?: () => string
}

const FLAG_WARNING =
  '--token is deprecated: command-line arguments are visible to every process on this machine, and to CI logs. ' +
  'Set WEBABILITY_API_KEY instead, or pipe the token in: echo <token> | webability-tunnel --port 3000'

/** `--token <t>`; '' when the flag is absent, or last with nothing after it. */
function flagToken(argv: readonly string[]): string {
  const i = argv.indexOf('--token')
  return i === -1 ? '' : (argv[i + 1] ?? '').trim()
}

/**
 * Resolve the tunnel token: `--token` (as before, so existing scripts keep
 * working), then the environment, then a piped stdin (CI, where an env var
 * lands in the job log), then the login config.
 *
 * `--token` stays first because it is what today's callers rely on; moving it
 * below the environment would silently substitute a different account's token
 * for the one on the command line.
 */
export async function resolveTunnelToken(input: TunnelTokenInput): Promise<TunnelToken> {
  const env = input.env ?? process.env
  const fromFlag = flagToken(input.argv)
  if (fromFlag) return { token: fromFlag, source: 'flag', warning: FLAG_WARNING }
  const fromEnv = (env.WEBABILITY_API_KEY || env.ABILYO_API_KEY || '').trim()
  if (fromEnv) return { token: fromEnv, source: 'env' }
  const piped = ((await input.readStdin?.()) ?? '').trim()
  if (piped) return { token: piped, source: 'stdin' }
  const fromConfig = (input.readConfig ?? resolveAuthToken)() || ''
  return { token: fromConfig.trim(), source: 'config' }
}

export async function readStdinLine(stream: Readable, timeoutMs = 1500): Promise<string> {
  // Destroying the stream at the deadline is what ends a `for await` that is
  // waiting on a pipe nobody will write to; a timer alone cannot wake it.
  const deadline = setTimeout(() => stream.destroy(), timeoutMs)
  let text = ''
  try {
    for await (const chunk of stream) {
      text += String(chunk)
      if (text.includes('\n')) break
    }
  } catch {
    // Destroyed at the deadline, or the pipe broke: whatever arrived is the token.
  } finally {
    clearTimeout(deadline)
  }
  const newline = text.indexOf('\n')
  return (newline === -1 ? text : text.slice(0, newline)).trim()
}
