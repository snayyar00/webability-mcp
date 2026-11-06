import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/**
 * Resolve a WebAbility auth token for Full tools that need a JWT (`visual_audit`, `start_audit`).
 * Free for the customer with a WebAbility account — the token identifies the account.
 *
 * Lookup order: explicit env var (the natural channel for an MCP server config) → the
 * token the `webability` CLI persisted after login. The CLI stores it with the `conf`
 * package (projectName "webability"); we read that JSON directly rather than depend on
 * the CLI package. Returns '' when nothing is found so callers can emit an actionable
 * "authenticate first" message instead of leaking a bare 401.
 */
export function resolveAuthToken(): string {
  const fromEnv = process.env.WEBABILITY_API_KEY || process.env.ABILYO_API_KEY || ''
  if (fromEnv) return fromEnv
  const home = homedir()
  const candidates: string[] = []
  if (process.platform === 'darwin') {
    candidates.push(join(home, 'Library', 'Preferences', 'webability-nodejs', 'config.json'))
  } else if (process.platform === 'win32') {
    const appData = process.env.APPDATA || join(home, 'AppData', 'Roaming')
    candidates.push(join(appData, 'webability-nodejs', 'Config', 'config.json'))
  }
  const xdg = process.env.XDG_CONFIG_HOME || join(home, '.config')
  candidates.push(join(xdg, 'webability-nodejs', 'config.json'))
  for (const p of candidates) {
    try {
      const parsed = JSON.parse(readFileSync(p, 'utf8'))
      if (parsed && typeof parsed.apiKey === 'string' && parsed.apiKey) return parsed.apiKey
    } catch {
      // file absent or unreadable — try the next candidate
    }
  }
  return ''
}
