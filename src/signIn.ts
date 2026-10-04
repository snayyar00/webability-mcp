/**
 * Hosted sign-in paths and the text an anonymous caller gets from an account tool.
 *
 * The hosted server has two MCP URLs:
 * - `/mcp` never answers an anonymous request with 401. A 401 on a tool call
 *   makes Claude Code cache the server as `needs-auth`, and every later session
 *   on that machine starts with zero tools (measured with Claude Code 2.1.288).
 *   So an anonymous call to an account tool gets a normal tool result with
 *   `isError: true` and the steps below. Clients that sign in on demand from
 *   the protected-resource metadata (Claude Code `claude mcp login`, Codex
 *   `codex mcp login`) use this URL for everything.
 * - `/mcp/auth` answers every request without a valid token with 401 +
 *   WWW-Authenticate, so a client that starts OAuth only on a 401 (claude.ai
 *   connectors per claude.com/docs/connectors/building/authentication; Cursor,
 *   VS Code, opencode) signs the user in when they add it.
 */
export const PUBLIC_URL = (process.env.MCP_PUBLIC_URL || 'https://mcp.webability.io').replace(/\/+$/, '')
export const MCP_PATH = '/mcp'
export const SIGN_IN_MCP_PATH = '/mcp/auth'

/** Tools that need the caller's own WebAbility account. */
export const ACCOUNT_TOOLS: ReadonlySet<string> = new Set(['start_audit', 'get_audit', 'visual_audit'])

/** The protected-resource metadata URL for one of the two MCP paths (RFC 9728 §3.1 path form). */
export function resourceMetadataUrl(mcpPath: string): string {
  return `${PUBLIC_URL}/.well-known/oauth-protected-resource${mcpPath}`
}

/** How to sign in from each client. The one source of sign-in text: the
 * account-tool refusal and the anonymous 429 both use it. */
export function signInSteps(): string[] {
  return [
    '- Claude Code: run `claude mcp login <server-name>` in a terminal, then reconnect it from `/mcp`. <server-name> is the name you gave this server (for example webability).',
    '- Codex: run `codex mcp login <server-name>`. opencode: run `opencode mcp auth <server-name>`.',
    `- claude.ai, Claude Desktop, Cursor, VS Code and other clients: add ${PUBLIC_URL}${SIGN_IN_MCP_PATH} as a server. It asks you to sign in when you connect, and it has every tool.`,
    '- Any client: send the header `Authorization: Bearer <token>` with the token `webability login` saves.',
  ]
}

/** Tool-result text for an anonymous call to an account tool on the hosted `/mcp`. */
export function signInRequired(tool: string): string {
  return [
    `${tool} needs a free WebAbility account, and this connection is not signed in. The scan and check tools keep working here without an account.`,
    '',
    'To sign in:',
    ...signInSteps(),
    '',
    `Then call ${tool} again.`,
  ].join('\n')
}
