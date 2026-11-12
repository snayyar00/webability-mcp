/**
 * Hosted sign-in paths and the text an anonymous caller gets from an account tool.
 *
 * The hosted server has three MCP URLs:
 * - `/mcp` never answers an anonymous request with 401. A 401 on a tool call
 *   makes Claude Code cache the server as `needs-auth`, and every later session
 *   on that machine starts with zero tools (measured with Claude Code 2.1.288).
 *   So an anonymous call to an account tool gets a normal tool result with
 *   no `isError` (a missing sign-in is a normal state, not a server failure,
 *   and connector health views count isError results as request errors) and
 *   the steps below. Clients that sign in on demand from
 *   the protected-resource metadata (Claude Code `claude mcp login`, Codex
 *   `codex mcp login`) use this URL for everything.
 * - `/mcp/auth` answers every request without a valid token with 401 +
 *   WWW-Authenticate, so a client that starts OAuth only on a 401 (claude.ai
 *   connectors per claude.com/docs/connectors/building/authentication; Cursor,
 *   VS Code, opencode) signs the user in when they add it.
 * - `/mcp/apps` is the ChatGPT (OpenAI Apps SDK) path. Anonymous requests are
 *   allowed, as on `/mcp`, but every tool declares `securitySchemes` and an
 *   anonymous call to an account tool returns `isError: true` with
 *   `_meta["mcp/www_authenticate"]`: that is the only signal that makes
 *   ChatGPT show its sign-in UI (developers.openai.com/apps-sdk/build/auth).
 */
export const PUBLIC_URL = (process.env.MCP_PUBLIC_URL || 'https://mcp.webability.io').replace(/\/+$/, '')
export const MCP_PATH = '/mcp'
export const SIGN_IN_MCP_PATH = '/mcp/auth'
export const APPS_MCP_PATH = '/mcp/apps'

/** Every hosted MCP path. */
export const MCP_PATHS: readonly string[] = [MCP_PATH, SIGN_IN_MCP_PATH, APPS_MCP_PATH]

/** Tools that need the caller's own WebAbility account. */
export const ACCOUNT_TOOLS: ReadonlySet<string> = new Set(['start_audit', 'get_audit', 'visual_audit', 'add_site', 'list_sites', 'create_upgrade_link'])

/** The protected-resource metadata URL for one of the MCP paths (RFC 9728 §3.1 path form). */
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
    '- An AI agent with its own AgentMail inbox needs no human account: on the WebAbility sign-in page choose "Sign in with AgentID". A new agent gets its own free account.',
  ]
}

/** Tool-result text for an anonymous call to an account tool on the hosted `/mcp`. */
export function signInRequired(tool: string): string {
  return [
    `${tool} needs a free WebAbility account, and this connection is not signed in. Nothing ran. The scan and check tools keep working here without an account.`,
    '',
    'To sign in:',
    ...signInSteps(),
    '',
    `Then call ${tool} again.`,
  ].join('\n')
}

/** Tool-result text for an anonymous call to an account tool on `/mcp/apps`.
 * The first line keeps "not signed in" and "Nothing ran": telemetry and the
 * PostHog filter classify the call by those phrases. ChatGPT shows its own
 * sign-in button from the challenge in `_meta`, so no client steps here. */
export function appsSignInRequired(tool: string): string {
  return [
    `${tool} needs a WebAbility account, and you are not signed in. Nothing ran: no account data was read and nothing was changed.`,
    '',
    `Sign in to WebAbility when ChatGPT asks, then call ${tool} again. The scan and check tools work without signing in.`,
  ].join('\n')
}

/** A `_meta["mcp/www_authenticate"]` challenge on `/mcp/apps`. `description` must hold no double quote. */
export function appsChallenge(description: string): string {
  return `Bearer resource_metadata="${resourceMetadataUrl(APPS_MCP_PATH)}", error="insufficient_scope", error_description="${description.replace(/"/g, "'")}"`
}

/** The challenge for an anonymous account-tool call on `/mcp/apps`. */
export function appsAuthChallenge(tool: string): string {
  return appsChallenge(`Sign in to WebAbility to use ${tool}`)
}
