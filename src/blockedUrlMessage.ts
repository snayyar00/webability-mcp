/**
 * What to tell someone whose URL the hosted server refused.
 *
 * The guard itself is correct and stays: a token holder must never be able to
 * make our cloud server fetch an internal address. The DEFECT is the message.
 * `Blocked URL: "localhost" resolves to blocked internal address ::1` reads as
 * a product fault, and it arrives on the single most obvious first thing a
 * developer tries with a dev-tool MCP — pointing it at their dev server.
 *
 * A user whose first call fails with a security error does not file a bug.
 * They uninstall.
 *
 * The fix is not to relax the guard. It is to explain WHY the hosted server
 * cannot reach their machine (it runs in our cloud, so `localhost` means OUR
 * localhost) and to name the stdio server, which runs on their machine and
 * scans localhost fine today.
 */

/**
 * Is this a developer pointing at their OWN machine or LAN?
 *
 * Deliberately narrower than `isBlockedAddress`. Cloud-metadata (169.254.x)
 * and CGNAT ranges are blocked too, but they are not a developer's dev server
 * — they are what an SSRF attempt looks like. Those keep the generic message:
 * a detailed explanation of what is blocked and why hands a prober a map, and
 * naming the metadata range confirms which cloud we run on.
 */
export function isDeveloperLocalAddress(addr: string): boolean {
  const a = (addr || '').toLowerCase()
  if (a === '::1' || a === '::') return true
  const mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
  const ipv4 = mapped ? mapped[1] : a
  const m = ipv4.match(/^(\d+)\.(\d+)\.\d+\.\d+$/)
  if (!m) return false
  const o1 = parseInt(m[1], 10)
  const o2 = parseInt(m[2], 10)
  if (o1 === 0 || o1 === 127) return true                  // this-host / loopback
  if (o1 === 10) return true                               // private
  if (o1 === 172 && o2 >= 16 && o2 <= 31) return true       // private
  if (o1 === 192 && o2 === 168) return true                 // private
  return false                                              // 169.254.x, 100.64-127.x: stay generic
}

/**
 * The message for a refused URL.
 *
 * `detail` is the guard's own error text, which already names the hostname and
 * the resolved address — the useful diagnostic when a public hostname
 * unexpectedly resolves somewhere private.
 */
export function blockedUrlMessage(detail: string, resolvedAddress?: string): string {
  const generic = `Blocked URL: ${detail}`
  if (!resolvedAddress || !isDeveloperLocalAddress(resolvedAddress)) return generic

  return [
    `Blocked URL: ${detail}`,
    '',
    'This is the HOSTED WebAbility MCP server, which runs in our cloud — so "localhost" and private addresses mean OUR network, not yours. It cannot reach your machine, and it must not be able to: without that check, any token holder could point this server at internal services.',
    '',
    'To scan a local dev server, run the MCP on your own machine instead — same tools, and localhost works because the browser is local:',
    '',
    '  claude mcp add webability-local -- npx -y @webability/mcp',
    '',
    'Other clients: add `npx -y @webability/mcp` as a stdio server. (The `-y` matters — without it npx may fail with "could not determine executable to run".)',
    '',
    'Alternatively, expose the dev server on a public URL and scan that. If you use Vite, add the tunnel hostname to `server.allowedHosts` or it answers 403 to everything.',
  ].join('\n')
}

/** Pull the resolved address out of the guard's error text, if it named one. */
export function resolvedAddressFrom(detail: string): string | undefined {
  const m = detail.match(/blocked internal address ([0-9a-f.:]+)/i)
  return m ? m[1] : undefined
}
