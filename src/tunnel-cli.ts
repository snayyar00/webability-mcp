#!/usr/bin/env node
/**
 * `webability-tunnel --port 3000`
 *
 * Opens a tunnel so the HOSTED scanner can reach a local dev server, and
 * prints the URL plus the header every request must carry. Runs until Ctrl-C;
 * the ingress dies with the process.
 *
 * Shipped in this package rather than as its own: anyone who needs a tunnel
 * already has the MCP installed, and a second package is a second thing to
 * version, publish and get wrong.
 */
import { openTunnel, type TunnelHandle } from './tunnel/client'
import { keepTunnel } from './tunnel/reconnect'

function arg(name: string, fallback = ''): string {
  const i = process.argv.indexOf(`--${name}`)
  return i > -1 ? (process.argv[i + 1] ?? fallback) : fallback
}

const port = Number(arg('port'))
const token = arg('token', process.env.WEBABILITY_API_KEY || '')
const relayUrl = arg('relay', process.env.WEBABILITY_TUNNEL_RELAY || 'wss://tunnel.webability.io')

if (!port) {
  console.error('usage: webability-tunnel --port 3000 [--token <t>] [--relay <url>]')
  console.error('\nMost people do NOT need this. Running the MCP locally (npx -y @webability/mcp)')
  console.error('reaches localhost directly, with nothing exposed. Use a tunnel only when the')
  console.error('scan has to run on the hosted server: CI, a remote agent, a dashboard scan.')
  process.exit(1)
}
if (!token) {
  console.error('No token. Pass --token or set WEBABILITY_API_KEY (free account at https://app.webability.io).')
  process.exit(1)
}

let current: TunnelHandle | null = null

const printTunnel = (tunnel: TunnelHandle, reconnect: boolean) => {
  current = tunnel
  if (reconnect) {
    console.log('\n  The relay restarted, so the tunnel reconnected with a NEW url and secret.')
    console.log('  The old pair no longer works. Start any new audit with these:\n')
  } else {
    console.log(`\n  Tunnel open: http://127.0.0.1:${port} is reachable at\n`)
  }
  console.log(`    ${tunnel.url}\n`)
  console.log(`  Requests MUST carry this header — the URL alone opens nothing:\n`)
  console.log(`    ${tunnel.secretHeader}: ${tunnel.secret}\n`)
  if (!reconnect) console.log(`  Anyone holding both can reach your dev server. Ctrl-C closes it.\n`)
}

const shutdown = () => {
  current?.close()
  console.log('\n  Tunnel closed.')
  process.exit(0)
}
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)

// openTunnel rejects on a bad token, an unusable relay, or an auth outage.
// Without a catch the CLI prints a stack trace at someone who mistyped a flag.
// A relay restart (RELAY_RESTART_CODE) reconnects; any other close is final.
const end = await keepTunnel({
  open: (onClosed) => openTunnel({ relayUrl, token, port, onStatus: (line) => console.log(`  → ${line}`), onClosed }),
  onOpened: printTunnel,
  onRetry: (attempt, delayMs, error) => console.log(`  → relay not back yet (${error}); retry ${attempt} in ${Math.round(delayMs / 1000)} s`),
}).catch((err: Error) => {
  console.error(`\n  ${err.message}\n`)
  process.exit(1)
})

// A tunnel that dies mid-session used to exit 0 in silence. Anything depending
// on it — a CI job most of all — would go green while the scans behind it had
// already stopped working.
if (end.reason === 'reconnect-failed') {
  console.error(`\n  The relay restarted and did not come back (${end.message || 'no answer'}).`)
} else {
  console.error(`\n  Tunnel closed by the relay (${end.code})${end.message ? `: ${end.message}` : ''}.`)
}
console.error('  Open a new one to continue.\n')
process.exit(1)
