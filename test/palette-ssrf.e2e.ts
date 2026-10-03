/**
 * Does the palette fetch ACTUALLY refuse a private address on hosted?
 *
 * The unit tests pin the `if (remote || tunnel)` condition. They would not
 * notice if installSsrfRoute or isBlockedAddress were weakened underneath —
 * the condition would still read correctly while the guard let everything
 * through. This one starts a real server on loopback and asks the real
 * browser to fetch it.
 *
 * Not part of `pnpm test` (it needs a chromium install). Run explicitly:
 *   tsx --test test/palette-ssrf.e2e.ts
 */
import assert from 'node:assert/strict'
import { createServer, Server } from 'node:http'
import { AddressInfo } from 'node:net'
import { test } from 'node:test'

import { extractBrandPaletteFromUrl } from '../src/server'

function listen(): Promise<{ server: Server; port: number }> {
  return new Promise((resolve) => {
    const server = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' })
      // Unmistakable colours, so a leak is obvious rather than plausible.
      // extractSiteTheme weights by painted area and reads CSS custom
      // properties, so a bare inline style on <body> yields nothing — the
      // first version of this fixture returned an empty palette LOCALLY,
      // which would have made the blocked case prove nothing at all.
      res.end(
        `<html><head><style>
           :root { --brand-primary: #ff00ff; --brand-text: #00ff00; }
           html, body { margin: 0; height: 100%; }
           .fill { background: #ff00ff; color: #00ff00; width: 100vw; height: 100vh;
                   font-size: 32px; padding: 40px; box-sizing: border-box; }
         </style></head>
         <body><div class="fill"><h1>secret internal page</h1><p>secret internal page</p></div></body></html>`,
      )
    })
    server.listen(0, '127.0.0.1', () => resolve({ server, port: (server.address() as AddressInfo).port }))
  })
}

test('remote: a loopback URL yields NO colours — the guard blocked it', async () => {
  const { server, port } = await listen()
  try {
    const palette = await extractBrandPaletteFromUrl(`http://127.0.0.1:${port}/`, true).catch(() => [] as string[])
    assert.ok(!palette.includes('#ff00ff'), "the private page's background leaked through the guard")
    assert.ok(!palette.includes('#00ff00'), "the private page's text colour leaked through the guard")
  } finally {
    server.close()
  }
})

test('local (remote: false): the same URL IS reachable', async () => {
  // The known-positive half. Without it the assertion above would pass against
  // a guard that does nothing, because a broken fetch also returns no colours.
  const { server, port } = await listen()
  try {
    const palette = await extractBrandPaletteFromUrl(`http://127.0.0.1:${port}/`, false)
    assert.ok(palette.includes('#ff00ff'), `expected the page's colours locally, got ${JSON.stringify(palette)}`)
  } finally {
    server.close()
  }
})
