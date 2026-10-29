/**
 * The hosted egress proxy (#198): every connection a hosted browser makes —
 * first request, redirect hop, sub-resource, websocket — goes through it, and
 * it refuses any destination that resolves to a private address. Driven with
 * raw sockets: no browser needed.
 */
import assert from 'node:assert/strict'
import { createServer, request, Server } from 'node:http'
import { AddressInfo, connect } from 'node:net'
import { test } from 'node:test'

import { isBlockedAddress, startEgressProxy } from '../src/egressProxy'

function listen(): Promise<{ server: Server; port: number }> {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end(`origin saw ${req.method} ${req.url} host=${req.headers.host}`)
    })
    server.listen(0, '127.0.0.1', () => resolve({ server, port: (server.address() as AddressInfo).port }))
  })
}

/** Plain-HTTP proxying: absolute-form request line, like Chromium sends. */
function viaProxy(proxyPort: number, target: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: proxyPort, method: 'GET', path: target, headers: { host: new URL(target).host } }, (res) => {
      let body = ''
      res.on('data', (c) => (body += c))
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body }))
    })
    req.on('error', reject)
    req.end()
  })
}

/** CONNECT (https / wss): the status line the proxy answers with. */
function connectVia(proxyPort: number, authority: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = connect(proxyPort, '127.0.0.1', () => s.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`))
    s.once('data', (d) => {
      resolve(d.toString().split('\r\n')[0])
      s.destroy()
    })
    s.on('error', reject)
  })
}

test('isBlockedAddress: loopback, private, link-local/metadata, CGNAT, v6 local are blocked; public is not', () => {
  for (const a of ['127.0.0.1', '10.0.0.5', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', '::', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:169.254.169.254']) {
    assert.equal(isBlockedAddress(a), true, a)
  }
  for (const a of ['93.184.215.14', '8.8.8.8', '172.32.0.1', '2606:4700::1111']) assert.equal(isBlockedAddress(a), false, a)
})

test('default check: a plain-HTTP request to loopback is refused (403) and never reaches the origin', async () => {
  const o = await listen()
  let hits = 0
  o.server.on('request', () => hits++)
  const proxy = await startEgressProxy()
  try {
    const r = await viaProxy(proxy.port, `http://127.0.0.1:${o.port}/latest/meta-data`)
    assert.equal(r.status, 403)
    assert.equal(hits, 0)
  } finally {
    await proxy.close()
    o.server.close()
  }
})

test('default check: a hostname that resolves to loopback is refused too (checked after DNS)', async () => {
  const o = await listen()
  const proxy = await startEgressProxy()
  try {
    assert.equal((await viaProxy(proxy.port, `http://localhost:${o.port}/`)).status, 403)
    assert.match(await connectVia(proxy.port, `localhost:${o.port}`), / 403 /)
  } finally {
    await proxy.close()
    o.server.close()
  }
})

test('default check: CONNECT to the metadata address is refused', async () => {
  const proxy = await startEgressProxy()
  try {
    assert.match(await connectVia(proxy.port, '169.254.169.254:443'), / 403 /)
  } finally {
    await proxy.close()
  }
})

test('allowed destination: plain HTTP is forwarded with path and Host intact', async () => {
  const o = await listen()
  const proxy = await startEgressProxy({ isBlocked: () => false })
  try {
    const r = await viaProxy(proxy.port, `http://127.0.0.1:${o.port}/a/b?c=1`)
    assert.equal(r.status, 200)
    assert.equal(r.body, `origin saw GET /a/b?c=1 host=127.0.0.1:${o.port}`)
  } finally {
    await proxy.close()
    o.server.close()
  }
})

test('allowed destination: CONNECT is established and bytes flow both ways', async () => {
  const o = await listen()
  const proxy = await startEgressProxy({ isBlocked: () => false })
  try {
    const reply = await new Promise<string>((resolve, reject) => {
      const s = connect(proxy.port, '127.0.0.1', () => s.write(`CONNECT 127.0.0.1:${o.port} HTTP/1.1\r\nHost: 127.0.0.1:${o.port}\r\n\r\n`))
      let buf = ''
      let tunnelled = false
      s.on('data', (d) => {
        buf += d.toString()
        if (!tunnelled && buf.includes('\r\n\r\n')) {
          assert.match(buf, /^HTTP\/1\.1 200 /)
          tunnelled = true
          buf = ''
          s.write(`GET /through HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`)
        }
      })
      s.on('end', () => resolve(buf))
      s.on('error', reject)
    })
    assert.match(reply, /origin saw GET \/through host=x/)
  } finally {
    await proxy.close()
    o.server.close()
  }
})

test('the check sees the resolved address and the port', async () => {
  const seen: Array<[string, number]> = []
  const proxy = await startEgressProxy({ isBlocked: (addr, port) => (seen.push([addr, port]), true) })
  try {
    await viaProxy(proxy.port, 'http://localhost:8123/')
    assert.ok(seen.some(([a, p]) => (a === '127.0.0.1' || a === '::1') && p === 8123), JSON.stringify(seen))
  } finally {
    await proxy.close()
  }
})

/** An origin that sends headers and part of a body, then waits forever. Resolves `closed` when its socket closes. */
async function stallingOrigin() {
  let markClosed!: () => void
  const closed = new Promise<void>((r) => (markClosed = r))
  const server = createServer((req, res) => {
    req.socket.once('close', markClosed)
    res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '1000000' })
    res.write('partial-body-')
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()))
  return { server, port: (server.address() as AddressInfo).port, closed }
}

const within = <T>(p: Promise<T>, ms: number) =>
  Promise.race([p.then(() => true), new Promise<boolean>((r) => setTimeout(() => r(false), ms))])

test('plain HTTP: when the browser side disconnects mid-response, the origin socket is closed too', async () => {
  const o = await stallingOrigin()
  const proxy = await startEgressProxy({ isBlocked: () => false })
  try {
    await new Promise<void>((resolve, reject) => {
      const req = request({ host: '127.0.0.1', port: proxy.port, method: 'GET', path: `http://127.0.0.1:${o.port}/slow`, headers: { host: `127.0.0.1:${o.port}` } }, (res) => {
        res.once('data', () => {
          req.destroy() // the browser / scan deadline goes away
          resolve()
        })
      })
      req.on('error', () => {})
      req.on('close', () => resolve())
      setTimeout(() => reject(new Error('no partial body reached the client')), 3000)
      req.end()
    })
    assert.equal(await within(o.closed, 2000), true, 'the proxy kept its outbound socket to the stalled origin open')
  } finally {
    await proxy.close()
    o.server.close()
    o.server.closeAllConnections()
  }
})

test('CONNECT: when the client disconnects, the origin socket is closed too', async () => {
  const o = await stallingOrigin()
  const proxy = await startEgressProxy({ isBlocked: () => false })
  try {
    await new Promise<void>((resolve, reject) => {
      const s = connect(proxy.port, '127.0.0.1', () => s.write(`CONNECT 127.0.0.1:${o.port} HTTP/1.1\r\nHost: x\r\n\r\n`))
      let buf = ''
      let sent = false
      s.on('data', (d) => {
        buf += d.toString()
        if (!sent && buf.includes('\r\n\r\n')) {
          sent = true
          s.write('GET /slow HTTP/1.1\r\nHost: x\r\n\r\n')
        } else if (sent && buf.includes('partial-body-')) {
          s.destroy()
          resolve()
        }
      })
      s.on('error', () => {})
      setTimeout(() => reject(new Error('no partial body through the tunnel')), 3000)
    })
    assert.equal(await within(o.closed, 2000), true, 'the tunnel kept its origin socket open')
  } finally {
    await proxy.close()
    o.server.close()
    o.server.closeAllConnections()
  }
})

test('CONNECT: when the origin closes, the client side of the tunnel is closed too', async () => {
  const o = await listen()
  const proxy = await startEgressProxy({ isBlocked: () => false })
  try {
    const clientClosed = await new Promise<boolean>((resolve) => {
      const s = connect(proxy.port, '127.0.0.1', () => s.write(`CONNECT 127.0.0.1:${o.port} HTTP/1.1\r\nHost: x\r\n\r\n`))
      let sent = false
      s.on('data', () => {
        if (sent) return
        sent = true
        // The origin answers and closes (Connection: close); the tunnel must follow.
        s.write('GET /bye HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')
      })
      s.on('close', () => resolve(true))
      s.on('error', () => {})
      setTimeout(() => resolve(false), 3000)
    })
    assert.equal(clientClosed, true)
  } finally {
    await proxy.close()
    o.server.close()
  }
})
