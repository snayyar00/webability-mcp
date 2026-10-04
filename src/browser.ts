/**
 * The one place the MCP launches Chromium. Every scan tool opens its browser
 * here, so launch recovery (missing browser, HTTP/2 failures) lives in one
 * spot instead of eight.
 */
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'

export interface LaunchOptions {
  /** Hosted/remote mode: never touches the filesystem to install anything. */
  remote?: boolean
  args?: string[]
}

/** package.json of the Playwright this module resolves (`playwright/cli.js` is not in its exports map; package.json is). */
function playwrightPackageJson(): string {
  return createRequire(import.meta.url).resolve('playwright/package.json')
}

/** Version of the Playwright this module actually loads, or undefined if it cannot be read. */
export function installedPlaywrightVersion(): string | undefined {
  try {
    const v = JSON.parse(readFileSync(playwrightPackageJson(), 'utf8')).version
    return typeof v === 'string' && v ? v : undefined
  } catch {
    return undefined
  }
}

/**
 * Browser builds are tied to the Playwright version, so the manual command
 * pins the one we run. A bare `npx playwright` installs the latest (or a
 * project-local) Playwright's Chromium, which this package may not find.
 */
export function notInstalledMessage(version: string | undefined): string {
  const cmd = version ? `npx playwright@${version} install chromium` : 'npx playwright install chromium'
  return `Chromium is not installed. Run: ${cmd} (one-time, ~150 MB). Or use the hosted server https://mcp.webability.io/mcp — no install.`
}

export const NOT_INSTALLED_MESSAGE = notInstalledMessage(installedPlaywrightVersion())
const REMOTE_UNAVAILABLE_MESSAGE = 'The browser engine is unavailable on this server. Retry shortly.'

/** Playwright's "browser binary not downloaded" failure. */
export function isMissingBrowserError(err: unknown): boolean {
  return /Executable doesn't exist|Looks like Playwright (Test or Playwright )?was just installed/i.test((err as Error)?.message ?? '')
}

export interface LauncherDeps {
  launch: (opts: { headless: boolean; args?: string[] }) => Promise<any>
  /** Downloads Chromium. Progress must go to stderr: stdout is the MCP stream. */
  install: () => Promise<void>
  env?: NodeJS.ProcessEnv
  log?: (msg: string) => void
}

/** Run the pinned Playwright's own CLI (no npx, no --with-deps: that needs root). */
async function installChromiumViaPlaywrightCli(): Promise<void> {
  const { spawn } = await import('node:child_process')
  const cli = join(dirname(playwrightPackageJson()), 'cli.js')
  await new Promise<void>((resolve, reject) => {
    // stdout -> our stderr (fd 2): the Playwright installer prints a progress bar.
    const child = spawn(process.execPath, [cli, 'install', 'chromium'], { stdio: ['ignore', 2, 2] })
    child.on('error', reject)
    child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`playwright install exited with code ${code}`))))
  })
}

const defaultDeps: LauncherDeps = {
  launch: async (opts) => {
    const pw = await import('playwright')
    return pw.chromium.launch(opts)
  },
  install: installChromiumViaPlaywrightCli,
  env: process.env,
  log: (msg) => process.stderr.write(`${msg}\n`),
}

export function createLauncher(deps: LauncherDeps = defaultDeps) {
  const env = deps.env ?? process.env
  const log = deps.log ?? (() => {})
  // Single flight: concurrent first-run tool calls share one download.
  let installing: Promise<void> | null = null
  let installedOnce = false

  const attempt = (opts: LaunchOptions) => deps.launch({ headless: true, ...(opts.args?.length ? { args: opts.args } : {}) })

  return async function launch(opts: LaunchOptions = {}): Promise<any> {
    try {
      return await attempt(opts)
    } catch (err) {
      if (!isMissingBrowserError(err)) throw err
      // Never download anything on a hosted server; never when opted out.
      if (opts.remote) throw new Error(REMOTE_UNAVAILABLE_MESSAGE)
      if (env.WEBABILITY_NO_AUTO_INSTALL === '1') throw new Error(NOT_INSTALLED_MESSAGE)
    }
    // A launch that failed just before the install finished lands here with
    // installedOnce set: retry, do not download again.
    if (!installing && !installedOnce) {
      log('webability-mcp: Chromium is not installed yet. Downloading it once (~150 MB)...')
      installing = deps
        .install()
        .then(() => {
          installedOnce = true
          log('webability-mcp: Chromium installed.')
        })
        .finally(() => {
          installing = null
        })
    }
    try {
      await installing
    } catch (err) {
      log(`webability-mcp: Chromium install failed: ${(err as Error).message}`)
      throw new Error(NOT_INSTALLED_MESSAGE)
    }
    try {
      return await attempt(opts)
    } catch (err) {
      if (isMissingBrowserError(err)) throw new Error(NOT_INSTALLED_MESSAGE)
      throw err
    }
  }
}

export const launchChromium = createLauncher()

export interface BrowserSession {
  browser: any
  context: any
  page: any
  goto: (url: string, opts?: Record<string, unknown>) => Promise<any>
  close: () => Promise<void>
}

export interface OpenSessionOptions {
  remote?: boolean
  contextOptions?: Record<string, unknown>
  /** Runs on every new context before its first page (SSRF route, etc). */
  setupContext?: (context: any) => Promise<void> | void
}

export function isHttp2ProtocolError(err: unknown): boolean {
  return /ERR_HTTP2_PROTOCOL_ERROR/.test((err as Error)?.message ?? '')
}

/** Scan targets may arrive without a scheme (core scan() used to add one). */
export function normalizeScanUrl(url: string): string {
  return /^https?:\/\//i.test(url) ? url : `https://${url}`
}

export function createSessionOpener(launch: (o: LaunchOptions) => Promise<any>) {
  return async function openSession(opts: OpenSessionOptions = {}): Promise<BrowserSession> {
    const build = async (args?: string[]) => {
      const browser = await launch({ remote: opts.remote, ...(args ? { args } : {}) })
      try {
        const context = await browser.newContext(opts.contextOptions)
        await opts.setupContext?.(context)
        const page = await context.newPage()
        return { browser, context, page }
      } catch (err) {
        await browser.close().catch(() => {})
        throw err
      }
    }

    const session: BrowserSession = {
      ...(await build()),
      goto: async (rawUrl, gotoOpts) => {
        const url = normalizeScanUrl(rawUrl)
        try {
          return await session.page.goto(url, gotoOpts)
        } catch (err) {
          // Some servers reset Chromium's HTTP/2 stream. Retry ONCE per
          // session, in a fresh browser with HTTP/2 off (a launch-level flag,
          // so the context cannot be reused). The same context setup runs
          // again, so the SSRF / relay guard still covers the retry.
          if (!isHttp2ProtocolError(err) || http2Disabled) throw err
          http2Disabled = true
          const old = session.browser
          Object.assign(session, await build(['--disable-http2']))
          await old.close().catch(() => {})
          return await session.page.goto(url, gotoOpts)
        }
      },
      close: async () => {
        await session.browser.close().catch(() => {})
      },
    }
    let http2Disabled = false
    return session
  }
}

export const openSession = createSessionOpener(launchChromium)
