#!/usr/bin/env node
import { resolveAuthToken } from './authToken.js'
import { checkInstallApi, installUrl } from './installApi.js'
import { assertSafeUrl } from './publicUrl.js'

try {
  const [command, raw, ...extra] = process.argv.slice(2)
  if (command !== 'check-install' || !raw || extra.length) {
    throw new Error('Usage: webability check-install <url>')
  }
  const url = installUrl(raw)
  await assertSafeUrl(url)
  const result = await checkInstallApi(url, resolveAuthToken())
  console.log(JSON.stringify(result, null, 2))
  process.exitCode = result.state === 'installed' ? 0 : 1
} catch (error) {
  console.error('check-install failed:', (error as Error).message)
  process.exitCode = 2
}
