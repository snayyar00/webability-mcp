import type { JudgeOptions } from '@webability/core'

/** A phase of tool work that did not finish inside its budget. */
export class DeadlineError extends Error {
  constructor(
    readonly phase: string,
    readonly ms: number,
  ) {
    super(`${phase} did not finish within ${(ms / 1000).toFixed(ms < 1000 ? 2 : 0)}s`)
    this.name = 'DeadlineError'
  }
}

/**
 * Run `work` with a hard time budget. On timeout the signal handed to `work`
 * is aborted, so it can stop a browser or a fetch instead of running on after
 * the caller has already given up.
 */
export async function withDeadline<T>(work: (signal: AbortSignal) => Promise<T>, ms: number, phase: string): Promise<T> {
  const controller = new AbortController()
  let timer: ReturnType<typeof setTimeout> | undefined
  const expired = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort()
      reject(new DeadlineError(phase, ms))
    }, ms)
  })
  try {
    return await Promise.race([work(controller.signal), expired])
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Cap the AI judge so it ends by `endsAt`. scan() spreads opts.judge when the
 * judge starts (after the engines), so timeoutMs is a getter: the judge gets
 * the time left at that moment. Without this the scan deadline fires mid-judge
 * and discards engine findings already made. There is no fixed judge budget on
 * top: a fast page leaves the judge more time, a slow page less. Only an
 * operator budget (WEBABILITY_JUDGE_TIMEOUT_MS) caps it further.
 *
 * Lives here, not in server.ts, because scan_html's judge runs on the worker
 * thread: a getter does not survive structured clone (it is evaluated at
 * postMessage time), so the worker must apply this itself with the deadline the
 * parent hands it.
 */
export function judgeWithin(judge: JudgeOptions | undefined, endsAt: number): JudgeOptions | undefined {
  if (!judge) return undefined
  const budget = judge.timeoutMs ?? Infinity
  const capped = { ...judge }
  Object.defineProperty(capped, 'timeoutMs', { enumerable: true, get: () => Math.max(1, Math.min(budget, endsAt - Date.now())) })
  return capped
}
