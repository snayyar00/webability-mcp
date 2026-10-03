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
