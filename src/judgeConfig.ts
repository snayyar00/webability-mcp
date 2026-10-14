/**
 * AI-judge configuration for every scan the MCP server runs.
 *
 * Local (stdio) installs talk to an OpenAI-compatible chat endpoint
 * (OpenRouter by default) with the operator's own key. The hosted server
 * never holds a model key in the scan path: it posts the undecided set to the
 * platform's `/api/judge-incomplete`, which fails closed (items stay dropped)
 * until that endpoint exists.
 *
 *   OPENROUTER_API_KEY            enables the local judge
 *   WEBABILITY_JUDGE=off          disables it everywhere
 *   WEBABILITY_JUDGE_BASE_URL     default https://openrouter.ai/api/v1
 *   WEBABILITY_JUDGE_VISION_MODEL default anthropic/claude-haiku-4.5
 *   WEBABILITY_JUDGE_TEXT_MODEL   default deepseek/deepseek-v4-flash
 *   WEBABILITY_JUDGE_TIMEOUT_MS   total budget per scan, default 20000
 */
import type { JudgeOptions } from '@webability/core'

export interface JudgeEnvContext {
  remote?: boolean
  anonymous?: boolean
  authToken?: string
  apiUrl: string
}

export function judgeOptionsFromEnv(ctx: JudgeEnvContext, env: NodeJS.ProcessEnv = process.env): JudgeOptions | undefined {
  if ((env.WEBABILITY_JUDGE || '').toLowerCase() === 'off') return undefined
  const timeoutRaw = Number(env.WEBABILITY_JUDGE_TIMEOUT_MS)
  const timeoutMs = Number.isFinite(timeoutRaw) && timeoutRaw > 0 ? Math.min(timeoutRaw, 120_000) : undefined
  if (ctx.remote) {
    return { apiUrl: ctx.apiUrl, ...(ctx.anonymous ? {} : ctx.authToken ? { apiToken: ctx.authToken } : {}), ...(timeoutMs ? { timeoutMs } : {}) }
  }
  const apiKey = env.OPENROUTER_API_KEY || ''
  if (!apiKey) return undefined
  return {
    apiKey,
    ...(env.WEBABILITY_JUDGE_BASE_URL ? { baseUrl: env.WEBABILITY_JUDGE_BASE_URL } : {}),
    ...(env.WEBABILITY_JUDGE_VISION_MODEL ? { visionModel: env.WEBABILITY_JUDGE_VISION_MODEL } : {}),
    ...(env.WEBABILITY_JUDGE_TEXT_MODEL ? { textModel: env.WEBABILITY_JUDGE_TEXT_MODEL } : {}),
    ...(timeoutMs ? { timeoutMs } : {}),
  }
}
