import { getContrastRatio } from '@webability/core'

/**
 * The brand palette check_color_contrast works from: the `brandColors`
 * entries that parse as colors. getContrastRatio returns 0 for anything it
 * cannot parse, and any real color against white is >= 1.
 *
 * Shared by the handler and the hosted anonymous gate, so "this call is
 * heavy" and "this call launches Chromium" cannot drift apart.
 */
export function contrastPalette(brandColors: unknown): string[] {
  if (!Array.isArray(brandColors)) return []
  return brandColors.filter((c): c is string => typeof c === 'string' && getContrastRatio(c, '#ffffff') > 0)
}

/**
 * True when check_color_contrast may load `url` in Chromium: to read an
 * element's colors (`url` + `selector`) or to extract a palette (no usable
 * `brandColors`). Any truthy url counts, as the handler decides on truthiness.
 */
export function contrastLaunchesBrowser(args: unknown): boolean {
  const a = (args ?? {}) as { url?: unknown; brandColors?: unknown; selector?: unknown }
  if (!a.url) return false
  return !!a.selector || contrastPalette(a.brandColors).length === 0
}
