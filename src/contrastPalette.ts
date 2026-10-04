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

/** True when check_color_contrast would load `url` in Chromium to extract a palette. */
export function contrastLaunchesBrowser(args: unknown): boolean {
  const a = (args ?? {}) as { url?: unknown; brandColors?: unknown }
  return contrastPalette(a.brandColors).length === 0 && !!a.url
}
