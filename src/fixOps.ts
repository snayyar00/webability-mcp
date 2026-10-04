/**
 * Structured fix ops + fixability tiers (DEV-1089 items 1 and 2).
 *
 * An agent in a coding loop should not have to parse prose to know what to
 * do with a finding. Every issue therefore carries:
 *
 *   fix.op        one of a CLOSED set of seven operations. The first six are
 *                 mechanically executable; `suggest` means "read the message,
 *                 judgment required".
 *   fixability    mechanical  — deterministic value, apply blind
 *                 contextual  — the op is known but the VALUE needs the DOM
 *                               context / an LLM (alt text, a label…)
 *                 visual      — needs rendered output (contrast, focus ring,
 *                               target size); never auto-apply
 *
 * The op is derived from the detector's existing fix payload (attribute /
 * currentValue / suggestedValue / needsManualReview) — the same shape the
 * widget applicator consumes — so no detector had to change. The rule-level
 * tables below are the census: every WebAbility rule id is classified on
 * purpose, and the unit test walks WCAG_BY_ISSUE to prove none fell through.
 */
import type { ScanIssue } from '@webability/core'

export const FIX_OPS = new Set(['add-attribute', 'set-attribute', 'remove-attribute', 'add-element', 'remove-element', 'add-text-content', 'suggest'] as const)
export type FixOp = typeof FIX_OPS extends Set<infer T> ? T : never

export const FIXABILITY_TIERS = new Set(['mechanical', 'contextual', 'visual'] as const)
export type Fixability = typeof FIXABILITY_TIERS extends Set<infer T> ? T : never

export interface StructuredFix {
  op: FixOp
  /** Attribute the op targets (absent for add-element / add-text-content / suggest). */
  attribute?: string
  /** Value to write. Present only when the engine already knows it. */
  value?: string
  fixability: Fixability
}

export interface RuleFixMeta {
  op: FixOp
  attribute?: string
  fixability: Fixability
}

/**
 * WebAbility rules whose verdict depends on rendered output. Even when the
 * detector proposes a value (a darker colour, a bigger hit area) the change
 * must be eyeballed — it touches design, not semantics.
 */
const VISUAL_RULES = new Set([
  'contrast_insufficient',
  'non_text_contrast_insufficient',
  'focus_not_visible',
  'focus_obscured_by_sticky',
  'target_too_small',
  'image_of_text',
  'reflow_overflow',
  'color_only_link',
  'text_spacing_blocked',
  'flashing_content',
  'motion_uncontrollable',
  'motion_without_reduced_motion',
  'animated_gif_no_pause',
])

/** Detector attributes that are review markers, not real DOM attributes. */
const isReviewMarker = (attribute: string) => attribute.startsWith('data-')

/** Detector attributes that mean "insert a node", not "set an attribute". */
const ELEMENT_ATTRS = new Set(['thead', 'caption', 'prepend'])

/**
 * Per-rule op/tier for the WebAbility engine, used by `get_rules` and as the
 * fallback when an issue arrives without a fix payload. Rules not listed here
 * resolve through `defaultMetaFor`, which keys off the rule name so a NEW
 * detector still lands in a sensible bucket — and the census test catches it.
 */
const WEBABILITY_RULE_META: Record<string, RuleFixMeta> = {
  // Mechanical — the value is fixed by the rule itself.
  missing_button_type: { op: 'add-attribute', attribute: 'type', fixability: 'mechanical' },
  redundant_role: { op: 'remove-attribute', attribute: 'role', fixability: 'mechanical' },
  aria_hidden_focusable: { op: 'set-attribute', attribute: 'tabindex', fixability: 'mechanical' },
  scrollable_not_focusable: { op: 'add-attribute', attribute: 'tabindex', fixability: 'mechanical' },
  missing_media_controls: { op: 'add-attribute', attribute: 'controls', fixability: 'mechanical' },
  unsafe_autoplay: { op: 'remove-attribute', attribute: 'autoplay', fixability: 'mechanical' },
  zoom_restriction: { op: 'set-attribute', attribute: 'content', fixability: 'mechanical' },
  missing_autocomplete: { op: 'add-attribute', attribute: 'autocomplete', fixability: 'mechanical' },
  identify_input_purpose: { op: 'add-attribute', attribute: 'autocomplete', fixability: 'mechanical' },
  decorative_icon: { op: 'add-attribute', attribute: 'aria-hidden', fixability: 'mechanical' },
  duplicate_id: { op: 'set-attribute', attribute: 'id', fixability: 'mechanical' },
  missing_table_scope: { op: 'add-attribute', attribute: 'scope', fixability: 'mechanical' },
  invalid_aria_role: { op: 'remove-attribute', attribute: 'role', fixability: 'mechanical' },
  broken_aria_reference: { op: 'remove-attribute', attribute: 'aria-describedby', fixability: 'mechanical' },
  aria_live: { op: 'add-attribute', attribute: 'aria-live', fixability: 'mechanical' },
  onfocus_context_change: { op: 'remove-attribute', attribute: 'onfocus', fixability: 'mechanical' },
  on_input_change: { op: 'remove-attribute', attribute: 'onchange', fixability: 'mechanical' },
  javascript_link: { op: 'suggest', fixability: 'contextual' },
  missing_button_role: { op: 'suggest', fixability: 'contextual' }, // tagName change: div → button
  // Contextual — op known, value needs judgment.
  missing_alt: { op: 'add-attribute', attribute: 'alt', fixability: 'contextual' },
  background_image_unlabeled: { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  svg_missing_name: { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  weak_svg_name: { op: 'set-attribute', attribute: 'aria-label', fixability: 'contextual' },
  weak_button_name: { op: 'set-attribute', attribute: 'aria-label', fixability: 'contextual' },
  weak_link_name: { op: 'set-attribute', attribute: 'aria-label', fixability: 'contextual' },
  weak_heading: { op: 'add-text-content', fixability: 'contextual' },
  weak_iframe_title: { op: 'set-attribute', attribute: 'title', fixability: 'contextual' },
  weak_page_title: { op: 'add-text-content', fixability: 'contextual' },
  weak_skip_link: { op: 'add-text-content', fixability: 'contextual' },
  unlabeled_button: { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  empty_link: { op: 'add-text-content', fixability: 'contextual' },
  placeholder_link: { op: 'suggest', fixability: 'contextual' },
  missing_label: { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  combobox_name_missing: { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  label_in_name: { op: 'set-attribute', attribute: 'aria-label', fixability: 'contextual' },
  missing_semantic_role: { op: 'add-attribute', attribute: 'role', fixability: 'contextual' },
  missing_landmark: { op: 'add-attribute', attribute: 'role', fixability: 'contextual' },
  nested_landmark: { op: 'remove-attribute', attribute: 'role', fixability: 'contextual' },
  landmark_duplicate_unlabeled: { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  heading_skip: { op: 'set-attribute', attribute: 'aria-level', fixability: 'contextual' },
  empty_heading: { op: 'add-text-content', fixability: 'contextual' },
  missing_h1: { op: 'add-element', fixability: 'contextual' },
  multiple_h1: { op: 'suggest', fixability: 'contextual' },
  skip_link: { op: 'add-element', fixability: 'contextual' },
  broken_anchor: { op: 'set-attribute', attribute: 'href', fixability: 'contextual' },
  adjacent_redundant_link: { op: 'suggest', fixability: 'contextual' },
  new_window_link: { op: 'set-attribute', attribute: 'aria-label', fixability: 'contextual' },
  external_link_warning: { op: 'set-attribute', attribute: 'aria-label', fixability: 'contextual' },
  download_link_warning: { op: 'set-attribute', attribute: 'aria-label', fixability: 'contextual' },
  link_consistency: { op: 'suggest', fixability: 'contextual' },
  missing_fieldset_legend: { op: 'add-element', fixability: 'contextual' },
  missing_table_header: { op: 'add-element', fixability: 'contextual' },
  missing_table_caption: { op: 'add-element', fixability: 'contextual' },
  missing_pattern_title: { op: 'add-attribute', attribute: 'title', fixability: 'contextual' },
  missing_required_indicator: { op: 'suggest', fixability: 'contextual' },
  semantic_emphasis: { op: 'suggest', fixability: 'contextual' },
  keyboard_trap: { op: 'suggest', fixability: 'contextual' },
  focus_order_disruption: { op: 'set-attribute', attribute: 'tabindex', fixability: 'contextual' },
  main_content_hidden: { op: 'remove-attribute', attribute: 'aria-hidden', fixability: 'contextual' },
  missing_captions: { op: 'add-element', fixability: 'contextual' },
  missing_audio_description: { op: 'suggest', fixability: 'contextual' },
  missing_transcript: { op: 'add-element', fixability: 'contextual' },
  auto_refresh: { op: 'remove-element', fixability: 'contextual' },
  meaningful_sequence: { op: 'suggest', fixability: 'contextual' },
  sensory_characteristic: { op: 'suggest', fixability: 'contextual' },
  orientation_lock: { op: 'suggest', fixability: 'contextual' },
  character_key_shortcut: { op: 'suggest', fixability: 'contextual' },
  pointer_gesture: { op: 'suggest', fixability: 'contextual' },
  pointer_cancellation: { op: 'suggest', fixability: 'contextual' },
  motion_actuation: { op: 'suggest', fixability: 'contextual' },
  error_prevention_missing: { op: 'suggest', fixability: 'contextual' },
  insufficient_navigation: { op: 'suggest', fixability: 'contextual' },
  inconsistent_navigation: { op: 'suggest', fixability: 'contextual' },
  // Visual — needs eyes.
  contrast_insufficient: { op: 'set-attribute', attribute: 'style', fixability: 'visual' },
  non_text_contrast_insufficient: { op: 'set-attribute', attribute: 'style', fixability: 'visual' },
  focus_not_visible: { op: 'set-attribute', attribute: 'style', fixability: 'visual' },
  focus_obscured_by_sticky: { op: 'suggest', fixability: 'visual' },
  target_too_small: { op: 'set-attribute', attribute: 'style', fixability: 'visual' },
  image_of_text: { op: 'suggest', fixability: 'visual' },
  reflow_overflow: { op: 'suggest', fixability: 'visual' },
  color_only_link: { op: 'set-attribute', attribute: 'style', fixability: 'visual' },
  text_spacing_blocked: { op: 'suggest', fixability: 'visual' },
  flashing_content: { op: 'suggest', fixability: 'visual' },
  motion_uncontrollable: { op: 'suggest', fixability: 'visual' },
  motion_without_reduced_motion: { op: 'suggest', fixability: 'visual' },
  animated_gif_no_pause: { op: 'suggest', fixability: 'visual' },
}

function defaultMetaFor(type: string): RuleFixMeta {
  return { op: 'suggest', fixability: VISUAL_RULES.has(type) ? 'visual' : 'contextual' }
}

/** Rule-level op/tier for a WebAbility rule id. Never throws; unknown → suggest. */
export function webabilityRuleFixMeta(type: string): RuleFixMeta {
  return WEBABILITY_RULE_META[type] ?? defaultMetaFor(type)
}

/**
 * axe-core rules. axe reports the failure, not a fix payload, so the op is a
 * template: the attribute is known, the value is the agent's job. Everything
 * not listed is `suggest`/`contextual`.
 */
const AXE_RULE_META: Record<string, RuleFixMeta> = {
  'color-contrast': { op: 'set-attribute', attribute: 'style', fixability: 'visual' },
  'color-contrast-enhanced': { op: 'set-attribute', attribute: 'style', fixability: 'visual' },
  'link-in-text-block': { op: 'set-attribute', attribute: 'style', fixability: 'visual' },
  'target-size': { op: 'set-attribute', attribute: 'style', fixability: 'visual' },
  'focus-order-semantics': { op: 'suggest', fixability: 'contextual' },
  'image-alt': { op: 'add-attribute', attribute: 'alt', fixability: 'contextual' },
  'input-image-alt': { op: 'add-attribute', attribute: 'alt', fixability: 'contextual' },
  'area-alt': { op: 'add-attribute', attribute: 'alt', fixability: 'contextual' },
  'object-alt': { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  'role-img-alt': { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  'svg-img-alt': { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  'image-redundant-alt': { op: 'set-attribute', attribute: 'alt', fixability: 'contextual' },
  'button-name': { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  'input-button-name': { op: 'add-attribute', attribute: 'value', fixability: 'contextual' },
  'link-name': { op: 'add-text-content', fixability: 'contextual' },
  'empty-heading': { op: 'add-text-content', fixability: 'contextual' },
  'empty-table-header': { op: 'add-text-content', fixability: 'contextual' },
  'label': { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  'label-title-only': { op: 'add-element', fixability: 'contextual' },
  'select-name': { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  'frame-title': { op: 'add-attribute', attribute: 'title', fixability: 'contextual' },
  'frame-title-unique': { op: 'set-attribute', attribute: 'title', fixability: 'contextual' },
  'document-title': { op: 'add-element', fixability: 'contextual' },
  'html-has-lang': { op: 'add-attribute', attribute: 'lang', fixability: 'contextual' },
  'html-lang-valid': { op: 'set-attribute', attribute: 'lang', fixability: 'contextual' },
  'valid-lang': { op: 'set-attribute', attribute: 'lang', fixability: 'contextual' },
  'html-xml-lang-mismatch': { op: 'set-attribute', attribute: 'xml:lang', fixability: 'mechanical' },
  'aria-hidden-body': { op: 'remove-attribute', attribute: 'aria-hidden', fixability: 'mechanical' },
  'aria-hidden-focus': { op: 'set-attribute', attribute: 'tabindex', fixability: 'mechanical' },
  'aria-allowed-attr': { op: 'remove-attribute', fixability: 'mechanical' },
  'aria-prohibited-attr': { op: 'remove-attribute', fixability: 'mechanical' },
  'aria-deprecated-role': { op: 'set-attribute', attribute: 'role', fixability: 'mechanical' },
  'aria-roles': { op: 'remove-attribute', attribute: 'role', fixability: 'mechanical' },
  'aria-valid-attr': { op: 'remove-attribute', fixability: 'mechanical' },
  'aria-valid-attr-value': { op: 'set-attribute', fixability: 'contextual' },
  'aria-required-attr': { op: 'add-attribute', fixability: 'contextual' },
  'aria-required-children': { op: 'suggest', fixability: 'contextual' },
  'aria-required-parent': { op: 'suggest', fixability: 'contextual' },
  'aria-allowed-role': { op: 'remove-attribute', attribute: 'role', fixability: 'contextual' },
  'aria-command-name': { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  'aria-dialog-name': { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  'aria-input-field-name': { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  'aria-meter-name': { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  'aria-progressbar-name': { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  'aria-toggle-field-name': { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  'aria-tooltip-name': { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  'aria-treeitem-name': { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  'aria-text': { op: 'suggest', fixability: 'contextual' },
  'duplicate-id': { op: 'set-attribute', attribute: 'id', fixability: 'mechanical' },
  'duplicate-id-active': { op: 'set-attribute', attribute: 'id', fixability: 'mechanical' },
  'duplicate-id-aria': { op: 'set-attribute', attribute: 'id', fixability: 'mechanical' },
  'meta-viewport': { op: 'set-attribute', attribute: 'content', fixability: 'mechanical' },
  'meta-viewport-large': { op: 'set-attribute', attribute: 'content', fixability: 'mechanical' },
  'meta-refresh': { op: 'remove-element', fixability: 'mechanical' },
  'meta-refresh-no-exceptions': { op: 'remove-element', fixability: 'mechanical' },
  'tabindex': { op: 'set-attribute', attribute: 'tabindex', fixability: 'mechanical' },
  'scrollable-region-focusable': { op: 'add-attribute', attribute: 'tabindex', fixability: 'mechanical' },
  'nested-interactive': { op: 'suggest', fixability: 'contextual' },
  'autocomplete-valid': { op: 'set-attribute', attribute: 'autocomplete', fixability: 'contextual' },
  'accesskeys': { op: 'set-attribute', attribute: 'accesskey', fixability: 'mechanical' },
  'blink': { op: 'remove-element', fixability: 'mechanical' },
  'marquee': { op: 'remove-element', fixability: 'mechanical' },
  'server-side-image-map': { op: 'suggest', fixability: 'contextual' },
  'video-caption': { op: 'add-element', fixability: 'contextual' },
  'audio-caption': { op: 'add-element', fixability: 'contextual' },
  'no-autoplay-audio': { op: 'remove-attribute', attribute: 'autoplay', fixability: 'mechanical' },
  'bypass': { op: 'add-element', fixability: 'contextual' },
  'skip-link': { op: 'set-attribute', attribute: 'href', fixability: 'contextual' },
  'region': { op: 'suggest', fixability: 'contextual' },
  'landmark-one-main': { op: 'add-element', fixability: 'contextual' },
  'landmark-no-duplicate-main': { op: 'suggest', fixability: 'contextual' },
  'landmark-no-duplicate-banner': { op: 'suggest', fixability: 'contextual' },
  'landmark-no-duplicate-contentinfo': { op: 'suggest', fixability: 'contextual' },
  'landmark-unique': { op: 'add-attribute', attribute: 'aria-label', fixability: 'contextual' },
  'landmark-banner-is-top-level': { op: 'suggest', fixability: 'contextual' },
  'landmark-contentinfo-is-top-level': { op: 'suggest', fixability: 'contextual' },
  'landmark-main-is-top-level': { op: 'suggest', fixability: 'contextual' },
  'landmark-complementary-is-top-level': { op: 'suggest', fixability: 'contextual' },
  'page-has-heading-one': { op: 'add-element', fixability: 'contextual' },
  'heading-order': { op: 'suggest', fixability: 'contextual' },
  'list': { op: 'suggest', fixability: 'contextual' },
  'listitem': { op: 'suggest', fixability: 'contextual' },
  'definition-list': { op: 'suggest', fixability: 'contextual' },
  'dlitem': { op: 'suggest', fixability: 'contextual' },
  'table-duplicate-name': { op: 'set-attribute', attribute: 'summary', fixability: 'contextual' },
  'table-fake-caption': { op: 'add-element', fixability: 'contextual' },
  'td-has-header': { op: 'suggest', fixability: 'contextual' },
  'td-headers-attr': { op: 'set-attribute', attribute: 'headers', fixability: 'contextual' },
  'th-has-data-cells': { op: 'suggest', fixability: 'contextual' },
  'scope-attr-valid': { op: 'set-attribute', attribute: 'scope', fixability: 'mechanical' },
  'form-field-multiple-labels': { op: 'suggest', fixability: 'contextual' },
  'presentation-role-conflict': { op: 'remove-attribute', attribute: 'role', fixability: 'mechanical' },
  'p-as-heading': { op: 'suggest', fixability: 'contextual' },
  'identical-links-same-purpose': { op: 'suggest', fixability: 'contextual' },
  'summary-name': { op: 'add-text-content', fixability: 'contextual' },
}

/** Op/tier template for an axe-core rule id. Never throws; unknown → suggest/contextual. */
export function axeRuleFixMeta(ruleId: string): RuleFixMeta {
  return AXE_RULE_META[ruleId] ?? { op: 'suggest', fixability: 'contextual' }
}

type IssueLike = Pick<ScanIssue, 'type'> & Partial<Pick<ScanIssue, 'fix' | 'confidence' | 'id'>>

/**
 * Derive the structured fix for ONE issue from its detector payload.
 *
 * The op comes from the payload when there is one (it knows whether the
 * attribute exists, whether removal was meant, whether it is a text/element
 * insertion); the rule table is the fallback. The tier is the stricter of the
 * rule tier and what the payload admits: a visual rule stays visual even with
 * a proposed value, and a value the engine could not compute (needsManualReview,
 * or a needs_review confidence) can never be mechanical.
 */
export function structuredFix(issue: IssueLike): StructuredFix {
  const type = String(issue.type ?? '')
  const isAxe = typeof issue.id === 'string' && issue.id.startsWith('axe-')
  const rule = isAxe ? axeRuleFixMeta(type) : webabilityRuleFixMeta(type)
  const f = issue.fix

  if (!f || !f.attribute) {
    return { op: rule.op, ...(rule.attribute ? { attribute: rule.attribute } : {}), fixability: rule.fixability }
  }

  const attribute = f.attribute
  const value = typeof f.suggestedValue === 'string' && f.suggestedValue.length > 0 ? f.suggestedValue : undefined
  const valueUnknown = f.needsManualReview || value === undefined || issue.confidence === 'needs_review'

  let op: FixOp
  let attr: string | undefined = attribute
  let out: string | undefined = value
  if (attribute === 'remove_attribute') {
    op = 'remove-attribute'
    attr = value ?? f.currentValue ?? rule.attribute
    out = undefined
  } else if (attribute === 'textContent') {
    op = 'add-text-content'
    attr = undefined
  } else if (ELEMENT_ATTRS.has(attribute)) {
    op = 'add-element'
    attr = undefined
  } else if (attribute === 'tagName' || isReviewMarker(attribute)) {
    op = 'suggest'
    attr = undefined
    out = undefined
  } else {
    op = f.currentValue === '' || f.currentValue == null ? 'add-attribute' : 'set-attribute'
  }

  let fixability: Fixability
  if (rule.fixability === 'visual' || VISUAL_RULES.has(type)) fixability = 'visual'
  else if (op === 'suggest') fixability = 'contextual'
  else if (op === 'remove-attribute') fixability = attr ? 'mechanical' : 'contextual'
  else fixability = valueUnknown ? 'contextual' : 'mechanical'

  return {
    op,
    ...(attr ? { attribute: attr } : {}),
    ...(out !== undefined ? { value: out } : {}),
    fixability,
  }
}

/**
 * Add `fix.op` / `fix.attribute` / `fix.value` and a top-level `fixability`
 * to a projected issue. Legacy `fix.{attribute,currentValue,suggestedValue,
 * needsManualReview}` stay as they were — consumers keyed on them keep working.
 */
export function enrichIssue<T extends IssueLike>(issue: T): T & { fixability: Fixability; fix: NonNullable<T['fix']> & StructuredFix } {
  const s = structuredFix(issue)
  const { fixability, ...opFields } = s
  return {
    ...issue,
    fixability,
    fix: { ...(issue.fix ?? {}), ...opFields } as NonNullable<T['fix']> & StructuredFix,
  }
}
