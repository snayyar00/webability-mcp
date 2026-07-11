# @webability/mcp

Accessibility testing MCP server for Cursor, VS Code Copilot, Claude Code, and any other MCP-compatible IDE.

## What is WebAbility?

[WebAbility.io](https://webability.io) is an AI-powered web accessibility platform — widget, scanner, and agents for **WCAG 2.2 / ADA / Section 508 / EAA** compliance. This MCP exposes the same scanning engine that powers the WebAbility widget and dashboard, so you can audit and fix accessibility issues from your IDE while you build.

The server registers an `instructions` block on initialize, so any MCP-compatible client picks up business context (what tool to call when, the three-tier output convention, etc.) automatically — no setup required beyond the install below.

## Why this over other accessibility MCPs

Most accessibility MCP servers stop at *find* and *suggest*. WebAbility closes the whole loop in your editor, and starts free:

- **Free, local scan — no account, no Docker.** `scan_page` runs entirely on your machine. (Deque's axe MCP needs a paid subscription, an API key, and a Docker install just to analyze a page.)
- **Fixes that fit your stack.** `generate_ai_fix` returns ready-to-paste code for the framework you actually use — Tailwind, MUI, Bootstrap, WordPress, Next.js — not generic guidance.
- **A vision pass DOM scanners can't do.** `visual_audit` catches focus visibility, icon contrast, and "looks like a button but isn't" — issues axe-core structurally cannot see.
- **Verification, not just detection.** `verify_fix` re-checks that your fix actually landed and returns `verified: true/false`. Every 2026 comparison of accessibility MCPs names this the biggest gap in the category — most tools never close it.
- **Evidence for compliance.** `start_audit` produces a persistent, timestamped report and Excel workbook you can hand to an auditor — not a result that vanishes with your session.

The full cycle, without leaving the editor: `scan_page` → `generate_ai_fix` → `verify_fix`, then `start_audit` when you need the paper trail.

## Install

```bash
npm install -g @webability/mcp
```

## Setup

Add to your IDE's MCP config:

```json
{
  "mcpServers": {
    "webability": {
      "command": "webability-mcp"
    }
  }
}
```

Optional env: `WEBABILITY_API_URL` (default `https://api.webability.io`) for self-hosted backends.

## Scan engines

`scan_page` runs three engines in parallel and deduplicates the results:

| Engine | Rules | What it covers |
|--------|-------|----------------|
| WebAbility detectors | 60+ | Gradient-aware contrast, weak names, decorative icons, landmark hierarchy, ARIA correctness, link consistency, target size, keyboard traps |
| axe-core | 104 | Industry-standard WCAG 2.2 baseline |
| HTML_CodeSniffer | 200+ | Section 508 + WCAG techniques cross-reference |

## Three-tier output (since v1.2.1)

Every scan returns:

- **`issues`** — high-confidence violations, safe to surface as bugs
- **`incomplete`** — findings that need human review (contrast against gradients, marketing imagery, framer-motion pre-animation states, axe-incomplete). **Never auto-fix these.**
- **`summary`** — counts by severity + an `incomplete` count

This mirrors axe-core's `violations` / `incomplete` / `passes` split and prevents agents from "fixing" false positives in destructive ways.

## Tools

| Tool | What it does |
|------|--------------|
| `scan_page` | Scan a URL for WCAG accessibility issues (3 engines) |
| `flow_scan` | Multi-page journey scan with deduplicated issues across pages |
| `scan_html` | Scan a raw HTML snippet (no URL needed) |
| `detect_framework` | Detect Tailwind / MUI / Bootstrap / Next.js / WP / plain CSS |
| `generate_ai_fix` | Framework-aware fix alternatives. Auto-extracts brand palette from the live URL on contrast issues. |
| `verify_fix` | Re-scan a fixed element and confirm the violation is gone — `verified: true/false`. Closes the find → fix → verify loop. |
| `visual_audit` | Pixel-level audit via vision (icon contrast, focus visibility, looks-like-a-button-but-isn't) |
| `start_audit` | Kick off the full server-side audit deliverable (report + Excel workbook). Returns an id to poll. Requires an account. |
| `get_audit` | Check an audit's progress and, once complete, get the severity summary + report/workbook download URLs. |
| `check_color_contrast` | WCAG contrast check on a color pair; pass `url` to get brand-aligned suggestions from the live page |
| `check_aria` | Validate ARIA attributes in an HTML snippet |
| `get_rules` | List axe-core rules with optional WCAG tag filter |
| `find_source` | Map a CSS selector back to local source files |

## When to use this MCP

- Building a new component and want it accessible from day one
- Auditing a localhost / staging build before pushing
- Triaging a Lighthouse / axe report — `scan_page` consolidates all three engines
- Generating fix suggestions that match the framework you're already using
- Checking color contrast against the user's actual brand palette (not generic suggestions)

## Examples

In Cursor / Claude Code:

> "Scan localhost:3000 for accessibility issues"

> "Walk login → dashboard → checkout and report unique issues across the flow"

> "Suggest a fix for the contrast issue on `.btn-primary` on https://example.com — match their brand colors"

> "What does WCAG 1.4.11 check?"

## Privacy, scan logs & telemetry

Every scan is logged **locally** to `~/.webability/scans/` — a one-line-per-scan `index.jsonl` ledger plus the full result of your last 500 scans. Browse them with the `scan_history` tool ("what did we scan earlier?") or plain `jq`. Set `WEBABILITY_SCAN_LOG=off` to disable, `WEBABILITY_SCAN_LOG_DIR` to relocate.

The server also reports one small **telemetry event** per tool call (every tool, not just scans) to the WebAbility API: tool name, a short target label (URL, selector, issue type — never page content), pass/fail, duration, issue counts, and a persistent anonymous install ID. Full scan results, HTML, and generated fix code never leave your machine via telemetry. Set `WEBABILITY_SCAN_TELEMETRY=off` to opt out.

Two tools — `generate_ai_fix` and `visual_audit` — additionally send page content (an HTML snippet or a screenshot) to WebAbility's API so it can call a third-party LLM on your behalf; WebAbility doesn't store that content, but the LLM provider sees it in transit. See [PRIVACY.md](./PRIVACY.md) for the full per-tool breakdown and WebAbility's [privacy policy](https://www.webability.io/privacy-policy).

## Links

- [WebAbility](https://webability.io) — platform, widget, dashboard
- [Documentation](https://webability.io/docs)
- [GitHub](https://github.com/snayyar00/webability-mcp)

## License

MIT
