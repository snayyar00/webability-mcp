# @webability/mcp

Accessibility testing MCP server for Cursor, VS Code Copilot, Claude Code, and any other MCP-compatible IDE.

## What is WebAbility?

[WebAbility.io](https://webability.io) is an AI-powered web accessibility platform — widget, scanner, and agents for **WCAG 2.2 / ADA / Section 508 / EAA** compliance. This MCP exposes the same scanning engine that powers the WebAbility widget and dashboard, so you can audit and fix accessibility issues from your IDE while you build.

The server registers an `instructions` block on initialize, so any MCP-compatible client picks up business context (what tool to call when, the three-tier output convention, etc.) automatically — no setup required beyond the install below.

## Lite (local) vs Full (hosted)

| | **Lite** — local stdio (`npx` / `webability-mcp`) | **Full** — hosted (`https://mcp.webability.io/mcp`) |
|---|---|---|
| Account | None | Free WebAbility account + token |
| Scan / fix / verify | Yes (on your machine) | Yes |
| `find_source` | Yes | No |
| `scan_history` / `generate_report_pdf` | Yes | No |
| `visual_audit` / `start_audit` / `get_audit` | Listed as stubs → connect Full (still free) | Yes — free with your account |
| PostHog / dashboard analytics | Optional env only | On by default on hosted |
| **`localhost` / private addresses** | **Yes** — the browser runs on your machine | **Via a tunnel** — see below |

Lite is the no-account wedge: DOM scanners and the find → fix → verify loop. Full adds vision audit and compliance reports — **free with a WebAbility account** (dashboard / Smithery). Lite lists those Full tools as stubs so agents know to upgrade.

## Scanning a local dev server

**Use Lite (stdio).** It runs the browser on your machine, so `http://localhost:3000` is just localhost:

```bash
claude mcp add webability-local -- npx -y @webability/mcp
```

Other clients: add `npx -y @webability/mcp` as a stdio server. The `-y` matters — without it `npx` can fail with `could not determine executable to run`.

**Full (hosted) cannot reach your machine directly, by design.** It runs in our cloud, so `localhost` there means *our* localhost. Every URL is checked before any fetch and loopback / private / link-local addresses are refused: without that check, anyone with a token could point the server at internal services or a cloud metadata endpoint. That check is not relaxed for anyone.

### When you need hosted: `webability-tunnel`

CI, a remote agent, or a dashboard-triggered scan cannot run Lite, because there is no laptop in the loop. For those, open a tunnel:

```bash
WEBABILITY_API_KEY=<your-token> npx -y -p @webability/mcp webability-tunnel --port 3000
```

It prints a `https://tunnel.webability.io/t/<id>/` URL and a secret. Pass the URL as `url` and the secret as `tunnel_secret`:

> "Scan https://tunnel.webability.io/t/abc123.../ with tunnel_secret &lt;secret&gt;"

Your machine dials **out** to the relay, so the URL is an ordinary public hostname and the SSRF check above still applies unchanged — nothing is weakened to make this work. Same idea as ngrok, with three differences that matter when the thing on the far side is your dev machine:

- **The URL is not a credential.** Every request must carry the secret header; the URL alone returns 401. URLs leak into shell history, CI logs and screenshots.
- **Only `GET` and `HEAD` reach you**, on the one port you named, and `Authorization` / `Cookie` are stripped before anything crosses in.
- **It dies when you do.** 30 minutes, 5 minutes idle, or the moment you press Ctrl-C.

Anyone holding both the URL and the secret can read your dev server. Treat the pair like a password, and prefer Lite whenever there is a human at a keyboard.

Third-party tunnels (ngrok, cloudflared) also work — the hosted scanner treats their hostnames like any other public site — but they expose your dev server to anyone who learns the URL. Vite users, either way: add the tunnel hostname to `server.allowedHosts`, or it answers `403 Blocked request` to everything.

`start_audit` is the exception on both transports — its pipeline runs on our servers even under Lite, so it can never reach a localhost URL.

## Why this over other accessibility MCPs

Most accessibility MCP servers stop at *find* and *suggest*. WebAbility closes the whole loop in your editor, and starts free:

- **Free Lite scan — no account, no Docker.** `scan_page` runs entirely on your machine. (Deque's axe MCP needs a paid subscription, an API key, and a Docker install just to analyze a page.)
- **Fixes that fit your stack.** `generate_ai_fix` returns ready-to-paste code for the framework you actually use — Tailwind, MUI, Bootstrap, WordPress, Next.js — not generic guidance.
- **A vision pass on Full (free with account).** Hosted `visual_audit` catches focus visibility, icon contrast, and "looks like a button but isn't" — issues axe-core structurally cannot see.
- **Verification, not just detection.** `verify_fix` re-checks that your fix actually landed and returns `verified: true/false`. Every 2026 comparison of accessibility MCPs names this the biggest gap in the category — most tools never close it.
- **Evidence for compliance on Full (free with account).** `start_audit` produces a persistent, timestamped report and Excel workbook you can hand to an auditor — not a result that vanishes with your session.

The Lite cycle: `scan_page` → `generate_ai_fix` → `verify_fix` — and `generate_report_pdf` when the findings need to become a shareable deliverable. On Full (free account), add `start_audit` when you need the paper trail.

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

Optional env:

- `WEBABILITY_API_URL` (default `https://api.webability.io`) for self-hosted backends.
- `POSTHOG_PROJECT_API_KEY` or `POSTHOG_API_KEY` to enable PostHog MCP Analytics for MCP initialize, tools/list, and tool-call usage events.
- `POSTHOG_HOST` (default `https://us.i.posthog.com`) for EU or self-hosted PostHog ingestion.
- `WEBABILITY_POSTHOG_MCP_ANALYTICS=off` to force-disable PostHog MCP Analytics even when a PostHog key is present.

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

## Structured fixes (since v1.6.0)

Every issue from `scan_page`, `flow_scan`, `diff_scan` and `scan_html` carries a machine-readable fix and a fixability tier, so an agent can act without parsing prose:

```json
{
  "id": "wa-missing_button_type-a1b2c3",
  "fixability": "mechanical",
  "fix": { "op": "add-attribute", "attribute": "type", "value": "button", "currentValue": "", "needsManualReview": false }
}
```

| Field | Values |
|-------|--------|
| `fix.op` | `add-attribute` · `set-attribute` · `remove-attribute` · `add-element` · `remove-element` · `add-text-content` · `suggest` |
| `fixability` | `mechanical` — value known, apply as given · `contextual` — op known, value needs judgment (alt text, a label) · `visual` — needs rendered output (contrast, focus ring, target size); propose, never auto-apply |

`fix.value` is present only when the engine already knows it. The legacy `fix.attribute` / `currentValue` / `suggestedValue` / `needsManualReview` fields are unchanged. `get_rules` lists the tier for every rule so you can pick the auto-fixable set up front.

## Source pointers (since v1.6.0)

On a React ≤18 or Vue dev build, `scan_page`, `flow_scan` and `diff_scan` read the component tree of the live page and attach the JSX call site to each finding:

```json
{ "selector": "img#hero", "source": { "framework": "react", "file": "/app/src/Hero.tsx", "line": 12, "column": 5, "component": "Hero" } }
```

Open that file — no `find_source` round-trip. React 19 dropped `_debugSource`; there you still get `component`. Production builds have no tree; pass `sourceRoot` (Lite only) and issues without a pointer get `sourceCandidates[]` from a token grep of the selector.

## Output controls (since v1.6.0)

`scan_page`, `flow_scan`, `scan_html` and `diff_scan` accept:

| Param | Effect |
|-------|--------|
| `minImpact` | `minor` · `moderate` · `serious` · `critical` — drop anything below |
| `rules[]` | keep only these rule ids (`missing_alt`, `image-alt`, …) |
| `wcag[]` | keep only these criteria; a prefix like `1.4` matches `1.4.3` |
| `format: "compact"` | one line per element, rule metadata printed once — a fraction of the JSON tokens |

Filters apply before the 50-item cap, so `minImpact: "serious"` returns every serious issue on a 300-issue page. The `scan_history` archive keeps the unfiltered result.

## In-process `scan_html` (since v1.6.0)

`scan_html` no longer launches a browser by default. It runs the WebAbility detectors and axe-core inside jsdom in the MCP process — milliseconds, no network — and returns the same three-tier `issues` / `incomplete` / `summary` shape as `scan_page`, with `fix.op` on every finding. Fragments are wrapped into a document automatically. jsdom has no layout, so visual-tier rules (contrast, target size, focus ring) are skipped and counted in `skippedVisual`; pass `engine: "browser"` for the previous headless-Chromium axe path.

## Tools

| Tool | Edition | What it does |
|------|---------|--------------|
| `scan_page` | Lite + Full | Scan a URL for WCAG accessibility issues (3 engines). `source` pointers on dev builds; `minImpact` / `rules` / `wcag` / `format` output controls |
| `flow_scan` | Lite + Full | Multi-page journey scan with deduplicated issues across pages |
| `scan_html` | Lite + Full | Scan a raw HTML snippet or fragment in-process (jsdom, ms, no browser); `engine: "browser"` for contrast |
| `detect_framework` | Lite + Full | Detect Tailwind / MUI / Bootstrap / Next.js / WP / plain CSS |
| `generate_ai_fix` | Lite + Full | Framework-aware fix alternatives. Auto-extracts brand palette from the live URL on contrast issues. |
| `verify_fix` | Lite + Full | Re-scan a fixed element and confirm the violation is gone — `verified: true/false`. Closes the find → fix → verify loop. |
| `diff_scan` | Lite + Full | Baseline vs current → `fixed[]` / `new[]` / `remaining[]`. Page-level regression check; baseline from `scan_history` (Lite) or a live URL. |
| `check_color_contrast` | Lite + Full | WCAG contrast check on a color pair; pass `url` to get brand-aligned suggestions from the live page |
| `check_aria` | Lite + Full | Validate ARIA attributes in an HTML snippet |
| `get_rules` | Lite + Full | List axe-core + WebAbility rules with `fixability` and a `fix` op template; filter by tag, tier, or engine |
| `find_source` | Lite only | Map a CSS selector back to local source files (fallback when the page has no framework `source` pointer) |
| `scan_history` | Lite only | Browse prior local scans under `~/.webability/scans/` |
| `generate_report_pdf` | Lite only | Turn scan findings into a branded WebAbility accessibility-report PDF saved next to the project — free, no account. Pass the `issues[]` from `scan_page`. For the full audit deliverable (Excel + evidence), use `start_audit`. |
| `visual_audit` | Full (free w/ account; stub on Lite) | Pixel-level audit via vision (icon contrast, focus visibility, looks-like-a-button-but-isn't) |
| `start_audit` | Full (free w/ account; stub on Lite) | Kick off the full server-side audit deliverable (report + Excel workbook). Returns an id to poll. |
| `get_audit` | Full (free w/ account; stub on Lite) | Check an audit's progress and, once complete, get the severity summary + report/workbook download URLs. |

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

> "Turn the issues you just found on localhost:3000 into a branded PDF report"

## Privacy, scan logs & telemetry

Every scan is logged **locally** to `~/.webability/scans/` — a one-line-per-scan `index.jsonl` ledger plus the full result of your last 500 scans. Browse them with the `scan_history` tool ("what did we scan earlier?") or plain `jq`. Set `WEBABILITY_SCAN_LOG=off` to disable, `WEBABILITY_SCAN_LOG_DIR` to relocate.

The server also reports one small **telemetry event** per tool call (every tool, not just scans) to the WebAbility API: tool name, a short target label (URL, selector, issue type — never page content), pass/fail, duration, issue counts, and a persistent anonymous install ID. Full scan results, HTML, and generated fix code never leave your machine via telemetry. Set `WEBABILITY_SCAN_TELEMETRY=off` to opt out.

If `POSTHOG_PROJECT_API_KEY` or `POSTHOG_API_KEY` is configured, the server additionally enables PostHog MCP Analytics. This captures MCP usage metadata such as initialize, tools/list, tool name, duration, client name/version, and success/failure. WebAbility strips PostHog's `$mcp_parameters` and `$mcp_response` fields before send, so raw HTML snippets, screenshots, scan responses, and generated code are not sent to PostHog by this integration.

Two tools — `generate_ai_fix` and `visual_audit` — additionally send page content (an HTML snippet or a screenshot) to WebAbility's API so it can call a third-party LLM on your behalf; WebAbility doesn't store that content, but the LLM provider sees it in transit. See [PRIVACY.md](./PRIVACY.md) for the full per-tool breakdown and WebAbility's [privacy policy](https://www.webability.io/privacy-policy).

## Links

- [WebAbility](https://webability.io) — platform, widget, dashboard
- [Documentation](https://webability.io/docs)
- [GitHub](https://github.com/snayyar00/webability-mcp)

## License

MIT
