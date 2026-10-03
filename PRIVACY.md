# Privacy & data handling — @webability/mcp

This document covers, per feature, what stays on your machine and what leaves it. It's verified against this package's actual source, not aspirational.

## TL;DR

- **Scanning itself is 100% local.** All scan tools launch a headless browser on your machine and never send page content anywhere by default.
- **A small telemetry event** (tool name, a short target label, pass/fail, duration, issue counts, and a persistent anonymous install ID) is sent to WebAbility's API per tool call — every tool, not just scans. Opt out of all of it with `WEBABILITY_SCAN_TELEMETRY=off`.
- **PostHog MCP Analytics is opt-in.** It only runs when `POSTHOG_PROJECT_API_KEY` or `POSTHOG_API_KEY` is configured. WebAbility removes PostHog's tool parameter and response payload fields before sending events.
- **Two tools** — `generate_ai_fix` and `visual_audit` — send additional content (an HTML snippet, or a screenshot) to WebAbility's API so it can call a third-party LLM on your behalf. WebAbility does not store that content; the LLM provider sees it in transit under its own retention policy.
- **Scan history is written only to your disk** (`~/.webability/scans/`) — never uploaded.

## Tools that run locally

`scan_page`, `flow_scan`, `diff_scan`, `detect_framework`, `scan_html`, `check_aria`, `check_color_contrast`, `get_rules`, `find_source`, `scan_history` all run entirely in a local headless browser process (or pure computation, for the non-browser ones — since 1.6.0 `scan_html` runs in-process in jsdom by default and launches no browser at all). Scanning a URL means *your machine* fetches that URL directly — no data about the target page goes to WebAbility. `check_color_contrast`'s optional brand-palette extraction from a live URL also runs locally. The only thing these tools send to WebAbility is the per-call telemetry event described below (which carries no page content) — disable it with `WEBABILITY_SCAN_TELEMETRY=off` and they make no WebAbility call at all.

Since 1.6.0, `scan_page`, `flow_scan` and `diff_scan` also read source pointers (`file`, `line`, `component`) from a React or Vue **dev build's** own component tree and return them with each finding. Those paths come from the page you scanned and go only to your MCP client (and the local `scan_history` archive); production builds carry none. `sourceRoot` greps a directory you name, on your machine, and sends nothing.

## Scan logging (local disk only)

Every scan-shaped tool call (`scan_page`, `flow_scan`, `scan_html`, `visual_audit`, `check_aria`) is written to `~/.webability/scans/`:
- `index.jsonl` — one line per scan (timestamp, tool, target, duration, pass/fail, a one-line summary)
- `<scan-id>.json` — the full tool response, capped at your most recent 500 results (older ones are pruned)

This never leaves your machine. Browse it with the `scan_history` tool or `jq`/`cat` directly. Disable with `WEBABILITY_SCAN_LOG=off`; relocate with `WEBABILITY_SCAN_LOG_DIR`.

## Telemetry (sent to WebAbility, on by default)

After each tool call — every tool, not just scans — the server reports one small event to `api.webability.io/mcp/scan-events`: the tool name, a short target label, pass/fail, duration, summary counts, and for a few tools one tiny metadata string. Never the full scan result, HTML, screenshots, or generated fix code — those stay local per above. What the target label is, per tool:

- **scan/audit tools** (`scan_page`, `flow_scan`, `visual_audit`, `detect_framework`, `check_color_contrast` with a `url`): the URL you pointed the tool at. `scan_html` / `check_aria`: a synthetic size label like `inline-html (1.2 KB)` — the HTML itself is never sent.
- **`generate_ai_fix`**: the issue's type and WCAG criterion (e.g. `img-alt wcag:1.1.1`), plus whether a fix was returned (`fix:yes`/`fix:no`) and how many alternatives — never the HTML or the generated code.
- **`detect_framework`**: also the detected framework name (e.g. `framework:tailwind`).
- **`check_color_contrast`** without a `url`: the two color values (e.g. `#777777 on #ffffff`), plus AA pass/fail.
- **`find_source`**: the CSS selector being looked up and the match count — never file paths or file contents.
- **`get_rules`**: the tag filter (or `all`) and the rule count. **`scan_history`**: `list`, `filter:<substring>`, or `id:<scan-id>`.

The event also includes a **persistent anonymous client ID** — a random identifier generated on first use and stored at `~/.webability/client-id`, so WebAbility can distinguish install-level usage patterns over time (e.g. "this install ran N scans this month") without any real-world identity attached. It is not derived from your machine, email, or account.

This is used for WebAbility's own product usage visibility (an internal admin dashboard), not sold or shared with third parties. Disable with `WEBABILITY_SCAN_TELEMETRY=off`.

## PostHog MCP Analytics (optional)

When `POSTHOG_PROJECT_API_KEY` or `POSTHOG_API_KEY` is set, the server instruments MCP protocol usage with `@posthog/mcp`. It sends usage metadata to PostHog, including initialize events, tools/list events, tool-call events, tool name, duration, client name/version, protocol version, and whether the call errored. For hosted HTTP mode, the caller is identified by a one-way SHA-256 hash of the WebAbility token; the token itself is never sent.

WebAbility applies a `beforeSend` redaction layer that deletes PostHog's `$mcp_parameters` and `$mcp_response` fields. This prevents raw tool arguments and responses from being sent to PostHog, including HTML snippets, issue HTML, screenshots, full scan results, generated code, local file paths, and `scan_history` responses.

Configure `POSTHOG_HOST` to change the ingestion host from the default `https://us.i.posthog.com`. Set `WEBABILITY_POSTHOG_MCP_ANALYTICS=off` to force-disable this integration even when a PostHog key is present.

## `generate_ai_fix` and `visual_audit` (the two tools that call an LLM)

These need a server-side AI model, so they're the only tools that send page *content* (not just a URL) to WebAbility:

- **`generate_ai_fix`** sends the flagged element's HTML (~600 chars), surrounding context HTML (~400 chars), the page URL, framework, and issue metadata to `POST /cli/ai-fix`.
- **`visual_audit`** sends a base64 PNG screenshot of the page (viewport or full-page) plus the URL to `POST /cli/visual-audit`.

Verified against the backend implementation: neither payload is logged (access logging is method/path/status/timing only — no request bodies) or persisted to any database or object store on WebAbility's side. Each is used to build a single stateless call — `generate_ai_fix` to an LLM via Vercel AI Gateway, `visual_audit` directly to Anthropic's API — and the payload is discarded once the response returns.

**The honest caveat:** "WebAbility doesn't store it" is not the same as "no one sees it." Both payloads transit to, and are briefly retained by, the underlying LLM provider under that provider's own data-retention policy, which WebAbility does not control. If a page contains sensitive content you don't want to leave your machine at all, use the local-only tools instead, or don't pass a URL/screenshot from that page to these two.

`generate_ai_fix` only ever returns *suggested* code — it never edits your source or applies changes automatically.

## Authentication

- **Local (stdio) mode** — the default when installed into your IDE — requires no authentication; it's a local child process of your editor, same trust boundary as any other local tool.
- **Remote (HTTP) mode** — for hosting this server centrally — requires a caller WebAbility bearer token (`Authorization: Bearer <token>` or `x-webability-token`) or a shared operator `MCP_AUTH_TOKEN`, and includes SSRF guards on outbound requests; `find_source` (filesystem access) is disabled in this mode.

## Links

- [WebAbility's privacy policy](https://www.webability.io/privacy-policy) — governs data WebAbility itself processes (the telemetry event and the two LLM-calling tools above).
- Questions or a data-handling concern specific to this package: open an issue at [github.com/snayyar00/webability-mcp](https://github.com/snayyar00/webability-mcp).
