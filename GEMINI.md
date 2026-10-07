# WebAbility accessibility tools

Use these tools when the user asks about accessibility, WCAG, ADA, Section 508, or screen-reader support.

- Scan a page: `scan_page` with `url`. For a local dev server, run `webability-tunnel --port 3000` and pass its URL with `tunnel_secret`.
- Results list `issues` (violations the scanner stands behind) and a `summary`. Uncertain findings are judged or dropped, never listed for review.
- Each issue has `fix.op` and `fixability`: apply `mechanical` fixes as given, write the value for `contextual` ones, and only propose `visual` ones.
- After you edit the code, call `verify_fix` with the same `url`, the `selector`, and the rule (`wcag`) to confirm the issue is gone.
- `generate_ai_fix` drafts a code fix for one issue. `get_rules` lists every rule.
- Free for everyone. `visual_audit` and `start_audit` need a free WebAbility account; the client asks you to sign in.
