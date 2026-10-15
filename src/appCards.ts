/**
 * MCP Apps result card (spec 2026-01-26) for scan_page and verify_fix.
 *
 * A host that renders MCP Apps (ChatGPT, Claude, VS Code) reads the tool's
 * `_meta.ui.resourceUri`, loads this HTML into a sandboxed iframe, and posts
 * the tool result to it over the `ui/*` postMessage bridge. The card reads
 * `structuredContent` only. Hosts without app support ignore both and keep
 * reading the text `content` blocks, which do not change.
 *
 * Hand-rolled rather than @modelcontextprotocol/ext-apps: its server helpers
 * need the v2 SDK, and the bridge is five messages.
 *
 * `structuredContent` is also shown to the model in ChatGPT, so the card data
 * stays small: counts and the top findings, never page HTML.
 */

export const CARD_RESOURCE_URI = 'ui://webability/result-card.html'
export const CARD_MIME_TYPE = 'text/html;profile=mcp-app'
export const CARD_TOOLS: ReadonlySet<string> = new Set(['scan_page', 'verify_fix'])

const REPORT_PAGE = 'https://www.webability.io/website-accessibility-checker'
const TOP_ISSUES = 6
const TOP_REMAINING = 5

/** Server `capabilities.extensions` entry for MCP Apps (extension id io.modelcontextprotocol/ui). */
export const cardExtension = () => ({ 'io.modelcontextprotocol/ui': { mimeTypes: [CARD_MIME_TYPE] } })

/** Tool `_meta` that points an Apps host at the card. */
export const cardToolMeta = () => ({ ui: { resourceUri: CARD_RESOURCE_URI } })

/**
 * Resource `_meta`, on both the listing and the read result (a host takes the
 * read result's `_meta.ui` whole, with no merge). The card is fully inline, so
 * its CSP is declared empty: no fetches, no remote assets. Declaring it, even
 * empty, is what lets ChatGPT apply a CSP; with none it labels the card
 * "CSP off". The `openai/*` keys mirror the same policy for ChatGPT, plus the
 * one place the card sends the user (the report link) and a description that
 * stops the model restating what the card already shows.
 */
export const cardResourceMeta = () => ({
  ui: { prefersBorder: true, csp: { connectDomains: [] as string[], resourceDomains: [] as string[] } },
  'openai/widgetPrefersBorder': true,
  'openai/widgetCSP': { connect_domains: [] as string[], resource_domains: [] as string[], redirect_domains: [new URL(REPORT_PAGE).origin] },
  'openai/widgetDescription':
    'Shows the result to the user: the page URL, the WCAG level, the issue count by impact, the top issues with their WCAG criteria and elements, and a link to the full report. Do not repeat these details; answer in one or two sentences with what to do next.',
})

/** resources/list entry. */
export const cardResource = () => ({
  uri: CARD_RESOURCE_URI,
  name: 'webability-result-card',
  title: 'WebAbility result card',
  description: 'Renders scan_page and verify_fix results as a card.',
  mimeType: CARD_MIME_TYPE,
  _meta: cardResourceMeta(),
})

/** resources/read contents. */
export const cardResourceContents = () => ({
  contents: [{ uri: CARD_RESOURCE_URI, mimeType: CARD_MIME_TYPE, text: cardHtml(), _meta: cardResourceMeta() }],
})

type Summary = { total: number; critical: number; serious: number; moderate: number; minor: number }
type Finding = { type?: string; wcag?: string; impact?: string; selector?: string; message?: string; count?: number }

export type ScanCard = {
  kind: 'scan'
  /** ISO time the result was produced; the card shows it, never render time. */
  at?: string
  url: string
  level: 'A' | 'AA' | 'AAA'
  summary: Summary
  issuesTotal: number
  framework?: string
  /** Active output controls; summary and topIssues then describe only the matching subset. */
  filters?: string
  /** Whole-page issue count when filters are on, so a filtered zero is never read as a clean page. */
  pageTotal?: number
  topIssues: Array<{ type?: string; wcag?: string; impact?: string; selector?: string; message?: string; count?: number }>
  reportUrl: string
}

export type VerifyCard = {
  kind: 'verify'
  at?: string
  url: string
  selector: string
  wcag?: string
  verified: boolean
  reason?: string
  remainingCount: number | null
  remaining: Array<{ type?: string; wcag?: string; impact?: string; message?: string }>
}

const clip = (s: unknown, n: number) => (typeof s === 'string' ? (s.length > n ? s.slice(0, n - 1) + '…' : s) : undefined)

export function scanCard(p: { url: string; summary: Summary; issues: readonly Finding[]; issuesTotal: number; framework?: string; level?: 'A' | 'AA' | 'AAA'; filters?: string; pageSummary?: Summary; at?: string }): ScanCard {
  return {
    kind: 'scan',
    ...(p.at ? { at: p.at } : {}),
    url: p.url,
    level: p.level ?? 'AA',
    summary: { total: p.summary.total, critical: p.summary.critical, serious: p.summary.serious, moderate: p.summary.moderate, minor: p.summary.minor },
    issuesTotal: p.issuesTotal,
    ...(p.framework && p.framework !== 'unknown' ? { framework: p.framework } : {}),
    ...(p.filters ? { filters: p.filters, pageTotal: (p.pageSummary ?? p.summary).total } : {}),
    topIssues: p.issues.slice(0, TOP_ISSUES).map((i) => ({
      type: i.type,
      wcag: i.wcag,
      impact: i.impact,
      selector: clip(i.selector, 120),
      message: clip(i.message, 160),
      ...(typeof i.count === 'number' && i.count > 1 ? { count: i.count } : {}),
    })),
    reportUrl: `${REPORT_PAGE}?url=${encodeURIComponent(p.url)}`,
  }
}

export function verifyCard(p: { url: string; selector: string; wcag?: string; verified: boolean; reason?: string; remainingCount: number | null; remainingIssues: readonly Finding[]; at?: string }): VerifyCard {
  return {
    kind: 'verify',
    ...(p.at ? { at: p.at } : {}),
    url: p.url,
    selector: p.selector,
    ...(p.wcag ? { wcag: p.wcag } : {}),
    verified: p.verified,
    ...(p.reason ? { reason: p.reason } : {}),
    remainingCount: p.remainingCount,
    remaining: p.remainingIssues.slice(0, TOP_REMAINING).map((i) => ({ type: i.type, wcag: i.wcag, impact: i.impact, message: clip(i.message, 160) })),
  }
}

/**
 * The card view. Host CSS variables first; the fallbacks are WebAbility
 * palette colours (brand blue #0052CC, ink #020817). Every string from the
 * result is escaped: it is page-derived and untrusted.
 */
export function cardHtml(): string {
  return CARD_HTML
}

const CARD_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WebAbility result</title>
<style>
:root{--ink:var(--color-text-primary,#020817);--muted:var(--color-text-secondary,#475569);--bg:var(--color-background-primary,#FFFFFF);--line:var(--color-border-secondary,#E2E8F0);--soft:var(--color-background-secondary,#F8FAFC);--brand:#0052CC;--radius:var(--border-radius-lg,12px);font-family:var(--font-sans,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif);color-scheme:light}
:root[data-theme="dark"]{--ink:var(--color-text-primary,#F8FAFC);--muted:var(--color-text-secondary,#94A3B8);--bg:var(--color-background-primary,#020817);--line:var(--color-border-secondary,#334155);--soft:var(--color-background-secondary,#0F172A);color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-size:14px;line-height:1.45}
.card{padding:16px 18px}
.head{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px}
.logo{width:18px;height:18px;border-radius:5px;background:var(--brand);color:#FFFFFF;font-weight:700;font-size:11px;display:grid;place-items:center}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-top:12px}
.sub{color:var(--muted);font-size:13px;word-break:break-all}
.big{font-size:30px;font-weight:600;letter-spacing:-.01em;margin:2px 0}
.pill{font-size:12px;font-weight:600;padding:3px 9px;border-radius:999px;white-space:nowrap}
.bad{background:#FEF2F2;color:#B91C1C}.good{background:#F0FDF4;color:#15803D}.warn{background:#FEF3C7;color:#B45309}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0 4px;padding-top:12px;border-top:1px solid var(--line)}
.grid.three{grid-template-columns:repeat(3,1fr)}
.k{color:var(--muted);font-size:12px}.v{font-weight:600;word-break:break-all}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px}
caption{text-align:left;font-weight:600;padding-bottom:6px}
th{text-align:left;color:var(--muted);font-weight:500;font-size:12px;padding:6px 8px 6px 0;border-bottom:1px solid var(--line)}
td{padding:7px 8px 7px 0;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
code{font-family:var(--font-mono,ui-monospace,Menlo,monospace);font-size:12px;word-break:break-all}
.more{color:var(--muted);font-size:12px;margin-top:6px}
.actions{margin-top:14px}
button{font:inherit;font-weight:600;color:#FFFFFF;background:var(--brand);border:0;border-radius:999px;padding:8px 16px;cursor:pointer}
button:focus-visible,a:focus-visible{outline:3px solid var(--brand);outline-offset:2px}
.foot{display:flex;justify-content:space-between;color:var(--muted);font-size:12px;margin-top:14px;padding-top:10px;border-top:1px solid var(--line)}
.foot a{color:inherit}
.wait{color:var(--muted)}
</style>
</head>
<body>
<main class="card" id="root" aria-live="polite"><p class="wait">Waiting for the result…</p></main>
<script>
(function(){
  var root = document.getElementById('root');
  var nextId = 1, pending = {};
  function send(msg){ window.parent.postMessage(Object.assign({ jsonrpc: '2.0' }, msg), '*'); }
  function request(method, params){ var id = nextId++; send({ id: id, method: method, params: params }); return new Promise(function(res){ pending[id] = res; }); }
  function notify(method, params){ send({ method: method, params: params || {} }); }
  function esc(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){ return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]; }); }
  function n(x){ return typeof x === 'number' ? x.toLocaleString() : '—'; }
  function short(u){ try { var p = new URL(u); return p.host + (p.pathname === '/' ? '' : p.pathname); } catch (e) { return u; } }
  function cap(s){ s = String(s || ''); return s.charAt(0).toUpperCase() + s.slice(1); }
  function label(t){ return cap(String(t || 'issue').replace(/[_-]+/g, ' ')); }
  function head(title){ return '<div class="head"><span class="logo" aria-hidden="true">W</span><span>WebAbility · ' + esc(title) + '</span></div>'; }
  // The time comes from the result (stamped when the scan ran): a re-mounted card must not show render time.
  function when(at){ var d = at ? new Date(at) : null; return d && !isNaN(d) ? ' ' + d.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : ''; }
  function foot(word, level, at){ return '<div class="foot"><span>' + esc(word + when(at)) + '</span><span>WCAG 2.2' + (level ? ' ' + esc(level) : '') + '</span></div>'; }

  function scan(d){
    var s = d.summary || {}, total = s.total || 0;
    var lvl = esc(d.level || 'AA');
    var pill = total ? '<span class="pill bad">' + n(total) + (d.filters ? ' match' : ' to fix') + '</span>'
      : d.filters ? '<span class="pill warn">No matches</span>'
      : '<span class="pill good">No ' + lvl + ' issues found</span>';
    var h = head('Accessibility scan') +
      '<div class="top"><div><div class="sub">' + esc(short(d.url)) + '</div><div class="big">' + n(total) + (total === 1 ? ' issue' : ' issues') + '</div>' +
      '<div class="sub">WCAG ' + lvl + (d.framework ? ' · ' + esc(d.framework) : '') + '</div>' +
      (d.filters ? '<div class="sub">Filtered: ' + esc(d.filters) + ' · ' + n(d.pageTotal) + ' issues on the whole page</div>' : '') + '</div>' + pill + '</div>' +
      '<div class="grid">' + ['critical','serious','moderate','minor'].map(function(k){ return '<div><div class="k">' + cap(k) + '</div><div class="v">' + n(s[k]) + '</div></div>'; }).join('') + '</div>';
    var rows = (d.topIssues || []);
    if (rows.length) {
      h += '<table><caption>Top issues</caption><thead><tr><th scope="col">Issue</th><th scope="col">WCAG</th><th scope="col">Impact</th><th scope="col">Element</th></tr></thead><tbody>' +
        rows.map(function(i){ return '<tr><td>' + esc(label(i.type)) + (i.count > 1 ? ' ×' + n(i.count) : '') + '</td><td>' + esc(i.wcag) + '</td><td>' + esc(cap(i.impact)) + '</td><td><code>' + esc(i.selector) + '</code></td></tr>'; }).join('') +
        '</tbody></table>';
      var shown = rows.reduce(function(a, i){ return a + (i.count || 1); }, 0);
      if (total > shown) h += '<div class="more">' + n(total - shown) + ' more in the full report.</div>';
    }
    h += '<div class="actions"><button type="button" id="open">Open full report on WebAbility ↗</button></div>' + foot('Scanned', d.level || 'AA', d.at);
    root.innerHTML = h;
    document.getElementById('open').addEventListener('click', function(){ request('ui/open-link', { url: d.reportUrl }); });
  }

  function verify(d){
    var pill = d.verified ? '<span class="pill good">Verified</span>' : d.reason ? '<span class="pill warn">Not checked</span>' : '<span class="pill bad">Not resolved</span>';
    var why = { 'not-found': 'No element matches this selector.', 'invalid-selector': 'The selector is not valid CSS.' }[d.reason];
    var h = head('Fix verification') +
      '<div class="top"><div><div class="sub">' + esc(short(d.url)) + '</div><div class="big"><code style="font-size:20px">' + esc(d.selector) + '</code></div>' +
      (why ? '<div class="sub">' + esc(why) + '</div>' : '') + '</div>' + pill + '</div>' +
      '<div class="grid three"><div><div class="k">Criterion</div><div class="v">' + esc(d.wcag || 'All rules') + '</div></div>' +
      '<div><div class="k">Remaining</div><div class="v">' + (d.remainingCount == null ? '—' : n(d.remainingCount)) + '</div></div>' +
      '<div><div class="k">Result</div><div class="v">' + (d.verified ? 'Fixed' : d.reason ? 'Unverified' : 'Still failing') + '</div></div></div>';
    if ((d.remaining || []).length) {
      h += '<table><caption>Remaining issues</caption><thead><tr><th scope="col">Issue</th><th scope="col">WCAG</th><th scope="col">Impact</th></tr></thead><tbody>' +
        d.remaining.map(function(i){ return '<tr><td>' + esc(cap(i.message) || label(i.type)) + '</td><td>' + esc(i.wcag) + '</td><td>' + esc(cap(i.impact)) + '</td></tr>'; }).join('') + '</tbody></table>';
    }
    root.innerHTML = h + foot('Checked', '', d.at);
  }

  // Error and blocked paths return text only: show that text, never a card stuck on "Waiting".
  function plain(r){
    var t = ((r && r.content) || []).filter(function(c){ return c && c.type === 'text' && c.text && c.text.indexOf('\u0060\u0060\u0060') !== 0; }).map(function(c){ return c.text; })[0];
    root.innerHTML = head(r && r.isError ? 'Could not complete' : 'Result') + '<p>' + esc(t || 'No result was returned.') + '</p>';
  }
  function render(r){
    var sc = r && r.structuredContent;
    if (sc && sc.kind === 'scan') scan(sc); else if (sc && sc.kind === 'verify') verify(sc); else plain(r);
    resize();
  }
  function resize(){ notify('ui/notifications/size-changed', { height: Math.ceil(document.documentElement.getBoundingClientRect().height) }); }
  function theme(ctx){
    if (!ctx) return;
    if (ctx.theme) document.documentElement.setAttribute('data-theme', ctx.theme);
    var vars = ctx.styles && ctx.styles.variables;
    if (vars) for (var k in vars) if (vars[k]) document.documentElement.style.setProperty(k, vars[k]);
  }

  window.addEventListener('message', function(e){
    var m = e.data;
    if (!m || m.jsonrpc !== '2.0') return;
    if (m.id != null && pending[m.id] && !m.method) { pending[m.id](m.result); delete pending[m.id]; return; }
    // Host requests (ping, ui/resource-teardown) wait for a reply.
    if (m.id != null && m.method) { send({ id: m.id, result: {} }); return; }
    if (m.method === 'ui/notifications/tool-result') render(m.params);
    else if (m.method === 'ui/notifications/host-context-changed') theme(m.params);
  });

  request('ui/initialize', { appInfo: { name: 'webability-result-card', version: '1' }, appCapabilities: {}, protocolVersion: '2026-01-26' })
    .then(function(r){ theme(r && r.hostContext); notify('ui/notifications/initialized'); resize(); });
  if (window.ResizeObserver) new ResizeObserver(resize).observe(document.body);
})();
</script>
</body>
</html>
`
