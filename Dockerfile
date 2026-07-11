# WebAbility MCP — remote (Streamable HTTP) server for hosting (e.g. Lovable chat connector).
#
# scan_page / flow_scan / visual_audit launch a real headless Chromium via Playwright,
# so this MUST be a Playwright base image (Chromium + system deps baked in), not plain node.
# Keep the Playwright tag in lockstep with the `playwright` version in mcp/package.json.
#
# BUILD CONTEXT = the abilyo repo root (the pnpm workspace root that contains
# pnpm-workspace.yaml, core/, mcp/ ...). In Coolify set Base Directory to that root
# and Dockerfile to `mcp/Dockerfile`.
FROM mcr.microsoft.com/playwright:v1.59.1-jammy

WORKDIR /app
# Chromium is baked into the base image — don't let the playwright npm package re-download it.
# NOTE: do NOT set NODE_ENV=production here — that makes pnpm skip the devDeps (tsup/typescript)
# the build needs. It's set at runtime by Coolify instead.
ENV CI=1 PORT=8080 PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

# pnpm via corepack (lockfile is pnpm).
RUN corepack enable && corepack prepare pnpm@8.11.0 --activate

# Copy the whole workspace (mcp depends on the @webability/core workspace package).
COPY . .

# Install all workspace deps, then build core then mcp.
# --no-frozen-lockfile: the repo's pnpm-lock.yaml lags some packages (e.g. react-native); we don't
#   want a stale lockfile to block the mcp build. --prod=false: force devDeps even if NODE_ENV leaks in.
# SKIP_DTS=1: skip type-declaration generation — a server image runs JS only, and core's .d.ts build
#   would otherwise need type-only deps (lighthouse, @anthropic-ai) the MCP never executes.
# mcp built via tsup directly (no --dts) for the same reason.
RUN pnpm install --no-frozen-lockfile --prod=false \
 && SKIP_DTS=1 pnpm --filter @webability/core build \
 && pnpm --filter @webability/mcp exec tsup src/index.ts src/http.ts --format esm --minify --clean

EXPOSE 8080

# Required env at runtime (set in Coolify):
#   MCP_AUTH_TOKEN   — bearer token Lovable/clients must send (Authorization: Bearer <token>)
#   WEBABILITY_API_URL — defaults to https://api.webability.io (ai-fix / visual-audit backend)
# Healthcheck hits /health.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.PORT||8080)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "mcp/dist/http.js"]
