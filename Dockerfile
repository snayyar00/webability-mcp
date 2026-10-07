# WebAbility MCP: stdio server for registry introspection (Glama and similar).
# scan_page and other browser tools launch headless Chromium through Playwright,
# so the image installs Chromium and its system libraries.
FROM node:22-slim

WORKDIR /app
ENV CI=1

RUN corepack enable && corepack prepare pnpm@10 --activate

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY tsconfig.json ./
COPY src ./src
RUN pnpm run build \
 && pnpm exec playwright install --with-deps chromium

CMD ["node", "dist/index.js"]
