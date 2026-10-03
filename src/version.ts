/**
 * MCP server version stamped into the MCP handshake (`createServer`). Kept in
 * sync with package.json by a drift-guard unit test — a stale published build
 * vs a fresh deploy are indistinguishable without it (the same incident that
 * gave @webability/core its CORE_VERSION: a months-old npm build was mistaken
 * for the freshly deployed server).
 */
export const MCP_VERSION = '1.6.3'
