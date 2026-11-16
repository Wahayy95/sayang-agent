// zkVerify Agent Games — agent service, local / long-lived host.
//
// All request handling lives in core.mjs (shared with the Vercel function
// in api/agent.js). This file is only the bootstrap: env pre-checks,
// CIRCUITS_DIR default, and the HTTP listener.
//
// Env: AGENT_GAMES_HMAC_SECRET (required), STRATEGY_SALT (required for Steal
// the VFY proofs), PORT (default 8080), SEEN_FILE, CIRCUITS_DIR.

import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const APP_DIR = path.dirname(fileURLToPath(import.meta.url));

// The circuit artifacts ship inside this app directory (./circuits). Only
// set the default when the operator has not chosen a location themselves.
if (!process.env.CIRCUITS_DIR) {
  process.env.CIRCUITS_DIR = path.join(APP_DIR, "circuits");
}

if (!process.env.AGENT_GAMES_HMAC_SECRET) {
  console.error("AGENT_GAMES_HMAC_SECRET is required");
  process.exit(1);
}

const { handleAgentRequest } = await import("./core.mjs");

const server = http.createServer(handleAgentRequest);

const PORT = Number(process.env.PORT || 8080);
server.listen(PORT, () => {
  console.log(`agent-games agent listening on :${PORT} (POST /agent)`);
});
