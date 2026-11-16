// Vercel serverless entry for the zkVerify Agent Games agent service.
//
// Vercel invokes this default export as (req, res) per request — there is
// no listen(). All logic lives in ../core.mjs (shared with server.mjs).
//
// bodyParser is disabled so the handler can read the RAW request stream
// itself: the platform's HMAC signature is computed over the exact raw
// bytes, and any pre-parsing/re-serialization would break verification.
//
// Routing: vercel.json rewrites /agent and /health onto this function with
// a ?route= marker; direct hits on /api/agent also work (POST = agent,
// GET = health). See core.mjs routeOf().

import path from "node:path";
import { fileURLToPath } from "node:url";

const APP_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// circuits.mjs resolves CIRCUITS_DIR at import time; point it at the
// artifacts bundled with this project (shipped to the function via
// includeFiles in vercel.json) unless the operator overrode it.
if (!process.env.CIRCUITS_DIR) {
  process.env.CIRCUITS_DIR = path.join(APP_DIR, "circuits");
}

const { handleAgentRequest } = await import("../core.mjs");

export const config = {
  api: {
    bodyParser: false,
  },
};

export default handleAgentRequest;
