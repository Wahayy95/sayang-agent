# Deploying the SAYANG agent on Vercel (Hobby, free)

Serverless adaptation of the agent service. The same code also runs as a
plain Node server (`server.mjs`) — both hosts share `core.mjs`, so behavior
is identical: HMAC over the raw body, signed responses, same dispatch.

## Layout

| Path | Role |
|---|---|
| `api/agent.js` | Vercel function entry. Default-exports the handler, `bodyParser: false` so the handler reads the **raw** request stream itself (required for HMAC verification). Defaults `CIRCUITS_DIR` to the bundled `./circuits`. |
| `core.mjs` | All request logic: preflight, Gatekeeper, Steal the VFY, seen-set. |
| `server.mjs` | Local/long-lived host (bootstrap + `listen()`), unchanged behavior. |
| `circuits.mjs`, `strategy.mjs`, `commitment.mjs` | Proving, Poseidon, policy — unchanged. |
| `circuits/` | wasm + zkey + verification keys (~5.7 MB), shipped to the function via `includeFiles`. |
| `vercel.json` | Function config (`maxDuration: 60`, `includeFiles: circuits/**`) + rewrites `/agent` and `/health` onto the function. |
| `test.mjs` | Original suite (spawns `server.mjs`). |
| `test-handler.mjs` | Suite for the Vercel handler shape (wraps `api/agent.js`). |

## Import settings (Vercel dashboard → Add New → Project)

Import the repository/tree that contains this directory at its root
(if this tree is in a subdirectory of the repo, set **Root Directory** to
that subdirectory — every path below is relative to it).

- **Framework Preset:** `Other`
- **Root Directory:** `./` (or the subdirectory holding this tree)
- **Build Command:** leave default / empty — there is no build step.
- **Output Directory:** leave empty (default).
- **Install Command:** leave default (Vercel installs from `package-lock.json`).

No code changes are needed at import time; `vercel.json` in the root is
picked up automatically.

## Environment variables (Project → Settings → Environment Variables)

Set for **Production** (and Preview if you test there):

| Name | Value | Notes |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | *the secret issued by the Agent Games dashboard when the agent is registered* | **Required** — the function throws at cold start without it. For the very first deploy, before registration, use the placeholder `placeholder-not-registered` so the deployment builds and `/health` answers; replace it with the real secret before registering the endpoint, then redeploy (or just set it before first deploy if you already have it). |
| `STRATEGY_SALT` | *the salt behind your registered strategy commitment* | Required for Steal the VFY proofs; without it Steal turns fail closed (HOLD, no proof). Placeholder for first deploy: `1`. Must match the commitment registered on the dashboard — changing it later invalidates the commitment. |
| `CIRCUITS_DIR` | *(leave unset)* | `api/agent.js` defaults it to the bundled `circuits/`. |
| `SEEN_FILE` | *(leave unset)* | Vercel's FS is read-only/ephemeral; the proof_tx seen-set automatically degrades to in-memory (see caveat below). |

## Final endpoint URLs

Given the project's production domain `<project>.vercel.app` (or a custom
domain, same paths):

- **Agent endpoint (register this one):** `https://<project>.vercel.app/agent`
  — `POST`, signed envelopes (preflight / Gatekeeper / Steal the VFY).
- **Health:** `https://<project>.vercel.app/health` — `GET` → `{ "ok": true }`.
- The function is also directly reachable at `/api/agent`
  (`POST` = agent, `GET` = health), but register the clean `/agent` URL.

## Limits & caveats (Hobby tier)

- `maxDuration` is set to **60s** (the Hobby cap). Measured locally: cold
  first Gatekeeper proof ≈ 0.9 s end-to-end, warm proofs ≈ 0.3–0.4 s,
  Steal proofs ≈ 0.6–0.8 s — far inside the budget, including cold starts.
- **Seen-set:** on Vercel the proof_tx seen-set cannot persist to disk, so
  it lives in the warm instance's memory. `PROOF_REUSED` is therefore
  detected reliably within one warm instance, but a cold start forgets
  previously seen proof_tx values. (The platform also tracks reuse on its
  side; locally and on any writable host the file persistence still works
  exactly as before.)
- Function bundle includes `circuits/**` (~5.7 MB) via `includeFiles` —
  inside Hobby size limits.
- Hobby functions are stateless and may cold-start; the agent keeps no
  other state, and all proving inputs are derived deterministically from
  the envelope + env secrets, so cold starts only cost latency.

## Local checks

```bash
npm ci
npm test                                   # original suite via server.mjs
set -a; . ../agent/.env; set +a            # test secret + salt (never commit)
CIRCUITS_DIR=$PWD/circuits node test-handler.mjs   # Vercel handler suite
```
