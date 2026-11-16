# SAYANG — zkVerify Agent Games agent service

Self-hosted agent service for **zkVerify Agent Games Season 01**
(agentgames.zkverify.io), competing in both automated arena tracks:

- **Proof Gatekeeper** — evaluates signed proof-verification tasks and
  returns APPROVE / REJECT decisions with a Groth16 proof generated against
  the official `gatekeeper` circuit.
- **Steal the VFY** — plays 20-turn matches under a strategy committed
  on-chain in advance; every move is proven against the official
  `vfy-policy` circuit (HOLD / FORTIFY / EXTRACT policy).

Implements the Agent Games protocol **v1**: the platform POSTs signed task
envelopes to the agent's public HTTPS endpoint (`POST /agent`). Every
inbound request is authenticated by verifying the
`x-agent-games-signature` header (HMAC-SHA256 hex over the raw request
body) before parsing, and every JSON response is signed the same way.
Handles the `agent-games.preflight.v1` handshake
(`{ ok: true, protocolVersion: "v1" }`), Gatekeeper tasks, and Steal the
VFY turns. `GET /health` is a liveness probe.

## Files

- `server.mjs` — HTTP service (`POST /agent`, `GET /health`).
- `strategy.mjs` — the committed Steal the VFY strategy parameters and the
  pure `policy()` function mirroring the vfy-policy circuit.
- `circuits.mjs` — Poseidon hashing, Groth16 proving/verification
  (snarkjs), `publicInputsHash`, and field conversions.
- `commitment.mjs` — prints the Steal the VFY strategy commitment to
  register on the dashboard:
  `Poseidon([strategyParams[0..7], STRATEGY_SALT])`.
- `test.mjs` — full local test suite (spawns the server with a throwaway
  test secret; verifies every returned proof against the exported VKs).
- `CIRCUIT_NOTES.md` — reverse-engineered circuit signal maps and
  semantics.
- `circuits/` — the platform's public circuit artifacts (wasm, final
  zkeys, verification keys) for both games.

## Run

```sh
npm install
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET + STRATEGY_SALT
set -a; . ./.env; set +a
npm start              # node server.mjs — listens on $PORT (default 8080)
npm test               # node test.mjs
STRATEGY_SALT=<salt> npm run commitment
```

Environment variables:

| Variable | Purpose |
| --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | Secret issued by the platform at agent registration (dashboard → Rotate Secret; shown exactly once). Verifies inbound signatures and signs responses. |
| `STRATEGY_SALT` | Secret salt for the Steal the VFY strategy commitment. Never change it after registering the commitment. |
| `PORT` | HTTP port (default 8080; set automatically by Render). |
| `CIRCUITS_DIR` | Path to the circuit artifacts. Set to `./circuits` in this repo layout (see `render.yaml`). |

The service must be reachable at a public HTTPS endpoint ending in
`/agent` (no localhost, private IPs, or custom ports) before it can be
registered on the dashboard.

## Deploy (Render)

`render.yaml` is a Render Blueprint for a plain Node web service:
build `npm install`, start `node server.mjs`, health check `/health`,
with `AGENT_GAMES_HMAC_SECRET` and `STRATEGY_SALT` prompted at deploy
time (`sync: false` — never committed). Render was chosen over Vercel
because `server.mjs` is a long-lived HTTP server that calls
`server.listen()` on `$PORT`; Vercel's serverless functions cannot host
that as-is, while a Render Web Service runs it unchanged.
