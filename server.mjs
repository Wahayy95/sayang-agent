// zkVerify Agent Games — agent service.
//
// POST /agent (single endpoint for every task type):
//   1. Read the RAW request body.
//   2. Verify HMAC-SHA256 (hex) over the raw body against the
//      x-agent-games-signature header BEFORE parsing JSON.
//   3. Dispatch on the envelope:
//        type "agent-games.preflight.v1"       -> { ok:true, protocolVersion:"v1" }
//        type "agent-games.proof-gatekeeper.v1" -> Gatekeeper decision + Groth16 proof
//        eventId "steal-the-vfy"                -> policy action + Groth16 proof
//   4. Sign every JSON response: x-agent-games-signature = HMAC-SHA256 hex
//      over the raw response body, same secret.
//
// Env: AGENT_GAMES_HMAC_SECRET (required), STRATEGY_SALT (required for Steal
// the VFY proofs), PORT (default 8080), SEEN_FILE (proof_tx seen-set path).

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import {
  proveGatekeeper,
  proveVfyPolicy,
  strategyCommitment,
  publicInputsHash,
  matchIdToField,
  taskIdToField,
  gatekeeperSalt,
  idempotencyKeyFor,
  parseFieldInt,
} from "./circuits.mjs";
import { STRATEGY_PARAMS, assertValidParams, policy } from "./strategy.mjs";

const AGENT_DIR = path.dirname(fileURLToPath(import.meta.url));
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
if (!SECRET) {
  console.error("AGENT_GAMES_HMAC_SECRET is required");
  process.exit(1);
}
assertValidParams(STRATEGY_PARAMS);

let STRATEGY_SALT = null;
try {
  STRATEGY_SALT = parseFieldInt(process.env.STRATEGY_SALT, "STRATEGY_SALT");
} catch {
  console.error("warning: STRATEGY_SALT unset/invalid — Steal the VFY will fail closed (HOLD, no proof)");
}

// ---------- HMAC helpers ----------

function hmacHex(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function signatureValid(rawBody, headerValue) {
  if (!headerValue) return false;
  let provided = String(headerValue).trim().toLowerCase();
  if (provided.startsWith("sha256=")) provided = provided.slice("sha256=".length);
  const expected = hmacHex(SECRET, rawBody);
  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------- proof_tx seen-set (persistent) ----------

const SEEN_FILE = process.env.SEEN_FILE || path.join(AGENT_DIR, "seen-proof-tx.json");
const seenProofTx = new Set();
try {
  const parsed = JSON.parse(fs.readFileSync(SEEN_FILE, "utf8"));
  if (Array.isArray(parsed)) for (const tx of parsed) seenProofTx.add(String(tx));
} catch {
  /* first run: no file yet */
}
function recordProofTx(tx) {
  seenProofTx.add(tx);
  const tmp = `${SEEN_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify([...seenProofTx], null, 2));
  fs.renameSync(tmp, SEEN_FILE);
}

// ---------- helpers ----------

const toBig = (v) => BigInt(typeof v === "string" ? v.trim() : v);
const dec = (v) => toBig(v).toString();

function sendJson(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  res.writeHead(status, {
    "content-type": "application/json",
    "x-agent-games-signature": hmacHex(SECRET, body),
  });
  res.end(body);
}

// ---------- Gatekeeper ----------

async function handleGatekeeper(task) {
  const input = task.input ?? {};
  const proofTx = String(input.proof_tx ?? "");
  // Record every proof_tx ever received; reuse is judged against prior tasks.
  const reused = proofTx !== "" && seenProofTx.has(proofTx);
  if (proofTx !== "") recordProofTx(proofTx);

  const registeredVk = toBig(input.registered_vk);
  const proofVk = toBig(input.proof_vk);
  const minimum = toBig(input.minimum);
  const publicBalance = toBig(input.public_balance);
  const expiryBlock = toBig(input.expiry_block);
  const currentBlock = toBig(input.current_block);
  const recipient = toBig(input.recipient);
  const conditionRecipient = toBig(input.condition_recipient);
  const amount = toBig(input.amount);
  const maxTransfer = toBig(input.max_transfer);

  const vkOk = proofVk === registeredVk;
  const thresholdOk = publicBalance >= minimum;
  // The circuit asserts expiryBlock > currentBlock (strict), so at
  // currentBlock == expiryBlock the condition counts as expired — an APPROVE
  // proof would be impossible to generate there.
  const expired = currentBlock >= expiryBlock;
  const recipientOk = recipient === conditionRecipient;
  const amountOk = amount <= maxTransfer;

  // Reason codes follow the mandated check order; the decision itself is the
  // circuit's AND of all conditions (reuse included, platform-side).
  let reasonCode;
  if (!vkOk) reasonCode = "VK_SUBSTITUTION";
  else if (!thresholdOk) reasonCode = "THRESHOLD_MISMATCH";
  else if (reused) reasonCode = "PROOF_REUSED";
  else if (expired) reasonCode = "EXPIRED_CONDITION";
  else if (!recipientOk) reasonCode = "RECIPIENT_MISMATCH";
  else if (!amountOk) reasonCode = "AMOUNT_OVERFLOW";
  else reasonCode = "VALID_CONDITION";

  const approve = reasonCode === "VALID_CONDITION";
  const response = {
    decision: approve ? "APPROVE" : "REJECT",
    reason_code: reasonCode,
    proof_tx: input.proof_tx,
  };
  // PROOF_REUSED responses carry no proof (there is no proof to submit).
  if (reasonCode === "PROOF_REUSED") return response;

  const circuitInput = {
    registeredVkHash: registeredVk.toString(),
    proofVkHash: proofVk.toString(),
    minimum: minimum.toString(),
    publicBalance: publicBalance.toString(),
    expiryBlock: expiryBlock.toString(),
    currentBlock: currentBlock.toString(),
    recipient: recipient.toString(),
    conditionRecipient: conditionRecipient.toString(),
    amount: amount.toString(),
    maxTransfer: maxTransfer.toString(),
    decision: approve ? "1" : "0",
    salt: gatekeeperSalt(SECRET, task.task_id).toString(),
    taskId: taskIdToField(task.task_id).toString(),
  };
  try {
    const { proof, publicSignals } = await proveGatekeeper(circuitInput);
    response.proof = proof;
    response.public_signals = publicSignals;
  } catch (err) {
    // Fail closed: keep the decision, omit the proof (scored as missing proof
    // rather than risking an unverifiable one).
    console.error(`gatekeeper proving failed for task ${task.task_id}:`, err.message);
  }
  return response;
}

// ---------- Steal the VFY ----------

async function handleStealTheVfy(envelope) {
  const { matchId, turn } = envelope;
  const state = envelope.state ?? {};
  const selfBalance = toBig(state.selfBalance ?? 0);
  const opponentBalance = toBig(state.opponentBalance ?? 0);
  const envelopeCommitment = envelope.strategyCommitment?.hash
    ? toBig(envelope.strategyCommitment.hash)
    : null;

  const holdResponse = (commitmentForHash) => ({
    matchId,
    turn,
    action: { type: "HOLD" },
    ...(commitmentForHash !== null
      ? {
          policyProof: {
            circuitVersion: "v1",
            publicInputsHash: publicInputsHash({
              commitment: commitmentForHash,
              matchId,
              turn,
              selfBalance,
              opponentBalance,
              actionCode: 0n,
              amount: 0n,
              circuitVersion: 1n,
            }),
          },
        }
      : {}),
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: idempotencyKeyFor(matchId, turn),
  });

  if (STRATEGY_SALT === null) {
    console.error("steal-the-vfy: STRATEGY_SALT missing — HOLD without proof");
    return holdResponse(envelopeCommitment);
  }

  try {
    const commitment = await strategyCommitment(STRATEGY_PARAMS, STRATEGY_SALT);
    if (envelopeCommitment !== null && envelopeCommitment !== commitment) {
      console.error(
        "steal-the-vfy: envelope strategyCommitment.hash differs from Poseidon(params, STRATEGY_SALT) — registration may be stale",
      );
    }
    const act = policy({ selfBalance, opponentBalance }, STRATEGY_PARAMS);
    const hash = publicInputsHash({
      commitment: envelopeCommitment ?? commitment,
      matchId,
      turn,
      selfBalance,
      opponentBalance,
      actionCode: act.code,
      amount: act.amount,
      circuitVersion: 1n,
    });
    const circuitInput = {
      commitment: commitment.toString(),
      matchId: matchIdToField(matchId).toString(),
      turnNumber: dec(turn),
      selfBalance: selfBalance.toString(),
      opponentBalance: opponentBalance.toString(),
      action: act.code.toString(),
      amount: act.amount.toString(),
      circuitVersion: "1",
      salt: STRATEGY_SALT.toString(),
      strategyParams: STRATEGY_PARAMS.map((p) => p.toString()),
    };
    const { proof, publicSignals } = await proveVfyPolicy(circuitInput);
    return {
      matchId,
      turn,
      // amount is present ONLY on EXTRACT — the schema rejects it otherwise.
      action:
        act.type === "EXTRACT"
          ? { type: "EXTRACT", amount: Number(act.amount) }
          : { type: act.type },
      policyProof: { circuitVersion: "v1", publicInputsHash: hash },
      proof,
      public_signals: publicSignals,
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: idempotencyKeyFor(matchId, turn),
    };
  } catch (err) {
    console.error(`steal-the-vfy turn failed (match ${matchId} turn ${turn}):`, err.message);
    return holdResponse(envelopeCommitment);
  }
}

// ---------- HTTP server ----------

const server = http.createServer((req, res) => {
  (async () => {
    if (req.method === "GET" && req.url === "/health") {
      return sendJson(res, 200, { ok: true });
    }
    if (req.method !== "POST" || req.url !== "/agent") {
      return sendJson(res, 404, { ok: false, error: "not_found" });
    }
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const rawBody = Buffer.concat(chunks);

    // Verify the signature over the RAW body before any parsing.
    if (!signatureValid(rawBody, req.headers["x-agent-games-signature"])) {
      return sendJson(res, 401, { ok: false, error: "invalid_signature" });
    }
    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString("utf8"));
    } catch {
      return sendJson(res, 400, { ok: false, error: "invalid_json" });
    }

    if (envelope.type === "agent-games.preflight.v1") {
      return sendJson(res, 200, { ok: true, protocolVersion: "v1" });
    }
    if (envelope.type === "agent-games.proof-gatekeeper.v1") {
      try {
        return sendJson(res, 200, await handleGatekeeper(envelope));
      } catch (err) {
        console.error("gatekeeper handler error:", err);
        return sendJson(res, 400, { ok: false, error: "bad_gatekeeper_task" });
      }
    }
    if (envelope.eventId === "steal-the-vfy") {
      return sendJson(res, 200, await handleStealTheVfy(envelope));
    }
    return sendJson(res, 400, { ok: false, error: "unsupported_envelope" });
  })().catch((err) => {
    console.error("request error:", err);
    if (!res.headersSent) sendJson(res, 500, { ok: false, error: "internal_error" });
  });
});

const PORT = Number(process.env.PORT || 8080);
server.listen(PORT, () => {
  console.log(`agent-games agent listening on :${PORT} (POST /agent)`);
});
