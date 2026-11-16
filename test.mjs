// Local test suite for the Agent Games agent service.
// Spawns server.mjs with a TEST secret (never a real one), then exercises:
//   preflight, bad signatures, the guide's valid Gatekeeper task, every
//   Gatekeeper trap, proof reuse, the expiry boundary, three Steal the VFY
//   turns (EXTRACT / FORTIFY / HOLD), and the commitment script.
// Every returned proof is verified with snarkjs against the exported vks.

import { spawn, execFile } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { keccak256, concat, numberToHex } from "viem";
import {
  loadVk,
  verifyProof,
  strategyCommitment,
  poseidonHash,
  matchIdToField,
} from "./circuits.mjs";
import { STRATEGY_PARAMS } from "./strategy.mjs";

const AGENT_DIR = path.dirname(fileURLToPath(import.meta.url));
const execFileP = promisify(execFile);

const SECRET = "test-secret-0123456789";
const SALT = 424242n;
const PORT = 18099;
const BASE = `http://127.0.0.1:${PORT}`;
const SEEN_FILE = path.join(os.tmpdir(), `agent-games-test-seen-${process.pid}.json`);
fs.rmSync(SEEN_FILE, { force: true });

const GATEKEEPER_VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const RECIPIENT = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
const OTHER_RECIPIENT = "0x1111111111111111111111111111111111111111";

let failures = 0;
function check(name, cond, extra = "") {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!cond) failures++;
}

const sign = (raw) => crypto.createHmac("sha256", SECRET).update(raw).digest("hex");

async function postAgent(payload, { signature } = {}) {
  const raw = Buffer.from(JSON.stringify(payload), "utf8");
  const res = await fetch(`${BASE}/agent`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": signature ?? sign(raw),
    },
    body: raw,
    signal: AbortSignal.timeout(120000),
  });
  const text = await res.text();
  const respSig = res.headers.get("x-agent-games-signature");
  const sigOk = respSig === sign(Buffer.from(text, "utf8"));
  return { status: res.status, body: JSON.parse(text), sigOk };
}

// Independent publicInputsHash (does not reuse circuits.mjs on purpose).
function independentHash({ commitment, matchId, turn, selfBalance, opponentBalance, actionCode, amount }) {
  const word = (v) => numberToHex(BigInt(v), { size: 32 });
  return keccak256(
    concat([
      word(commitment),
      word(BigInt("0x" + matchId.replace(/-/g, ""))),
      word(turn),
      word(selfBalance),
      word(opponentBalance),
      word(actionCode),
      word(amount),
      word(1n),
    ]),
  );
}

let taskCounter = 0;
function gatekeeperTask(overrides = {}) {
  taskCounter += 1;
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: `gk_test_${taskCounter.toString(16).padStart(4, "0")}`,
    mode: "practice",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: GATEKEEPER_VK_HASH,
      proof_vk: GATEKEEPER_VK_HASH,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0xtx" + taskCounter.toString(16).padStart(8, "0"),
      ...overrides,
    },
  };
}

async function expectGatekeeper(name, task, { decision, reason, withProof }) {
  const { status, body, sigOk } = await postAgent(task);
  let ok = status === 200 && sigOk && body.decision === decision && body.reason_code === reason;
  let detail = `status=${status} decision=${body.decision} reason=${body.reason_code} respSig=${sigOk}`;
  if (withProof) {
    const hasProof = Boolean(body.proof && Array.isArray(body.public_signals));
    ok = ok && hasProof;
    if (hasProof) {
      const verified = await verifyProof("gatekeeper", gkVk, body.public_signals, body.proof);
      const decisionSignal = body.public_signals[11];
      ok = ok && verified && body.public_signals.length === 13 &&
        decisionSignal === (decision === "APPROVE" ? "1" : "0");
      detail += ` proofVerifies=${verified} nPublic=${body.public_signals.length} decisionSignal=${decisionSignal}`;
    } else detail += " proof=MISSING";
  } else {
    ok = ok && !("proof" in body);
    detail += ` proofAbsent=${!("proof" in body)}`;
  }
  check(name, ok, detail);
  return body;
}

function stealEnvelope({ selfBalance, opponentBalance, turn, commitment }) {
  return {
    protocolVersion: "v1",
    eventId: "steal-the-vfy",
    mode: "practice",
    matchId: "3f6d1c2e-9a4b-4e5f-8c7d-1a2b3c4d5e6f",
    turn,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 30000).toISOString(),
    state: {
      selfBalance,
      opponentBalance,
      selfFortifiedUntilTurn: 0,
      opponentFortifiedUntilTurn: 0,
    },
    strategyCommitment: { hash: "0x" + commitment.toString(16).padStart(64, "0") },
    resolverVersion: "v1",
    nonce: "n-" + turn,
  };
}

async function expectSteal(name, envelope, { type, amount, actionCode }) {
  const { status, body, sigOk } = await postAgent(envelope);
  let ok = status === 200 && sigOk && body.action?.type === type && body.matchId === envelope.matchId &&
    body.turn === envelope.turn && typeof body.agentTimestamp === "string" &&
    typeof body.idempotencyKey === "string" && body.idempotencyKey.length > 0;
  let detail = `status=${status} action=${JSON.stringify(body.action)} respSig=${sigOk}`;
  if (type === "EXTRACT") ok = ok && body.action.amount === amount;
  else ok = ok && !("amount" in (body.action ?? {}));
  const expectedHash = independentHash({
    commitment,
    matchId: envelope.matchId,
    turn: envelope.turn,
    selfBalance: envelope.state.selfBalance,
    opponentBalance: envelope.state.opponentBalance,
    actionCode,
    amount: type === "EXTRACT" ? amount : 0,
  });
  ok = ok && body.policyProof?.circuitVersion === "v1" && body.policyProof?.publicInputsHash === expectedHash;
  detail += ` hashMatches=${body.policyProof?.publicInputsHash === expectedHash}`;
  if (body.proof) {
    const verified = await verifyProof("vfyPolicy", vfyVk, body.public_signals, body.proof);
    const expectedOut = await poseidonHash([matchIdToField(envelope.matchId), BigInt(envelope.turn), 1n]);
    ok = ok && verified && body.public_signals.length === 9 &&
      body.public_signals[1] === commitment.toString() && body.public_signals[0] === expectedOut.toString();
    detail += ` proofVerifies=${verified} nPublic=${body.public_signals.length}`;
  } else {
    ok = false;
    detail += " proof=MISSING";
  }
  check(name, ok, detail);
  return body;
}

// ---------- boot server ----------
const server = spawn("node", [path.join(AGENT_DIR, "server.mjs")], {
  env: {
    ...process.env,
    AGENT_GAMES_HMAC_SECRET: SECRET,
    STRATEGY_SALT: SALT.toString(),
    PORT: String(PORT),
    SEEN_FILE,
  },
  stdio: ["ignore", "pipe", "pipe"],
});
server.stderr.on("data", (d) => process.stderr.write(`[server] ${d}`));
try {
  let up = false;
  for (let i = 0; i < 50 && !up; i++) {
    try {
      const r = await fetch(`${BASE}/health`);
      up = r.ok;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  if (!up) throw new Error("server did not come up");

  var gkVk = loadVk("gatekeeper");
  var vfyVk = loadVk("vfyPolicy");
  var commitment = await strategyCommitment(STRATEGY_PARAMS, SALT);

  // 1. Preflight
  {
    const { status, body, sigOk } = await postAgent({
      type: "agent-games.preflight.v1",
      agent_id: "test-agent",
      issued_at: new Date().toISOString(),
      nonce: "abc",
    });
    check("preflight", status === 200 && body.ok === true && body.protocolVersion === "v1" && sigOk,
      `status=${status} body=${JSON.stringify(body)} respSig=${sigOk}`);
  }

  // 2. Bad / missing signature
  {
    const raw = Buffer.from(JSON.stringify({ type: "agent-games.preflight.v1" }), "utf8");
    const bad = await fetch(`${BASE}/agent`, {
      method: "POST",
      headers: { "x-agent-games-signature": "0".repeat(64) },
      body: raw,
    });
    check("bad signature rejected", bad.status === 401, `status=${bad.status}`);
    const none = await fetch(`${BASE}/agent`, { method: "POST", body: raw });
    check("missing signature rejected", none.status === 401, `status=${none.status}`);
  }

  // 3. Gatekeeper: valid task -> APPROVE with verifying proof
  await expectGatekeeper("gatekeeper valid -> APPROVE", gatekeeperTask(), {
    decision: "APPROVE", reason: "VALID_CONDITION", withProof: true,
  });

  // 4. Traps
  await expectGatekeeper("trap vk substitution", gatekeeperTask({
    proof_vk: "0x0000000000000000000000000000000000000000000000000000000000000001",
  }), { decision: "REJECT", reason: "VK_SUBSTITUTION", withProof: true });

  await expectGatekeeper("trap threshold", gatekeeperTask({ public_balance: "900" }), {
    decision: "REJECT", reason: "THRESHOLD_MISMATCH", withProof: true,
  });

  await expectGatekeeper("trap expired", gatekeeperTask({ current_block: 8430001 }), {
    decision: "REJECT", reason: "EXPIRED_CONDITION", withProof: true,
  });

  await expectGatekeeper("boundary current == expiry", gatekeeperTask({ current_block: 8430000 }), {
    decision: "REJECT", reason: "EXPIRED_CONDITION", withProof: true,
  });

  await expectGatekeeper("trap recipient mismatch", gatekeeperTask({ recipient: OTHER_RECIPIENT }), {
    decision: "REJECT", reason: "RECIPIENT_MISMATCH", withProof: true,
  });

  await expectGatekeeper("trap amount overflow", gatekeeperTask({ amount: "1500" }), {
    decision: "REJECT", reason: "AMOUNT_OVERFLOW", withProof: true,
  });

  // 5. Proof reuse: same proof_tx twice -> second is PROOF_REUSED, no proof
  {
    const tx = "0xreuseddeadbeef";
    await expectGatekeeper("reuse: first use approves", gatekeeperTask({ proof_tx: tx }), {
      decision: "APPROVE", reason: "VALID_CONDITION", withProof: true,
    });
    await expectGatekeeper("reuse: second use rejected", gatekeeperTask({ proof_tx: tx }), {
      decision: "REJECT", reason: "PROOF_REUSED", withProof: false,
    });
  }

  // 6. Steal the VFY turns
  await expectSteal("steal EXTRACT", stealEnvelope({ selfBalance: 95, opponentBalance: 105, turn: 3, commitment }), {
    type: "EXTRACT", amount: 10, actionCode: 2,
  });
  await expectSteal("steal FORTIFY", stealEnvelope({ selfBalance: 50, opponentBalance: 105, turn: 4, commitment }), {
    type: "FORTIFY", actionCode: 1,
  });
  await expectSteal("steal HOLD", stealEnvelope({ selfBalance: 95, opponentBalance: 30, turn: 5, commitment }), {
    type: "HOLD", actionCode: 0,
  });

  // 7. Commitment script prints exactly Poseidon(params, salt)
  {
    const { stdout } = await execFileP("node", [path.join(AGENT_DIR, "commitment.mjs")], {
      env: { ...process.env, STRATEGY_SALT: SALT.toString() },
    });
    const expected = "0x" + commitment.toString(16).padStart(64, "0");
    check("commitment.mjs output", stdout.trim() === expected, `got=${stdout.trim()}`);
  }
} finally {
  server.kill("SIGTERM");
  fs.rmSync(SEEN_FILE, { force: true });
}

console.log(failures === 0 ? "\nALL TESTS PASSED" : `\n${failures} TEST(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
