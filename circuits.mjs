// Circuit helpers: Poseidon, Groth16 proving, and the field conversions the
// Agent Games protocol needs.
//
// Signal maps (discovered empirically via circom_runtime fnvHash probes and
// confirmed against the decompiled wasm templates):
//
// gatekeeper (getInputSize 13, nPublic 13 — every input is public except salt):
//   public signals in order:
//     [0]  out = Poseidon([salt, taskId])
//     [1]  registeredVkHash   [2] proofVkHash        [3] minimum
//     [4]  publicBalance      [5] expiryBlock        [6] currentBlock
//     [7]  recipient          [8] conditionRecipient [9] amount
//     [10] maxTransfer        [11] decision (1 = approve, 0 = reject)
//     [12] taskId
//   private: salt
//   circuit decision = (registeredVkHash == proofVkHash)
//                      && (publicBalance >= minimum)
//                      && (expiryBlock > currentBlock)      // strict!
//                      && (recipient == conditionRecipient)
//                      && (amount <= maxTransfer)
//
// vfy-policy (getInputSize 17, nPublic 9):
//   public signals in order:
//     [0] out = Poseidon([matchId, turnNumber, circuitVersion])
//     [1] commitment  [2] matchId  [3] turnNumber  [4] selfBalance
//     [5] opponentBalance  [6] action  [7] amount  [8] circuitVersion
//   private: strategyParams[8], salt
//   commitment = Poseidon([strategyParams[0..7], salt])

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { keccak256, concat, numberToHex } from "viem";

const require = createRequire(import.meta.url);
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");

const AGENT_DIR = path.dirname(fileURLToPath(import.meta.url));
export const CIRCUITS_DIR = process.env.CIRCUITS_DIR || path.join(AGENT_DIR, "..", "circuits");

export const CIRCUIT_FILES = {
  gatekeeper: {
    wasm: path.join(CIRCUITS_DIR, "gatekeeper.wasm"),
    zkey: path.join(CIRCUITS_DIR, "gatekeeper_final.zkey"),
    vk: path.join(CIRCUITS_DIR, "gatekeeper_vk.json"),
  },
  vfyPolicy: {
    wasm: path.join(CIRCUITS_DIR, "vfy-policy.wasm"),
    zkey: path.join(CIRCUITS_DIR, "vfy-policy_final.zkey"),
    vk: path.join(CIRCUITS_DIR, "vfy-policy_vk.json"),
  },
};

// BN128 scalar field prime.
export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let poseidonPromise = null;
export function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

/** Poseidon hash over an array of BigInt-able values, returned as BigInt. */
export async function poseidonHash(values) {
  const poseidon = await getPoseidon();
  const out = poseidon(values.map((v) => BigInt(v)));
  return BigInt(poseidon.F.toString(out));
}

/** strategy commitment = Poseidon([params[0..7], salt]) */
export async function strategyCommitment(params, salt) {
  return poseidonHash([...params.map(BigInt), BigInt(salt)]);
}

// Serialize proof generation: snarkjs fullProve is CPU-bound; a simple queue
// keeps concurrent tasks from interleaving wasm work.
let proveChain = Promise.resolve();
function withProveLock(fn) {
  const run = proveChain.then(fn, fn);
  proveChain = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

export function proveGatekeeper(input) {
  return withProveLock(() =>
    snarkjs.groth16.fullProve(input, CIRCUIT_FILES.gatekeeper.wasm, CIRCUIT_FILES.gatekeeper.zkey),
  );
}

export function proveVfyPolicy(input) {
  return withProveLock(() =>
    snarkjs.groth16.fullProve(input, CIRCUIT_FILES.vfyPolicy.wasm, CIRCUIT_FILES.vfyPolicy.zkey),
  );
}

export async function verifyProof(kind, vkJson, publicSignals, proof) {
  return snarkjs.groth16.verify(vkJson, publicSignals, proof);
}

export function loadVk(kind) {
  return JSON.parse(fs.readFileSync(CIRCUIT_FILES[kind].vk, "utf8"));
}

/** Parse an env-style integer: 0x-prefixed = hex, otherwise decimal. */
export function parseFieldInt(value, name) {
  if (value === undefined || value === null || value === "") {
    throw new Error(`${name} is not set`);
  }
  const s = String(value).trim();
  const v = BigInt(s);
  if (v < 0n || v >= FIELD_PRIME) throw new Error(`${name} is outside the BN128 field`);
  return v;
}

/**
 * Convert a gatekeeper envelope task_id to the circuit's taskId field element.
 * UNCERTAIN: the platform's exact conversion is not documented. Conventions:
 *   "0x…" hex string -> its integer value
 *   all digits       -> its integer value
 *   anything else    -> keccak256(utf8(task_id)) mod p
 * (The guide's example id "gk_8d31_…" is truncated, so the real format — and
 * therefore the platform's conversion — cannot be confirmed locally.)
 */
export function taskIdToField(taskId) {
  const s = String(taskId);
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s) % FIELD_PRIME;
  if (/^\d+$/.test(s)) return BigInt(s) % FIELD_PRIME;
  return BigInt(keccak256(Buffer.from(s, "utf8"))) % FIELD_PRIME;
}

/**
 * Deterministic per-task gatekeeper salt, derived from the HMAC secret so
 * retried tasks (same task_id) reproduce identical proof inputs.
 * salt is a private circuit input; any field element is valid.
 */
export function gatekeeperSalt(secret, taskId) {
  const digest = keccak256(Buffer.from(`agent-games/gatekeeper-salt:${secret}:${taskId}`, "utf8"));
  return BigInt(digest) % FIELD_PRIME;
}

/** UUID (matchId) -> field element: hex of the dash-less UUID, per the guide. */
export function matchIdToField(matchId) {
  return BigInt("0x" + String(matchId).replace(/-/g, ""));
}

/**
 * Steal the VFY publicInputsHash, exactly per the build guide:
 * keccak256 of the eight fields, each as a 32-byte big-endian word:
 * commitment, matchId, turn, selfBalance, opponentBalance, actionCode,
 * amount, circuitVersion.
 */
export function publicInputsHash({ commitment, matchId, turn, selfBalance, opponentBalance, actionCode, amount, circuitVersion }) {
  const word = (v) => numberToHex(BigInt(v), { size: 32 });
  return keccak256(
    concat([
      word(commitment),
      word(matchIdToField(matchId)),
      word(turn),
      word(selfBalance),
      word(opponentBalance),
      word(actionCode),
      word(amount),
      word(circuitVersion),
    ]),
  );
}

/** Deterministic UUID-shaped idempotency key, unique per (matchId, turn). */
export function idempotencyKeyFor(matchId, turn) {
  const h = keccak256(Buffer.from(`agent-games/vfy:${matchId}:${turn}`, "utf8")).slice(2);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
}
