// Steal the VFY strategy — the parameters committed to on the dashboard and
// enforced by the vfy-policy circuit.
//
// Circuit semantics (reverse-engineered from vfy-policy.wasm and verified
// empirically against the witness calculator):
//   commitment == Poseidon([p0, p1, p2, p3, p4, p5, p6, p7, salt])
//   p4 == p5 == p6 == p7 == 0
//   1 <= p0 <= 10
//   p3 in {0, 1}
//   expectedAction =
//       selfBalance < p1                                  -> 1 (FORTIFY)
//       opponentBalance > p2 && p3 == 0                   -> 2 (EXTRACT, amount = p0)
//       otherwise                                         -> 0 (HOLD, amount = 0)
//   amount must equal p0 when action == EXTRACT, and 0 otherwise.
//
// So only the first four parameters are free:
//   p0 = EXTRACT_AMOUNT               how much to steal on an EXTRACT turn
//   p1 = FORTIFY_WHEN_SELF_BELOW      fortify while our balance is below this
//   p2 = EXTRACT_WHEN_OPPONENT_ABOVE extract while opponent balance exceeds this
//   p3 = EXTRACT_DISABLED             0 = extraction enabled, 1 = never extract

export const STRATEGY_PARAMS = Object.freeze([
  10n, // p0 EXTRACT_AMOUNT: steal the maximum the game allows
  60n, // p1 FORTIFY_WHEN_SELF_BELOW: play defence while below 60 VFY
  40n, // p2 EXTRACT_WHEN_OPPONENT_ABOVE: attack whenever opponent holds > 40
  0n,  // p3 EXTRACT_DISABLED: extraction enabled
  0n,  // p4..p7 must be zero (circuit assert)
  0n,
  0n,
  0n,
]);

export const ACTION_CODES = Object.freeze({ HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n });
export const ACTION_NAMES = Object.freeze(["HOLD", "FORTIFY", "EXTRACT"]);

/**
 * Pure deterministic policy — mirrors the vfy-policy circuit exactly.
 * state: { selfBalance, opponentBalance } (BigInt-able values)
 * params: array of 8 BigInts (defaults to STRATEGY_PARAMS)
 * returns { type, code, amount } with amount a BigInt (p0 for EXTRACT else 0).
 */
export function policy(state, params = STRATEGY_PARAMS) {
  const self = BigInt(state.selfBalance);
  const opp = BigInt(state.opponentBalance);
  const [p0, p1, p2, p3] = params;
  if (self < p1) return { type: "FORTIFY", code: ACTION_CODES.FORTIFY, amount: 0n };
  if (opp > p2 && p3 === 0n) return { type: "EXTRACT", code: ACTION_CODES.EXTRACT, amount: p0 };
  return { type: "HOLD", code: ACTION_CODES.HOLD, amount: 0n };
}

/** Validate params against the circuit's hard constraints. Throws on violation. */
export function assertValidParams(params) {
  if (!Array.isArray(params) || params.length !== 8) {
    throw new Error("strategy params must be an array of 8 values");
  }
  const [p0, , , p3, p4, p5, p6, p7] = params.map(BigInt);
  if (p0 < 1n || p0 > 10n) throw new Error("p0 (extract amount) must satisfy 1 <= p0 <= 10");
  if (p3 !== 0n && p3 !== 1n) throw new Error("p3 (extract disabled) must be 0 or 1");
  if (p4 !== 0n || p5 !== 0n || p6 !== 0n || p7 !== 0n) {
    throw new Error("p4..p7 must be 0 (circuit assert)");
  }
}
