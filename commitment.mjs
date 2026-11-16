// Print the Steal the VFY strategy commitment for THIS agent:
//   commitment = Poseidon([strategyParams[0..7], salt])
// with STRATEGY_PARAMS from strategy.mjs and salt from env STRATEGY_SALT.
// Register this hash on the dashboard (My Agents -> Edit agent -> strategy
// commitment) before Swiss Round 1 pairing. Prints ONLY the hash (hex).
import { strategyCommitment, parseFieldInt } from "./circuits.mjs";
import { STRATEGY_PARAMS, assertValidParams } from "./strategy.mjs";

assertValidParams(STRATEGY_PARAMS);
const salt = parseFieldInt(process.env.STRATEGY_SALT, "STRATEGY_SALT");
const commitment = await strategyCommitment(STRATEGY_PARAMS, salt);
console.log("0x" + commitment.toString(16).padStart(64, "0"));
