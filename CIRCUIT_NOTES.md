# Circuit reverse-engineering notes (zkVerify Agent Games)

Signal names were discovered by building a witness calculator with
`circom_runtime` and probing `getInputSignalSize(fnvHash(name))` over
vocabulary candidates until the counts matched `getInputSize()`. Semantics
were then read from the wasm decompile (`wasm-decompile` of the `*_run`
functions) and every rule below was confirmed empirically against the
witness calculator.

## gatekeeper.wasm — template GatekeeperEvaluation

Inputs (13 total; all public except `salt`):

| slot | name | notes |
|---|---|---|
| out | — | `Poseidon([salt, taskId])` |
| 1 | registeredVkHash | |
| 2 | proofVkHash | |
| 3 | minimum | |
| 4 | publicBalance | |
| 5 | expiryBlock | |
| 6 | currentBlock | |
| 7 | recipient | |
| 8 | conditionRecipient | |
| 9 | amount | |
| 10 | maxTransfer | |
| 11 | decision | 1 = approve, 0 = reject |
| 12 | taskId | |
| private | salt | only private input |

Circuit decision (single AND, asserted equal to `decision`):

```
decision == (registeredVkHash == proofVkHash)
         && (publicBalance >= minimum)
         && (expiryBlock > currentBlock)        // STRICTLY greater
         && (recipient == conditionRecipient)
         && (amount <= maxTransfer)
         && decision in {0, 1}
```

Note: the expiry check is strict — at `currentBlock == expiryBlock` the
circuit only accepts REJECT. Proof reuse is NOT checked in-circuit (no
proofTx input); it is a platform/agent-level rule.

## vfy-policy.wasm — template VfyPolicyProof

Inputs (17 total; public = first 9):

| slot | name | notes |
|---|---|---|
| out | — | `Poseidon([matchId, turnNumber, circuitVersion])` |
| 1 | commitment | `Poseidon([strategyParams[0..7], salt])` |
| 2 | matchId | |
| 3 | turnNumber | |
| 4 | selfBalance | |
| 5 | opponentBalance | |
| 6 | action | 0 HOLD, 1 FORTIFY, 2 EXTRACT |
| 7 | amount | |
| 8 | circuitVersion | |
| private | strategyParams[8], salt | |

Constraints (assert lines in the template):

```
commitment == Poseidon([p0, p1, p2, p3, p4, p5, p6, p7, salt])   // salt LAST
p4 == p5 == p6 == p7 == 0
1 <= p0 <= 10
p3 in {0, 1}
action == (selfBalance < p1 ? 1 : 0)
        + ((opponentBalance > p2 && p3 == 0 && selfBalance >= p1) ? 2 : 0)
action == 2  =>  amount == p0
action != 2  =>  amount == 0
```

So the committed policy structure is fixed; only four parameters are free:
p0 = extract amount, p1 = fortify-when-self-below, p2 =
extract-when-opponent-above, p3 = extract-disabled flag. The fortified-until
turn fields from the game state are NOT circuit inputs and cannot influence
the committed policy.
