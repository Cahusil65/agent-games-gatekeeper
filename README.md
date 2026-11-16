# codet-gatekeeper

Proof Gatekeeper agent for **zkVerify Agent Games Season 01** — codet entry.

A public HTTPS endpoint. The platform POSTs a signed task envelope describing
a transfer guarded by a condition; the agent answers `APPROVE` or `REJECT`
plus a Groth16 zero-knowledge proof of that decision, generated locally with
`snarkjs` and the tournament's own gatekeeper circuit. The platform re-verifies
the proof against its registered verification key.

## Protocol

- `GET /health` — readiness: HMAC configured, startup proof self-test, state sizes.
- `POST /gatekeeper` (alias `POST /agent`) — signed task envelopes.
  - Inbound HMAC-SHA256 verified over the **raw body** before parsing
    (`x-agent-games-signature` header); bad signature → 401.
  - Preflight `{"type":"agent-games.preflight.v1"}` → `{ok:true, protocolVersion:"v1"}`.
  - Task `{"type":"agent-games.proof-gatekeeper.v1"}` → `{decision, reason_code,
    proof_tx, proof, public_signals}`, signed. Condition fields arrive inside
    `input`; `task_id` stays at envelope level.
  - Retried `task_id`s return the byte-identical cached response.
  - `PROOF_REUSED` answers carry no proof (excluded from the reliability bonus).
  - Proof generation has a 45s internal budget (platform deadline is 60s); on
    failure the decision is still returned without a proof. Fail closed: any
    malformed task, timeout, or uncertainty means REJECT.

## Decision checklist (first failing trap wins)

| Reason | Rule |
|---|---|
| `VK_SUBSTITUTION` | `proof_vk != registered_vk` |
| `PROOF_REUSED` | `proof_tx` seen under a different `task_id` |
| `THRESHOLD_MISMATCH` | `public_balance < minimum` (equality is valid) |
| `EXPIRED_CONDITION` | `current_block >= expiry_block` (equality is expired) |
| `RECIPIENT_MISMATCH` | `recipient != condition_recipient` (case-insensitive) |
| `AMOUNT_OVERFLOW` | `amount > max_transfer` (equality is valid) |
| `VALID_CONDITION` | all pass → APPROVE |

Boundaries were confirmed by probing the circuit itself (`probe-boundary.js`):
the circuit refuses to build a witness for a wrong decision, so the checklist
must be a bit-exact mirror of the circuit's logic.

Circuit inputs (13): `taskId, minimum, publicBalance, expiryBlock,
currentBlock, recipient, conditionRecipient, amount, maxTransfer,
registeredVkHash, proofVkHash, salt, decision`. Task IDs map to field elements
as `keccak256(utf8(task_id)) mod p` (override with `GATEKEEPER_TASK_ID_MODE`:
`keccak` / `numeric` / `hex` / `utf8bytes`). Verification-key hash:
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.

## Run locally

```bash
npm install
npm test        # end-to-end: health, preflight, valid + all traps, replay, 401
AGENT_GAMES_HMAC_SECRET=<secret from dashboard Rotate Secret> npm start
```

Circuit artifacts (`gatekeeper.wasm`, `gatekeeper_final.zkey`) are downloaded
from `agentgames.zkverify.io/circuits` at boot if missing; they are not
committed to git.

## Deploy (Railway)

1. Create a Railway project from this repo (Nixpacks; `railway.json` included).
2. Set env var `AGENT_GAMES_HMAC_SECRET` to the platform-issued secret
   (dashboard → Rotate Secret; shown once). **Apply the change / redeploy** —
   a staged variable is not live until deployed.
3. Generate a public domain; register `https://<domain>/gatekeeper` as the
   agent endpoint on the Agent Games dashboard.
4. Check `/health` reports `selfTest: PASS` and `hmacConfigured: true`,
   then run the signed preflight and a practice task from the dashboard.

## Config

| Env var | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | Listen port |
| `AGENT_GAMES_HMAC_SECRET` | — | Platform HMAC secret (required live) |
| `AGENT_GAMES_HMAC_FORMAT` | `hex` | `hex` or `sha256=` |
| `GATEKEEPER_TASK_ID_MODE` | `keccak` | task_id → field encoding |
| `PROOF_TIMEOUT_MS` | `45000` | Internal proof budget |
| `STATE_FILE` | `state.json` | Seen proof refs + cached responses |

No private keys, no wallet, no spending: the only secret this agent holds is
the platform HMAC secret.
