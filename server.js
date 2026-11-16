// Proof Gatekeeper agent — Agent Games Season 01 (zkVerify). Codet entry.
// Plain Node http server, no framework. Endpoints:
//   GET  /health     -> readiness incl. startup proof self-test result
//   POST /gatekeeper -> signed task envelope in, signed decision + proof out
//   POST /agent      -> alias of /gatekeeper
//
// Behaviour:
// - Inbound HMAC is verified over the RAW body before JSON parsing, when a
//   secret is configured (AGENT_GAMES_HMAC_SECRET from the dashboard's
//   Rotate Secret — never logged, never committed).
// - Every response is signed with x-agent-games-signature over its raw body.
// - Preflight envelopes {"type":"agent-games.preflight.v1"} are answered
//   {ok:true, protocolVersion:"v1"}.
// - Task envelopes wrap the condition fields in `input`; task_id stays at
//   envelope level. Retried task_ids return the byte-identical cached
//   response (idempotency).
// - PROOF_REUSED answers carry no proof (platform excludes them from the
//   reliability bonus). If proof generation ever fails or exceeds the 45s
//   internal budget, the decision is still returned without a proof rather
//   than timing out (fail visible, -2, instead of a hang).
// - Fail closed: any malformed task, timeout, or uncertainty means REJECT.
const http = require('http');
const fs = require('fs');
const path = require('path');
const { signatureFor, verifySignature } = require('./lib/hmac');
const { decide } = require('./gatekeeper/decide');
const { proveTask } = require('./gatekeeper/prove');
const { verifyLocally } = require('./lib/snark');
const { ensureCircuits } = require('./scripts/fetch-circuits');

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const HMAC_SECRET = (process.env.AGENT_GAMES_HMAC_SECRET || '').trim();
const HMAC_FORMAT = process.env.AGENT_GAMES_HMAC_FORMAT || 'hex';
const TASK_ID_MODE = process.env.GATEKEEPER_TASK_ID_MODE || 'keccak';
const PROOF_TIMEOUT_MS = Number(process.env.PROOF_TIMEOUT_MS || 45_000);
const STATE_FILE = process.env.STATE_FILE || path.join(__dirname, 'state.json');

const VK_HASH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const PREFLIGHT_TYPE = 'agent-games.preflight.v1';
const TASK_TYPE = 'agent-games.proof-gatekeeper.v1';

// --- persistent state: seen proof refs + cached responses (idempotency) ---
const state = { seenProofTx: {}, cachedResponses: {} };
try {
  const saved = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  if (saved && typeof saved === 'object') {
    Object.assign(state.seenProofTx, saved.seenProofTx || {});
    Object.assign(state.cachedResponses, saved.cachedResponses || {});
  }
} catch { /* no state file yet — start empty */ }

let saveTimer = null;
function saveState() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    try {
      fs.writeFileSync(STATE_FILE, JSON.stringify(state));
    } catch (e) {
      console.error('[state] could not persist state:', e.message);
    }
  }, 500);
}

// --- startup self-test: prove a synthetic valid task, verify locally ---
let selfTest = 'pending';
async function runSelfTest() {
  const task = {
    task_id: 'selftest_1',
    registered_vk: VK_HASH,
    proof_vk: VK_HASH,
    minimum: '1000',
    public_balance: '1460',
    expiry_block: '8430000',
    current_block: '8420000',
    recipient: '0xDe42000000000000000000000000000000009f01',
    condition_recipient: '0xDe42000000000000000000000000000000009f01',
    amount: '500',
    max_transfer: '1000',
    proof_tx: '0xselftest',
  };
  const t0 = Date.now();
  try {
    const { decision } = decide(task, state.seenProofTx);
    if (decision !== 'APPROVE') throw new Error('self-test decision was ' + decision);
    const { proof, publicSignals } = await proveTask(task, decision, TASK_ID_MODE);
    if (publicSignals.length !== 13) throw new Error('expected 13 public signals, got ' + publicSignals.length);
    const ok = await verifyLocally(publicSignals, proof);
    selfTest = ok ? `PASS (${Date.now() - t0}ms)` : 'FAIL (proof did not verify)';
  } catch (e) {
    selfTest = 'FAIL (' + e.message + ')';
  }
  console.log('[selftest] gatekeeper proof self-test:', selfTest);
}

function sendSigned(res, status, obj) {
  const body = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  if (HMAC_SECRET) {
    headers['x-agent-games-signature'] = signatureFor(HMAC_SECRET, body, HMAC_FORMAT);
  }
  res.writeHead(status, headers);
  res.end(body);
}

function sendRawSigned(res, status, body) {
  const headers = { 'content-type': 'application/json' };
  if (HMAC_SECRET) {
    headers['x-agent-games-signature'] = signatureFor(HMAC_SECRET, body, HMAC_FORMAT);
  }
  res.writeHead(status, headers);
  res.end(body);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');

  if (req.method === 'GET' && url.pathname === '/health') {
    return sendSigned(res, 200, {
      ok: true,
      agent: 'codet-gatekeeper',
      protocolVersion: 'v1',
      hmacConfigured: Boolean(HMAC_SECRET),
      taskIdMode: TASK_ID_MODE,
      selfTest,
      state: {
        seenProofTx: Object.keys(state.seenProofTx).length,
        cachedResponses: Object.keys(state.cachedResponses).length,
      },
    });
  }

  if (req.method === 'POST' && (url.pathname === '/gatekeeper' || url.pathname === '/agent')) {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 1_000_000) { req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', async () => {
      const raw = Buffer.concat(chunks);
      // 1. HMAC first, BEFORE parsing. Fail closed.
      if (HMAC_SECRET && !verifySignature(HMAC_SECRET, raw, req.headers['x-agent-games-signature'], HMAC_FORMAT)) {
        return sendSigned(res, 401, { ok: false, error: 'bad signature' });
      }
      let envelope;
      try {
        envelope = JSON.parse(raw.toString('utf8'));
      } catch {
        return sendSigned(res, 400, { ok: false, error: 'invalid json' });
      }
      // 2. Preflight handshake.
      if (envelope && envelope.type === PREFLIGHT_TYPE) {
        return sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
      }
      if (!envelope || envelope.type !== TASK_TYPE) {
        return sendSigned(res, 400, { ok: false, error: 'unexpected type: ' + String(envelope && envelope.type) });
      }
      try {
        const started = Date.now();
        // Platform envelopes wrap the condition fields in `input`; decide/prove
        // work on the flat shape (task_id stays at envelope level).
        const input = envelope && typeof envelope.input === 'object' && envelope.input ? envelope.input : null;
        if (!input || typeof envelope.task_id !== 'string' || !envelope.task_id) {
          return sendSigned(res, 200, { decision: 'REJECT', reason_code: 'INVALID_TASK' });
        }
        const flatTask = { ...input, task_id: envelope.task_id };
        // 3. Idempotency: same task_id -> same response (platform retries).
        const cached = state.cachedResponses[flatTask.task_id];
        if (cached) {
          console.log('[gatekeeper]', flatTask.task_id, 'idempotent replay');
          return sendRawSigned(res, 200, cached);
        }
        const { decision, reason_code } = decide(flatTask, state.seenProofTx);
        const out = { decision, reason_code };
        if (flatTask.proof_tx) out.proof_tx = flatTask.proof_tx;
        // 4. Prove the decision locally (except PROOF_REUSED: nothing to submit).
        if (reason_code !== 'PROOF_REUSED') {
          try {
            const work = proveTask(flatTask, decision, TASK_ID_MODE);
            const timer = new Promise((_, reject) =>
              setTimeout(() => reject(new Error('proof timeout')), PROOF_TIMEOUT_MS));
            const { proof, publicSignals } = await Promise.race([work, timer]);
            out.proof = proof;
            out.public_signals = publicSignals;
          } catch (e) {
            console.error('[gatekeeper] proof failed for', flatTask.task_id, e.message);
            out.proof_error = 'proof generation failed';
          }
        }
        // 5. Record the reference as seen + cache the response, then answer signed.
        if (flatTask.proof_tx) {
          const key = String(flatTask.proof_tx).toLowerCase();
          if (!(key in state.seenProofTx)) state.seenProofTx[key] = flatTask.task_id;
        }
        const body = JSON.stringify(out);
        state.cachedResponses[flatTask.task_id] = body;
        saveState();
        console.log('[gatekeeper]', flatTask.task_id, decision, reason_code, Date.now() - started + 'ms');
        return sendRawSigned(res, 200, body);
      } catch (e) {
        console.error('[gatekeeper] handler error', e);
        return sendSigned(res, 200, { decision: 'REJECT', reason_code: 'INVALID_TASK' });
      }
    });
    return;
  }

  return sendSigned(res, 404, { ok: false, error: 'not found' });
});

server.requestTimeout = 55_000;
server.headersTimeout = 60_000;

ensureCircuits()
  .then(() => {
    server.listen(PORT, HOST, () => {
      console.log(`[gatekeeper] listening on ${HOST}:${PORT} (hmac ${HMAC_SECRET ? 'on' : 'OFF — set AGENT_GAMES_HMAC_SECRET before going live'})`);
      runSelfTest();
    });
  })
  .catch((e) => {
    console.error('[circuits] could not prepare circuit artifacts:', e.message);
    process.exit(1);
  });
