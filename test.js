// Local end-to-end test for the gatekeeper server.
// Starts the server on a test port with a throwaway HMAC secret, then runs:
//   health, preflight (signed), valid APPROVE + local proof verify,
//   every trap type, bad signature (401), idempotent replay, malformed JSON.
// Usage: node test.js
const { spawn } = require('child_process');
const crypto = require('crypto');
const path = require('path');

const PORT = 18080;
const SECRET = 'test-secret-do-not-use-in-production';
const BASE = `http://127.0.0.1:${PORT}`;
const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const OTHER_VK = '0xa4c1b8ff00000000000000000000000000000000000000000000000000000000';
const ADDR = '0xDe42000000000000000000000000000000009f01';
const ADDR2 = '0x1111111111111111111111111111111111111111';

function sign(body) {
  return crypto.createHmac('sha256', SECRET).update(body).digest('hex');
}

async function post(pathname, obj, sigOverride) {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  const sig = sigOverride === undefined ? sign(body) : sigOverride;
  if (sig) headers['x-agent-games-signature'] = sig;
  const res = await fetch(BASE + pathname, { method: 'POST', headers, body });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* non-json */ }
  return { status: res.status, json, text, sigHeader: res.headers.get('x-agent-games-signature') };
}

function taskEnvelope(taskId, input) {
  return { type: 'agent-games.proof-gatekeeper.v1', task_id: taskId, mode: 'practice', input };
}

function baseInput(overrides = {}) {
  return {
    registered_vk: VK,
    proof_vk: VK,
    minimum: '1000',
    public_balance: '1460',
    expiry_block: 19842201,
    current_block: 19832000,
    recipient: ADDR,
    condition_recipient: ADDR,
    amount: '500',
    max_transfer: '1000',
    proof_tx: '0xa4c1000000000000000000000000000000000000000000000000000000000001',
    ...overrides,
  };
}

let failures = 0;
function check(label, cond, extra = '') {
  console.log((cond ? 'PASS' : 'FAIL') + '  ' + label + (extra ? ' — ' + extra : ''));
  if (!cond) failures++;
}

async function waitHealth(tries = 60) {
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(BASE + '/health');
      if (res.ok) return await res.json();
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error('server did not come up');
}

(async () => {
  const server = spawn(process.execPath, [path.join(__dirname, 'server.js')], {
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: SECRET,
      STATE_FILE: path.join(__dirname, 'state.test.json'),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stdout.on('data', (d) => process.stdout.write('[srv] ' + d));
  server.stderr.on('data', (d) => process.stderr.write('[srv:err] ' + d));
  try {
    const health = await waitHealth();
    check('health ok', health.ok === true && health.hmacConfigured === true, JSON.stringify(health.selfTest));
    // Wait for the startup self-test to finish (it proves a task, ~seconds).
    for (let i = 0; i < 60 && String(health.selfTest) === 'pending'; i++) {
      await new Promise((r) => setTimeout(r, 2000));
      const h = await (await fetch(BASE + '/health')).json();
      if (String(h.selfTest) !== 'pending') { health.selfTest = h.selfTest; break; }
    }
    check('startup self-test PASS', String(health.selfTest).startsWith('PASS'), String(health.selfTest));

    // Preflight (signed)
    const pre = await post('/gatekeeper', { type: 'agent-games.preflight.v1', nonce: 'abc123' });
    check('preflight 200 + {ok, v1}', pre.status === 200 && pre.json.ok === true && pre.json.protocolVersion === 'v1');
    check('preflight response signed', typeof pre.sigHeader === 'string' && pre.sigHeader === sign(JSON.stringify(pre.json)));

    // Bad signature -> 401
    const bad = await post('/gatekeeper', { type: 'agent-games.preflight.v1' }, 'deadbeef');
    check('bad signature -> 401', bad.status === 401);

    // Malformed JSON -> 400
    const malformed = await post('/gatekeeper', '{not json', sign('{not json'));
    check('malformed JSON -> 400', malformed.status === 400);

    // Valid task -> APPROVE with verifying proof
    const { verifyLocally } = require('./lib/snark');
    const valid = await post('/gatekeeper', taskEnvelope('gk_test_valid', baseInput()));
    check('valid task APPROVE', valid.status === 200 && valid.json.decision === 'APPROVE' && valid.json.reason_code === 'VALID_CONDITION');
    check('valid task has proof + 13 signals', Array.isArray(valid.json.proof && valid.json.proof.pi_a) && Array.isArray(valid.json.public_signals) && valid.json.public_signals.length === 13);
    const proofOk = valid.json.proof ? await verifyLocally(valid.json.public_signals, valid.json.proof) : false;
    check('valid task proof verifies locally', proofOk === true);

    // Idempotent replay: same task_id returns byte-identical body
    const replay = await post('/gatekeeper', taskEnvelope('gk_test_valid', baseInput()));
    check('idempotent replay identical', replay.text === valid.text);

    // Traps
    const traps = [
      ['VK_SUBSTITUTION', baseInput({ proof_vk: OTHER_VK, proof_tx: '0xa4c1000000000000000000000000000000000000000000000000000000000002' })],
      ['THRESHOLD_MISMATCH', baseInput({ public_balance: '999', proof_tx: '0xa4c1000000000000000000000000000000000000000000000000000000000003' })],
      ['EXPIRED_CONDITION', baseInput({ current_block: 19842201, proof_tx: '0xa4c1000000000000000000000000000000000000000000000000000000000004' })],
      ['RECIPIENT_MISMATCH', baseInput({ recipient: ADDR2, proof_tx: '0xa4c1000000000000000000000000000000000000000000000000000000000005' })],
      ['AMOUNT_OVERFLOW', baseInput({ amount: '1001', proof_tx: '0xa4c1000000000000000000000000000000000000000000000000000000000006' })],
    ];
    for (const [reason, input] of traps) {
      const r = await post('/gatekeeper', taskEnvelope('gk_test_' + reason.toLowerCase(), input));
      const ok = r.status === 200 && r.json.decision === 'REJECT' && r.json.reason_code === reason;
      const hasProof = Array.isArray(r.json.public_signals) && r.json.public_signals.length === 13;
      const vOk = hasProof ? await verifyLocally(r.json.public_signals, r.json.proof) : false;
      check(`trap ${reason}: REJECT + proof verifies`, ok && hasProof && vOk === true);
    }

    // PROOF_REUSED: same proof_tx as the valid task, different task_id
    const reused = await post('/gatekeeper', taskEnvelope('gk_test_reused', baseInput()));
    check('PROOF_REUSED: REJECT, no proof', reused.status === 200 && reused.json.decision === 'REJECT' && reused.json.reason_code === 'PROOF_REUSED' && !reused.json.proof);

    // Boundary: balance == minimum and amount == max are VALID
    const boundary = await post('/gatekeeper', taskEnvelope('gk_test_boundary', baseInput({ public_balance: '1000', amount: '1000', proof_tx: '0xa4c1000000000000000000000000000000000000000000000000000000000007' })));
    check('boundary balance==min, amount==max APPROVE', boundary.status === 200 && boundary.json.decision === 'APPROVE');

    console.log(failures === 0 ? '\nALL TESTS PASSED' : `\n${failures} TEST(S) FAILED`);
    process.exitCode = failures === 0 ? 0 : 1;
  } catch (e) {
    console.error('TEST HARNESS ERROR:', e);
    process.exitCode = 2;
  } finally {
    server.kill('SIGTERM');
    // snarkjs keeps the event loop alive after the run; exit explicitly.
    setTimeout(() => process.exit(process.exitCode || 0), 500);
  }
})();
