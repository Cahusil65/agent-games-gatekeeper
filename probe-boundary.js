// Boundary probe: does the gatekeeper circuit treat currentBlock == expiryBlock
// as EXPIRED (decision must be 0) or VALID (decision may be 1)?
// The circuit is the referee: witness generation fails for a wrong decision.
const crypto = require('crypto');
const snarkjs = require('snarkjs');
const { keccak_256 } = require('js-sha3');

const P = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const WASM = __dirname + '/circuits/gatekeeper.wasm';
const ZKEY = __dirname + '/circuits/gatekeeper_final.zkey';

function base(decision, currentBlock, expiryBlock, extra = {}) {
  return {
    registeredVkHash: (BigInt(VK) % P).toString(),
    proofVkHash: (BigInt(VK) % P).toString(),
    minimum: '1000',
    publicBalance: '1460',
    expiryBlock: String(expiryBlock),
    currentBlock: String(currentBlock),
    recipient: BigInt('0xDe42000000000000000000000000000000009f01').toString(),
    conditionRecipient: BigInt('0xDe42000000000000000000000000000000009f01').toString(),
    amount: '500',
    maxTransfer: '1000',
    decision: String(decision),
    taskId: (BigInt('0x' + keccak_256(Buffer.from('probe-boundary', 'utf8'))) % P).toString(),
    salt: BigInt('0x' + crypto.randomBytes(32).toString('hex')).toString(),
    ...extra,
  };
}

async function attempt(label, input) {
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const vk = await snarkjs.zKey.exportVerificationKey(ZKEY);
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    console.log(label, '=> witness+proof OK, verify:', ok, '| nPublic:', publicSignals.length);
    return true;
  } catch (e) {
    console.log(label, '=> FAILED:', String(e.message).slice(0, 160));
    return false;
  }
}

(async () => {
  // Expiry boundary: current == expiry
  await attempt('expiry: current==expiry, decision=1 (APPROVE)', base(1, 100, 100));
  await attempt('expiry: current==expiry, decision=0 (REJECT) ', base(0, 100, 100));
  // Sanity: current < expiry, decision=1 must work; decision=0 must fail
  await attempt('sanity: current<expiry, decision=1 (APPROVE)', base(1, 99, 100));
  await attempt('sanity: current<expiry, decision=0 (REJECT) ', base(0, 99, 100));
  // Threshold boundary: balance == minimum, decision=1 must work
  await attempt('threshold: balance==minimum, decision=1', base(1, 99, 100, { publicBalance: '1000' }));
  // Amount boundary: amount == max, decision=1 must work
  await attempt('amount: amount==max, decision=1', base(1, 99, 100, { amount: '1000' }));
  // Trap: recipient mismatch + decision=1 must FAIL; decision=0 must work
  await attempt('trap: recipient mismatch, decision=1', base(1, 99, 100, { recipient: BigInt('0x1111111111111111111111111111111111111111').toString() }));
  await attempt('trap: recipient mismatch, decision=0', base(0, 99, 100, { recipient: BigInt('0x1111111111111111111111111111111111111111').toString() }));
})().then(() => process.exit(0)); // snarkjs keeps the event loop alive; exit explicitly
