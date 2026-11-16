// Gatekeeper proof generation.
// Circuit inputs (13, probed from the compiled wasm; the official docs do
// not publish signal names): taskId, minimum, publicBalance, expiryBlock,
// currentBlock, recipient, conditionRecipient, amount, maxTransfer,
// registeredVkHash, proofVkHash, salt (private), decision (1=APPROVE, 0=REJECT).
// Public signals (13): Poseidon(salt, taskId) commitment first, then the 12
// public fields in output-then-public order.
//
// taskId mapping: the envelope task_id is a string (e.g. "gk_24_9d1") and the
// circuit needs a field element. Default mode "keccak":
// keccak256(utf8(task_id)) mod p. Alternatives via GATEKEEPER_TASK_ID_MODE:
// "numeric" (digits of the id), "hex" (hex chars), "utf8bytes" (BigInt of the
// raw UTF-8 bytes). Confirm against a practice task after registration;
// switch if the platform rejects the proof.
const crypto = require('crypto');
const { toField, keccak256ModP, FIELD_PRIME } = require('../lib/field');
const { prove } = require('../lib/snark');

function taskIdToField(taskId, mode) {
  const id = String(taskId || '');
  if (mode === 'numeric') {
    const digits = id.replace(/\D/g, '');
    return digits ? toField(BigInt(digits)) : 0n;
  }
  if (mode === 'hex') {
    const hex = id.replace(/[^0-9a-fA-F]/g, '');
    return hex ? toField(BigInt('0x' + hex)) : 0n;
  }
  if (mode === 'utf8bytes') {
    return toField(BigInt('0x' + Buffer.from(id, 'utf8').toString('hex')));
  }
  return keccak256ModP([Buffer.from(id, 'utf8')]);
}

function reduceHex(hex) {
  return (BigInt(hex) % FIELD_PRIME).toString();
}

function buildInput(task, decision, taskIdMode) {
  return {
    registeredVkHash: reduceHex(String(task.registered_vk)),
    proofVkHash: reduceHex(String(task.proof_vk)),
    minimum: String(task.minimum),
    publicBalance: String(task.public_balance),
    expiryBlock: String(task.expiry_block),
    currentBlock: String(task.current_block),
    recipient: BigInt(String(task.recipient)).toString(),
    conditionRecipient: BigInt(String(task.condition_recipient)).toString(),
    amount: String(task.amount),
    maxTransfer: String(task.max_transfer),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToField(task.task_id, taskIdMode).toString(),
    salt: BigInt('0x' + crypto.randomBytes(32).toString('hex')).toString(),
  };
}

async function proveTask(task, decision, taskIdMode) {
  return prove(buildInput(task, decision, taskIdMode));
}

module.exports = { taskIdToField, buildInput, proveTask };
