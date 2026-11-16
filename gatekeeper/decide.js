// Proof Gatekeeper decision logic — the documented 7-trap checklist.
// The circuit enforces the same evaluation: a decision that disagrees with
// the circuit fails witness generation, so this logic must match exactly.
// Boundaries were confirmed by probing the circuit itself (probe-boundary.js,
// 2026-11-16): expiry is inclusive (current == expiry is EXPIRED), threshold
// and amount caps are inclusive (equality is VALID).
//
// Order (first failing trap wins):
//   VK_SUBSTITUTION    proof_vk != registered_vk
//   PROOF_REUSED       proof_tx already seen under a DIFFERENT task_id
//                      (a retry of the same task_id is not a reuse — the
//                      server answers retries from its response cache)
//   THRESHOLD_MISMATCH public_balance < minimum   (== minimum is VALID)
//   EXPIRED_CONDITION  current_block >= expiry_block (== is EXPIRED)
//   RECIPIENT_MISMATCH recipient != condition_recipient (case-insensitive)
//   AMOUNT_OVERFLOW    amount > max_transfer      (== max is VALID)
//   else VALID_CONDITION -> APPROVE
function decide(task, seenProofTx) {
  const registeredVk = String(task.registered_vk || '').toLowerCase();
  const proofVk = String(task.proof_vk || '').toLowerCase();
  if (proofVk !== registeredVk) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  }

  const proofTx = String(task.proof_tx || '').toLowerCase();
  const taskId = String(task.task_id || '');
  if (proofTx && seenProofTx) {
    const prev = seenProofTx[proofTx];
    if (prev !== undefined && prev !== taskId) {
      return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
    }
  }

  if (BigInt(task.public_balance) < BigInt(task.minimum)) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  }
  if (BigInt(task.current_block) >= BigInt(task.expiry_block)) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  }
  if (String(task.recipient || '').toLowerCase() !== String(task.condition_recipient || '').toLowerCase()) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }
  if (BigInt(task.amount) > BigInt(task.max_transfer)) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  }
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

module.exports = { decide };
