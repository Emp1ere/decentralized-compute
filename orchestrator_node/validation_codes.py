REJECT_CODES = {
    "JOB_NOT_FOUND": "job.not_found",
    "JOB_FORBIDDEN": "job.forbidden",
    "JOB_CONTRACT_MISMATCH": "job.contract_mismatch",
    "JOB_EXPIRED": "job.expired",
    "JOB_ALREADY_REJECTED": "job.already_rejected",
    "JOB_ALREADY_REASSIGNED": "job.already_reassigned",
    "JOB_ALREADY_USED_OTHER_PROOF": "job.already_used_other_proof",
    "NONCE_REQUIRED": "verification.nonce_required",
    "PROOF_USED_OTHER_CLIENT": "verification.proof_used_other_client",
    "VERIFICATION_FAILED": "verification.failed",
    "REPLAY_ATTEMPT": "replay.attempt_detected",
    "REPLICATION_PENDING": "replication.pending",
    "REPLICATION_DISPUTED": "replication.disputed",
    "REPLICATION_REJECTED": "replication.rejected",
    "ESCROW_FAILED": "escrow.failed",
    "ESCROW_PENALIZED": "escrow.penalized",
    "CHALLENGE_DISABLED": "challenge.disabled",
    "CHALLENGE_WINDOW_EXPIRED": "challenge.window_expired",
    "CHALLENGE_ALREADY_OPEN": "challenge.already_open",
}

PENALTY_CODES = {
    "VERIFICATION_REJECT": "penalty.verification_reject",
    "REPLICATION_REJECT": "penalty.replication_reject",
    "CHALLENGE_REJECT": "penalty.challenge_reject",
}


def error_payload(*, code_key, message, extra=None):
    payload = {"error": message, "code": REJECT_CODES.get(code_key, code_key)}
    if isinstance(extra, dict):
        payload.update(extra)
    return payload
