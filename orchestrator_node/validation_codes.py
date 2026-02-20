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

USER_FRIENDLY_MESSAGES = {
    "JOB_NOT_FOUND": "Задача не найдена или уже устарела. Запросите новую задачу.",
    "JOB_FORBIDDEN": "Эта задача выдана другому исполнителю.",
    "JOB_CONTRACT_MISMATCH": "Задача и контракт не совпадают.",
    "JOB_EXPIRED": "Время выполнения задачи истекло. Запросите новую задачу.",
    "JOB_ALREADY_REJECTED": "Задача уже отклонена и не может быть отправлена повторно.",
    "JOB_ALREADY_REASSIGNED": "Задача уже переиздана другому исполнителю.",
    "JOB_ALREADY_USED_OTHER_PROOF": "Для этой задачи уже отправлен другой результат.",
    "NONCE_REQUIRED": "Нужен nonce для проверки результата.",
    "PROOF_USED_OTHER_CLIENT": "Этот proof уже использован другим исполнителем.",
    "VERIFICATION_FAILED": "Проверка результата не пройдена.",
    "REPLAY_ATTEMPT": "Повторная отправка той же попытки заблокирована (anti-replay).",
    "REPLICATION_PENDING": "Результат принят, ожидается кворум репликации.",
    "REPLICATION_DISPUTED": "Обнаружен спор по репликации. Откройте challenge или дождитесь решения.",
    "REPLICATION_REJECTED": "Результат отклонен репликацией.",
    "ESCROW_FAILED": "Операция escrow завершилась ошибкой.",
    "ESCROW_PENALIZED": "Применен штраф escrow.",
    "CHALLENGE_DISABLED": "Для этой задачи challenge сейчас недоступен.",
    "CHALLENGE_WINDOW_EXPIRED": "Окно challenge уже закрыто.",
    "CHALLENGE_ALREADY_OPEN": "По задаче уже открыт challenge.",
}

PENALTY_CODES = {
    "VERIFICATION_REJECT": "penalty.verification_reject",
    "REPLICATION_REJECT": "penalty.replication_reject",
    "CHALLENGE_REJECT": "penalty.challenge_reject",
}


def error_payload(*, code_key, message, extra=None):
    payload = {
        "error": message,
        "code": REJECT_CODES.get(code_key, code_key),
        "user_message": USER_FRIENDLY_MESSAGES.get(code_key, message),
    }
    if isinstance(extra, dict):
        payload.update(extra)
    return payload
