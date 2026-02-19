import json
import os
import threading
import time
import uuid


DATA_DIR = os.environ.get("AUTH_DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))
RUNTIME_FILE = os.path.join(DATA_DIR, "decentralized_runtime.json")
_lock = threading.Lock()


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _now():
    return int(time.time())


def _blank_state():
    return {
        "replication_groups": {},
        "escrow_holds": {},
        "challenges": {},
        "validator_verdicts": {},
        "replay_index": {},
        "reputations": {},
        "disputes": {},
        "governance": {
            "admitted_nodes": {},
            "admitted_validators": {},
            "protocol_rollout": None,
        },
    }


def _load_state():
    _ensure_dir()
    if not os.path.exists(RUNTIME_FILE):
        return _blank_state()
    try:
        with open(RUNTIME_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return _blank_state()
        state = _blank_state()
        for key in state:
            value = data.get(key)
            if isinstance(value, dict):
                state[key] = value
        return state
    except (json.JSONDecodeError, OSError):
        return _blank_state()


def _save_state(state):
    _ensure_dir()
    with open(RUNTIME_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def acquire_replication_group(*, contract_id, client_id, replication_factor, quorum_threshold=None):
    factor = max(1, int(replication_factor))
    threshold = int(quorum_threshold) if quorum_threshold is not None else _default_quorum_threshold(factor)
    threshold = max(1, min(factor, threshold))
    with _lock:
        state = _load_state()
        groups = state["replication_groups"]
        now = _now()
        for group in groups.values():
            if group.get("contract_id") != contract_id:
                continue
            if group.get("status") != "open":
                continue
            issued = group.get("issued_clients") or []
            if client_id in issued:
                continue
            if len(issued) >= factor:
                continue
            issued.append(client_id)
            group["issued_clients"] = issued
            group["updated_at"] = now
            _save_state(state)
            return {
                "group_id": group["group_id"],
                "task_seed": int(group["task_seed"]),
                "replication_factor": int(group["replication_factor"]),
                "quorum_threshold": int(group.get("quorum_threshold", _default_quorum_threshold(factor))),
            }

        group_id = f"rg-{uuid.uuid4().hex[:16]}"
        task_seed = uuid.uuid4().int & ((1 << 64) - 1)
        created = {
            "group_id": group_id,
            "contract_id": contract_id,
            "task_seed": int(task_seed),
            "replication_factor": factor,
            "quorum_threshold": threshold,
            "issued_clients": [client_id],
            "submissions": [],
            "status": "open",
            "winner_manifest_hash": None,
            "resolution_reason": None,
            "created_at": now,
            "updated_at": now,
        }
        groups[group_id] = created
        _save_state(state)
        return {
            "group_id": group_id,
            "task_seed": int(task_seed),
            "replication_factor": factor,
            "quorum_threshold": threshold,
        }


def _default_quorum_threshold(replication_factor):
    factor = max(1, int(replication_factor))
    return (factor // 2) + 1


def register_replication_submission(*, group_id, job_id, client_id, result_data, artifact_manifest_hash, attempt_id):
    with _lock:
        state = _load_state()
        group = state["replication_groups"].get(group_id)
        if not group:
            return {"status": "pending", "reason": "group_not_found", "code": "replication.group_not_found"}
        submissions = group.get("submissions") or []
        for sub in submissions:
            if sub.get("job_id") == job_id and int(sub.get("attempt_id", 0) or 0) == int(attempt_id):
                return _build_replication_decision(group, client_id, result_data, artifact_manifest_hash)
        submissions.append(
            {
                "job_id": job_id,
                "client_id": client_id,
                "result_data": result_data or "",
                "artifact_manifest_hash": artifact_manifest_hash or "",
                "attempt_id": int(attempt_id),
                "created_at": _now(),
            }
        )
        group["submissions"] = submissions
        _resolve_group_if_ready(group)
        group["updated_at"] = _now()
        _save_state(state)
        return _build_replication_decision(group, client_id, result_data, artifact_manifest_hash)


def _resolve_group_if_ready(group):
    submissions = group.get("submissions") or []
    required = max(1, int(group.get("replication_factor", 1)))
    quorum_threshold = max(1, min(required, int(group.get("quorum_threshold", _default_quorum_threshold(required)))))
    counts = {}
    for sub in submissions:
        key = sub.get("artifact_manifest_hash") or ""
        counts[key] = counts.get(key, 0) + 1
    winner_hash = None
    winner_votes = 0
    for key, votes in counts.items():
        if votes > winner_votes:
            winner_hash = key
            winner_votes = votes
    if winner_hash and winner_votes >= quorum_threshold:
        group["status"] = "resolved"
        group["winner_manifest_hash"] = winner_hash
        group["resolution_reason"] = "quorum_reached"
        return
    if len(submissions) < required:
        return
    group["status"] = "disputed"
    group["winner_manifest_hash"] = None
    group["resolution_reason"] = "quorum_not_reached"


def _build_replication_decision(group, client_id, result_data, artifact_manifest_hash):
    status = group.get("status")
    winner = group.get("winner_manifest_hash")
    submissions = group.get("submissions") or []
    required = max(1, int(group.get("replication_factor", 1)))
    quorum_threshold = max(1, min(required, int(group.get("quorum_threshold", _default_quorum_threshold(required)))))
    if status == "open":
        return {
            "status": "pending",
            "received_submissions": len(submissions),
            "required_submissions": required,
            "quorum_threshold": quorum_threshold,
            "group_id": group.get("group_id"),
            "code": "replication.pending",
        }
    if status == "resolved":
        return {
            "status": "accepted" if (artifact_manifest_hash or "") == (winner or "") else "rejected",
            "group_id": group.get("group_id"),
            "winner_manifest_hash": winner,
            "received_submissions": len(submissions),
            "required_submissions": required,
            "quorum_threshold": quorum_threshold,
            "code": "replication.accepted" if (artifact_manifest_hash or "") == (winner or "") else "replication.rejected",
        }
    if status == "disputed":
        return {
            "status": "disputed",
            "group_id": group.get("group_id"),
            "received_submissions": len(submissions),
            "required_submissions": required,
            "quorum_threshold": quorum_threshold,
            "code": "replication.disputed",
        }
    return {
        "status": "pending",
        "received_submissions": len(submissions),
        "required_submissions": required,
        "quorum_threshold": quorum_threshold,
        "group_id": group.get("group_id"),
        "code": "replication.pending",
    }


def create_escrow_hold(
    *,
    job_id,
    contract_id,
    provider_client_id,
    worker_client_id,
    currency,
    amount,
):
    hold_amount = max(0, int(amount))
    if hold_amount <= 0:
        return None
    with _lock:
        state = _load_state()
        holds = state["escrow_holds"]
        for hold in holds.values():
            if hold.get("job_id") == job_id:
                return dict(hold)
        hold_id = f"esc-{uuid.uuid4().hex[:16]}"
        now = _now()
        hold = {
            "hold_id": hold_id,
            "job_id": job_id,
            "contract_id": contract_id,
            "provider_client_id": provider_client_id,
            "worker_client_id": worker_client_id,
            "currency": currency,
            "amount": hold_amount,
            "status": "held",
            "created_at": now,
            "updated_at": now,
        }
        holds[hold_id] = hold
        _save_state(state)
        return dict(hold)


def get_escrow_hold_by_job(job_id):
    with _lock:
        state = _load_state()
        for hold in state["escrow_holds"].values():
            if hold.get("job_id") == job_id:
                return dict(hold)
    return None


def release_escrow_hold(job_id):
    with _lock:
        state = _load_state()
        for hold in state["escrow_holds"].values():
            if hold.get("job_id") != job_id:
                continue
            if hold.get("status") != "held":
                return dict(hold)
            hold["status"] = "released"
            hold["updated_at"] = _now()
            _save_state(state)
            return dict(hold)
    return None


def penalize_escrow_hold(job_id, *, penalty_percent):
    with _lock:
        state = _load_state()
        for hold in state["escrow_holds"].values():
            if hold.get("job_id") != job_id:
                continue
            if hold.get("status") != "held":
                return dict(hold)
            pct = max(0, min(100, int(penalty_percent)))
            penalty_amount = int((int(hold.get("amount", 0)) * pct) / 100)
            if pct > 0 and penalty_amount == 0 and int(hold.get("amount", 0)) > 0:
                penalty_amount = 1
            hold["status"] = "penalized"
            hold["penalty_percent"] = pct
            hold["penalty_amount"] = penalty_amount
            hold["updated_at"] = _now()
            _save_state(state)
            return dict(hold)
    return None


def open_challenge(*, job_id, contract_id, opened_by, reason, window_seconds):
    with _lock:
        state = _load_state()
        challenges = state["challenges"]
        for challenge in challenges.values():
            if challenge.get("job_id") == job_id and challenge.get("status") == "open":
                return None, "Challenge is already open"
        now = _now()
        challenge_id = f"chg-{uuid.uuid4().hex[:16]}"
        record = {
            "challenge_id": challenge_id,
            "job_id": job_id,
            "contract_id": contract_id,
            "opened_by": opened_by,
            "reason": (reason or "").strip()[:1000],
            "status": "open",
            "decision": None,
            "opened_at": now,
            "deadline_at": now + max(0, int(window_seconds)),
            "resolved_at": None,
            "resolved_by": None,
        }
        challenges[challenge_id] = record
        _save_state(state)
        return dict(record), None


def get_open_challenge_by_job(job_id):
    with _lock:
        state = _load_state()
        for record in state["challenges"].values():
            if record.get("job_id") == job_id and record.get("status") == "open":
                return dict(record)
    return None


def get_challenge(challenge_id):
    with _lock:
        state = _load_state()
        challenge = state["challenges"].get(challenge_id)
        if not challenge:
            return None
        return dict(challenge)


def resolve_challenge(*, challenge_id, resolved_by, decision):
    with _lock:
        state = _load_state()
        challenge = state["challenges"].get(challenge_id)
        if not challenge:
            return None, "Challenge not found"
        if challenge.get("status") != "open":
            return None, "Challenge already resolved"
        normalized = (decision or "").strip().lower()
        if normalized not in {"accept_worker", "reject_worker"}:
            return None, "Unsupported decision"
        challenge["status"] = "resolved"
        challenge["decision"] = normalized
        challenge["resolved_by"] = resolved_by
        challenge["resolved_at"] = _now()
        _save_state(state)
        return dict(challenge), None


def check_and_register_replay(*, replay_key, job_id, attempt_id, artifact_manifest_hash):
    if not replay_key:
        return False, None
    with _lock:
        state = _load_state()
        replay_index = state["replay_index"]
        existing = replay_index.get(replay_key)
        if existing:
            return True, dict(existing)
        replay_index[replay_key] = {
            "replay_key": replay_key,
            "job_id": job_id,
            "attempt_id": int(attempt_id),
            "artifact_manifest_hash": artifact_manifest_hash or "",
            "created_at": _now(),
        }
        _save_state(state)
        return False, None


def add_validator_verdict(*, group_id, validator_client_id, decision, reason, weight=1):
    normalized_decision = (decision or "").strip().lower()
    if normalized_decision not in {"accept", "reject"}:
        return None, "Unsupported validator decision"
    verdict_weight = max(1, int(weight))
    with _lock:
        state = _load_state()
        group = state["replication_groups"].get(group_id)
        if not group:
            return None, "Replication group not found"
        verdicts = state["validator_verdicts"].setdefault(group_id, [])
        for row in verdicts:
            if row.get("validator_client_id") == validator_client_id:
                row["decision"] = normalized_decision
                row["reason"] = (reason or "").strip()[:1000]
                row["weight"] = verdict_weight
                row["updated_at"] = _now()
                _save_state(state)
                return dict(row), None
        verdict = {
            "validator_client_id": validator_client_id,
            "decision": normalized_decision,
            "reason": (reason or "").strip()[:1000],
            "weight": verdict_weight,
            "created_at": _now(),
            "updated_at": _now(),
        }
        verdicts.append(verdict)
        _save_state(state)
        return dict(verdict), None


def summarize_validator_verdicts(group_id):
    with _lock:
        state = _load_state()
        verdicts = state["validator_verdicts"].get(group_id) or []
        accept_weight = 0
        reject_weight = 0
        for row in verdicts:
            if row.get("decision") == "accept":
                accept_weight += int(row.get("weight", 1) or 1)
            if row.get("decision") == "reject":
                reject_weight += int(row.get("weight", 1) or 1)
        return {
            "group_id": group_id,
            "accept_weight": accept_weight,
            "reject_weight": reject_weight,
            "verdicts": [dict(v) for v in verdicts],
        }


def bump_reputation(*, actor_id, role, delta, reason):
    normalized_role = (role or "").strip().lower()
    if normalized_role not in {"worker", "validator"}:
        normalized_role = "worker"
    with _lock:
        state = _load_state()
        rep_key = f"{normalized_role}:{actor_id}"
        row = state["reputations"].get(rep_key) or {
            "actor_id": actor_id,
            "role": normalized_role,
            "score": 0,
            "events": [],
            "updated_at": _now(),
        }
        row["score"] = int(row.get("score", 0)) + int(delta)
        events = row.get("events") or []
        events.append({"delta": int(delta), "reason": (reason or "").strip()[:200], "at": _now()})
        row["events"] = events[-50:]
        row["updated_at"] = _now()
        state["reputations"][rep_key] = row
        _save_state(state)
        return dict(row)


def get_reputation(*, actor_id, role):
    normalized_role = (role or "").strip().lower()
    if normalized_role not in {"worker", "validator"}:
        normalized_role = "worker"
    with _lock:
        state = _load_state()
        rep_key = f"{normalized_role}:{actor_id}"
        row = state["reputations"].get(rep_key)
        if not row:
            return {
                "actor_id": actor_id,
                "role": normalized_role,
                "score": 0,
                "events": [],
                "updated_at": None,
            }
        return dict(row)


DISPUTE_ALLOWED_TRANSITIONS = {
    "opened": {"start_review": "under_review", "cancel": "cancelled"},
    "under_review": {"resolve_accept": "resolved_accept", "resolve_reject": "resolved_reject"},
    "resolved_accept": {"open_appeal": "appealed"},
    "resolved_reject": {"open_appeal": "appealed"},
    "appealed": {"close_appeal_accept": "closed_accept", "close_appeal_reject": "closed_reject"},
}


def create_dispute(*, job_id, contract_id, opened_by, reason, review_deadline_seconds=3600, appeal_deadline_seconds=3600):
    with _lock:
        state = _load_state()
        now = _now()
        dispute_id = f"dsp-{uuid.uuid4().hex[:16]}"
        row = {
            "dispute_id": dispute_id,
            "job_id": job_id,
            "contract_id": contract_id,
            "opened_by": opened_by,
            "reason": (reason or "").strip()[:1000],
            "state": "opened",
            "review_deadline_at": now + max(0, int(review_deadline_seconds)),
            "appeal_deadline_at": now + max(0, int(review_deadline_seconds)) + max(0, int(appeal_deadline_seconds)),
            "events": [{"event": "create", "from_state": None, "to_state": "opened", "at": now, "by": opened_by}],
            "created_at": now,
            "updated_at": now,
        }
        state["disputes"][dispute_id] = row
        _save_state(state)
        return dict(row)


def get_dispute(dispute_id):
    with _lock:
        state = _load_state()
        row = state["disputes"].get(dispute_id)
        if not row:
            return None
        return dict(row)


def transition_dispute(*, dispute_id, event, actor_id, payload=None):
    with _lock:
        state = _load_state()
        row = state["disputes"].get(dispute_id)
        if not row:
            return None, "Dispute not found"
        current_state = row.get("state")
        next_state = (DISPUTE_ALLOWED_TRANSITIONS.get(current_state) or {}).get(event)
        if not next_state:
            return None, "Invalid dispute transition"
        now = _now()
        events = row.get("events") or []
        events.append(
            {
                "event": event,
                "from_state": current_state,
                "to_state": next_state,
                "at": now,
                "by": actor_id,
                "payload": payload if isinstance(payload, dict) else {},
            }
        )
        row["state"] = next_state
        row["events"] = events
        row["updated_at"] = now
        _save_state(state)
        return dict(row), None


def enforce_dispute_deadlines(now_ts_value=None):
    now = int(now_ts_value or _now())
    changed = []
    with _lock:
        state = _load_state()
        for dispute in state["disputes"].values():
            current = dispute.get("state")
            review_deadline = int(dispute.get("review_deadline_at", 0) or 0)
            appeal_deadline = int(dispute.get("appeal_deadline_at", 0) or 0)
            events = dispute.get("events") or []
            if current == "under_review" and review_deadline and now > review_deadline:
                events.append(
                    {
                        "event": "deadline_auto_resolve_reject",
                        "from_state": "under_review",
                        "to_state": "resolved_reject",
                        "at": now,
                        "by": "system",
                        "payload": {"reason": "review_deadline_expired"},
                    }
                )
                dispute["state"] = "resolved_reject"
                dispute["events"] = events
                dispute["updated_at"] = now
                changed.append(dispute.get("dispute_id"))
            if current in {"resolved_accept", "resolved_reject"} and appeal_deadline and now > appeal_deadline:
                final_state = "closed_accept" if current == "resolved_accept" else "closed_reject"
                events.append(
                    {
                        "event": "deadline_close_appeal_window",
                        "from_state": current,
                        "to_state": final_state,
                        "at": now,
                        "by": "system",
                        "payload": {"reason": "appeal_deadline_expired"},
                    }
                )
                dispute["state"] = final_state
                dispute["events"] = events
                dispute["updated_at"] = now
                changed.append(dispute.get("dispute_id"))
        if changed:
            _save_state(state)
    return changed


def governance_snapshot():
    with _lock:
        state = _load_state()
        return dict(state.get("governance") or {"admitted_nodes": {}, "protocol_rollout": None})


def governance_admit_node(*, node_id, admitted_by, node_meta=None):
    normalized = (node_id or "").strip()
    if not normalized:
        return None, "node_id is required"
    meta = node_meta if isinstance(node_meta, dict) else {}
    with _lock:
        state = _load_state()
        gov = state["governance"]
        nodes = gov["admitted_nodes"]
        rec = nodes.get(normalized) or {
            "node_id": normalized,
            "admitted_at": _now(),
            "admitted_by": admitted_by,
            "status": "admitted",
            "meta": {},
        }
        rec["status"] = "admitted"
        rec["admitted_by"] = admitted_by
        rec["admitted_at"] = rec.get("admitted_at") or _now()
        rec["meta"] = meta
        rec["updated_at"] = _now()
        nodes[normalized] = rec
        _save_state(state)
        return dict(rec), None


def governance_admit_validator(*, validator_client_id, admitted_by, validator_meta=None):
    normalized = (validator_client_id or "").strip()
    if not normalized:
        return None, "validator_client_id is required"
    meta = validator_meta if isinstance(validator_meta, dict) else {}
    with _lock:
        state = _load_state()
        gov = state["governance"]
        validators = gov["admitted_validators"]
        rec = validators.get(normalized) or {
            "validator_client_id": normalized,
            "admitted_at": _now(),
            "admitted_by": admitted_by,
            "status": "admitted",
            "meta": {},
        }
        rec["status"] = "admitted"
        rec["admitted_by"] = admitted_by
        rec["admitted_at"] = rec.get("admitted_at") or _now()
        rec["meta"] = meta
        rec["updated_at"] = _now()
        validators[normalized] = rec
        _save_state(state)
        return dict(rec), None


def governance_is_validator_admitted(*, validator_client_id):
    normalized = (validator_client_id or "").strip()
    if not normalized:
        return False
    with _lock:
        state = _load_state()
        rec = (state.get("governance") or {}).get("admitted_validators", {}).get(normalized)
        if not rec:
            return False
        return (rec.get("status") or "").strip() == "admitted"


def governance_propose_rollout(*, protocol_version, proposed_by, required_acks):
    version = (protocol_version or "").strip()
    if not version:
        return None, "protocol_version is required"
    req = max(1, int(required_acks))
    with _lock:
        state = _load_state()
        gov = state["governance"]
        gov["protocol_rollout"] = {
            "protocol_version": version,
            "proposed_by": proposed_by,
            "required_acks": req,
            "acks": [],
            "status": "proposed",
            "created_at": _now(),
            "updated_at": _now(),
        }
        _save_state(state)
        return dict(gov["protocol_rollout"]), None


def governance_ack_rollout(*, node_id):
    normalized = (node_id or "").strip()
    with _lock:
        state = _load_state()
        gov = state["governance"]
        rollout = gov.get("protocol_rollout")
        if not rollout:
            return None, "No active protocol rollout"
        acks = rollout.get("acks") or []
        if normalized and normalized not in acks:
            acks.append(normalized)
        rollout["acks"] = acks
        if len(acks) >= int(rollout.get("required_acks", 1) or 1):
            rollout["status"] = "ready"
        rollout["updated_at"] = _now()
        _save_state(state)
        return dict(rollout), None


def governance_finalize_rollout(*, finalized_by):
    with _lock:
        state = _load_state()
        gov = state["governance"]
        rollout = gov.get("protocol_rollout")
        if not rollout:
            return None, "No active protocol rollout"
        if rollout.get("status") != "ready":
            return None, "Rollout is not ready"
        rollout["status"] = "finalized"
        rollout["finalized_by"] = finalized_by
        rollout["finalized_at"] = _now()
        rollout["updated_at"] = _now()
        _save_state(state)
        return dict(rollout), None


def runtime_snapshot():
    with _lock:
        state = _load_state()
        groups = state.get("replication_groups") or {}
        challenges = state.get("challenges") or {}
        disputes = state.get("disputes") or {}
        statuses = {"open": 0, "resolved": 0, "disputed": 0}
        for row in groups.values():
            key = (row.get("status") or "open").strip()
            if key not in statuses:
                statuses[key] = 0
            statuses[key] += 1
        challenge_status = {"open": 0, "resolved": 0}
        for row in challenges.values():
            key = (row.get("status") or "open").strip()
            if key not in challenge_status:
                challenge_status[key] = 0
            challenge_status[key] += 1
        dispute_status = {}
        for row in disputes.values():
            key = (row.get("state") or "opened").strip()
            dispute_status[key] = dispute_status.get(key, 0) + 1
        return {
            "replication_groups_total": len(groups),
            "replication_groups_by_status": statuses,
            "challenges_total": len(challenges),
            "challenges_by_status": challenge_status,
            "disputes_total": len(disputes),
            "disputes_by_state": dispute_status,
            "replay_index_size": len(state.get("replay_index") or {}),
        }


def export_runtime_state():
    with _lock:
        state = _load_state()
        return json.loads(json.dumps(state))


def merge_runtime_state(remote_state):
    if not isinstance(remote_state, dict):
        return 0
    changed = 0
    with _lock:
        local = _load_state()
        sections = [
            "replication_groups",
            "escrow_holds",
            "challenges",
            "validator_verdicts",
            "replay_index",
            "reputations",
            "disputes",
        ]
        for section in sections:
            remote_map = remote_state.get(section)
            if not isinstance(remote_map, dict):
                continue
            local_map = local.get(section)
            if not isinstance(local_map, dict):
                continue
            for key, remote_item in remote_map.items():
                if not isinstance(remote_item, dict):
                    continue
                local_item = local_map.get(key)
                remote_updated = int(remote_item.get("updated_at", remote_item.get("created_at", 0)) or 0)
                local_updated = int((local_item or {}).get("updated_at", (local_item or {}).get("created_at", 0)) or 0)
                if local_item is None or remote_updated > local_updated:
                    local_map[key] = remote_item
                    changed += 1

        remote_gov = remote_state.get("governance")
        if isinstance(remote_gov, dict):
            local_gov = local.get("governance")
            if isinstance(local_gov, dict):
                for gov_section in ("admitted_nodes", "admitted_validators"):
                    remote_map = remote_gov.get(gov_section)
                    local_map = local_gov.get(gov_section)
                    if not isinstance(remote_map, dict) or not isinstance(local_map, dict):
                        continue
                    for key, remote_item in remote_map.items():
                        if not isinstance(remote_item, dict):
                            continue
                        local_item = local_map.get(key)
                        remote_updated = int(remote_item.get("updated_at", remote_item.get("admitted_at", 0)) or 0)
                        local_updated = int((local_item or {}).get("updated_at", (local_item or {}).get("admitted_at", 0)) or 0)
                        if local_item is None or remote_updated > local_updated:
                            local_map[key] = remote_item
                            changed += 1
                remote_rollout = remote_gov.get("protocol_rollout")
                local_rollout = local_gov.get("protocol_rollout")
                if isinstance(remote_rollout, dict):
                    remote_updated = int(remote_rollout.get("updated_at", remote_rollout.get("created_at", 0)) or 0)
                    local_updated = int((local_rollout or {}).get("updated_at", (local_rollout or {}).get("created_at", 0)) or 0)
                    if local_rollout is None or remote_updated > local_updated:
                        local_gov["protocol_rollout"] = remote_rollout
                        changed += 1

        if changed > 0:
            _save_state(local)
    return changed
