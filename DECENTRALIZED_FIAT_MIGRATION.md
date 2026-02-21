# Decentralized Compute + Fiat Settlement (3-phase migration)

This document describes the target architecture for this repository branch.

**См. также:** [DSCM v2 ТЗ](DSCM_v2_final.docx), [ARCHITECTURE.md](ARCHITECTURE.md), [ROADMAP.md](ROADMAP.md).

## Why desktop-agent stays

Desktop Agent remains a core component. It evolves from "task executor" to
"execution + policy-aware participant":

- fetches jobs with validation and escrow policy metadata;
- collects and uploads deterministic outputs/artifacts;
- supports replicated/challengeable validation modes;
- keeps user-friendly controls (schedule, throttling, profile selection).

## Phase 1 (current)

- Keep existing fiat ledger and payout rails.
- Introduce explicit contract policy payload:
  - `validation_policy`: `mode`, `replication_factor`, `challenge_window_seconds`
  - `escrow_policy`: `enabled`, `worker_collateral`, `penalty_percent_on_reject`
- Expose policy in issued task spec (non-breaking for old agents).
- Keep settlement logic unchanged (policy is persisted and visible, not enforced yet).

## Phase 2

- Add replicated verification flow:
  - same workunit can be assigned to `N` workers according to `replication_factor`.
  - compare outputs and mark canonical result.
- Add challenge window and dispute endpoints:
  - claim/challenge/resolve lifecycle.
- Introduce escrow holds in fiat ledger:
  - lock collateral on assignment;
  - release on success;
  - apply penalty on confirmed bad result.

## Phase 3

- Partial decentralization of validation and assignment:
  - multi-orchestrator coordinator behavior hardened;
  - policy-driven validator selection;
  - stronger anti-Sybil/reputation weighting for workers and validators.
- Keep fiat settlement through regulated payment rails.
- Add operator SLOs:
  - reject rate,
  - challenge success ratio,
  - reassignment rate,
  - settlement latency.

## Compatibility notes

- Old clients continue to work: default deterministic mode + escrow disabled.
- New policy fields are optional and safe defaults are always applied.
