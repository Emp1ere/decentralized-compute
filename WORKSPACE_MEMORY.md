# Workspace Memory (decentralized-compute)

This file captures the active context after creating the project copy from
`distributed-compute`, so future sessions can continue with the same intent.

## Branch/project intent

- Repository: `decentralized-compute`
- Goal: evolve current orchestrator-centric system into a
  decentralized-compute + fiat-settlement architecture.
- Keep fiat rails (RUB/USD/EUR) and UX practicality.
- Do not modify `distributed-compute` during this phase.

## Decisions already made

1. Keep Desktop Agent as a core component.
2. Move from simple execution client to policy-aware agent:
   - receives validation/escrow policy with tasks,
   - supports heavier workloads and adaptive scheduler behavior.
3. Keep 3 orchestrator nodes in ring topology for now.
4. Keep blockchain tab in dashboard as compact summary and route details to Explorer.
5. Introduce migration in 3 phases (documented in
   `DECENTRALIZED_FIAT_MIGRATION.md`).

## Implemented in this repo copy

- Added policy helpers:
  `orchestrator_node/decentralized_fiat_policy.py`
- Added contract policy ingestion in provider API:
  `validation_policy`, `escrow_policy`
- Added policy projection into task spec:
  `validation_policy`, `escrow_policy`
- Desktop agent now logs active validation/escrow policy per task.
- Added migration doc:
  `DECENTRALIZED_FIAT_MIGRATION.md`

## Next target (Phase 2)

1. Replicated verification path:
   - assign same workunit to N workers based on replication policy.
2. Challenge flow:
   - challenge window, challenge submit, resolve.
3. Fiat escrow lifecycle:
   - hold collateral on assignment,
   - release on success,
   - apply penalty on confirmed reject/dispute loss.
