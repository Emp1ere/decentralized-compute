#!/usr/bin/env python3
"""
10 сквозных транзакций DSCM chaincode (Phase 1b).
Вызовы через Fabric Sidecar HTTP API.
Запуск: python test_chaincode_flows.py [--base-url http://localhost:7051]
"""
import argparse
import json
import sys
import uuid

import httpx

BASE_URL = "http://localhost:7051"


def invoke(base: str, contract: str, fn: str, args: list) -> dict:
    r = httpx.post(
        f"{base}/chaincode/invoke",
        json={"contract": contract, "function": fn, "args": [json.dumps(a) if isinstance(a, (dict, list, bool)) else str(a) for a in args]},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def query(base: str, contract: str, fn: str, args=None) -> dict:
    args = args or []
    args_json = json.dumps([json.dumps(a) if isinstance(a, (dict, list, bool)) else str(a) for a in args])
    r = httpx.get(
        f"{base}/chaincode/query",
        params={"contract": contract, "function": fn, "args": args_json},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()


def run_flows(base: str) -> list[tuple[str, bool, str]]:
    results = []
    cid = f"c-{uuid.uuid4().hex[:8]}"
    wid = "worker-001"
    jid = f"job-{uuid.uuid4().hex[:6]}"

    def ok(name: str, data: dict) -> None:
        results.append((name, "error" not in data, data.get("error", data.get("result", ""))[:80]))

    # 1. listContract
    try:
        d = invoke(base, "Marketplace", "listContract", [{"contractId": cid, "owner": "org1", "spec": {"type": "cpu"}}])
        ok("1.listContract", d)
    except Exception as e:
        results.append(("1.listContract", False, str(e)[:80]))

    # 2. getAvailableContracts
    try:
        d = query(base, "Marketplace", "getAvailableContracts", [])
        ok("2.getAvailableContracts", d)
    except Exception as e:
        results.append(("2.getAvailableContracts", False, str(e)[:80]))

    # 3. claimContract
    try:
        d = invoke(base, "Marketplace", "claimContract", [cid, wid])
        ok("3.claimContract", d)
    except Exception as e:
        results.append(("3.claimContract", False, str(e)[:80]))

    # 4. activateContract
    try:
        d = invoke(base, "Contract", "activateContract", [cid])
        ok("4.activateContract", d)
    except Exception as e:
        results.append(("4.activateContract", False, str(e)[:80]))

    # 5. submitWork
    try:
        d = invoke(base, "Contract", "submitWork", [cid, jid, "hash-abc123"])
        ok("5.submitWork", d)
    except Exception as e:
        results.append(("5.submitWork", False, str(e)[:80]))

    # 6. verifyWork
    try:
        d = invoke(base, "Contract", "verifyWork", [cid, jid])
        ok("6.verifyWork", d)
    except Exception as e:
        results.append(("6.verifyWork", False, str(e)[:80]))

    # 7. recordResult (Reputation)
    try:
        d = invoke(base, "Reputation", "recordResult", [wid, cid, True])
        ok("7.recordResult", d)
    except Exception as e:
        results.append(("7.recordResult", False, str(e)[:80]))

    # 8. completeContract
    try:
        d = invoke(base, "Contract", "completeContract", [cid])
        ok("8.completeContract", d)
    except Exception as e:
        results.append(("8.completeContract", False, str(e)[:80]))

    # 9. triggerPayout
    try:
        d = invoke(base, "EscrowTrigger", "triggerPayout", [jid, wid, 100])
        ok("9.triggerPayout", d)
    except Exception as e:
        results.append(("9.triggerPayout", False, str(e)[:80]))

    # 10. getReputation
    try:
        d = query(base, "Reputation", "getReputation", [wid])
        ok("10.getReputation", d)
    except Exception as e:
        results.append(("10.getReputation", False, str(e)[:80]))

    return results


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base-url", default=BASE_URL, help="Sidecar base URL")
    args = p.parse_args()
    base = args.base_url.rstrip("/")

    # Health check
    try:
        r = httpx.get(f"{base}/health", timeout=5)
        health = r.json()
        if health.get("mode") == "stub":
            print("WARNING: Sidecar in stub mode (Fabric not configured)")
    except Exception as e:
        print(f"Sidecar unreachable: {e}")
        sys.exit(1)

    print("Running 10 chaincode flows...")
    results = run_flows(base)
    failed = sum(1 for _, ok_, _ in results if not ok_)
    for name, ok_, msg in results:
        status = "OK" if ok_ else "FAIL"
        print(f"  [{status}] {name}: {msg}")
    print(f"\n{len(results) - failed}/{len(results)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
