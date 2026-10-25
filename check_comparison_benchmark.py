"""Targeted checks for timing boundaries, scheduling and failure statistics.

Uses a fake nanosecond clock, not performance evidence; no legacy test entry.
"""
from pathlib import Path
import json
import math
import benchmark_comparison as b


def require(value, message):
    if not value:
        raise RuntimeError(message)


def clock_checks():
    ticks = iter([100, 137, 200, 253])
    runner = b.TimedRunner(lambda: next(ticks))
    context = b.h.PhaseContext("test", "test", 0, "issue")
    sentinel = object()
    require(runner(context, lambda: sentinel) is sentinel, "return identity")
    def bad():
        raise ValueError("fixture")
    try:
        runner(context, bad)
    except ValueError:
        pass
    else:
        raise RuntimeError("error swallowed")
    require([x["elapsed_ns"] for x in runner.records] == [37, 53], "fake clock boundaries")
    require(runner.records[1]["call_status"] == "raised", "failure timing retained")
    return {"unchanged_return": True, "exception_propagated_and_timed": True}


def schedule_checks():
    plan = list(b.schedule(20, 200))
    require(len(plan) == 2200, "sample budget")
    for c in b.h.CONFIGURATIONS:
        for partition, expected in (("warmup", 20), ("formal", 200)):
            subset = [x for x in plan if x[0] == partition and x[3] == c]
            require(len(subset) == expected, "counts/config")
        require(all(sum(x[2] == p for x in plan if x[0] == "formal" and x[3] == c) == 20 for p in range(10)), "balanced order")
    require(all(x[0] == "warmup" for x in plan[:200]), "warmup before measurement")
    return {"records": 2200, "warmup_per_config": 20, "formal_per_config": 200, "position_balance": True}


def statistics_checks():
    d = b.distribution([1000, 2000, 3000])
    require(d["mean_ns"] == d["median_ns"] == 2000 and d["sample_sd_ns"] == 1000 and math.isclose(d["p95_ns"],2900), "known stats")
    require(b.distribution([])["mean_ns"] is None and b.distribution([3])["sample_sd_ns"] is None, "empty and singleton")
    config = b.h.CONFIGURATIONS[0].id
    def row(ok, timings):
        return {"partition":"formal", "config_id":config, "success":ok, "timings":timings}
    rows = [row(True, [{"phase":"issue","elapsed_ns":1000,"call_status":"returned"}]),
            row(False,[{"phase":"issue","elapsed_ns":9000,"call_status":"raised"}]), row(False,[])]
    out = b.summarize(rows)["rows"][0]
    issue = out["phases"]["issue"]
    require(out["formal_trials"] == 3 and out["formal_failed"] == 2, "failures retained")
    require(issue["attempted"] == 2 and issue["not_timed"] == 1, "skipped vs attempt")
    require(issue["successful_trial_samples"]["mean_ns"] == 1000 and issue["all_attempted_samples"]["mean_ns"] == 5000, "failure populations distinct")
    return {"hand_calculated_statistics": True, "failures_and_skips_preserved": True, "no_trimming": True}


def integration_checks():
    original = b.TimedRunner
    counter = 0
    def fake():
        nonlocal counter
        counter += 10
        return counter
    b.TimedRunner = lambda: original(fake)
    try:
        row = b.run_one(b.h.CONFIGURATIONS[1], "preflight-fake-clock", 0, 0, 0)
    finally:
        b.TimedRunner = original
    require(row["success"], "integrated harness and diagnostics")
    require([x["phase"] for x in row["timings"]] == list(b.PHASES), "all eight boundaries")
    require(all(x["elapsed_ns"] == 10 for x in row["timings"]), "fake-clock evidence only")
    require(json.loads(json.dumps(row))["success"], "raw sample JSON serializable")
    require(row["trial"]["private_trace_summary"]["nonce"], "trace summary retained")
    return {"eight_phases": True, "fake_clock_only": True, "real_harness_P256_PV_flow": True, "serialization": True}


def main():
    results = []
    for label, operation in (("timer",clock_checks),("schedule",schedule_checks),
                             ("statistics",statistics_checks),("integration",integration_checks)):
        try:
            results.append({"id":label,"status":"PASS","evidence":operation()})
        except Exception as exc:
            results.append({"id":label,"status":"FAIL","error":str(exc)})
    failed = sum(x["status"] != "PASS" for x in results)
    report = {"task":"W3-COMP-BENCH-preflight", "checks":results,"total":4,"passed":4-failed,"failed":failed,
              "timing_values_are_fake_fixtures":True,"legacy_suites_executed":False}
    Path(__file__).with_name("comparison_benchmark_verification_results.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report))
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
