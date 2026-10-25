"""CMP09 serial wall-time measurements around unchanged harness operations.

Fresh explicit session/setup per trial; all warmup, failures and outliers saved.
No security-time, constant-time, signature, GQ or native-W2-replay claim.
"""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import gc
import hashlib
import json
import math
import os
import statistics
import time

import comparison_harness as h

PHASES = ("group_setup", *h.TRIAL_PHASES)


def utc():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


class TimedRunner:
    """Exactly one call; clock surrounds the harness's once-wrapper.

    Record allocation/error formatting occurs after the ending clock read.
    Failed operations keep their actual elapsed time. No baseline subtraction.
    """
    def __init__(self, clock=time.perf_counter_ns):
        self.clock, self.records = clock, []

    def __call__(self, context, operation):
        start = self.clock()
        try:
            value = operation()
        except BaseException as exc:
            end = self.clock()
            self.records.append({"phase": context.phase, "elapsed_ns": end-start,
                                 "call_status": "raised", "error_type": type(exc).__name__})
            raise
        end = self.clock()
        self.records.append({"phase": context.phase, "elapsed_ns": end-start,
                             "call_status": "returned"})
        return value


def schedule(warmups, trials):
    for value in (warmups, trials):
        if type(value) is not int or value < 0:
            raise ValueError("nonnegative integer counts required")
    if trials < 1:
        raise ValueError("at least one formal trial required")
    configs = h.CONFIGURATIONS
    for partition, count in (("warmup", warmups), ("formal", trials)):
        for round_index in range(count):
            offset = round_index % len(configs)
            order = configs[offset:] + configs[:offset]
            for position, config in enumerate(order):
                yield partition, round_index, position, config


def diagnostics(session, result):
    """Outside timing: consistency checks, no new trust bypass or timing cache."""
    if not result.success:
        return {"status": "not-run", "reason": "trial did not complete successfully"}
    a, i = result.artifacts, session.instance
    service, (C, r) = a["service"], a["issuance"]
    tests = {
        "CA_public_matches_import": a["ca"].public == i.pub_encode(service.Y),
        "one_issuance_state": service.issued == {C},
        "response_state_matches": service._last_issuance_state["response"] == r,
        "request_state_matches": service._last_issuance_state["request"] == a["user"].request,
        "encoded_reconstruction_matches": a["reconstructed_public"] == i.pub_encode(service.recon(C)),
        "preimage_accepted": a["preimage_valid"] is True,
    }
    return {"status": "ok" if all(tests.values()) else "failed", "checks": tests}


def run_one(config, partition, round_index, position, sequence):
    runner = TimedRunner()
    session_id = f"CMP09/{partition}/{round_index}/{config.id}"
    session = h.HarnessSession(config, session_id=session_id, runner=runner,
                               bits_factory=h.OSBits())
    row = {"schema": "W3-COMP-sample-v1", "sequence": sequence,
           "partition": partition, "round": round_index, "position": position,
           "config_id": config.id, "session_id": session_id, "started_utc": utc()}
    result = None
    try:
        session.setup()
        result = session.run_trial(0)
        row["trial"] = result.summary()
        row["diagnostics"] = diagnostics(session, result)
        row["success"] = result.success and row["diagnostics"]["status"] == "ok"
    except Exception as exc:
        row.update(success=False, orchestration_error={"type": type(exc).__name__, "message": str(exc)})
        if result is not None:
            row["trial_ledger_fallback"] = [dict(v) for v in result.ledger]
    finally:
        row["timings"] = runner.records
        row["setup_ledger"] = [dict(v) for v in session.setup_ledger]
        row["finished_utc"] = utc()
    # Canonical PUBLIC setup metadata is not a complete pp wire format.
    try:
        public = session.public_setup()
        row["public_setup"] = public
        row["public_setup_sha256"] = hashlib.sha256(
            json.dumps(public, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    except Exception as exc:
        row.update(success=False, setup_metadata_error={"type": type(exc).__name__, "message": str(exc)})
    return row


def distribution(values):
    """Raw nanoseconds; sample SD, linear (n-1)*.95 percentile, no trimming."""
    if not values:
        return {"n": 0, "mean_ns": None, "sample_sd_ns": None, "median_ns": None,
                "p95_ns": None, "min_ns": None, "max_ns": None}
    ordered = sorted(values)
    index = .95 * (len(ordered)-1)
    lo, hi = math.floor(index), math.ceil(index)
    return {"n": len(values), "mean_ns": statistics.mean(values),
            "sample_sd_ns": statistics.stdev(values) if len(values) > 1 else None,
            "median_ns": statistics.median(values),
            "p95_ns": ordered[lo] + (ordered[hi]-ordered[lo]) * (index-lo),
            "min_ns": ordered[0], "max_ns": ordered[-1]}


def summarize(rows):
    output = []
    for config in h.CONFIGURATIONS:
        formal = [r for r in rows if r["partition"] == "formal" and r["config_id"] == config.id]
        warmup = [r for r in rows if r["partition"] == "warmup" and r["config_id"] == config.id]
        phases = {}
        for phase in PHASES:
            attempted, successful, failed = [], [], []
            for row in formal:
                records = [t for t in row["timings"] if t["phase"] == phase]
                if len(records) > 1:
                    raise ValueError("duplicate phase timing")
                if not records:
                    continue
                t = records[0]
                if type(t["elapsed_ns"]) is not int or t["elapsed_ns"] < 0:
                    raise ValueError("invalid timing")
                attempted.append(t["elapsed_ns"])
                if row["success"] and t["call_status"] == "returned":
                    successful.append(t["elapsed_ns"])
                else:
                    failed.append(t["elapsed_ns"])
            phases[phase] = {"scheduled": len(formal), "attempted": len(attempted),
                             "not_timed": len(formal)-len(attempted),
                             "successful_trial_samples": distribution(successful),
                             "failed_trial_attempt_samples": distribution(failed),
                             "all_attempted_samples": distribution(attempted)}
        output.append({"config_id": config.id, "formal_trials": len(formal),
                       "formal_success": sum(r["success"] for r in formal),
                       "formal_failed": sum(not r["success"] for r in formal),
                       "warmup_trials": len(warmup),
                       "warmup_failed": sum(not r["success"] for r in warmup), "phases": phases})
    return {"task": "W3-COMP-BENCH", "statistics_unit": "nanoseconds",
            "primary_population": "phase timings conditional on complete trial AND diagnostics success",
            "failure_policy": "all failures retained; separate failed-trial and all-attempted statistics; no outlier trimming",
            "percentile": "linear interpolation at .95*(n-1)",
            "rows": output, "records": len(rows)}


def protocol(warmups, trials):
    info = time.get_clock_info("perf_counter")
    manifest = h.describe()
    return {"task": "W3-COMP-BENCH", "schema": "W3-COMP-benchmark-v1",
            "planned_warmups_per_config": warmups, "planned_formal_trials_per_config": trials,
            "planned_configurations": 10, "clock": {"api": "perf_counter_ns", "unit": "ns",
                "resolution_seconds": info.resolution, "monotonic": info.monotonic,
                "adjustable": info.adjustable, "implementation": info.implementation},
            "timing_boundary": "two clock reads around unchanged harness once-wrapper; no overhead subtraction; record construction after ending read",
            "setup_policy": "fresh explicit session/setup for EVERY warmup/formal trial; setup counted separately, never amortized",
            "schedule": "serial round-robin; rotate initial configuration by round modulo 10; all warmup rounds precede all formal rounds",
            "randomness": "OSBits/secrets.randbits; fresh full-domain samples; no deterministic seed; exact rejection with full traces",
            "trace_policy": "complete traces retained through each trial; raw export stores counts, not private blocks; artifacts released after logging",
            "outside_timer": ["imports", "source metadata", "harness shape/ledger checks", "independent correctness diagnostics", "JSON/logging/statistics"],
            "gc": {"enabled": gc.isenabled(), "thresholds": gc.get_threshold(), "policy": "unchanged Python automatic GC; no forced collections inside phases"},
            "environment": {**manifest["environment"], "logical_processors": os.cpu_count(),
                            "processor_identifier": os.environ.get("PROCESSOR_IDENTIFIER", "unavailable"),
                            "affinity_frequency_thermal_background_controls": "not controlled or monitored"},
            "harness_manifest": manifest,
            "benchmark_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "interpretation": ["single host/process serial observations", "not equal-security ranking",
                "not native W2 replay or historical R7 reproduction", "no bit-time/worst-case/constant-time guarantee",
                "no signatures or GQ execution", "fixed concrete hash, not ROM instantiation"]}


def run(output, warmups=20, trials=200):
    # Validate before creating anything. Existing outputs are never overwritten.
    plan = list(schedule(warmups, trials))
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    metadata = protocol(warmups, trials)
    metadata.update(started_utc=utc(), status="running")
    write_json(output/"run_metadata.json", metadata)
    rows, failure_count = [], 0
    try:
        with (output/"raw_samples.jsonl").open("x", encoding="utf-8") as stream:
            for sequence, (partition, index, position, config) in enumerate(plan):
                row = run_one(config, partition, index, position, sequence)
                stream.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
                stream.flush()
                rows.append(row)
                failure_count += not row["success"]
                if position == 9 and ((index+1) % 5 == 0 or index == 0):
                    progress = {"partition": partition, "rounds_completed": index+1,
                                "records_saved": len(rows), "failed_trials": failure_count}
                    write_json(output/"progress.json", progress)
                    print(json.dumps(progress), flush=True)
    except BaseException as exc:
        metadata.update(status="interrupted", interruption={"type": type(exc).__name__, "message": str(exc)})
        raise
    else:
        metadata["status"] = "completed"
    finally:
        metadata.update(finished_utc=utc(), records_saved=len(rows), failed_trials=failure_count)
        write_json(output/"summary.json", summarize(rows))
        write_json(output/"run_metadata.json", metadata)
    return failure_count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--warmups", type=int, default=20)
    parser.add_argument("--trials", type=int, default=200)
    args = parser.parse_args()
    return int(bool(run(args.output, args.warmups, args.trials)))


if __name__ == "__main__":
    raise SystemExit(main())
