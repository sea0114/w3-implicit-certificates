"""Minimal integration acceptance for the ten-configuration comparison harness.

All inputs are synthetic functional fixtures.  This entry point does not use a
clock, run warmups/performance trials, invoke a legacy test suite, or establish
security or equal-security performance.  Temporary injections affect only the
new harness module and are restored even on failure.
"""

from pathlib import Path
import json

import comparison_harness as harness
from w3_reference import BitID, G1, add, dec_point, enc_point, Trace


RESULTS = []
IDENTITY = BitID(128, b"0123456789abcdef")
PHASES = (
    "ca_keygen", "ca_import", "user_prepare", "issue", "completion",
    "reconstruction", "preimage_validation",
)


class CheckFailure(Exception):
    pass


def require(condition, message):
    # Remains active with Python optimization enabled.
    if not condition:
        raise CheckFailure(message)


def reject(operation, label):
    try:
        operation()
    except (ValueError, TypeError, RuntimeError):
        return
    raise CheckFailure("accepted invalid harness use: " + label)


def check(check_id, config, operation):
    record = {"id": check_id, "config": config}
    try:
        evidence = operation()
        require(isinstance(evidence, dict), "evidence dictionary required")
        record.update(status="PASS", evidence=evidence)
    except Exception as exc:
        record.update(status="FAIL", error=type(exc).__name__ + ": " + str(exc))
    RESULTS.append(record)


def choose(family, mode="ECQV", profile=None):
    matches = [config for config in harness.CONFIGURATIONS
               if config.family == family and config.mode == mode
               and (profile is None or config.profile == profile)]
    require(bool(matches), "requested test configuration exists")
    return matches[0]


def source(label):
    return harness.ScopedSyntheticBits("W3-COMP-HARNESS-acceptance/" + label)


def session(config, label, **kwargs):
    return harness.HarnessSession(config, session_id=label,
                                  bits_factory=source(label), **kwargs)


def successful_ledger(result):
    require([entry["phase"] for entry in result.ledger] == list(PHASES), "all seven phases retain their order")
    require(all(entry["status"] == "ok" for entry in result.ledger), "every honest phase succeeds")
    require(result.success is True, "honest trial succeeds")


def no_private_summary(result, setup_summary):
    summary = result.summary()
    text = json.dumps(summary, sort_keys=True)
    private = result.artifacts
    for raw in (private["ca"].secret, private["user"].secret,
                private["completed_secret"], private["service"]._last_issuance_state["nonce"]):
        require(raw.hex() not in text, "public trial summary excludes private secret bytes")
    for traces in (private["ca"].traces, private["user"].traces,
                   private["service"]._last_issuance_state["consumed_traces"]):
        for trace in traces:
            require(all(str(block) not in text for block in trace.blocks), "public summary excludes consumed random blocks")
    json.dumps(setup_summary, sort_keys=True)
    return summary


def honest_flow(config):
    observed = []

    def runner(context, operation):
        observed.append((context.phase, context.session_id, context.config_id, context.trial_id))
        return operation()

    current = session(config, "flow-" + config.id, runner=runner)
    inst = current.setup()
    require(inst is current.instance, "setup returns installed public instance")
    result = current.run_trial(0)
    successful_ledger(result)
    artifacts = result.artifacts
    ca, user, service = artifacts["ca"], artifacts["user"], artifacts["service"]
    issuance = artifacts["issuance"]
    require(type(issuance) is tuple and len(issuance) == 2, "UF issuance returns exactly (C,r)")
    C, response = issuance
    require(all(isinstance(item, bytes) for item in (ca.secret, ca.public, user.secret, user.request,
                                                   C, response, artifacts["completed_secret"],
                                                   artifacts["reconstructed_public"])), "all phase wire outputs are bytes")
    require(artifacts["preimage_valid"] is True, "fresh=False honest preimage acceptance")
    require(C in service.issued, "normal issuance state committed")
    require(inst.pub_encode(inst.mu(inst.sec_decode(artifacts["completed_secret"]))) ==
            artifacts["reconstructed_public"], "reconstruction matches fully decoded secret image")
    _, identity = inst.parse(C)
    require(identity == IDENTITY, "shared identity survives each native frame")
    expected_traces = 2 if config.family in ("PS", "Okamoto") else 1
    state = service._last_issuance_state
    trace_groups = (ca.traces, user.traces, state["consumed_traces"])
    require(all(len(group) == expected_traces for group in trace_groups), "per-role trace multiplicity retained")
    require(all(isinstance(trace, Trace) and trace.blocks for group in trace_groups for trace in group),
            "full nonempty sampling trace objects remain in private artifacts")
    require(state["C"] == C and state["response"] == response, "public response agrees with retained private state")
    require([item[0] for item in observed] == ["group_setup", *PHASES], "setup separated from seven trial phases")
    require(observed[0][3] is None and all(item[3] == 0 for item in observed[1:]), "setup has no trial identifier")
    require(all(item[1] == current.session_id and item[2] == config.id for item in observed), "all runner contexts are explicit")
    no_private_summary(result, current.summary())
    expected = {
        "PS": (219, 64, 192), "Waters": (123, 144, 96), "Okamoto": (75, 64, 48),
    }
    if config.family == "Scalar":
        expected["Scalar"] = (60, 32, 33) if config.profile == "P256" else (75, 32, 48)
    c_size, secret_size, public_size = expected[config.family]
    require((len(C), len(response), len(artifacts["completed_secret"]), len(artifacts["reconstructed_public"])) ==
            (c_size, secret_size, secret_size, public_size), "native codec sizes match static comparison")
    return {"seven_phases": list(PHASES), "separate_setup": True,
            "wire_bytes": {"request": len(user.request), "certificate": len(C), "response": len(response),
                           "completed_secret": len(artifacts["completed_secret"]), "public": len(artifacts["reconstructed_public"])},
            "traces_per_role": expected_traces, "public_issuance_arity": 2,
            "private_artifacts_retained": True, "public_summary_excludes_secret_and_trace_blocks": True,
            "full_secret_decode_before_image_check": True}


class RejectionBits:
    """One rejection followed by one small accepted value per coordinate."""

    def __init__(self):
        self.contexts = []

    def __call__(self, context):
        self.contexts.append(context)
        calls = 0

        def bits(width):
            nonlocal calls
            calls += 1
            return (1 << width) - 1 if calls % 2 else 4 + calls // 2

        return bits


def full_rejection_traces():
    evidence = []
    for family, profile in (("Scalar", "P256"), ("PS", None), ("Waters", None), ("Okamoto", None)):
        config = choose(family, profile=profile)
        bit_source = RejectionBits()
        current = harness.HarnessSession(config, session_id="trace-" + config.id, bits_factory=bit_source)
        current.setup()
        result = current.run_trial(0)
        successful_ledger(result)
        a = result.artifacts
        groups = (a["ca"].traces, a["user"].traces, a["service"]._last_issuance_state["consumed_traces"])
        count = 2 if family in ("PS", "Okamoto") else 1
        for group in groups:
            require(len(group) == count, "role trace coordinate count")
            for coordinate, trace in enumerate(group):
                require(trace.blocks == ((1 << trace.width) - 1, 5 + coordinate), "both rejection and accepted block retained")
        phases = [context.phase for context in bit_source.contexts]
        require(phases == ["group_setup", "ca_keygen", "user_prepare", "issue"], "only setup and sampling roles request bit sources")
        evidence.append({"config": config.id, "traces_per_role": count, "blocks_per_trace": 2})
    return {"configurations": evidence, "setup_trace_not_in_trial_outputs": True}


def synthetic_scope_isolation():
    config = harness.CONFIGURATIONS[0]
    other = harness.CONFIGURATIONS[1]
    context = harness.PhaseContext("scope-session", config.id, 0, "ca_keygen")
    create = source("scope")
    first, again = create(context), source("scope")(context)
    values = [first(256), first(129), first(1)]
    require(values == [again(256), again(129), again(1)], "identical seed and scope reproduce bit stream")
    variants = (
        harness.PhaseContext("other-session", config.id, 0, "ca_keygen"),
        harness.PhaseContext("scope-session", other.id, 0, "ca_keygen"),
        harness.PhaseContext("scope-session", config.id, 1, "ca_keygen"),
        harness.PhaseContext("scope-session", config.id, 0, "issue"),
    )
    require(all(create(item)(256) != values[0] for item in variants), "session/config/trial/role domains separated")
    require(len(set(create(item)(256) for item in variants)) == len(variants), "distinct fixture scopes have distinct deterministic outputs")
    return {"repeatable_synthetic_fixture": True, "separation_fields": ["session", "config", "trial", "role"],
            "randomness_quality_claim": False}


def injected_phase_failure():
    config = choose("Scalar", profile="P256")

    def runner(context, operation):
        if context.phase == "user_prepare":
            raise ValueError("intentional integration failure")
        return operation()

    current = session(config, "injected-error", runner=runner)
    current.setup()
    result = current.run_trial(3)
    require(result.success is False, "phase exception fails trial")
    require([row["phase"] for row in result.ledger] == list(PHASES), "failure does not drop ledger rows")
    require([row["status"] for row in result.ledger] == ["ok", "ok", "failed", "skipped", "skipped", "skipped", "skipped"],
            "dependent phases are explicitly skipped")
    require("intentional integration failure" in result.ledger[2]["error"]["message"], "failure reason retained")
    require(len(current.trials) == 1 and current.trials[3] is result, "failed trial retained in session history")
    require("ca" in result.artifacts and "user" not in result.artifacts, "completed artifacts retained without inventing failed output")
    require(result.summary()["success"] is False, "public summary retains failed outcome")
    original = harness.phase_ca_keygen
    harness.phase_ca_keygen = lambda inst, bits: (b"wrong", b"shape")
    try:
        malformed = session(config, "malformed-phase-return")
        malformed.setup()
        malformed_result = malformed.run_trial(0)
    finally:
        harness.phase_ca_keygen = original
    require(malformed_result.success is False and malformed_result.ledger[0]["status"] == "failed", "malformed phase return rejected before commit")
    require("ca" not in malformed_result.artifacts, "invalid phase shape not installed as valid artifact")
    require(all(row["status"] == "skipped" for row in malformed_result.ledger[1:]), "invalid shape stops dependent phases")
    json.dumps(malformed.summary())
    return {"failed_phase": "user_prepare", "ledger_rows_retained": 7, "explicit_skipped_rows": 4,
            "failed_trial_kept": True, "partial_artifacts_kept": True,
            "malformed_phase_return_rejected_before_commit": True, "failure_summary_serializable": True}


def false_validation():
    original = harness.phase_preimage_validation
    calls = []

    def fail_validation(service, certificate, secret):
        calls.append((certificate, secret))
        return False

    harness.phase_preimage_validation = fail_validation
    try:
        current = session(choose("Scalar", profile="P256"), "false-validation")
        current.setup()
        result = current.run_trial(0)
    finally:
        harness.phase_preimage_validation = original
    require(len(calls) == 1, "validation phase invoked exactly once")
    require(result.success is False and result.ledger[-1]["status"] == "failed", "false acceptance is a failed phase")
    require(all(row["status"] == "ok" for row in result.ledger[:-1]), "prior successes retained")
    require(result.artifacts.get("preimage_valid") is False, "false validation result preserved")
    return {"false_is_failure": True, "prior_successes_retained": 6, "injection_restored": True}


def waters_relation_validation():
    original = harness.phase_completion
    changed = []

    def malformed_completion(service, user_raw, certificate, response):
        secret = original(service, user_raw, certificate, response)
        # Both coordinates remain canonical subgroup points.  Adding nonzero
        # G1 changes only w, so e(G2,w)=e(z,h) necessarily fails.
        malformed = enc_point(add(dec_point(secret[:48], 1), G1), 1) + secret[48:]
        changed.append((secret, malformed))
        return malformed

    harness.phase_completion = malformed_completion
    try:
        current = session(choose("Waters"), "waters-relation")
        current.setup()
        result = current.run_trial(0)
    finally:
        harness.phase_completion = original
    require(len(changed) == 1 and changed[0][0] != changed[0][1], "actual Waters completed secret corrupted")
    raw = changed[0][1]
    # Individual point validity is insufficient; relation decoding must reject.
    dec_point(raw[:48], 1)
    dec_point(raw[48:], 2)
    reject(lambda: current.instance.sec_decode(raw), "Waters H_h relation")
    require(result.success is False and result.ledger[-1]["status"] == "failed", "full validation rejects malformed pair")
    require(result.artifacts["completed_secret"] == raw, "bad completed secret retained for diagnosis")
    require(result.artifacts.get("preimage_valid") is False, "normal validator records relation failure")
    return {"canonical_individual_points": True, "same_G2_projection": True,
            "actual_H_h_relation_rejected": True, "failed_trial_retained": True,
            "projection_only_validation_used": False, "injection_restored": True}


def runner_guards():
    outcomes = []
    for kind in ("zero", "twice", "swallowed-twice", "replacement"):
        def runner(context, operation, kind=kind):
            if context.phase != "user_prepare":
                return operation()
            if kind == "zero":
                return None
            value = operation()
            if kind == "twice":
                return operation()
            if kind == "swallowed-twice":
                try:
                    operation()
                except RuntimeError:
                    pass
                return value
            return object()

        current = session(choose("Scalar", profile="P256"), "runner-" + kind, runner=runner)
        current.setup()
        result = current.run_trial(0)
        require(result.success is False and result.ledger[2]["status"] == "failed", "runner contract breach rejected: " + kind)
        require(all(row["status"] == "skipped" for row in result.ledger[3:]), "runner failure skips dependent work")
        outcomes.append(kind)
    return {"rejected_runner_behaviors": outcomes, "timer_used": False}


def lifecycle_guards():
    config = choose("Scalar", profile="P256")
    current = session(config, "lifecycle")
    reject(lambda: current.run_trial(0), "trial before setup")
    current.setup()
    reject(current.setup, "setup reused")
    result = current.run_trial(0)
    successful_ledger(result)
    reject(lambda: current.run_trial(0), "duplicate trial id")
    reject(lambda: current.run_trial(-1), "negative trial id")
    reject(lambda: current.run_trial(True), "boolean trial id")
    require(len(current.trials) == 1, "invalid lifecycle calls do not overwrite trial history")
    original_instance = current.instance
    second = current.run_trial(1)
    successful_ledger(second)
    first_service, second_service = result.artifacts["service"], second.artifacts["service"]
    require(current.instance is original_instance and len(current.setup_ledger) == 1, "one setup reused without rerunning it")
    require(first_service is not second_service, "fresh service per trial")
    require(first_service.issued is not second_service.issued, "issued sets do not alias across trials")
    require(first_service.issued == {result.artifacts["issuance"][0]} and
            second_service.issued == {second.artifacts["issuance"][0]}, "each trial retains only its own issuance state")
    require(result.artifacts["ca"].secret != second.artifacts["ca"].secret and
            result.artifacts["user"].secret != second.artifacts["user"].secret, "scoped fixture draws fresh CA and user per trial")
    reject(lambda: harness.HarnessSession(config, lam=True), "boolean challenge length")
    reject(lambda: harness.HarnessSession(config, lam=0), "empty challenge length")
    reject(lambda: harness.HarnessSession(config, identity=b"not-BitID"), "untyped identity")
    reject(lambda: harness.Configuration("GQ", "ECQV"), "GQ excluded from runtime configurations")
    reject(lambda: harness.Configuration("Scalar", "BAD", "P256"), "invalid mode")
    reject(lambda: harness.Configuration("Scalar", "ECQV", "unknown"), "invalid scalar profile")
    return {"setup_once": True, "unique_nonnegative_trial_ids": True, "history_preserved": True,
            "fresh_service_and_role_state_per_trial": True, "shared_setup_reused": True,
            "config_identity_lambda_guards": True, "GQ_static_only": True}


def setup_failure_retention():
    def runner(context, operation):
        if context.phase == "group_setup":
            raise ValueError("intentional setup failure")
        return operation()

    current = session(choose("Okamoto"), "setup-failure", runner=runner)
    require(current.setup() is None, "failed setup returns no instance")
    require(current.instance is None, "failed setup does not install partial instance")
    require(current.setup_ledger[0]["status"] == "failed", "setup error retained separately")
    result = current.run_trial(0)
    require(result.success is False and len(result.ledger) == 7, "trial blocked by setup retained")
    require(all(row["status"] == "skipped" for row in result.ledger), "setup failure skips all dependent trial phases")
    require(len(current.trials) == 1, "setup-blocked trial not silently dropped")
    return {"separate_setup_error": True, "blocked_trial_kept": True, "skipped_phases": 7}


def main():
    RESULTS.clear()
    require(len(harness.CONFIGURATIONS) == 10 and len({config.id for config in harness.CONFIGURATIONS}) == 10,
            "exactly ten distinct runtime configurations")
    for config in harness.CONFIGURATIONS:
        check("CMP-FLOW", config.id, lambda config=config: honest_flow(config))
    for suffix, operation in (
        ("REJECTION-TRACES", full_rejection_traces),
        ("SYNTHETIC-SCOPES", synthetic_scope_isolation),
        ("PHASE-FAILURE", injected_phase_failure),
        ("FALSE-VALIDATION", false_validation),
        ("WATERS-RELATION", waters_relation_validation),
        ("RUNNER-GUARDS", runner_guards),
        ("LIFECYCLE", lifecycle_guards),
        ("SETUP-FAILURE", setup_failure_retention),
    ):
        check("CMP-" + suffix, "harness-integration", operation)
    failures = sum(record["status"] != "PASS" for record in RESULTS)
    report = {
        "task": "W3-COMP-HARNESS", "scope": "minimal functional integration acceptance",
        "configurations": [config.id for config in harness.CONFIGURATIONS],
        "synthetic_fixtures_only": True, "clock_used": False, "benchmark_executed": False,
        "warmup_executed": False, "legacy_test_suites_executed": False, "GQ_runtime_implementation": False,
        "does_not_establish": ["runtime ranking", "equal-security comparison", "bit-time bound", "uniform BGen",
                               "fair randomness", "setup secrecy", "production isolation", "new theorem", "signature composition"],
        "checks": RESULTS, "total": len(RESULTS), "passed": len(RESULTS) - failures, "failed": failures,
    }
    destination = Path(__file__).with_name("comparison_harness_verification_results.json")
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"task": report["task"], "total": report["total"], "passed": report["passed"], "failed": failures}))
    if failures:
        for record in RESULTS:
            if record["status"] == "FAIL":
                print(json.dumps(record, ensure_ascii=False))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
