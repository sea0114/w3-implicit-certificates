"""Untimed CMP09 phase harness for ten finite certificate configurations.

This module does not measure performance.  Provider imports happen before any
phase.  An optional external runner may observe one phase callable, but must
execute it exactly once and return its unchanged result.  No benchmark schedule,
clock, signature algorithm, or GQ execution is provided here.

CA/user/nonce sampler traces remain complete private diagnostic objects.  Global
setup exponents and setup traces are not returned by the existing setup helpers.
Synthetic streams are reproducible test inputs, not certified fair randomness.
"""

from dataclasses import dataclass, field
from pathlib import Path
import argparse
import hashlib
import json
import platform
import secrets
import sys

from w3_reference import (
    BitID, Trace, Instance, FixedHash, CertificateService as CoreService,
    setup_waters, Q, P, G1, G2, enc_point,
)
from scalar_reference import ScalarInstance, ScalarFixedHash, ScalarCertificateService
from okamoto_reference import OkamotoInstance, setup_okamoto, OkamotoFixedHash, OkamotoCertificateService
import ecdsa
import py_ecc
import ecdsa.ellipticcurve
import py_ecc.optimized_bls12_381.optimized_curve
import py_ecc.optimized_bls12_381.optimized_pairing


DEFAULT_ID = BitID(128, b"0123456789abcdef")
WATERS_MESSAGE_BITS = 8  # Setup has h plus nine U points; no signature is run.
TRIAL_PHASES = (
    "ca_keygen", "ca_import", "user_prepare", "issue", "completion",
    "reconstruction", "preimage_validation",
)


@dataclass(frozen=True)
class Configuration:
    family: str
    mode: str
    profile: str = ""

    def __post_init__(self):
        if self.mode not in ("ECQV", "PV"):
            raise ValueError("configuration mode")
        profiles = {"Scalar": ("P256", "BLSG1"), "PS": ("",),
                    "Waters": ("",), "Okamoto": ("BLSG1",)}
        if self.family not in profiles or self.profile not in profiles[self.family]:
            raise ValueError("configuration family/profile")

    @property
    def id(self):
        family = "scalar" if self.family == "Scalar" else self.family
        return "-".join(x for x in (family, self.profile, self.mode) if x)


Config = Configuration
CONFIGURATIONS = tuple(
    Configuration(family, mode, profile)
    for family, profile in (("Scalar", "P256"), ("Scalar", "BLSG1"),
                            ("PS", ""), ("Waters", ""), ("Okamoto", "BLSG1"))
    for mode in ("ECQV", "PV")
)


@dataclass(frozen=True)
class PhaseContext:
    session_id: str
    config_id: str
    trial_id: object
    phase: str


@dataclass(frozen=True)
class CAKey:
    secret: bytes
    public: bytes
    traces: tuple


@dataclass(frozen=True)
class UserPreparation:
    secret: bytes
    request: bytes
    traces: tuple


class OSBits:
    """Default entropy API; the API name is not a fair-bit proof."""
    description = "secrets.randbits; uncapped exact rejection; fairness is a contract"
    synthetic = False

    def __call__(self, context):
        return secrets.randbits


class ScopedSyntheticBits:
    """Independent *labels* per session/config/trial/role, for functional checks.

    This deterministic SHAKE stream is not an information-theoretically fair
    source.  In particular its public seed can reproduce setup exponents; it is
    unsuitable as evidence of hidden-setup security.  No seed or consumed setup
    blocks are serialized in a session's public summary.
    """
    description = "synthetic SHAKE256 counter streams scoped by session/config/trial/phase"
    synthetic = True

    def __init__(self, seed):
        if isinstance(seed, str):
            seed = b"str\0" + seed.encode("utf-8")
        elif type(seed) is int and seed >= 0:
            seed = b"int\0" + str(seed).encode("ascii")
        elif isinstance(seed, bytes):
            seed = b"bytes\0" + seed
        else:
            raise ValueError("synthetic seed must be bytes, string or nonnegative int")
        self._seed = seed

    def __call__(self, context):
        if not isinstance(context, PhaseContext):
            raise ValueError("phase context")
        label = json.dumps([context.session_id, context.config_id,
                            context.trial_id, context.phase],
                           ensure_ascii=True, separators=(",", ":")).encode("ascii")
        key = hashlib.sha256(b"W3-COMP-source-v1\0" +
                             len(self._seed).to_bytes(8, "big") + self._seed + label).digest()
        counter = 0

        def randbits(width):
            nonlocal counter
            if type(width) is not int or width < 1:
                raise ValueError("synthetic bit width")
            raw = hashlib.shake_256(b"W3-COMP-block-v1\0" + key +
                                   counter.to_bytes(16, "big") +
                                   width.to_bytes(8, "big")).digest((width + 7) // 8)
            counter += 1
            return int.from_bytes(raw, "big") >> ((8 - width % 8) % 8)

        return randbits


class GuardedLegacyService(CoreService):
    """Harness-local PS/Waters FixedHash range guard; legacy files are unchanged.

    Only the fixed existing SHAKE implementation is accepted.  Every call has
    the same exact-int/range output check as the newer finite adapters.  All
    legacy secret decoding, including Waters relation pairings, stays intact.
    """
    def __init__(self, inst, mode, ca_raw, H, *, lam=128):
        if not isinstance(inst, Instance) or inst.kind not in ("PS", "Waters"):
            raise ValueError("legacy PS/Waters instance required")
        if type(H) is not FixedHash or H.lam != lam:
            raise ValueError("fixed SHAKE hash and matching lambda required")
        if type(lam) is not int or lam < 1 or (1 << lam) >= Q:
            raise ValueError("challenge range")

        def checked_hash(C):
            e = H(C)
            if type(e) is not int or not 1 <= e <= 1 << lam:
                raise ValueError("hash challenge type/range")
            return e

        super().__init__(inst, mode, ca_raw, checked_hash)
        self.hash_source, self.lam = H, lam


def phase_group_setup(config, bits):
    """Warm-provider constructor, plus actual h/U setup where required."""
    if config.family == "Scalar":
        return ScalarInstance(config.profile)
    if config.family == "PS":
        return Instance("PS")
    if config.family == "Waters":
        return setup_waters(WATERS_MESSAGE_BITS, bits)
    if config.family == "Okamoto":
        return setup_okamoto(bits)
    raise ValueError("configuration")


def phase_ca_keygen(inst, bits):
    """Fresh full-domain sample, mu, both encodings, complete trace retention."""
    c, traces = inst.sample_secret(bits)
    return CAKey(inst.sec_encode(c), inst.pub_encode(inst.mu(c)), traces)


def phase_ca_import(inst, config, ca_raw, lam=128):
    """Decode existing CA secret, recompute Y, construct guarded fixed-H service.

    This deliberately recomputes mu after fresh keygen when chained in a trial.
    It is a separately reported real workload, not an idealized fused keygen.
    """
    if config.family == "Scalar":
        return ScalarCertificateService(inst, config.mode, ca_raw,
                                        ScalarFixedHash(inst, lam), lam=lam)
    if config.family == "Okamoto":
        return OkamotoCertificateService(inst, config.mode, ca_raw,
                                         OkamotoFixedHash(inst, lam), lam=lam)
    return GuardedLegacyService(inst, config.mode, ca_raw, FixedHash(lam), lam=lam)


def phase_user_prepare(inst, identity, bits):
    """Fresh full-domain sample, mu, canonical request/secret, complete traces."""
    u, traces = inst.sample_secret(bits)
    return UserPreparation(inst.sec_encode(u),
                           inst.frame(inst.mu(u), identity, request=True), traces)


def phase_issue(service, request, bits):
    """Wire validation, fresh nonce/complete traces, C/r and private state."""
    return service.issue(request, bits)


def phase_completion(service, user_raw, certificate, response):
    """Parse C, decode both secrets, fixed H, completion and secret encoding."""
    return service.derive(user_raw, certificate, response)


def phase_reconstruction(service, certificate):
    """Parse/membership/H/reconstruction AND canonical public output encoding."""
    return service.inst.pub_encode(service.recon(certificate))


def phase_preimage_validation(service, certificate, secret):
    """Full internal reconstruction and secret/mu check; freshness is False.

    A verifier workflow containing this phase must not additionally count the
    separately exercised reconstruction phase as if it were necessary again.
    """
    return service.verify_preimage(certificate, secret, fresh=False)


def immediate_runner(context, operation):
    return operation()


def _trace_summary(traces):
    """Diagnostic summaries only; full Trace objects remain in private artifacts."""
    if not isinstance(traces, tuple) or any(not isinstance(t, Trace) for t in traces):
        raise ValueError("complete trace tuple expected")
    return [{"width": t.width, "proposals": len(t.blocks),
             "consumed_bits": t.width * len(t.blocks)} for t in traces]


def _check_output_shape(phase, value, artifacts):
    """Cheap diagnostic shape checks outside phase calls, without re-decoding.

    In particular, malformed outputs must not enter the retained artifacts and
    later break failure-ledger serialization.  These checks do not replace the
    cryptographic/wire validation within the phase implementation.
    """
    if phase in ("ca_keygen", "user_prepare"):
        expected = CAKey if phase == "ca_keygen" else UserPreparation
        public = "public" if phase == "ca_keygen" else "request"
        valid = (isinstance(value, expected) and isinstance(value.secret, bytes)
                 and isinstance(getattr(value, public), bytes)
                 and isinstance(value.traces, tuple)
                 and all(isinstance(t, Trace) for t in value.traces))
    elif phase == "ca_import":
        valid = isinstance(value, CoreService)
    elif phase == "issue":
        state = getattr(artifacts.get("service"), "_last_issuance_state", None)
        valid = (isinstance(value, tuple) and len(value) == 2
                 and all(isinstance(item, bytes) for item in value)
                 and isinstance(state, dict)
                 and isinstance(state.get("consumed_traces"), tuple)
                 and all(isinstance(t, Trace) for t in state["consumed_traces"]))
    elif phase in ("completion", "reconstruction"):
        valid = isinstance(value, bytes)
    elif phase == "preimage_validation":
        valid = type(value) is bool
    else:
        valid = False
    if not valid:
        raise ValueError("malformed phase output: " + phase)


@dataclass
class TrialResult:
    config_id: str
    session_id: str
    trial_id: int
    ledger: list = field(default_factory=list)
    artifacts: dict = field(default_factory=dict, repr=False)

    @property
    def success(self):
        return (len(self.ledger) == len(TRIAL_PHASES)
                and all(row["status"] == "ok" for row in self.ledger)
                and self.artifacts.get("preimage_valid") is True)

    def summary(self):
        """JSON-safe outcome without CA/user/nonce secrets or sampler blocks."""
        a = self.artifacts
        sizes, traces = {}, {}
        if "ca" in a:
            sizes.update(ca_secret=len(a["ca"].secret), ca_public=len(a["ca"].public))
            traces["ca"] = _trace_summary(a["ca"].traces)
        if "user" in a:
            sizes.update(user_secret=len(a["user"].secret), request=len(a["user"].request))
            traces["user"] = _trace_summary(a["user"].traces)
        if "issuance" in a:
            C, r = a["issuance"]
            sizes.update(certificate=len(C), response=len(r), certificate_plus_response=len(C)+len(r))
            traces["nonce"] = _trace_summary(a["service"]._last_issuance_state["consumed_traces"])
        if "completed_secret" in a:
            sizes["completed_secret"] = len(a["completed_secret"])
        if "reconstructed_public" in a:
            sizes["reconstructed_public"] = len(a["reconstructed_public"])
        return {"config_id": self.config_id, "session_id": self.session_id,
                "trial_id": self.trial_id, "success": self.success,
                "phases": [dict(row) for row in self.ledger], "bytes": sizes,
                "private_trace_summary": traces,
                "trace_summary_is_communication_payload": False,
                "preimage_valid": a.get("preimage_valid"), "freshness": False}


class HarnessSession:
    """One explicit shared setup per configuration, fresh service per trial.

    setup() is attempted exactly once.  A failed setup is retained and cannot
    be retried in place; use a distinct, explicitly named session.  Failed trials
    are retained and trial IDs cannot be reused.  Nothing rolls back a failed
    callable's internal side effects; its service is never reused by a trial.
    """
    def __init__(self, config, *, session_id="session-0", bits_factory=None,
                 runner=None, lam=128, identity=DEFAULT_ID):
        if not isinstance(config, Configuration):
            raise ValueError("configuration required")
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("nonempty session identifier required")
        if type(lam) is not int or lam < 1 or lam >= 255:
            raise ValueError("finite challenge length")
        if not isinstance(identity, BitID):
            raise ValueError("bit identity required")
        self.config, self.session_id = config, session_id
        self.lam, self.identity = lam, identity
        self.bits_factory = OSBits() if bits_factory is None else bits_factory
        self.runner = immediate_runner if runner is None else runner
        if not callable(self.bits_factory) or not callable(self.runner):
            raise ValueError("callable bits factory and phase runner required")
        self.instance, self.setup_ledger, self.trials = None, [], {}
        self._setup_attempted = False

    def _context(self, trial_id, phase):
        return PhaseContext(self.session_id, self.config.id, trial_id, phase)

    def _run(self, context, operation):
        calls, captured = 0, []

        def once():
            nonlocal calls
            calls += 1
            if calls > 1:
                raise RuntimeError("phase runner called operation more than once")
            result = operation()
            captured.append(result)
            return result

        result = self.runner(context, once)
        if calls != 1 or len(captured) != 1:
            raise RuntimeError("phase runner must execute operation exactly once")
        if result is not captured[0]:
            raise RuntimeError("phase runner must return the unchanged operation result")
        return result

    @staticmethod
    def _failure(phase, exc):
        return {"phase": phase, "status": "failed",
                "error": {"type": type(exc).__name__, "message": str(exc)}}

    def setup(self):
        if self._setup_attempted:
            raise RuntimeError("setup already attempted; create an explicitly new session")
        self._setup_attempted = True
        context = self._context(None, "group_setup")
        try:
            value = self._run(context, lambda: phase_group_setup(
                self.config, self.bits_factory(context)))
            expected = (ScalarInstance if self.config.family == "Scalar" else
                        OkamotoInstance if self.config.family == "Okamoto" else Instance)
            if not isinstance(value, expected) or value.kind != self.config.family:
                raise ValueError("malformed group_setup output")
            if self.config.family == "Scalar" and value.profile != self.config.profile:
                raise ValueError("group_setup scalar profile mismatch")
            self.instance = value
            self.setup_ledger.append({"phase": "group_setup", "status": "ok"})
        except Exception as exc:
            self.instance = None
            self.setup_ledger.append(self._failure("group_setup", exc))
        return self.instance

    def run_trial(self, trial_id):
        if not self._setup_attempted:
            raise RuntimeError("call setup explicitly before run_trial")
        if type(trial_id) is not int or trial_id < 0:
            raise ValueError("trial identifier must be a nonnegative integer")
        if trial_id in self.trials:
            raise RuntimeError("trial identifier already retained")
        result = TrialResult(self.config.id, self.session_id, trial_id)
        self.trials[trial_id] = result  # Retain even an immediate failure.
        if self.instance is None:
            result.ledger.extend({"phase": name, "status": "skipped", "reason": "group_setup_failed"}
                                 for name in TRIAL_PHASES)
            return result
        a, inst = result.artifacts, self.instance
        operations = {
            "ca_keygen": ("ca", lambda ctx: phase_ca_keygen(inst, self.bits_factory(ctx))),
            "ca_import": ("service", lambda ctx: phase_ca_import(inst, self.config, a["ca"].secret, self.lam)),
            "user_prepare": ("user", lambda ctx: phase_user_prepare(inst, self.identity, self.bits_factory(ctx))),
            "issue": ("issuance", lambda ctx: phase_issue(a["service"], a["user"].request, self.bits_factory(ctx))),
            "completion": ("completed_secret", lambda ctx: phase_completion(
                a["service"], a["user"].secret, *a["issuance"])),
            "reconstruction": ("reconstructed_public", lambda ctx: phase_reconstruction(a["service"], a["issuance"][0])),
            "preimage_validation": ("preimage_valid", lambda ctx: phase_preimage_validation(
                a["service"], a["issuance"][0], a["completed_secret"])),
        }
        failure = None
        for name in TRIAL_PHASES:
            if failure is not None:
                result.ledger.append({"phase": name, "status": "skipped", "reason": "prior_phase_failed", "failed_phase": failure})
                continue
            key, operation = operations[name]
            try:
                context = self._context(trial_id, name)
                value = self._run(context, lambda: operation(context))
                _check_output_shape(name, value, a)
                a[key] = value
                # Outcome classification is outside the runner's operation.
                if name == "preimage_validation" and a[key] is not True:
                    raise ValueError("preimage validation returned False or a non-bool result")
                result.ledger.append({"phase": name, "status": "ok"})
            except Exception as exc:
                failure = name
                result.ledger.append(self._failure(name, exc))
        return result

    def public_setup(self):
        """Public setup snapshot prepared outside all phase runner calls."""
        if self.instance is None:
            return None
        i = self.instance
        if self.config.family == "Okamoto":
            return i.public_parameters()
        if self.config.family == "Scalar":
            return {"profile": i.profile, "q": str(i.q),
                    "generator": i.pub_encode(i.P).hex(),
                    "identity": i.pub_encode(i.O).hex(), "aux": []}
        info = {"profile": i.kind, "q": str(Q), "field_modulus": str(P),
                "generator_G1": enc_point(G1, 1).hex(),
                "generator_G2": enc_point(G2, 2).hex(), "aux": []}
        if self.config.family == "Waters":
            info.update(h=enc_point(i.h, 1).hex(), U=[enc_point(u, 1).hex() for u in i.U],
                        signature_message_bits=WATERS_MESSAGE_BITS,
                        additional_shared_points_bytes=48*(1+len(i.U)))
        return info

    def summary(self):
        return {"config_id": self.config.id, "session_id": self.session_id,
                "setup_attempted": self._setup_attempted,
                "setup_phases": [dict(row) for row in self.setup_ledger],
                "public_setup": self.public_setup(),
                "randomness": {"description": getattr(self.bits_factory, "description", "caller-supplied bit source factory"),
                               "synthetic": getattr(self.bits_factory, "synthetic", None),
                               "fairness_certified": False},
                "lambda": self.lam,
                "identity": {"bits": self.identity.bits, "hex": self.identity.data.hex()},
                "trials": [result.summary() for result in self.trials.values()]}


PHASE_CONTRACTS = {
    "group_setup": "Warm provider constructor; Waters exact nonzero beta plus n+1 full scalars, h/U multiplication and validation; Okamoto exact nonzero b, h multiplication and import validation; global exponents/traces not exported.",
    "ca_keygen": "Fresh full-domain secret sampling, mu, secret/public encoding, complete private trace tuple.",
    "ca_import": "Decode/validate existing secret, recompute mu/Y, create fixed SHAKE hash, context/challenge guards and fresh service state; distinct from key generation.",
    "user_prepare": "Fresh full-domain user sampling, mu, canonical request and secret encoding, complete private traces.",
    "issue": "Canonical wire request/member validation before random bits; full nonce sampling/traces, KC/R/C, fixed SHAKE hash, response, issued/private state and encoded outputs.",
    "completion": "Certificate parse/member validation; decode both user/response secrets (including Waters relation); fixed H, secret operations and canonical secret output.",
    "reconstruction": "Certificate parse/member validation, fixed H, public operations AND canonical public output encoding.",
    "preimage_validation": "fresh=False; full internal reconstruction, secret decode/member validation, mu, canonical equality; does not reuse the separately reconstructed public value.",
}


def _source_metadata():
    root = Path(__file__).resolve().parent
    paths = {name: root / name for name in (
        "comparison_harness.py", "w3_reference.py", "scalar_reference.py", "okamoto_reference.py")}
    for name, module in (("py_ecc_package", py_ecc), ("ecdsa_package", ecdsa),
                         ("ecdsa_ellipticcurve", ecdsa.ellipticcurve),
                         ("py_ecc_optimized_curve", py_ecc.optimized_bls12_381.optimized_curve),
                         ("py_ecc_optimized_pairing", py_ecc.optimized_bls12_381.optimized_pairing)):
        paths[name] = Path(module.__file__).resolve()
    return {name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for name, path in paths.items()}


def describe():
    """Static manifest and source provenance; no group setup or trial is run."""
    return {
        "schema": "W3-COMP-HARNESS-v1", "task": "W3-COMP-HARNESS",
        "execution_kind": "untimed functional phase harness",
        "configurations": [{"id": c.id, "family": c.family, "profile": c.profile,
                            "mode": c.mode} for c in CONFIGURATIONS],
        "phase_order": ["group_setup", *TRIAL_PHASES], "phase_contracts": dict(PHASE_CONTRACTS),
        "default_identity": {"bits": DEFAULT_ID.bits, "hex": DEFAULT_ID.data.hex()},
        "lambda": 128, "challenge_range": "1..2^lambda inclusive; 2^lambda < q",
        "hash": {"algorithm": "existing w3_reference.FixedHash SHAKE256",
                 "byte_domain_hex": b"W3-Hcert-v1\0".hex(),
                 "bit_domain_hex": b"W3-Hcert-bits-v1\0".hex(),
                 "rule": "first lambda output bits as integer, plus 1; complete C bytes; no hash cache",
                 "model": "fixed deterministic H; concrete tests are not ROM security"},
        "environment": {"python": platform.python_version(), "implementation": platform.python_implementation(),
                        "platform": platform.platform(), "executable": sys.executable,
                        "providers": {"py-ecc": py_ecc.__version__, "ecdsa": ecdsa.__version__}},
        "sources": _source_metadata(),
        "scope": {
            "provider_imports": "already imported/warm; excluded from every phase; no cold-start claim",
            "setup_reuse": "one explicit setup per session/configuration; reused by its trials; independent sessions by default per mode",
            "freshness": "fresh CA/user/nonce and fresh service per trial; verify_preimage fresh=False",
            "source_initialization": "bits_factory(context) is inside the consuming setup/keygen/user/issue phase",
            "cache_policy": "no harness application hash/point-validation/pairing cache or cross-certificate precomputation; interpreter/provider warm and their intrinsic behavior retained",
            "trace_policy": "complete immutable CA/user/nonce traces retained privately; summaries/trace exports/JSON/source hashing outside phase calls; no global setup trace or exponent export",
            "diagnostics": "cheap result-shape checks and success classification occur outside phase callables, without duplicate secret decoding or group operations",
            "legacy_guard": "PS/Waters use a harness-local exact-int/range guard around unchanged FixedHash/core; legacy source modules are not modified",
            "Waters_setup": "n=8; h plus nine U points included even though no signatures are executed; certificate id is separately 128 bits",
            "Okamoto_setup": "fresh nonzero b and H=bG1, including public-import validation; empty aux; public provider also exposes G2/GT/pairing",
            "runner_contract": "exactly one callable invocation and unchanged returned object; failure retained; no rollback or adversarial runner isolation",
            "failure_policy": "retain phase/error and skipped successors; no silent sample deletion; repeated setup/trial IDs rejected",
            "accounting": "keygen and import both compute Y; separately report actual costs. Recon and full preimage validation are alternative verifier workflows; never add recon twice",
            "pp_encoding": "public metadata only; no complete serialized pp wire-size claim",
            "GQ": "static source-separated comparison only; no execution",
            "signatures": "not executed; no composed-signature security claim",
            "clock": "none; no formal performance trials/statistics; no bit-time or constant-time claim",
        },
    }


def run_smoke(seed=b"W3-COMP-HARNESS-smoke-v1"):
    """Exactly one synthetic functional trial per configuration, no clock."""
    sessions = []
    for config in CONFIGURATIONS:
        session = HarnessSession(config, session_id="functional-smoke", bits_factory=ScopedSyntheticBits(seed))
        session.setup()
        session.run_trial(0)
        sessions.append(session.summary())
    results = [row for session in sessions for row in session["trials"]]
    return {"manifest": describe(), "sessions": sessions,
            "passed": sum(row["success"] for row in results),
            "failed": sum(not row["success"] for row in results),
            "formal_measurement_executed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--describe", action="store_true", help="print static manifest (default); no setup/trials")
    mode.add_argument("--smoke", action="store_true", help="one synthetic untimed trial per configuration")
    args = parser.parse_args(argv)
    output = run_smoke() if args.smoke else describe()
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return int(bool(output.get("failed", 0)))


if __name__ == "__main__":
    raise SystemExit(main())
