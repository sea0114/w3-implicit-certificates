"""Focused scalar-adapter acceptance checks; no benchmark or security estimate.

All injected bit tapes and challenges are synthetic test fixtures. They do not
establish fair randomness, a uniform setup family, a proof clock, or signature
security. Only this file's main guard runs checks; the historical PS/Waters
check and benchmark entry points are never imported or executed here.
"""

from pathlib import Path
import copy
import hashlib
import json

from scalar_reference import (
    BitID, ScalarInstance, ScalarFixedHash, ScalarTestRO,
    CertificateService, create_ca, user_prepare,
)
from w3_reference import (
    nat, decompress_G1, compress_G1, multiply, is_inf, Q,
)


RESULTS = []
ID128 = BitID(128, b"0123456789abcdef")
LAM = 128
D = 1 << LAM


class CheckFailure(Exception):
    pass


def require(condition, message):
    # Deliberately not assert: checks continue to operate under python -O.
    if not condition:
        raise CheckFailure(message)


def reject(operation, label, exceptions=(ValueError, TypeError)):
    try:
        operation()
    except exceptions:
        return
    raise CheckFailure("accepted invalid input: " + label)


class Tape:
    def __init__(self, *values):
        self.values, self.calls = list(values), []

    def __call__(self, width):
        self.calls.append(width)
        if not self.values:
            raise CheckFailure("synthetic tape exhausted")
        return self.values.pop(0)


class HashProbe:
    def __init__(self, value=1):
        self.value, self.seen = value, []

    def __call__(self, certificate):
        self.seen.append(certificate)
        return self.value


def check(check_id, config, operation):
    record = {"id": check_id, "config": config}
    try:
        evidence = operation()
        require(isinstance(evidence, dict), "check must return evidence")
        record.update(status="PASS", evidence=evidence)
    except Exception as exc:
        record.update(status="FAIL", error=type(exc).__name__ + ": " + str(exc))
    RESULTS.append(record)


def equal_public(inst, left, right):
    return inst.pub_encode(left) == inst.pub_encode(right)


def snapshot(service):
    return (set(service.issued), copy.deepcopy(getattr(service, "_last_issuance_state", None)))


def correct_flow(inst, mode, hash_kind):
    H = ScalarFixedHash(inst, LAM) if hash_kind == "FixedHash" else ScalarTestRO(inst, LAM, Tape(19))
    c_raw, Y_raw, ca_traces = create_ca(inst, Tape(3))
    u_raw, request, user_traces = user_prepare(inst, ID128, Tape(5))
    service = CertificateService(inst, mode, c_raw, H)
    require(Y_raw == inst.pub_encode(service.Y), "fresh CA public value")
    issued = service.issue(request, Tape(7))
    require(type(issued) is tuple and len(issued) == 2 and all(type(x) is bytes for x in issued), "UF output must be exactly (C, r) bytes")
    C, r_raw = issued
    e = H(C)
    expected_r = ((7 * e + 3) if mode == "ECQV" else (7 + e * 3)) % inst.q
    expected_s = ((5 * e + expected_r) if mode == "ECQV" else (5 + expected_r)) % inst.q
    require(inst.sec_decode(r_raw) == expected_r, "response formula")
    secret = service.derive(u_raw, C, r_raw)
    require(inst.sec_decode(secret) == expected_s, "completion formula")
    require(equal_public(inst, service.recon(C), inst.mu(expected_s)), "public reconstruction")
    require(service.verify_preimage(C, secret), "preimage validation")
    require(not service.verify_preimage(C, secret, fresh=True), "issued certificate cannot be fresh")
    state = service._last_issuance_state
    require(state["response"] == r_raw and state["C"] == C and state["request"] == request, "private issuance state")
    require(ca_traces[0].blocks == (3,) and user_traces[0].blocks == (5,) and state["consumed_traces"][0].blocks == (7,), "separate complete traces")
    require(len(r_raw) == len(secret) == 32, "response/secret width")
    return {"hash": hash_kind, "challenge_in_domain": 1 <= e <= D, "public_outputs": ["C", "r"], "trace_owners": ["CA keygen", "user", "issuer"]}


def scalar_endpoints(inst, mode):
    # Each c/u/k takes both full-domain endpoints, including all-zero and
    # all-(q-1) cases. Both challenge endpoints are checked independently.
    corners = ((0, 0, 0), (inst.q - 1,) * 3, (0, inst.q - 1, 0), (inst.q - 1, 0, inst.q - 1))
    cases = 0
    for c, u, k in corners:
        for e in (1, D):
            probe = HashProbe(e)
            service = CertificateService(inst, mode, inst.sec_encode(c), probe)
            request = inst.frame(inst.mu(u), ID128, True)
            C, response = service.issue(request, Tape(k))
            r = ((e * k + c) if mode == "ECQV" else (k + e * c)) % inst.q
            s = ((e * u + r) if mode == "ECQV" else (u + r)) % inst.q
            secret = service.derive(inst.sec_encode(u), C, response)
            require(inst.sec_decode(response) == r and inst.sec_decode(secret) == s, "endpoint scalar formula")
            require(equal_public(inst, service.recon(C), inst.mu(s)), "endpoint reconstructed key")
            require(service.verify_preimage(C, secret), "endpoint preimage")
            require(probe.seen and all(x == C for x in probe.seen), "hash must receive complete C bytes")
            cases += 1
    return {"cases": cases, "secret_endpoints": ["0", "q-1"], "challenge_endpoints": ["1", "2^128"], "full_certificate_hashed": True}


def traces(inst, mode):
    width = inst.q.bit_length()
    values = ((1 << width) - 1, inst.q, 0)
    ca_tape, user_tape, issuer_tape = Tape(*values), Tape(*values), Tape(*values)
    c_raw, Y_raw, ca_trace = create_ca(inst, ca_tape)
    u_raw, request, user_trace = user_prepare(inst, ID128, user_tape)
    service = CertificateService(inst, mode, c_raw, HashProbe(1))
    C, response = service.issue(request, issuer_tape)
    require(inst.sec_decode(c_raw) == inst.sec_decode(u_raw) == inst.sec_decode(response) == 0, "zero accepted after rejected blocks")
    require(Y_raw == inst.pub_encode(inst.O), "zero CA key")
    issuer_trace = service._last_issuance_state["consumed_traces"]
    expected_export = "".join("1" + bit for value in values for bit in f"{value:0{width}b}") + "00"
    for owner_trace, tape in ((ca_trace, ca_tape), (user_trace, user_tape), (issuer_trace, issuer_tape)):
        require(len(owner_trace) == 1 and owner_trace[0].width == width and owner_trace[0].blocks == values, "lossless reject/accept blocks")
        require(owner_trace[0].export_bits() == expected_export, "lossless trace serialization")
        require(tape.calls == [width] * 3 and not tape.values, "exact sampler bit requests")
    require(service.verify_preimage(C, inst.sec_encode(0)), "trace path correctness")
    return {"width_bits": width, "blocks_per_owner": ["2^width-1", "q", "0"], "all_three_owners_retained": True, "trace_export_length": len(expected_export)}


def malformed_frames(inst):
    identity = BitID(13, b"\xa6\x50")
    public = inst.pub_encode(inst.P)
    prefix = b"W3SC\x01CR"
    good = inst.frame(inst.P, identity)
    suffix = public + b"I" + nat(13) + identity.data
    payload_end = prefix + nat(len(public)) + public
    bad = {
        "prefix": b"X" + good[1:],
        "version": good[:4] + b"\x02" + good[5:],
        "role": inst.frame(inst.P, identity, True),
        "LP-short": prefix + nat(len(public) - 1) + suffix,
        "LP-long": prefix + nat(len(public) + 1) + suffix,
        "LP-nonminimal": prefix + bytes([len(public) | 128, 0]) + suffix,
        "LP-unterminated": prefix + b"\x80",
        "id-tag": payload_end + b"J" + nat(13) + identity.data,
        "id-Nat-nonminimal": payload_end + b"I\x8d\x00" + identity.data,
        "id-Nat-unterminated": payload_end + b"I\x80",
        "id-length": payload_end + b"I" + nat(17) + identity.data,
        "id-padding": good[:-1] + bytes([good[-1] | 1]),
        "trailing": good + b"\x00",
        "truncated": good[:-1],
        "mutable-bytes": bytearray(good),
        "empty": b"",
    }
    if inst.profile == "P256":
        bad["LP1-nonidentity-payload"] = prefix + nat(1) + b"\x02I" + nat(13) + identity.data
        bad["LP33-padded-identity"] = prefix + nat(33) + bytes(33) + b"I" + nat(13) + identity.data
    parsed, parsed_id = inst.parse(good)
    require(equal_public(inst, parsed, inst.P) and parsed_id == identity, "valid non-byte-aligned id")
    for label, raw in bad.items():
        reject(lambda raw=raw: inst.parse(raw), label)
    reject(lambda: inst.parse(good, request=True), "certificate used as request")
    reject(lambda: inst.parse(good, request=1), "non-bool parse role")
    reject(lambda: inst.frame(inst.P, identity, request=1), "non-bool encode role")
    reject(lambda: inst.frame(inst.P, b"id"), "untyped identity")
    reject(lambda: BitID(True, b"\x00"), "bool identity bit length")
    return {"rejected_classes": list(bad) + ["certificate-as-request", "non-bool-role", "untyped-id", "bool-id-length"], "13_bit_id_roundtrip": True}


def point_codec(inst):
    finite, identity = inst.pub_encode(inst.P), inst.pub_encode(inst.O)
    require(equal_public(inst, inst.pub_decode(finite), inst.P), "finite point roundtrip")
    require(equal_public(inst, inst.pub_decode(identity), inst.O), "identity roundtrip")
    bad = {"empty": b"", "trailing": finite + b"\x00", "truncated": finite[:-1], "mutable-bytes": bytearray(finite)}
    if inst.profile == "P256":
        require(len(finite) == 33 and identity == b"\x00", "P-256 SEC1/identity widths")
        bad.update({"padded-identity": b"\x00\x00", "finite-prefix": b"\x06" + finite[1:], "x-field-overflow": b"\x02" + inst.field_modulus.to_bytes(32, "big"), "uncompressed": b"\x04" + finite[1:] + bytes(32)})
        # x=1 is a fixed invalid P-256 compressed-point fixture; explicitly
        # establish the nonresidue property rather than assuming rejection.
        from ecdsa.curves import NIST256p
        p = inst.field_modulus
        rhs = (1 + NIST256p.curve.a() + NIST256p.curve.b()) % p
        require(pow(rhs, (p - 1) // 2, p) == p - 1, "off-curve fixture must be nonsquare")
        bad["off-curve"] = b"\x02" + (1).to_bytes(32, "big")
    else:
        require(len(finite) == len(identity) == 48, "BLS G1 fixed width")
        bad.update({"missing-compression-flag": bytes([finite[0] & 0x7f]) + finite[1:], "noncanonical-identity-sign": bytes([identity[0] | 0x20]) + identity[1:], "noncanonical-identity-payload": identity[:-1] + b"\x01"})
        # Fixed valid curve point x=4, canonical compressed, outside G1's
        # prime-order subgroup. A minimal read-only fixture probe confirmed it.
        encoded = (1 << 383) + 4
        nonmember = decompress_G1(encoded)
        require(int(compress_G1(nonmember)) == encoded and not is_inf(multiply(nonmember, Q)), "genuine canonical on-curve non-subgroup fixture")
        bad["on-curve-nonsubgroup"] = encoded.to_bytes(48, "big")
    for label, raw in bad.items():
        reject(lambda raw=raw: inst.pub_decode(raw), label)
    return {"finite_bytes": len(finite), "identity_bytes": len(identity), "rejected_classes": list(bad), "membership_strategy": "cofactor-one curve check" if inst.profile == "P256" else "explicit qP=O"}


def scalar_codec(inst):
    for s in (0, 1, inst.q - 1):
        require(inst.sec_decode(inst.sec_encode(s)) == s and len(inst.sec_encode(s)) == 32, "canonical scalar roundtrip")
    for bad in (-1, inst.q, inst.q + 1, True, False, 1.0, "1"):
        reject(lambda bad=bad: inst.sec_encode(bad), repr(bad))
    for raw in (inst.q.to_bytes(32, "big"), bytes(31), bytes(33), bytearray(32), "0"):
        reject(lambda raw=raw: inst.sec_decode(raw), "scalar wire")
    c_raw, _, ca_trace = create_ca(inst, Tape(inst.q - 1))
    u_raw, _, user_trace = user_prepare(inst, ID128, Tape(inst.q - 1))
    require(inst.sec_decode(c_raw) == inst.sec_decode(u_raw) == inst.q - 1, "helpers retain upper endpoint")
    require(ca_trace[0].blocks == user_trace[0].blocks == (inst.q - 1,), "upper endpoint sampled without rejecting")
    return {"accepted_endpoints": ["0", "q-1"], "width_bytes": 32, "range_is_profile_q": True, "bool_rejected": True, "CA_and_user_upper_endpoint_sampled": True}


def sizes(inst):
    lengths = {}
    for name, point in (("finite", inst.P), ("identity", inst.O)):
        LP = len(inst.pub_encode(point))
        expected = 8 + len(nat(LP)) + LP + len(nat(128)) + 16
        C, request = inst.frame(point, ID128), inst.frame(point, ID128, True)
        require(len(C) == len(request) == expected, "exact frame size formula")
        require(inst.parse(C)[1] == inst.parse(request, True)[1] == ID128, "size fixture parsed")
        require(expected == (60 if name == "finite" else 28) if inst.profile == "P256" else expected == 75, "contract byte size")
        lengths[name] = expected
    require(len(inst.sec_encode(0)) == len(inst.sec_encode(inst.q - 1)) == 32, "scalar payload size")
    return {"certificate_and_request_bytes": lengths, "response_and_secret_bytes": 32, "id_bits": 128, "classification": "functional byte-count check, no runtime comparison"}


def invalid_before_rng_hash(inst, mode):
    H = HashProbe(1)
    service = CertificateService(inst, mode, inst.sec_encode(3), H)
    request = inst.frame(inst.P, ID128, True)
    service.issue(request, Tape(2))
    before = snapshot(service)
    calls = len(H.seen)

    def forbidden_bits(width):
        raise CheckFailure("invalid request consumed randomness")

    bad_point = (b"\x02" + inst.field_modulus.to_bytes(32, "big")) if inst.profile == "P256" else ((1 << 383) + 4).to_bytes(48, "big")
    bad_point_request = b"W3SC\x01QK" + nat(len(bad_point)) + bad_point + b"I" + nat(ID128.bits) + ID128.data
    invalid = (b"invalid", inst.frame(inst.P, ID128), request + b"\x00", bytearray(request), bad_point_request)
    for bad in invalid:
        reject(lambda bad=bad: service.issue(bad, forbidden_bits), "invalid request")
        require(snapshot(service) == before and len(H.seen) == calls, "invalid request changed state/hash")
    return {"invalid_inputs": len(invalid), "including_invalid_group_element": True, "RNG_calls": 0, "H_calls": 0, "prior_issued_and_private_state_preserved": True}


def arbitrary_request(inst, mode):
    # Service input contains only the public point and typed identity. The
    # scalar used to generate this deterministic fixture is not passed to issue.
    public = inst.pub_add(inst.P, inst.pub_mul(inst.P, 12))
    service = CertificateService(inst, mode, inst.sec_encode(0), HashProbe(1))
    request = inst.frame(public, BitID(0, b""), True)
    C, response = service.issue(request, Tape(0))
    require(equal_public(inst, service.recon(C), public), "arbitrary request reconstruction")
    require(inst.sec_decode(response) == 0, "arbitrary request response")
    return {"request_fields": ["KU", "id"], "PoP_or_user_secret_input": False, "finite_valid_KU_accepted": True}


def duplicate_and_hit(inst, mode):
    bits = Tape(6)
    ro = ScalarTestRO(inst, LAM, bits)
    service = CertificateService(inst, mode, inst.sec_encode(2), ro)
    request = inst.frame(inst.P, ID128, True)
    predicted_C = inst.frame(inst.P, ID128)
    require(ro(predicted_C) == 7, "ordinary query fixture")
    first = service.issue(request, Tape(0))
    second = service.issue(request, Tape(0))
    require(first == second and first[0] == predicted_C, "real duplicate permitted")
    require(len(service.issued) == len(ro.table) == len(ro.ordinary_index) == 1 and bits.calls == [LAM], "ordinary hit reuses table value")
    return {"ordinary_query_before_issue": True, "successful_issuances": 2, "distinct_certificates": 1, "RO_fresh_draws": 1}


def final_lookup_identity(inst, mode):
    ro = ScalarTestRO(inst, LAM, Tape(0))
    service = CertificateService(inst, mode, inst.sec_encode(0), ro)
    C = inst.frame(inst.O, BitID(1, b"\x80"))
    require(C not in ro.table and C not in service.issued, "fresh no-query fixture")
    require(service.verify_preimage(C, inst.sec_encode(0), fresh=True), "identity no-query branch")
    require(ro.table[C] == 1 and ro.ordinary_index[C] == 1 and not service.issued, "verifier performs final lookup")
    # Also establish that this is independent of the endpoint challenge, not a
    # claim that all fresh/no-query forgeries are bounded by 1/|D|.
    high = CertificateService(inst, mode, inst.sec_encode(0), HashProbe(D))
    require(high.verify_preimage(C, inst.sec_encode(0), fresh=True), "identity upper challenge endpoint")
    return {"before_verification_queries": 0, "final_lookup_index": 1, "identity_exception_retained": True, "not_a_full_UF_security_test": True}


def bad_hash_state(inst, mode):
    H = HashProbe(1)
    service = CertificateService(inst, mode, inst.sec_encode(3), H)
    request = inst.frame(inst.P, ID128, True)
    C, response = service.issue(request, Tape(2))
    before = snapshot(service)
    cases = (0, D + 1, -1, True, False, 1.0, "1", None)
    for value in cases:
        H.value = value
        reject(lambda: service.issue(request, Tape(4)), "invalid H challenge")
        require(snapshot(service) == before, "invalid H issue committed state")
        reject(lambda: service.recon(C), "invalid H recon")
        reject(lambda: service.derive(inst.sec_encode(1), C, response), "invalid H derive")
        require(not service.verify_preimage(C, inst.sec_encode(0)), "invalid H verify must fail")
        require(snapshot(service) == before, "invalid H read path changed state")
    return {"invalid_H_values": len(cases), "issued_and_private_state_preserved": True, "nonce_consumption_before_H_failure_permitted": True}


def ro_validation(inst):
    bad_values = (-1, D, True, False, 1.0, "0", None)
    for value in bad_values:
        ro = ScalarTestRO(inst, LAM, Tape(value, 0))
        reject(lambda: ro(b"new"), "RO bad bits")
        require(not ro.table and not ro.ordinary_index, "RO failed draw poisoned state")
        require(ro(b"new") == 1 and ro.ordinary_index[b"new"] == 1, "RO clean recovery")
    ro = ScalarTestRO(inst, LAM, Tape(0, D - 1))
    require(ro(b"lo") == 1 and ro(b"hi") == D, "RO challenge endpoints")
    for value in (0, D + 1, True, 1.0):
        before = (dict(ro.table), dict(ro.ordinary_index))
        reject(lambda value=value: ro.program_fresh(b"program", value), "bad programming value")
        require((ro.table, ro.ordinary_index) == before, "bad programming committed state")
    ro.program_fresh(b"program", D)
    require(ro(b"program") == D and b"program" not in ro.ordinary_index, "programmed hit does not become ordinary query")
    reject(lambda: ro.program_fresh(b"program", 1), "programmed duplicate", (RuntimeError,))
    return {"bad_bit_values": len(bad_values), "validate_then_commit": True, "program_fresh_is_harness_only": True, "endpoints": ["1", "2^128"]}


def ro_owner(inst, mode):
    ro = ScalarTestRO(inst, LAM, Tape(2))
    reject(lambda: CertificateService(inst, "invalid", inst.sec_encode(0), ro), "owner assignment after bad mode")
    require(ro._service_owner is None, "failed mode constructor bound RO")
    reject(lambda: CertificateService(inst, mode, inst.q.to_bytes(32, "big"), ro), "owner assignment after bad CA")
    require(ro._service_owner is None, "failed CA constructor bound RO")
    first = CertificateService(inst, mode, inst.sec_encode(0), ro)
    reject(lambda: CertificateService(inst, mode, inst.sec_encode(0), ro), "same-context second owner")
    reject(lambda: CertificateService(inst, "PV" if mode == "ECQV" else "ECQV", inst.sec_encode(1), ro), "different-context second owner")
    request = inst.frame(inst.O, ID128, True)
    first.issue(request, Tape(0))
    first.issue(request, Tape(0))
    require(len(ro.table) == 1, "original RO owner remains usable")
    return {"single_service_RO_owner": True, "failed_constructor_leaves_RO_unbound": True, "original_owner_duplicate_issue_allowed": True, "wire_cross_mode_security_claim": False}


def hash_bitstrings(inst):
    tape = Tape(0, 1, 2)
    ro = ScalarTestRO(inst, LAM, tape)
    require(ro(b"\x80") == ro(BitID(8, b"\x80")) == 1, "byte-aligned alias")
    require(ro(BitID(1, b"\x80")) == 2 and ro(BitID(2, b"\x80")) == 3, "distinct non-byte-aligned bitstrings")
    require(len(ro.table) == 3 and len(tape.calls) == 3, "bitstring table partition")
    H = ScalarFixedHash(inst, LAM)
    byte_expected = 1 + int.from_bytes(hashlib.shake_256(b"W3-Hcert-v1\0\x80").digest(16), "big")
    bit_expected = 1 + int.from_bytes(hashlib.shake_256(b"W3-Hcert-bits-v1\0" + nat(1) + b"\x80").digest(16), "big")
    require(H(b"\x80") == H(BitID(8, b"\x80")) == byte_expected, "fixed hash byte domain")
    require(H(BitID(1, b"\x80")) == bit_expected, "fixed hash bit domain")
    before = (dict(ro.table), dict(ro.ordinary_index))
    reject(lambda: ro(bytearray(b"\x80")), "mutable hash input")
    require((ro.table, ro.ordinary_index) == before, "invalid hash input changed RO")
    return {"byte_alias": True, "nonbyte_lengths_distinct": [1, 2], "fixed_domain_encodings_checked": ["W3-Hcert-v1", "W3-Hcert-bits-v1"]}


def profile_contracts(p256, bls):
    require(p256.q != bls.q and p256.q > bls.q, "independent profile orders")
    require(p256.sec_decode(bls.q.to_bytes(32, "big")) == bls.q, "BLS q is valid P-256 scalar")
    reject(lambda: bls.sec_decode(bls.q.to_bytes(32, "big")), "BLS q is not BLS scalar")
    require(1 <= ScalarFixedHash(p256, 255)(b"lambda255") <= 1 << 255, "P-256 lambda255 fixed H")
    high_ro = ScalarTestRO(p256, 255, Tape((1 << 255) - 1))
    require(high_ro(b"lambda255") == 1 << 255, "P-256 lambda255 RO endpoint")
    CertificateService(p256, "PV", p256.sec_encode(0), HashProbe(1), lam=255)
    for constructor in (lambda: ScalarFixedHash(bls, 255), lambda: ScalarTestRO(bls, 255), lambda: CertificateService(bls, "PV", bls.sec_encode(0), HashProbe(1), lam=255)):
        reject(constructor, "BLS lambda255")
    for inst in (p256, bls):
        for lam in (0, -1, True, 1.0, 256, 10**6):
            reject(lambda lam=lam: ScalarFixedHash(inst, lam), "invalid lambda")
        for point in (inst.P, inst.O):
            frame = inst.frame(point, ID128)
            other = bls if inst is p256 else p256
            reject(lambda frame=frame, other=other: other.parse(frame), "cross-profile frame")
    reject(lambda: CertificateService(p256, "PV", p256.sec_encode(0), ScalarFixedHash(bls)), "wrong hash profile")
    reject(lambda: CertificateService(p256, "PV", p256.sec_encode(0), ScalarFixedHash(p256, 127), lam=128), "hash lambda mismatch")
    reject(lambda: CertificateService(p256, "invalid", p256.sec_encode(0), ScalarFixedHash(p256)), "invalid mode")
    return {"BLS_q_accepted_only_in_P256": True, "lambda255": {"P256": "accepted", "BLSG1": "rejected"}, "cross_curve_finite_and_identity_frames_rejected": True, "cross_mode_wire_replay_claim": False}


def main():
    RESULTS.clear()
    instances = {profile: ScalarInstance(profile) for profile in ("P256", "BLSG1")}
    for profile, inst in instances.items():
        for suffix, operation in (
            ("CODEC-POINT", lambda inst=inst: point_codec(inst)),
            ("CODEC-SCALAR", lambda inst=inst: scalar_codec(inst)),
            ("FRAME", lambda inst=inst: malformed_frames(inst)),
            ("SIZE", lambda inst=inst: sizes(inst)),
            ("RO-COMMIT", lambda inst=inst: ro_validation(inst)),
            ("HASH-BITS", lambda inst=inst: hash_bitstrings(inst)),
        ):
            check("SC-" + suffix, profile, operation)
        for mode in ("ECQV", "PV"):
            config = profile + "/" + mode
            for hash_kind in ("FixedHash", "TestRO"):
                check("SC-FLOW-" + hash_kind.upper(), config, lambda inst=inst, mode=mode, hash_kind=hash_kind: correct_flow(inst, mode, hash_kind))
            for suffix, operation in (
                ("ENDPOINTS", scalar_endpoints), ("FULL-TRACE", traces),
                ("INVALID-FIRST", invalid_before_rng_hash), ("NO-POP", arbitrary_request),
                ("DUPLICATE-HIT", duplicate_and_hit), ("FINAL-IDENTITY", final_lookup_identity),
                ("H-GUARD-STATE", bad_hash_state), ("RO-OWNER", ro_owner),
            ):
                check("SC-" + suffix, config, lambda inst=inst, mode=mode, operation=operation: operation(inst, mode))
    check("SC-PROFILE-CONTRACTS", "P256+BLSG1", lambda: profile_contracts(instances["P256"], instances["BLSG1"]))
    failures = sum(record["status"] != "PASS" for record in RESULTS)
    report = {
        "task": "W3-SC-IMPL", "scope": "targeted finite functional and boundary acceptance",
        "synthetic_fixtures_only": True, "benchmark_executed": False,
        "historical_PS_Waters_checks_executed": False,
        "does_not_establish": ["fair random bits", "uniform BGen", "bit-time clock", "ROM instantiation", "signature composition", "cross-context protocol security"],
        "configs": [profile + "/" + mode for profile in instances for mode in ("ECQV", "PV")],
        "checks": RESULTS, "total": len(RESULTS), "passed": len(RESULTS) - failures, "failed": failures,
    }
    Path(__file__).with_name("scalar_verification_results.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"task": "W3-SC-IMPL", "total": len(RESULTS), "passed": len(RESULTS) - failures, "failed": failures}))
    if failures:
        for record in RESULTS:
            if record["status"] == "FAIL":
                print(json.dumps(record, ensure_ascii=False))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
