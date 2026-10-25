"""Targeted W3 representation-adapter acceptance; no timing or benchmark.

The known setup exponent b=7 and every injected tape are synthetic fixtures.
These checks do not establish fair randomness, setup secrecy, a uniform BGen,
a bit-time bound, a security reduction, or composition with an Okamoto
signature. Historical PS/Waters/Schnorr check entry points are not executed.
"""

from pathlib import Path
import copy
import hashlib
import json

from okamoto_reference import (
    BitID, Trace, OkamotoInstance, setup_okamoto, OkamotoFixedHash,
    OkamotoTestRO, CertificateService, create_ca, user_prepare,
    to_okamoto_public,
)
from scalar_reference import ScalarInstance, ScalarFixedHash
from w3_reference import nat, decompress_G1, compress_G1, multiply, is_inf, Q


RESULTS = []
ID128 = BitID(128, b"0123456789abcdef")
LAM = 128
D = 1 << LAM
B_FIXTURE = 7
PROBE_DESCRIPTION = "Synthetic constant challenge held by this acceptance fixture; no ROM claim."


class CheckFailure(Exception):
    pass


def require(condition, message):
    # Deliberately active under python -O.
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


def custom_service(inst, mode, secret, H=None, **kwargs):
    if H is None:
        H = HashProbe(1)
    return CertificateService(inst, mode, inst.sec_encode(secret), H,
                              hash_description=PROBE_DESCRIPTION, **kwargs)


def check(check_id, config, operation):
    record = {"id": check_id, "config": config}
    try:
        evidence = operation()
        require(isinstance(evidence, dict), "check must return evidence")
        record.update(status="PASS", evidence=evidence)
    except Exception as exc:
        record.update(status="FAIL", error=type(exc).__name__ + ": " + str(exc))
    RESULTS.append(record)


def same_public(inst, left, right):
    return inst.pub_encode(left) == inst.pub_encode(right)


def snapshot(service):
    return (set(service.issued), copy.deepcopy(getattr(service, "_last_issuance_state", None)))


def known_rep(inst, pair):
    """Independent one-generator value for the test-only known b=7."""
    return multiply(inst.P, (pair[0] + B_FIXTURE * pair[1]) % inst.q)


def setup_contract(inst):
    width = inst.q.bit_length()
    tape = Tape(0, inst.q, (1 << width) - 1, B_FIXTURE)
    fresh = setup_okamoto(tape)
    require(type(fresh) is OkamotoInstance, "setup must return only public instance")
    require(fresh.h_raw == inst.h_raw and tape.calls == [width] * 4 and not tape.values, "setup rejects zero/out-of-range blocks before b=7")
    unit = setup_okamoto(Tape(1))
    require(unit.h_raw == inst.pub_encode(inst.P), "b=1 is in full nonzero support")
    for public in (inst.P, inst.h):
        imported = OkamotoInstance(inst.pub_encode(public))
        require(imported.h_raw == inst.pub_encode(public), "valid imported h")
        require(imported.public_parameters()["setup"]["distribution_certified_by_import"] is False, "import must not certify the setup law")
    for raw in (inst.pub_encode(inst.O), b"", inst.h_raw + b"\x00", bytearray(inst.h_raw), ((1 << 383) + 4).to_bytes(48, "big")):
        reject(lambda raw=raw: OkamotoInstance(raw), "invalid distinguished h")
    for value in (-1, 1 << width, True, False, 1.0, "7"):
        reject(lambda value=value: setup_okamoto(Tape(value)), "setup bit source contract")
    require(not any(k in vars(fresh) for k in ("b", "setup_b", "setup_trace", "trace", "traces", "aux")), "setup secret/trace leaked as instance fields")
    require(not any(isinstance(value, Trace) for value in vars(fresh).values()), "setup trace returned as instance value")
    require(fresh.public_parameters()["aux"] == [], "baseline aux must be empty")
    return {"setup_rejected_blocks": ["0", "q", "2^width-1"], "accepted_test_b": B_FIXTURE,
            "b1_accepted": True, "returned_values": ["public instance"], "public_import_checks_only_support": True,
            "does_not_test_secrecy_or_fairness": True, "no_secure_erasure_claim": True}


def pair_codec(inst):
    pairs = ((0, 0), (0, inst.q - 1), (inst.q - 1, 0), (inst.q - 1, inst.q - 1), (1, 2))
    for pair in pairs:
        encoded = inst.sec_encode(pair)
        require(len(encoded) == 64 and inst.sec_decode(encoded) == pair, "full pair domain roundtrip")
        require(same_public(inst, inst.mu(pair), known_rep(inst, pair)), "representation includes both coordinates")
    invalid = ((0,), (0, 0, 0), [0, 0], 0, (-1, 0), (0, -1), (inst.q, 0), (0, inst.q), (True, 0), (0, False), (0, 1.0), ("1", 0))
    for pair in invalid:
        reject(lambda pair=pair: inst.sec_encode(pair), "invalid pair coordinate/type")
        reject(lambda pair=pair: inst.mu(pair), "mu invalid pair coordinate/type")
    raw_invalid = (bytes(63), bytes(65), bytearray(64), "0", inst.q.to_bytes(32, "big") + bytes(32), bytes(32) + inst.q.to_bytes(32, "big"))
    for raw in raw_invalid:
        reject(lambda raw=raw: inst.sec_decode(raw), "noncanonical secret wire")
    require(inst.sec_add((inst.q - 1, 0), (1, inst.q - 1)) == (0, inst.q - 1), "independent pair addition")
    require(inst.sec_mul((1, 2), -1) == (inst.q - 1, inst.q - 2), "integer action modulo q")
    reject(lambda: inst.sec_mul((1, 2), True), "bool action")
    return {"accepted_pairs": ["(0,0)", "(0,q-1)", "(q-1,0)", "(q-1,q-1)", "(1,2)"],
            "secret_bytes": 64, "invalid_pair_classes": len(invalid), "invalid_wire_classes": len(raw_invalid),
            "both_coordinates_validated_without_input_reduction": True}


def point_codec(inst):
    finite, identity = inst.pub_encode(inst.P), inst.pub_encode(inst.O)
    require(len(finite) == len(identity) == 48, "fixed G1 point width")
    require(same_public(inst, inst.pub_decode(finite), inst.P), "finite point roundtrip")
    require(same_public(inst, inst.pub_decode(identity), inst.O), "identity point roundtrip")
    encoded = (1 << 383) + 4
    nonmember = decompress_G1(encoded)
    require(int(compress_G1(nonmember)) == encoded and not is_inf(multiply(nonmember, Q)), "non-subgroup fixture is canonical and on curve")
    bad = {"empty": b"", "trailing": finite + b"\x00", "truncated": finite[:-1], "mutable": bytearray(finite),
           "missing-compression": bytes([finite[0] & 0x7f]) + finite[1:],
           "identity-sign": bytes([identity[0] | 0x20]) + identity[1:],
           "identity-payload": identity[:-1] + b"\x01", "on-curve-nonsubgroup": encoded.to_bytes(48, "big")}
    for label, raw in bad.items():
        reject(lambda raw=raw: inst.pub_decode(raw), label)
    return {"finite_and_identity_bytes": 48, "rejected_classes": list(bad), "subgroup_test": "qP=O; no cofactor clearing"}


def frames(inst):
    identity = BitID(13, b"\xa6\x50")
    good = inst.frame(inst.P, identity)
    point = inst.pub_encode(inst.P)
    prefix = b"W3RP\x01CR"
    tail = point + b"I" + nat(13) + identity.data
    point_end = prefix + nat(48) + point
    bad = {"wrong-prefix": b"W3SC" + good[4:], "version": good[:4] + b"\x02" + good[5:],
           "request-role": inst.frame(inst.P, identity, True), "width47": prefix + nat(47) + tail,
           "width49": prefix + nat(49) + tail, "nonminimal-width": prefix + b"\xb0\x00" + tail,
           "unterminated-width": prefix + b"\x80", "id-tag": point_end + b"J" + nat(13) + identity.data,
           "nonminimal-id-length": point_end + b"I\x8d\x00" + identity.data,
           "unterminated-id-length": point_end + b"I\x80", "id-length": point_end + b"I" + nat(17) + identity.data,
           "id-padding": good[:-1] + bytes([good[-1] | 1]), "trailing": good + b"\x00",
           "truncated": good[:-1], "mutable": bytearray(good), "empty": b""}
    parsed, parsed_id = inst.parse(good)
    require(same_public(inst, parsed, inst.P) and parsed_id == identity, "13-bit ID roundtrip")
    for label, raw in bad.items():
        reject(lambda raw=raw: inst.parse(raw), label)
    reject(lambda: inst.parse(good, True), "certificate-as-request")
    reject(lambda: inst.parse(good, 1), "non-bool parse role")
    reject(lambda: inst.frame(inst.P, identity, 1), "non-bool frame role")
    reject(lambda: inst.frame(inst.P, b"id"), "untyped id")
    reject(lambda: BitID(True, b"\x00"), "bool ID length")
    return {"rejected_classes": list(bad), "13_bit_ID_roundtrip": True, "shared_frame_for_both_modes": True,
            "context_external_to_frame": ["h", "CA", "mode", "hash"]}


def sizes(inst):
    for point in (inst.P, inst.O):
        C, request = inst.frame(point, ID128), inst.frame(point, ID128, True)
        require(len(C) == len(request) == 75, "128-bit ID frame size")
        require(inst.parse(C)[1] == inst.parse(request, True)[1] == ID128, "both roles parsed")
    require(len(inst.sec_encode((0, 0))) == len(inst.sec_encode((inst.q - 1, inst.q - 1))) == 64, "pair width")
    return {"id_bits": 128, "certificate_bytes": 75, "request_bytes": 75,
            "response_bytes": 64, "secret_bytes": 64, "public_key_bytes": 48,
            "certificate_plus_response_bytes": 139, "additional_shared_h_bytes": 48,
            "full_pp_transport_encoding_defined": False, "runtime_comparison": False}


def correct_flow(inst, mode, hash_kind):
    H = OkamotoFixedHash(inst, LAM) if hash_kind == "FixedHash" else OkamotoTestRO(inst, LAM, Tape(19))
    c_raw, Y_raw, ca_trace = create_ca(inst, Tape(3, 4))
    u_raw, request, user_trace = user_prepare(inst, ID128, Tape(5, 6))
    service = CertificateService(inst, mode, c_raw, H)
    require(Y_raw == inst.pub_encode(service.Y), "CA public key")
    issued = service.issue(request, Tape(7, 8))
    require(type(issued) is tuple and len(issued) == 2 and all(type(v) is bytes for v in issued), "UF output exactly two byte strings")
    C, response = issued
    e = H(C)
    r = tuple(((e * k + c) if mode == "ECQV" else (k + e * c)) % inst.q for k, c in ((7, 3), (8, 4)))
    s = tuple(((e * u + v) if mode == "ECQV" else (u + v)) % inst.q for u, v in zip((5, 6), r))
    secret = service.derive(u_raw, C, response)
    require(inst.sec_decode(response) == r and inst.sec_decode(secret) == s, "response/completion on each coordinate")
    require(same_public(inst, service.recon(C), known_rep(inst, s)), "reconstruction against independent one-generator fixture")
    require(service.verify_preimage(C, secret) and not service.verify_preimage(C, secret, fresh=True), "preimage and issued freshness")
    state = service._last_issuance_state
    require(state["response"] == response and state["C"] == C and state["request"] == request, "private state references issued outputs")
    require(inst.sec_decode(state["nonce"]) == (7, 8), "both nonce coordinates retained for SH")
    require([v.blocks for v in ca_trace] == [(3,), (4,)] and [v.blocks for v in user_trace] == [(5,), (6,)] and [v.blocks for v in state["consumed_traces"]] == [(7,), (8,)], "each role owns two traces")
    return {"hash": hash_kind, "challenge_in_domain": 1 <= e <= D, "public_outputs": ["C", "r"],
            "private_nonce_coordinates": 2, "traces_per_role": 2, "freshness_rejection": True}


def endpoints(inst, mode):
    corners = (((0, 0),) * 3, ((inst.q - 1, inst.q - 1),) * 3,
               ((0, inst.q - 1), (inst.q - 1, 0), (0, 0)))
    count = 0
    for c, u, k in corners:
        for e in (1, D):
            H = HashProbe(e)
            service = custom_service(inst, mode, c, H)
            C, response = service.issue(inst.frame(inst.mu(u), ID128, True), Tape(*k))
            r = tuple(((e * ki + ci) if mode == "ECQV" else (ki + e * ci)) % inst.q for ki, ci in zip(k, c))
            s = tuple(((e * ui + ri) if mode == "ECQV" else (ui + ri)) % inst.q for ui, ri in zip(u, r))
            secret = service.derive(inst.sec_encode(u), C, response)
            require(inst.sec_decode(response) == r and inst.sec_decode(secret) == s, "full-domain endpoint formulas")
            require(same_public(inst, service.recon(C), known_rep(inst, s)) and service.verify_preimage(C, secret), "endpoint reconstruction/preimage")
            require(all(value == C for value in H.seen), "H receives complete C")
            count += 1
    return {"cases": count, "coordinate_endpoints": ["0", "q-1"], "challenge_endpoints": ["1", "2^128"], "full_C_hashed": True}


def pair_traces(inst, mode):
    width = inst.q.bit_length()
    first, second = ((1 << width) - 1, inst.q, 0), (inst.q, inst.q - 1)
    values = first + second
    ca_bits, user_bits, issuer_bits = Tape(*values), Tape(*values), Tape(*values)
    c_raw, _, ca_trace = create_ca(inst, ca_bits)
    u_raw, request, user_trace = user_prepare(inst, ID128, user_bits)
    require(inst.sec_decode(c_raw) == inst.sec_decode(u_raw) == (0, inst.q - 1), "independent coordinate endpoints sampled")
    service = custom_service(inst, mode, inst.sec_decode(c_raw))
    C, response = service.issue(request, issuer_bits)
    state = service._last_issuance_state
    require(inst.sec_decode(state["nonce"]) == (0, inst.q - 1), "nonce pair retained")
    for traces, bits in ((ca_trace, ca_bits), (user_trace, user_bits), (state["consumed_traces"], issuer_bits)):
        require(type(traces) is tuple and len(traces) == 2, "two traces per pair")
        for trace, blocks in zip(traces, (first, second)):
            exported = "".join("1" + bit for value in blocks for bit in f"{value:0{width}b}") + "00"
            require(trace.width == width and trace.blocks == blocks and trace.export_bits() == exported, "complete separate rejection/acceptance trace")
        require(bits.calls == [width] * 5 and not bits.values, "no hidden or omitted bit blocks")
    require(service.verify_preimage(C, service.derive(u_raw, C, response)), "traced flow correctness")
    require(not any(key in state for key in ("b", "setup_b", "setup_trace", "setup_traces")), "SH state must not include setup hidden state")
    return {"width_bits": width, "first_coordinate_blocks": ["2^width-1", "q", "0"],
            "second_coordinate_blocks": ["q", "q-1"], "trace_owners": ["CA", "user", "issuer"],
            "SH_nonce_and_traces": ["two nonce coordinates", "two complete traces"], "global_setup_trace_in_SH": False}


def kernel_alias(inst, mode):
    service = custom_service(inst, mode, (3, 4), HashProbe(11))
    u = (5, 6)
    C, response = service.issue(inst.frame(inst.mu(u), ID128, True), Tape(9, 10))
    original = service.derive(inst.sec_encode(u), C, response)
    pair = inst.sec_decode(original)
    delta = ((-B_FIXTURE * 17) % inst.q, 17)
    alternative = inst.sec_encode(((pair[0] + delta[0]) % inst.q, (pair[1] + delta[1]) % inst.q))
    require(delta != (0, 0) and is_inf(inst.mu(delta)), "nonzero kernel witness")
    require(original != alternative and service.verify_preimage(C, original) and service.verify_preimage(C, alternative), "every tested preimage accepted, not equality to original secret")
    outside = inst.sec_encode(((pair[0] + 1) % inst.q, pair[1]))
    require(not service.verify_preimage(C, outside), "nonkernel perturbation rejected")
    for e in (1, D):
        require(is_inf(inst.mu(inst.sec_mul(delta, e))), "tested nonzero challenge preserves kernel")
    return {"synthetic_known_b": B_FIXTURE, "kernel_witness": "(-7*17 mod q,17)",
            "distinct_secret_same_certificate_accepted": True, "nonkernel_shift_rejected": True,
            "not_a_new_kernel_theorem": True}


def identity_values(inst, mode):
    kernel_secret = (inst.q - B_FIXTURE, 1)
    require(kernel_secret != (0, 0) and is_inf(inst.mu(kernel_secret)), "nonzero secret maps to identity")
    service = custom_service(inst, mode, kernel_secret, HashProbe(D))
    request = inst.frame(inst.mu(kernel_secret), ID128, True)
    C, response = service.issue(request, Tape(*kernel_secret))
    secret = service.derive(inst.sec_encode(kernel_secret), C, response)
    state = service._last_issuance_state
    require(is_inf(service.Y) and is_inf(service.recon(C)), "identity Y and Q legal")
    for name in ("KU", "KC", "R"):
        require(is_inf(inst.pub_decode(state[name])), "identity " + name + " legal")
    require(inst.sec_decode(state["nonce"]) == kernel_secret and service.verify_preimage(C, secret), "kernel nonce retained and resulting preimage valid")
    return {"legal_identity_values": ["Y", "KU", "KC", "R", "Q"], "nonzero_kernel_CA_user_nonce": True,
            "only_distinguished_h_requires_nonidentity": True}


def invalid_first(inst, mode):
    H = HashProbe(1)
    service = custom_service(inst, mode, (3, 4), H)
    request = inst.frame(inst.P, ID128, True)
    service.issue(request, Tape(2, 3))
    before, hash_calls = snapshot(service), len(H.seen)
    def forbidden_bits(width):
        raise CheckFailure("invalid request consumed nonce randomness")
    bad_point = ((1 << 383) + 4).to_bytes(48, "big")
    bad_request = b"W3RP\x01QK" + nat(48) + bad_point + b"I" + nat(128) + ID128.data
    inputs = (b"invalid", inst.frame(inst.P, ID128), request + b"\x00", bytearray(request), bad_request)
    for raw in inputs:
        reject(lambda raw=raw: service.issue(raw, forbidden_bits), "invalid request")
        require(snapshot(service) == before and len(H.seen) == hash_calls, "invalid request changed prior state or H")
    return {"malformed_requests": len(inputs), "includes_nonsubgroup": True, "nonce_calls": 0, "H_calls": 0,
            "prior_issued_and_private_state_preserved": True}


def arbitrary_request(inst, mode):
    service = custom_service(inst, mode, (0, 0))
    public = multiply(inst.P, 13)
    C, response = service.issue(inst.frame(public, BitID(0, b""), True), Tape(0, 0))
    require(same_public(inst, service.recon(C), public) and inst.sec_decode(response) == (0, 0), "arbitrary valid public request")
    return {"request_fields": ["KU", "id"], "user_secret_or_PoP_passed_to_issue": False, "zero_bit_ID_accepted": True}


def duplicate_hit(inst, mode):
    bits = Tape(6)
    ro = OkamotoTestRO(inst, LAM, bits)
    service = CertificateService(inst, mode, inst.sec_encode((2, 3)), ro)
    request, predicted = inst.frame(inst.P, ID128, True), inst.frame(inst.P, ID128)
    require(ro(predicted) == 7, "ordinary prequery")
    first, second = service.issue(request, Tape(0, 0)), service.issue(request, Tape(0, 0))
    require(first == second and first[0] == predicted, "duplicate certificate is permitted")
    require(len(service.issued) == len(ro.table) == len(ro.ordinary_index) == 1 and bits.calls == [LAM], "ordinary hit reused")
    return {"ordinary_query_before_issue": True, "successful_issuances": 2, "distinct_certificates": 1,
            "fresh_RO_draws": 1, "proof_only_programming_stop_added_to_real_protocol": False}


def final_identity(inst, mode):
    ro = OkamotoTestRO(inst, LAM, Tape(0))
    service = CertificateService(inst, mode, inst.sec_encode((0, 0)), ro)
    C = inst.frame(inst.O, BitID(1, b"\x80"))
    require(C not in ro.table and C not in service.issued, "fresh no-query fixture")
    require(service.verify_preimage(C, inst.sec_encode((0, 0)), fresh=True), "identity no-query preimage")
    require(ro.table[C] == 1 and ro.ordinary_index[C] == 1 and not service.issued, "final verification lookup")
    high = custom_service(inst, mode, (0, 0), HashProbe(D))
    require(high.verify_preimage(C, inst.sec_encode((inst.q - 7, 1)), fresh=True), "upper challenge also admits kernel identity preimage")
    return {"queries_before_verification": 0, "final_lookup_index": 1, "identity_exception_retained": True,
            "not_a_full_UF_security_test": True}


def bad_hash_state(inst, mode):
    H = HashProbe(1)
    service = custom_service(inst, mode, (3, 4), H)
    request = inst.frame(inst.P, ID128, True)
    C, response = service.issue(request, Tape(2, 3))
    before = snapshot(service)
    invalid = (0, D + 1, -1, True, False, 1.0, "1", None)
    for value in invalid:
        H.value = value
        reject(lambda: service.issue(request, Tape(4, 5)), "invalid H issue")
        require(snapshot(service) == before, "H failure committed issuance state")
        reject(lambda: service.recon(C), "invalid H recon")
        reject(lambda: service.derive(inst.sec_encode((1, 2)), C, response), "invalid H derive")
        require(not service.verify_preimage(C, inst.sec_encode((0, 0))), "invalid H verification must fail")
        require(snapshot(service) == before, "failed read path changed state")
    return {"invalid_H_values": len(invalid), "issued_and_private_state_preserved": True,
            "nonce_consumption_before_H_failure_permitted": True}


def ro_commit(inst):
    invalid = (-1, D, True, False, 1.0, "0", None)
    for value in invalid:
        ro = OkamotoTestRO(inst, LAM, Tape(value, 0))
        reject(lambda: ro(b"fresh"), "invalid RO bits")
        require(not ro.table and not ro.ordinary_index, "failed draw changed RO")
        require(ro(b"fresh") == 1 and ro.ordinary_index[b"fresh"] == 1, "recovery after failed draw")
    ro = OkamotoTestRO(inst, LAM, Tape(0, D - 1))
    require(ro(b"low") == 1 and ro(b"high") == D, "RO output endpoints")
    for e in (0, D + 1, True, 1.0):
        before = (dict(ro.table), dict(ro.ordinary_index))
        reject(lambda e=e: ro.program_fresh(b"program", e), "invalid programming value")
        require((ro.table, ro.ordinary_index) == before, "invalid programming committed")
    ro.program_fresh(b"program", D)
    require(ro(b"program") == D and b"program" not in ro.ordinary_index, "programming remains separate from ordinary lookup")
    reject(lambda: ro.program_fresh(b"program", 1), "programming hit", (RuntimeError,))
    return {"invalid_draw_values": len(invalid), "validate_before_commit": True, "program_fresh_is_proof_harness_only": True}


def ro_owner(inst, mode):
    ro = OkamotoTestRO(inst, LAM, Tape(2))
    bad_ca = bytes(32) + inst.q.to_bytes(32, "big")
    failures = (
        lambda: CertificateService(inst, "bad", inst.sec_encode((0, 0)), ro),
        lambda: CertificateService(inst, mode, bad_ca, ro),
        lambda: CertificateService(inst, mode, inst.sec_encode((0, 0)), ro, hash_description="override"),
    )
    for operation in failures:
        reject(operation, "failed constructor")
        require(ro._service_owner is None, "failed constructor consumed RO owner")
    first = CertificateService(inst, mode, inst.sec_encode((0, 0)), ro)
    reject(lambda: CertificateService(inst, mode, inst.sec_encode((0, 0)), ro), "second same-context owner")
    reject(lambda: CertificateService(inst, "PV" if mode == "ECQV" else "ECQV", inst.sec_encode((1, 0)), ro), "second other-context owner")
    request = inst.frame(inst.O, ID128, True)
    first.issue(request, Tape(0, 0))
    first.issue(request, Tape(0, 0))
    require(len(ro.table) == 1, "original owner remains usable")
    return {"failed_constructors_leave_unbound": len(failures), "single_service_owner": True,
            "owner_remains_usable": True, "cross_context_wire_security_claim": False}


def hash_bits(inst):
    ro = OkamotoTestRO(inst, LAM, Tape(0, 1, 2))
    require(ro(b"\x80") == ro(BitID(8, b"\x80")) == 1, "byte-aligned alias")
    require(ro(BitID(1, b"\x80")) == 2 and ro(BitID(2, b"\x80")) == 3, "nonbyte bit lengths distinguished")
    H = OkamotoFixedHash(inst, LAM)
    byte_expected = 1 + int.from_bytes(hashlib.shake_256(b"W3-Hcert-v1\0\x80").digest(16), "big")
    bit_expected = 1 + int.from_bytes(hashlib.shake_256(b"W3-Hcert-bits-v1\0" + nat(1) + b"\x80").digest(16), "big")
    require(H(b"\x80") == H(BitID(8, b"\x80")) == byte_expected and H(BitID(1, b"\x80")) == bit_expected, "fixed hash domains unchanged")
    before = (dict(ro.table), dict(ro.ordinary_index))
    reject(lambda: ro(bytearray(b"\x80")), "mutable hash input")
    require((ro.table, ro.ordinary_index) == before, "invalid input changed RO")
    return {"bytes_alias_byte_aligned_BitID": True, "nonbyte_lengths_distinct": [1, 2],
            "fixed_hash_domains": ["W3-Hcert-v1", "W3-Hcert-bits-v1"]}


def hash_context(inst):
    other = setup_okamoto(Tape(9))
    c_raw = inst.sec_encode((0, 0))
    for H in (OkamotoFixedHash(other), OkamotoTestRO(other, bits=Tape(0)), ScalarFixedHash(ScalarInstance("BLSG1"))):
        reject(lambda H=H: CertificateService(inst, "PV", c_raw, H), "foreign hash context")
        if isinstance(H, OkamotoTestRO):
            require(H._service_owner is None, "foreign h rejection bound RO")
    for name, value in (("q", inst.q + 1), ("profile", "BLSG1"), ("domain", "Zq"), ("h_raw", other.h_raw), ("lam", 127)):
        H = HashProbe(1)
        setattr(H, name, value)
        reject(lambda H=H: CertificateService(inst, "PV", c_raw, H, lam=128, hash_description=PROBE_DESCRIPTION), "custom metadata " + name)
    for desc in (None, "", "  ", 1):
        reject(lambda desc=desc: CertificateService(inst, "PV", c_raw, HashProbe(), hash_description=desc), "custom hash needs description")
    reject(lambda: CertificateService(inst, "PV", c_raw, HashProbe(), hash_description=PROBE_DESCRIPTION, hash_model="test-ROM"), "custom ROM label")
    valid = custom_service(inst, "PV", (0, 0))
    require(valid.public_configuration()["hash_description"] == PROBE_DESCRIPTION and valid.public_configuration()["hash_model"] == "fixed", "explicit custom contract")
    for lam in (0, -1, True, 1.0, 255, 10**6):
        reject(lambda lam=lam: OkamotoFixedHash(inst, lam), "fixed H challenge range")
        reject(lambda lam=lam: OkamotoTestRO(inst, lam), "RO challenge range")
        reject(lambda lam=lam: custom_service(inst, "PV", (0, 0), lam=lam), "service challenge range")
    reject(lambda: CertificateService(inst, "PV", c_raw, OkamotoFixedHash(inst, 127), lam=128), "lambda mismatch")
    return {"foreign_h_hash_rejected": True, "scalar_hash_rejected": True,
            "custom_metadata_fields_checked": ["q", "profile", "domain", "h_raw", "lam"],
            "custom_description_required": True, "custom_cannot_claim_builtin_test_ROM": True,
            "challenge_contract": "1 <= lambda and 2^lambda < q"}


def public_configuration(inst):
    first = CertificateService(inst, "PV", inst.sec_encode((3, 4)), OkamotoFixedHash(inst))
    # A kernel-shifted CA has the same public setup and therefore the same cfg.
    second = CertificateService(inst, "PV", inst.sec_encode(((3 - 7) % inst.q, 5)), OkamotoFixedHash(inst))
    cfg = first.public_configuration()
    require(cfg == second.public_configuration(), "configuration must depend on CA public value, not its chosen preimage")
    before = json.dumps(cfg, sort_keys=True)
    require(json.loads(before) == cfg, "JSON-safe deterministic cfg")
    first.issue(inst.frame(inst.P, ID128, True), Tape(8, 9))
    require(json.dumps(first.public_configuration(), sort_keys=True) == before, "private issuance state must not enter cfg")
    params = cfg["parameters"]
    require(cfg["aux"] == params["aux"] == [], "empty aux contract")
    require(params["q"] == str(inst.q) and len(bytes.fromhex(params["generator_G1"])) == 48 and len(bytes.fromhex(params["generator_G2"])) == 96 and params["h"] == inst.h_raw.hex(), "full public group/provider description")
    require(set(params["provider"]["public_capabilities"]) == {"G1", "G2", "GT", "pairing"} and params["provider"]["adapter_pairing_calls"] is False, "public pairing availability disclosed separately from adapter operations")
    require(params["setup"]["global_b_and_setup_trace_exposed"] is False and params["setup"]["secure_erasure_claim"] is False, "visibility limitation explicit")
    require(cfg["CA_public"] == inst.pub_encode(first.Y).hex() and "SHAKE256" in cfg["hash_description"] and cfg["lambda"] == 128, "CA public and complete builtin hash description")
    require(not any(key in cfg for key in ("ca_secret", "b", "seed", "trace", "nonce")), "private fields in cfg")
    cfg["aux"].append("mutated copy")
    params["aux"].append("mutated copy")
    require(first.public_configuration()["aux"] == first.public_configuration()["parameters"]["aux"] == [], "configuration returns fresh lists")
    reject(lambda: CertificateService(inst, "PV", inst.sec_encode((0, 0)), OkamotoFixedHash(inst), aux=["advice"]), "unspecified runtime aux")
    return {"deterministic_for_same_public_setup_and_CA": True, "independent_of_private_preimage_and_issuance_state": True,
            "aux": [], "public_provider_capabilities": ["G1", "G2", "GT", "pairing"],
            "import_does_not_certify_setup_law": True, "no_process_isolation_or_erasure_claim": True}


def sign_bridge(inst, mode):
    service = custom_service(inst, mode, (3, 4), HashProbe(11))
    u = (5, 6)
    C, response = service.issue(inst.frame(inst.mu(u), ID128, True), Tape(7, 8))
    secret = service.derive(inst.sec_encode(u), C, response)
    Q_raw = inst.pub_encode(service.recon(C))
    v = inst.to_okamoto_public(Q_raw)
    require(v == to_okamoto_public(Q_raw), "method/module sign bridge agree")
    require(is_inf(inst.pub_add(inst.pub_decode(v), known_rep(inst, inst.sec_decode(secret)))), "original public sign is negative completed representation")
    zero_raw = inst.pub_encode(inst.O)
    require(inst.to_okamoto_public(zero_raw) == to_okamoto_public(zero_raw) == zero_raw, "negative identity is identity")
    for bad in (b"", Q_raw + b"\x00", ((1 << 383) + 4).to_bytes(48, "big")):
        reject(lambda bad=bad: to_okamoto_public(bad), "invalid public sign input")
    return {"relation": "v_O=-Q=-(s_x*G+s_y*h)", "identity_bridge": True,
            "signature_algorithm_executed": False, "signature_composition_security_claim": False}


def main():
    RESULTS.clear()
    inst = setup_okamoto(Tape(B_FIXTURE))
    for suffix, operation in (
        ("SETUP", setup_contract), ("PAIR-CODEC", pair_codec), ("POINT-CODEC", point_codec),
        ("FRAME", frames), ("SIZE", sizes), ("RO-COMMIT", ro_commit),
        ("HASH-BITS", hash_bits), ("HASH-CONTEXT", hash_context), ("PUBLIC-CFG", public_configuration),
    ):
        check("OKA-" + suffix, inst.profile, lambda operation=operation: operation(inst))
    for mode in ("ECQV", "PV"):
        config = inst.profile + "/" + mode
        for kind in ("FixedHash", "TestRO"):
            check("OKA-FLOW-" + kind.upper(), config, lambda mode=mode, kind=kind: correct_flow(inst, mode, kind))
        for suffix, operation in (
            ("ENDPOINTS", endpoints), ("FULL-TRACE", pair_traces), ("KERNEL-ALIAS", kernel_alias),
            ("IDENTITY", identity_values), ("INVALID-FIRST", invalid_first), ("NO-POP", arbitrary_request),
            ("DUPLICATE-HIT", duplicate_hit), ("FINAL-IDENTITY", final_identity),
            ("H-GUARD-STATE", bad_hash_state), ("RO-OWNER", ro_owner), ("SIGN-BRIDGE", sign_bridge),
        ):
            check("OKA-" + suffix, config, lambda mode=mode, operation=operation: operation(inst, mode))
    failures = sum(record["status"] != "PASS" for record in RESULTS)
    report = {
        "task": "W3-OKA-IMPL", "scope": "targeted finite functional and boundary acceptance",
        "synthetic_fixtures_only": True, "known_setup_b_fixture": B_FIXTURE, "benchmark_executed": False,
        "historical_PS_Waters_Schnorr_checks_executed": False,
        "does_not_establish": ["fair random bits", "uniform BGen", "setup secrecy", "secure erasure", "bit-time clock",
                               "ROM instantiation", "full security games", "new core theorem", "signature composition", "cross-context protocol security"],
        "configs": [inst.profile + "/" + mode for mode in ("ECQV", "PV")],
        "checks": RESULTS, "total": len(RESULTS), "passed": len(RESULTS) - failures, "failed": failures,
    }
    Path(__file__).with_name("okamoto_verification_results.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"task": "W3-OKA-IMPL", "total": len(RESULTS), "passed": len(RESULTS) - failures, "failed": failures}))
    if failures:
        for record in RESULTS:
            if record["status"] == "FAIL":
                print(json.dumps(record, ensure_ascii=False))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
