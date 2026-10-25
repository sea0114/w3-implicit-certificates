"""Finite P-256/BLS G1 scalar adapters for the W3 certificate reference.

These are functional reference points, not a uniform setup family, a signature
implementation, a constant-time implementation, or a bit-time clock. The shared
certificate service is unchanged. External points enter through pub_decode or
parse; group-operation methods consume already validated/internal group values.
All secret scalars, including zero, have a canonical 32-byte representation.
"""

from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "vendor"))

from ecdsa.curves import NIST256p
from ecdsa.ellipticcurve import INFINITY, Point, PointJacobi
from py_ecc.optimized_bls12_381 import G1, Z1, add, multiply, curve_order

from w3_reference import (
    BitID, Trace, CertificateService as _CertificateService, FixedHash,
    enc_point, dec_point, hash_key, nat, read_nat, sample,
)


class ScalarInstance:
    """One fixed, explicit curve profile; no inference from a wire prefix.

    P-256 uses ecdsa 0.19.1, and BLS12-381 G1 uses py-ecc 8.0.0. Neither
    profile performs a pairing or invokes a signature algorithm. P/O denote the
    generator/identity. A frame contains no CA key, mode, or complete setup.
    """

    def __init__(self, profile="P256"):
        if profile not in ("P256", "BLSG1"):
            raise ValueError("unknown scalar profile")
        self.profile, self.kind, self.scalar_width = profile, "Scalar", 32
        if profile == "P256":
            self.q, self.P, self.O = NIST256p.order, NIST256p.generator, INFINITY
            self.field_modulus = NIST256p.curve.p()
            self.provider, self.provider_version = "ecdsa", "0.19.1"
        else:
            self.q, self.P, self.O = curve_order, G1, Z1
            self.provider, self.provider_version = "py-ecc", "8.0.0"

    def sec_encode(self, s):
        if type(s) is not int or not 0 <= s < self.q:
            raise ValueError("scalar type/range")
        return s.to_bytes(self.scalar_width, "big")

    def sec_decode(self, raw):
        if not isinstance(raw, bytes) or len(raw) != self.scalar_width:
            raise ValueError("scalar length/type")
        s = int.from_bytes(raw, "big")
        self.sec_encode(s)  # Reject q and above; do not normalize an input.
        return s

    def sample_secret(self, bits=secrets.randbits):
        # The shared exact sampler records every rejected and accepted block.
        # It is deliberately uncapped here; a proposal cap is not a clock.
        s, trace = sample(q=self.q, bits=bits)
        return s, (trace,)

    def mu(self, s):
        self.sec_encode(s)
        return self.pub_mul(self.P, s)

    def sec_add(self, a, b):
        self.sec_encode(a)
        self.sec_encode(b)
        return (a + b) % self.q

    def sec_mul(self, a, e):
        self.sec_encode(a)
        if type(e) is not int:
            raise ValueError("integer action")
        return (a * e) % self.q

    def pub_add(self, a, b):
        # Trusted group objects only. External bytes must use pub_decode first.
        return a + b if self.profile == "P256" else add(a, b)

    def pub_mul(self, a, e):
        # Reduction here is an internal group action, never input acceptance.
        if type(e) is not int:
            raise ValueError("integer action")
        return (e % self.q) * a if self.profile == "P256" else multiply(a, e % self.q)

    def pub_encode(self, p):
        # BLS serialization expects an internal/subgroup-validated object.
        # Its external decode below performs the explicit qP=O check.
        if self.profile == "BLSG1":
            return enc_point(p, 1)
        if not isinstance(p, (Point, PointJacobi)):
            raise ValueError("P-256 point type")
        if p == INFINITY:
            return b"\x00"
        try:
            x, y = p.x(), p.y()
            valid = (p.curve() == NIST256p.curve
                     and 0 <= x < self.field_modulus
                     and 0 <= y < self.field_modulus
                     and NIST256p.curve.contains_point(x, y))
        except (AttributeError, TypeError, ValueError):
            valid = False
        if not valid:
            raise ValueError("P-256 curve membership")
        return bytes([2 | (y & 1)]) + x.to_bytes(32, "big")

    def pub_decode(self, raw):
        if not isinstance(raw, bytes):
            raise ValueError("point type")
        if self.profile == "BLSG1":
            # Existing codec verifies curve decoding, prime-order subgroup,
            # and canonical re-encoding, including the identity.
            return dec_point(raw, 1)
        if raw == b"\x00":
            return INFINITY
        if len(raw) != 33 or raw[0] not in (2, 3):
            raise ValueError("P-256 compressed point format")
        x = int.from_bytes(raw[1:], "big")
        p = self.field_modulus
        if x >= p:
            raise ValueError("P-256 x range")
        rhs = (pow(x, 3, p) + NIST256p.curve.a() * x + NIST256p.curve.b()) % p
        # P-256's fixed field prime is 3 modulo 4.
        y = pow(rhs, (p + 1) // 4, p)
        if y * y % p != rhs:
            raise ValueError("P-256 point is off curve")
        if (y & 1) != (raw[0] & 1):
            y = (-y) % p
        point = Point(NIST256p.curve, x, y, self.q)
        # P-256 has cofactor one: curve membership implies q-subgroup membership.
        if self.pub_encode(point) != raw:
            raise ValueError("noncanonical P-256 point")
        return point

    def frame(self, public, identity, request=False):
        if not isinstance(identity, BitID) or type(request) is not bool:
            raise ValueError("frame identity/role")
        payload = self.pub_encode(public)
        return (b"W3SC\x01" + (b"QK" if request else b"CR")
                + nat(len(payload)) + payload + b"I"
                + nat(identity.bits) + identity.data)

    def parse(self, raw, request=False):
        if not isinstance(raw, bytes) or type(request) is not bool:
            raise ValueError("frame type/role")
        prefix = b"W3SC\x01" + (b"QK" if request else b"CR")
        if not raw.startswith(prefix):
            raise ValueError("frame prefix/version/role")
        size, pos = read_nat(raw, len(prefix))
        if size not in ((1, 33) if self.profile == "P256" else (48,)):
            raise ValueError("profile point length")
        public = self.pub_decode(raw[pos:pos + size])
        pos += size
        if raw[pos:pos + 1] != b"I":
            raise ValueError("id tag")
        n, pos = read_nat(raw, pos + 1)
        identity = BitID(n, raw[pos:])
        if self.frame(public, identity, request) != raw:
            raise ValueError("noncanonical frame")
        return public, identity


def _challenge_contract(inst, lam):
    if not isinstance(inst, ScalarInstance):
        raise ValueError("scalar instance required")
    if (type(lam) is not int or lam < 1 or lam >= inst.q.bit_length()
            or (1 << lam) >= inst.q):
        raise ValueError("challenge range must satisfy 2^lambda < q")


class ScalarFixedHash(FixedHash):
    """Same fixed W3 hash/bitstring encoding, with this profile's q bound.

    This deterministic SHAKE function is not an implementation of ROM security.
    Byte-aligned BitID inputs identify the same bitstring as their bytes value.
    """

    def __init__(self, inst, lam=128):
        _challenge_contract(inst, lam)
        self.lam, self.q, self.profile = lam, inst.q, inst.profile


class ScalarTestRO:
    """Injectable classical table for one fixed service context.

    program_fresh is only a proof-harness operation. A table cannot be attached
    to a second service; this prevents accidental shared CA/mode RO state. No
    result here proves cross-context protocol security or the full UF game.
    """

    def __init__(self, inst, lam=128, bits=secrets.randbits):
        _challenge_contract(inst, lam)
        if not callable(bits):
            raise ValueError("RO bit source")
        self.lam, self.q, self.profile = lam, inst.q, inst.profile
        self.bits, self.table, self.ordinary_index = bits, {}, {}
        self._service_owner = None

    def __call__(self, c):
        c = hash_key(c)
        if c not in self.table:
            value = self.bits(self.lam)
            if type(value) is not int or not 0 <= value < 1 << self.lam:
                raise ValueError("RO bit source")
            # Validate before committing: failed calls leave no poisoned entry.
            self.table[c] = 1 + value
            self.ordinary_index[c] = len(self.ordinary_index) + 1
        return self.table[c]

    def program_fresh(self, c, e):
        c = hash_key(c)
        if c in self.table:
            raise RuntimeError("proof-only programming hit")
        if type(e) is not int or not 1 <= e <= 1 << self.lam:
            raise ValueError("challenge")
        self.table[c] = e


class ScalarCertificateService(_CertificateService):
    """Shared W3 algebra with a scalar-profile challenge guard.

    A service owns one fixed (instance, CA, mode) context. The frame itself does
    not carry those fields, so mode/CA replay rejection is not a wire property.
    Invalid requests fail in parse before nonce/H use. An injected H contract
    failure may occur after nonce use, but never commits issued/private state.
    Python attributes remain diagnostic objects, not an isolation boundary.
    """

    def __init__(self, inst, mode, ca_raw, H, *, lam=None):
        if not callable(H):
            raise ValueError("hash callable required")
        declared_lam = getattr(H, "lam", None)
        if declared_lam is not None:
            _challenge_contract(inst, declared_lam)
        if lam is None:
            lam = declared_lam if declared_lam is not None else 128
        elif declared_lam is not None and declared_lam != lam:
            raise ValueError("hash lambda mismatch")
        _challenge_contract(inst, lam)
        if getattr(H, "q", inst.q) != inst.q or getattr(H, "profile", inst.profile) != inst.profile:
            raise ValueError("hash profile mismatch")
        if isinstance(H, ScalarTestRO) and H._service_owner is not None:
            raise ValueError("RO table already bound to a service")

        def checked_hash(c):
            e = H(c)
            if type(e) is not int or not 1 <= e <= 1 << lam:
                raise ValueError("hash challenge type/range")
            return e

        super().__init__(inst, mode, ca_raw, checked_hash)
        self.lam, self.hash_source = lam, H
        if isinstance(H, ScalarTestRO):
            H._service_owner = self


# The short import name deliberately selects the guarded scalar specialization.
CertificateService = ScalarCertificateService


def create_ca(inst, bits=secrets.randbits):
    """Fresh CA key generation, separate from existing-key service import.

    Return (canonical secret bytes, canonical public bytes, complete traces).
    The returned secret/traces are private diagnostic data, not a UF response.
    """
    if not isinstance(inst, ScalarInstance):
        raise ValueError("scalar instance required")
    c, traces = inst.sample_secret(bits)
    return inst.sec_encode(c), inst.pub_encode(inst.mu(c)), traces


def user_prepare(inst, identity, bits=secrets.randbits):
    """Return (user secret bytes, request frame, complete user-sampler traces)."""
    if not isinstance(inst, ScalarInstance) or not isinstance(identity, BitID):
        raise ValueError("scalar instance/identity required")
    u, traces = inst.sample_secret(bits)
    return inst.sec_encode(u), inst.frame(inst.mu(u), identity, request=True), traces


__all__ = [
    "BitID", "Trace", "ScalarInstance", "ScalarFixedHash", "ScalarTestRO",
    "ScalarCertificateService", "CertificateService", "create_ca", "user_prepare",
]
