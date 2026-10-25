"""Finite BLS G1 representation-key adapters for W3 ECQV and PV.

The full secret group is Zq^2 and mu(x,y)=x*P+y*h.  This implements the
existing P3-13 representation contract; it is not an Okamoto signature,
a security-game implementation, a bit-time clock, or constant-time code.
The py-ecc provider also exposes G2/GT/pairing operations.  Matching DL
assumptions must include those public capabilities, even though this adapter
does not call a pairing.  External group values enter through pub_decode.
"""

from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "vendor"))

from py_ecc import __version__ as PY_ECC_VERSION
from py_ecc.optimized_bls12_381 import G2, field_modulus, is_inf, neg

from scalar_reference import ScalarInstance
from w3_reference import (
    BitID, Trace, CertificateService as _CertificateService, FixedHash,
    enc_point, hash_key, nat, read_nat, sample,
)


class OkamotoInstance:
    """Public representation parameters, imported from one canonical h.

    Import checks only support: h is canonical, prime-order and nonidentity.
    It cannot certify an honest sampling distribution or independence.  The
    setup exponent and its consumed randomness are never instance fields.
    Python attributes remain diagnostic objects, not an isolation boundary.
    """

    def __init__(self, h_raw):
        self._group = ScalarInstance("BLSG1")
        self.q, self.P, self.O = self._group.q, self._group.P, self._group.O
        self.h = self._group.pub_decode(h_raw)
        if is_inf(self.h):
            raise ValueError("setup h must be nonidentity")
        self.h_raw = self._group.pub_encode(self.h)
        self.kind, self.profile, self.domain = "Okamoto", "BLSG1-REP", "Zq^2"
        self.scalar_width, self.secret_width, self.public_width = 32, 64, 48
        self.provider, self.provider_version = "py-ecc", PY_ECC_VERSION

    def sec_encode(self, s):
        if type(s) is not tuple or len(s) != 2:
            raise ValueError("secret must be a two-scalar tuple")
        return self._group.sec_encode(s[0]) + self._group.sec_encode(s[1])

    def sec_decode(self, raw):
        if not isinstance(raw, bytes) or len(raw) != self.secret_width:
            raise ValueError("pair secret length/type")
        # Validate both coordinates without reducing noncanonical inputs.
        return (self._group.sec_decode(raw[:32]),
                self._group.sec_decode(raw[32:]))

    def sample_secret(self, bits=secrets.randbits):
        if not callable(bits):
            raise ValueError("secret bit source")
        x, tx = sample(q=self.q, bits=bits)
        y, ty = sample(q=self.q, bits=bits)
        return (x, y), (tx, ty)

    def mu(self, s):
        self.sec_encode(s)
        return self.pub_add(self.pub_mul(self.P, s[0]),
                            self.pub_mul(self.h, s[1]))

    def sec_add(self, a, b):
        self.sec_encode(a)
        self.sec_encode(b)
        return ((a[0] + b[0]) % self.q, (a[1] + b[1]) % self.q)

    def sec_mul(self, a, e):
        self.sec_encode(a)
        if type(e) is not int:
            raise ValueError("integer action")
        return (a[0] * e % self.q, a[1] * e % self.q)

    def pub_add(self, a, b):
        return self._group.pub_add(a, b)

    def pub_mul(self, a, e):
        return self._group.pub_mul(a, e)

    def pub_encode(self, p):
        return self._group.pub_encode(p)

    def pub_decode(self, raw):
        # Identity is legal here, unlike the distinguished setup h.
        return self._group.pub_decode(raw)

    def frame(self, public, identity, request=False):
        if not isinstance(identity, BitID) or type(request) is not bool:
            raise ValueError("frame identity/role")
        return (b"W3RP\x01" + (b"QK" if request else b"CR")
                + nat(48) + self.pub_encode(public) + b"I"
                + nat(identity.bits) + identity.data)

    def parse(self, raw, request=False):
        if not isinstance(raw, bytes) or type(request) is not bool:
            raise ValueError("frame type/role")
        prefix = b"W3RP\x01" + (b"QK" if request else b"CR")
        if not raw.startswith(prefix):
            raise ValueError("frame prefix/version/role")
        width, pos = read_nat(raw, len(prefix))
        if width != 48:
            raise ValueError("representation point width")
        public = self.pub_decode(raw[pos:pos + width])
        pos += width
        if raw[pos:pos + 1] != b"I":
            raise ValueError("id tag")
        n, pos = read_nat(raw, pos + 1)
        identity = BitID(n, raw[pos:])
        if self.frame(public, identity, request) != raw:
            raise ValueError("noncanonical frame")
        return public, identity

    def to_okamoto_public(self, Q_raw):
        """Public sign-convention bridge v_O=-Q; no Sign/Verify operation."""
        return self.pub_encode(neg(self.pub_decode(Q_raw)))

    def public_parameters(self):
        """Fresh JSON-safe description of the full fixed public provider.

        No complete transport-pp encoding is claimed.  The sampling law is
        the required setup contract, not a property certified by import.
        """
        return {
            "schema": "W3-REP-BLSG1-public-parameters-v1",
            "profile": self.profile,
            "domain": self.domain,
            "curve": "BLS12-381",
            "q": str(self.q),
            "field_modulus": str(field_modulus),
            "generator_G1": self.pub_encode(self.P).hex(),
            "generator_G2": enc_point(G2, 2).hex(),
            "h": self.h_raw.hex(),
            "identity_G1": self.pub_encode(self.O).hex(),
            "provider": {
                "name": self.provider,
                "version": self.provider_version,
                "implementation": "vendored py_ecc.optimized_bls12_381",
                "public_capabilities": ["G1", "G2", "GT", "pairing"],
                "adapter_pairing_calls": False,
            },
            "setup": {
                "required_honest_law": "b uniform in Zq*; h=b*G1",
                "sampler": "q.bit_length fair bits; reject 0 and values >=q",
                "import_validation": "canonical G1, q-subgroup, nonidentity",
                "distribution_certified_by_import": False,
                "global_b_and_setup_trace_exposed": False,
                "secure_erasure_claim": False,
            },
            "codec": {
                "frame_prefix": "W3RP",
                "version": 1,
                "certificate_role": "CR",
                "request_role": "QK",
                "point_width": 48,
                "point_format": "py-ecc canonical compressed G1, including identity",
                "secret_format": "two canonical 32-byte big-endian scalars in [0,q)",
                "nat": "minimal unsigned base-128, least-significant digit first",
                "id": "bit length; high bits first; zero low-bit padding",
                "embedded_context_fields": [],
            },
            "aux": [],
        }


def setup_okamoto(bits=secrets.randbits):
    """Sample an honest public h, returning neither b nor its setup trace.

    Exact rejection is uncapped and uses the supplied bit source contract.
    Not returning Python values is not a claim of secure memory erasure or
    evidence that an injected source is fair or independent.
    """
    if not callable(bits):
        raise ValueError("setup bit source")
    group = ScalarInstance("BLSG1")
    b, _ = sample(q=group.q, bits=bits, nonzero=True)
    return OkamotoInstance(group.pub_encode(group.pub_mul(group.P, b)))


def _challenge_contract(inst, lam):
    if not isinstance(inst, OkamotoInstance):
        raise ValueError("Okamoto representation instance required")
    if (type(lam) is not int or lam < 1 or lam >= inst.q.bit_length()
            or (1 << lam) >= inst.q):
        raise ValueError("challenge range must satisfy 2^lambda < q")


def _hash_metadata(H, inst, lam):
    for name in ("q", "profile", "domain", "h_raw"):
        if getattr(H, name, getattr(inst, name)) != getattr(inst, name):
            raise ValueError("hash setup/domain/profile mismatch")
    if getattr(H, "lam", lam) != lam:
        raise ValueError("hash lambda mismatch")


class OkamotoFixedHash(FixedHash):
    """Existing fixed W3 SHAKE hash, declared for one representation setup.

    h and mode are not added to the hash input or frame.  Context binding is
    local service configuration, not a cross-context protocol-security claim.
    """

    def __init__(self, inst, lam=128):
        _challenge_contract(inst, lam)
        self.lam, self.q = lam, inst.q
        self.profile, self.domain, self.h_raw = inst.profile, inst.domain, inst.h_raw


class OkamotoTestRO:
    """Classical table test double, bound to at most one service context."""

    def __init__(self, inst, lam=128, bits=secrets.randbits):
        _challenge_contract(inst, lam)
        if not callable(bits):
            raise ValueError("RO bit source")
        self.lam, self.q = lam, inst.q
        self.profile, self.domain, self.h_raw = inst.profile, inst.domain, inst.h_raw
        self.bits, self.table, self.ordinary_index = bits, {}, {}
        self._service_owner = None

    def __call__(self, c):
        c = hash_key(c)
        if c not in self.table:
            value = self.bits(self.lam)
            if type(value) is not int or not 0 <= value < 1 << self.lam:
                raise ValueError("RO bit source")
            self.table[c] = 1 + value
            self.ordinary_index[c] = len(self.ordinary_index) + 1
        return self.table[c]

    def program_fresh(self, c, e):
        """Proof-harness-only programming; genuine issuance never calls this."""
        c = hash_key(c)
        if c in self.table:
            raise RuntimeError("proof-only programming hit")
        if type(e) is not int or not 1 <= e <= 1 << self.lam:
            raise ValueError("challenge")
        self.table[c] = e


class OkamotoCertificateService(_CertificateService):
    """Unchanged W3 certificate core with representation/context guards.

    Custom callables require an explicit nonempty hash_description and may
    declare metadata that must match the service context.  The description is
    a caller-supplied contract, not certification of purity or effectiveness.
    Invalid requests fail before nonce/hash use.  Hash failures after sampling
    do not commit new issued/private state.  Python is not an access boundary.
    """

    def __init__(self, inst, mode, ca_raw, H, *, lam=None,
                 hash_description=None, hash_model=None):
        if not callable(H):
            raise ValueError("hash callable required")
        declared_lam = getattr(H, "lam", None)
        if declared_lam is not None:
            _challenge_contract(inst, declared_lam)
        if lam is None:
            lam = declared_lam if declared_lam is not None else 128
        _challenge_contract(inst, lam)
        _hash_metadata(H, inst, lam)

        if type(H) is OkamotoFixedHash:
            if hash_model not in (None, "fixed") or hash_description is not None:
                raise ValueError("built-in fixed-hash description is fixed")
            model = "fixed"
            description = (
                "w3_reference.FixedHash: SHAKE256; byte input domain "
                "W3-Hcert-v1\\0 followed by input bytes; non-byte-aligned BitID "
                "domain W3-Hcert-bits-v1\\0 followed by Nat(bit length) and padded "
                "bytes; byte-aligned BitID aliases bytes; take first lambda "
                "output bits as an integer and add 1"
            )
        elif type(H) is OkamotoTestRO:
            if hash_model not in (None, "test-ROM") or hash_description is not None:
                raise ValueError("built-in RO description is fixed")
            model = "test-ROM"
            description = (
                "one classical lazy table on all bitstrings; each fresh ordinary "
                "lookup reads lambda injected bits and returns 1+value; byte-aligned "
                "BitID aliases bytes; separate proof-only program_fresh interface; "
                "fair independent bits are a contract, not verified by the table"
            )
        else:
            if hash_model not in (None, "fixed"):
                raise ValueError("only built-in RO may declare test-ROM")
            if not isinstance(hash_description, str) or not hash_description.strip():
                raise ValueError("custom hash requires an explicit description")
            model, description = "fixed", hash_description
        if isinstance(H, OkamotoTestRO) and H._service_owner is not None:
            raise ValueError("RO table already bound to a service")

        def checked_hash(c):
            e = H(hash_key(c))
            if type(e) is not int or not 1 <= e <= 1 << lam:
                raise ValueError("hash challenge type/range")
            return e

        super().__init__(inst, mode, ca_raw, checked_hash)
        self.lam, self.hash_source = lam, H
        self._hash_model, self._hash_description = model, description
        if isinstance(H, OkamotoTestRO):
            H._service_owner = self

    def public_configuration(self):
        """Deterministic public metadata; excludes CA secret and all traces.

        The frame omits h, CA and mode.  This metadata records the local
        context and does not authenticate it or provide cross-context security.
        """
        return {
            "schema": "W3-REP-certificate-configuration-v1",
            "parameters": self.inst.public_parameters(),
            "mode": self.mode,
            "hash_model": self._hash_model,
            "hash_description": self._hash_description,
            "lambda": self.lam,
            "challenge_interval": ["1", str(1 << self.lam)],
            "CA_public": self.inst.pub_encode(self.Y).hex(),
            "aux": [],
        }


CertificateService = OkamotoCertificateService


def create_ca(inst, bits=secrets.randbits):
    """Return (64-byte CA secret, 48-byte public, two complete traces)."""
    if not isinstance(inst, OkamotoInstance):
        raise ValueError("Okamoto representation instance required")
    c, traces = inst.sample_secret(bits)
    return inst.sec_encode(c), inst.pub_encode(inst.mu(c)), traces


def user_prepare(inst, identity, bits=secrets.randbits):
    """Return (64-byte user secret, request frame, two complete traces)."""
    if not isinstance(inst, OkamotoInstance) or not isinstance(identity, BitID):
        raise ValueError("Okamoto representation instance/identity required")
    u, traces = inst.sample_secret(bits)
    return inst.sec_encode(u), inst.frame(inst.mu(u), identity, request=True), traces


def to_okamoto_public(Q_raw):
    """Validate and negate a canonical G1 public key; no secret is needed."""
    group = ScalarInstance("BLSG1")
    return group.pub_encode(neg(group.pub_decode(Q_raw)))


__all__ = [
    "BitID", "Trace", "OkamotoInstance", "setup_okamoto", "OkamotoFixedHash",
    "OkamotoTestRO", "OkamotoCertificateService", "CertificateService",
    "create_ca", "user_prepare", "to_okamoto_public",
]
