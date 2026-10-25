"""Finite-parameter W3 research reference. No production or signature-security claim.

Only locally installed vendor packages are used. Exact samplers keep all blocks;
optional proposal caps are diagnostics, NOT the proof's bit-time clock.
"""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / 'vendor'))
from dataclasses import dataclass
import hashlib
import secrets
from py_ecc.optimized_bls12_381 import (
    G1, G2, Z1, Z2, add, multiply, neg, eq, is_inf, pairing,
    curve_order as Q, field_modulus as P,
)
from py_ecc.bls.point_compression import (
    compress_G1, compress_G2, decompress_G1, decompress_G2,
)


def enc_point(p, group):
    if group == 1:
        return int(compress_G1(p)).to_bytes(48, 'big')
    if group == 2:
        a, b = compress_G2(p)
        return int(a).to_bytes(48, 'big') + int(b).to_bytes(48, 'big')
    raise ValueError('group')


def dec_point(raw, group):
    if not isinstance(raw, bytes) or group not in (1, 2) or len(raw) != 48 * group:
        raise ValueError('point length/type')
    if group == 1:
        p = decompress_G1(int.from_bytes(raw, 'big'))
    else:
        p = decompress_G2((int.from_bytes(raw[:48], 'big'), int.from_bytes(raw[48:], 'big')))
    if not is_inf(multiply(p, Q)):
        raise ValueError('not in prime-order subgroup')
    if enc_point(p, group) != raw:
        raise ValueError('noncanonical')
    return p


def scalar_bytes(x):
    if type(x) is not int or not 0 <= x < Q:
        raise ValueError('scalar range')
    return x.to_bytes(32, 'big')


def dec_scalar(raw):
    if not isinstance(raw, bytes) or len(raw) != 32:
        raise ValueError('scalar length')
    x = int.from_bytes(raw, 'big')
    scalar_bytes(x)
    return x


def nat(n):
    if type(n) is not int or n < 0:
        raise ValueError('natural number')
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def read_nat(raw, pos):
    start, n, shift = pos, 0, 0
    while pos < len(raw):
        c = raw[pos]
        pos += 1
        n |= (c & 127) << shift
        if c < 128:
            if raw[start:pos] != nat(n):
                raise ValueError('nonminimal Nat')
            return n, pos
        shift += 7
    raise ValueError('unterminated Nat')


@dataclass(frozen=True)
class BitID:
    bits: int
    data: bytes

    def __post_init__(self):
        if type(self.bits) is not int or self.bits < 0 or not isinstance(self.data, bytes):
            raise ValueError('id type')
        if len(self.data) != (self.bits + 7) // 8:
            raise ValueError('id length')
        if self.bits % 8 and self.data[-1] & ((1 << (8 - self.bits % 8)) - 1):
            raise ValueError('id padding')


@dataclass(frozen=True)
class Trace:
    width: int
    blocks: tuple
    # Lossless consumed-bit representation. Terminator used only in export_bits.
    def export_bits(self):
        return ''.join('1' + b for x in self.blocks for b in f'{x:0{self.width}b}') + '00'


def sample(q=Q, bits=secrets.randbits, nonzero=False, proposal_cap=None):
    width = q.bit_length()
    blocks = []
    while proposal_cap is None or len(blocks) < proposal_cap:
        a = bits(width)
        if type(a) is not int or not 0 <= a < 1 << width:
            raise ValueError('bit source contract')
        blocks.append(a)
        if int(nonzero) <= a < q:
            return a, Trace(width, tuple(blocks))
    raise TimeoutError('proposal cap; not the theorem bit-time clock')


class FixedHash:
    """One fixed deterministic H. This does not instantiate ROM security."""
    def __init__(self, lam=128):
        if type(lam) is not int or lam < 1 or (1 << lam) >= Q:
            raise ValueError('challenge range')
        self.lam = lam

    def __call__(self, c):
        c = hash_key(c)
        if isinstance(c, BitID):
            raw = hashlib.shake_256(b'W3-Hcert-bits-v1\0' + nat(c.bits) + c.data).digest((self.lam+7)//8)
            return 1 + (int.from_bytes(raw,'big') >> ((8-self.lam%8)%8))
        raw = hashlib.shake_256(b'W3-Hcert-v1\0' + c).digest((self.lam + 7) // 8)
        return 1 + (int.from_bytes(raw, 'big') >> ((8 - self.lam % 8) % 8))


def hash_key(c):
    if isinstance(c, bytes):
        return c
    if isinstance(c, BitID):
        return c.data if c.bits % 8 == 0 else c
    raise ValueError('hash bitstring input')


class TestRO:
    """Injectable classical table; programming is ONLY a reduction-harness API."""
    def __init__(self, lam=128, bits=secrets.randbits):
        FixedHash(lam)
        self.lam, self.bits, self.table = lam, bits, {}
        self.ordinary_index = {}

    def __call__(self, c):
        c = hash_key(c)
        if c not in self.table:
            self.table[c] = 1 + self.bits(self.lam)
            if not 1 <= self.table[c] <= 1 << self.lam:
                raise ValueError('RO bit source')
            self.ordinary_index[c] = len(self.ordinary_index) + 1
        return self.table[c]

    def program_fresh(self, c, e):
        c = hash_key(c)
        if c in self.table:
            raise RuntimeError('proof-only programming hit')
        if not 1 <= e <= 1 << self.lam:
            raise ValueError('challenge')
        self.table[c] = e


class Instance:
    def __init__(self, kind, h=None, U=()):
        if kind not in ('PS', 'Waters'):
            raise ValueError('instance')
        self.kind, self.h, self.U = kind, h, tuple(U)
        if kind == 'Waters':
            if h is None or not self.U:
                raise ValueError('Waters setup')
            self.h = dec_point(enc_point(h, 1), 1)
            if is_inf(self.h):
                raise ValueError('h must be nonidentity')
            self.U = tuple(dec_point(enc_point(u, 1), 1) for u in self.U)

    def secret_from_scalar(self, a):
        # Waters internal sampler only; operation algorithms use element pairs.
        scalar_bytes(a)
        return multiply(self.h, a), multiply(G2, a)

    def sample_secret(self, bits=secrets.randbits):
        a, ta = sample(bits=bits)
        if self.kind == 'PS':
            b, tb = sample(bits=bits)
            return (a, b), (ta, tb)
        return self.secret_from_scalar(a), (ta,)

    def sec_encode(self, s):
        if self.kind == 'PS':
            return scalar_bytes(s[0]) + scalar_bytes(s[1])
        return enc_point(s[0], 1) + enc_point(s[1], 2)

    def sec_decode(self, raw):
        if self.kind == 'PS':
            if len(raw) != 64:
                raise ValueError('PS secret length')
            return dec_scalar(raw[:32]), dec_scalar(raw[32:])
        if len(raw) != 144:
            raise ValueError('Waters secret length')
        w, z = dec_point(raw[:48], 1), dec_point(raw[48:], 2)
        if pairing(G2, w) != pairing(z, self.h):
            raise ValueError('H_h relation')
        return w, z

    def mu(self, s):
        return (multiply(G2, s[0]), multiply(G2, s[1])) if self.kind == 'PS' else s[1]

    def sec_add(self, a, b):
        if self.kind == 'PS':
            return tuple((x+y) % Q for x, y in zip(a, b))
        return add(a[0], b[0]), add(a[1], b[1])

    def sec_mul(self, a, e):
        if self.kind == 'PS':
            return tuple(x * e % Q for x in a)
        return multiply(a[0], e % Q), multiply(a[1], e % Q)

    def pub_encode(self, p):
        return b''.join(enc_point(x, 2) for x in p) if self.kind == 'PS' else enc_point(p, 2)

    def pub_decode(self, raw):
        if self.kind == 'PS':
            if len(raw) != 192:
                raise ValueError('PS public length')
            return dec_point(raw[:96], 2), dec_point(raw[96:], 2)
        return dec_point(raw, 2)

    def pub_add(self, a, b):
        return tuple(add(x,y) for x,y in zip(a,b)) if self.kind == 'PS' else add(a,b)

    def pub_mul(self, a, e):
        return tuple(multiply(x,e % Q) for x in a) if self.kind == 'PS' else multiply(a,e % Q)

    def frame(self, public, identity, request=False):
        prefix = b'W3PS' if self.kind == 'PS' else b'W3WT'
        return prefix + b'\x01' + (b'QK' if request else b'CR') + nat(96) + self.pub_encode(public) + b'I' + nat(identity.bits) + identity.data

    def parse(self, raw, request=False):
        if not isinstance(raw, bytes):
            raise ValueError('frame type')
        prefix = (b'W3PS' if self.kind == 'PS' else b'W3WT') + b'\x01' + (b'QK' if request else b'CR')
        if not raw.startswith(prefix):
            raise ValueError('frame prefix')
        width, pos = read_nat(raw, len(prefix))
        if width != 96:
            raise ValueError('provider width')
        size = 192 if self.kind == 'PS' else 96
        public = self.pub_decode(raw[pos:pos+size])
        pos += size
        if raw[pos:pos+1] != b'I':
            raise ValueError('id tag')
        n, pos = read_nat(raw, pos+1)
        identity = BitID(n, raw[pos:])
        if self.frame(public, identity, request) != raw:
            raise ValueError('canonical frame')
        return public, identity


def setup_waters(n=8, bits=secrets.randbits):
    if type(n) is not int or n < 0:
        raise ValueError('message length')
    beta, _ = sample(bits=bits, nonzero=True)
    h = multiply(G1, beta)
    U = tuple(multiply(G1, sample(bits=bits)[0]) for _ in range(n+1))
    # Logs are not returned. This is NOT secure erasure or a distributed setup.
    return Instance('Waters', h, U)


class CertificateService:
    """Single pp, CA and mode. Private issuance state is explicit for SH harnesses."""
    def __init__(self, inst, mode, ca_raw, H):
        if mode not in ('PV', 'ECQV'):
            raise ValueError('mode')
        self.inst, self.mode, self.H = inst, mode, H
        self.c = inst.sec_decode(ca_raw)
        self.Y = inst.mu(self.c)
        self.issued = set()

    def issue(self, request, bits=secrets.randbits):
        i = self.inst
        ku, identity = i.parse(request, request=True)  # before randomness and H
        k, traces = i.sample_secret(bits)
        kc = i.mu(k)
        R = i.pub_add(ku, kc)
        C = i.frame(R, identity)
        e = self.H(C)
        r = i.sec_add(k, i.sec_mul(self.c, e)) if self.mode == 'PV' else i.sec_add(i.sec_mul(k,e), self.c)
        self.issued.add(C)  # repeated C is allowed; no programming abort
        self._last_issuance_state = {'nonce': i.sec_encode(k), 'consumed_traces': traces,
                   'request': request, 'KU': i.pub_encode(ku), 'KC': i.pub_encode(kc),
                   'R': i.pub_encode(R), 'C': C, 'e': e, 'response': i.sec_encode(r)}
        # UF caller receives only the two public outputs. SH harness may separately
        # inspect CA-owned state; Python object access is not a process boundary.
        return C, i.sec_encode(r)

    def recon(self, C):
        i = self.inst
        R, _ = i.parse(C)
        e = self.H(C)
        return i.pub_add(R, i.pub_mul(self.Y,e)) if self.mode == 'PV' else i.pub_add(i.pub_mul(R,e),self.Y)

    def derive(self, user_raw, C, response_raw):
        i = self.inst
        i.parse(C)
        u, r = i.sec_decode(user_raw), i.sec_decode(response_raw)
        e = self.H(C)
        s = i.sec_add(u,r) if self.mode == 'PV' else i.sec_add(i.sec_mul(u,e),r)
        return i.sec_encode(s)

    def verify_preimage(self, C, secret_raw, fresh=False):
        i = self.inst
        try:
            public = self.recon(C)  # includes final hash lookup before freshness
            if fresh and C in self.issued:
                return False
            s = i.sec_decode(secret_raw)
            return i.pub_encode(i.mu(s)) == i.pub_encode(public)
        except (ValueError, TypeError, IndexError):
            return False


def message_base(i, msg):
    if not isinstance(msg, BitID) or msg.bits != len(i.U)-1:
        raise ValueError('Waters message length')
    F = i.U[0]
    for j in range(msg.bits):
        if (msg.data[j//8] >> (7-j%8)) & 1:
            F = add(F, i.U[j+1])
    return F


def sign(i, secret_raw, msg, bits=secrets.randbits):
    s = i.sec_decode(secret_raw)
    if i.kind == 'PS':
        scalar_bytes(msg)
        t, _ = sample(bits=bits, nonzero=True)
        h = multiply(G1,t)
        return enc_point(h,1) + enc_point(multiply(h,(s[0]+s[1]*msg) % Q),1)
    F = message_base(i,msg)
    t, _ = sample(bits=bits, nonzero=True)
    return enc_point(add(s[0],multiply(F,t)),1) + enc_point(multiply(G2,t),2) + enc_point(multiply(G1,t),1)


def verify_signature(i, public_raw, msg, sig):
    try:
        pk = i.pub_decode(public_raw)
        if i.kind == 'PS':
            scalar_bytes(msg)
            if len(sig) != 96:
                return False
            h,z = dec_point(sig[:48],1),dec_point(sig[48:],1)
            return not is_inf(h) and pairing(add(pk[0],multiply(pk[1],msg)),h) == pairing(G2,z)
        if len(sig) != 192:
            return False
        a,b,c = dec_point(sig[:48],1),dec_point(sig[48:144],2),dec_point(sig[144:],1)
        F = message_base(i,msg)
        return pairing(G2,a) == pairing(pk,i.h)*pairing(b,F) and pairing(G2,c) == pairing(b,G1)
    except (ValueError, TypeError, IndexError):
        return False
