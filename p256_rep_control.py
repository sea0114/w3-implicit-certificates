"""Isolated P-256 representation control; original adapters remain unchanged.

All external point/secret/frame/hash guards are inherited. Finite decoded
points and mu outputs become non-precomputed Jacobian points with Z=1.
The fixed generator keeps the provider's shared warm precomputation, equally
for both modes; variable points never inherit its generator flag, even mu(1).
Identity retains the provider's canonical INFINITY sentinel.
"""
from scalar_reference import ScalarInstance, PointJacobi, INFINITY
import comparison_harness as h

CONFIGURATIONS = tuple(c for c in h.CONFIGURATIONS
                       if c.family == 'Scalar' and c.profile == 'P256')


class P256JacobianControl(ScalarInstance):
    def __init__(self):
        super().__init__('P256')

    def pub_decode(self, raw):
        # All original type/length/curve/canonical checks finish BEFORE lifting.
        point = super().pub_decode(raw)
        if point == INFINITY:
            return INFINITY
        return PointJacobi.from_affine(point, generator=False)

    def mu(self, secret):
        # Retains scalar-domain checking and fixed-base provider multiplication.
        point = super().mu(secret)
        if point == INFINITY:
            return INFINITY
        # scale is at most one field inversion; the new object strips fixed
        # generator/precompute flags even when secret==1 returns self.P.
        point.scale()
        return PointJacobi(point.curve(), point.x(), point.y(), 1,
                           point.order(), generator=False)


class ControlSession(h.HarnessSession):
    """Only setup's instance factory differs; all seven trial phases inherited."""
    def __init__(self, config, **kwargs):
        if config not in CONFIGURATIONS:
            raise ValueError('control supports only scalar P256 ECQV/PV')
        super().__init__(config, **kwargs)

    def setup(self):
        if self._setup_attempted:
            raise RuntimeError('setup already attempted; use a new session')
        self._setup_attempted = True
        context = self._context(None, 'group_setup')
        def construct():
            self.bits_factory(context)  # Keep original in-phase initialization.
            return P256JacobianControl()
        try:
            value = self._run(context, construct)
            if type(value) is not P256JacobianControl or value.profile != 'P256':
                raise ValueError('control setup output')
            self.instance = value
            self.setup_ledger.append({'phase': 'group_setup', 'status': 'ok'})
        except Exception as exc:
            self.instance = None
            self.setup_ledger.append(self._failure('group_setup', exc))
        return self.instance


def point_policy(point):
    """Pinned-provider read-only diagnostics, outside performance boundaries.

    Private field inspection certifies this finite provider configuration only;
    it is not access isolation and is never used to bypass point validation.
    """
    if point == INFINITY:
        return {'identity': True, 'class': type(point).__name__, 'aligned': True}
    if type(point) is not PointJacobi:
        return {'identity': False, 'class': type(point).__name__, 'aligned': False}
    z = point._PointJacobi__coords[2]
    generator = point._PointJacobi__generator
    entries = len(point._PointJacobi__precompute)
    return {'identity': False, 'class': 'PointJacobi', 'z_is_one': z == 1,
            'generator_flag': generator, 'precompute_entries': entries,
            'aligned': z == 1 and not generator and entries == 0}


POLICY = {
    'implementation_id': 'P256-Jacobian-Z1-variable-no-precompute-v1',
    'external_validation': 'unchanged full superclass pub_decode/parse/secret/hash guards',
    'decoder': 'validated affine Point -> PointJacobi.from_affine(generator=False), Z=1; identity unchanged',
    'mu_output': 'fixed-base multiplication -> scale to Z=1 -> fresh generator=False clone; zero stays INFINITY',
    'variable_multiplication': 'reconstruction R and CA Y both Jacobian Z=1, no variable-base precompute table',
    'other_intermediates': 'add/action outputs may have Z!=1; existing encoder and provider arithmetic retained',
    'fixed_generator': 'same NIST256p.generator for both modes; provider intrinsic precomputation warms in warmup; no resets per trial',
    'conversion_timing': 'decoder lift inside each consuming parse phase; mu normalization/clone inside each mu-producing phase; no subtraction',
    'standalone_conversion_latency': 'not separately timed; do not infer it by subtracting old and new phase medians',
    'count_scope': 'normal successful nonidentity trial; each D one affine->Jacobian object lift; each N one scale+clone, at most one field inversion',
    'conversion_operations_by_phase': {
        'group_setup': {'D':0,'N':0}, 'ca_keygen': {'D':0,'N':1},
        'ca_import': {'D':0,'N':1}, 'user_prepare': {'D':0,'N':1},
        'issue': {'D':1,'N':1}, 'completion': {'D':1,'N':0},
        'reconstruction': {'D':1,'N':0}, 'preimage_validation': {'D':1,'N':1}},
    'limits': 'normalization shifts/removes later inversion work; joint representation policy control, not an isolated one-instruction causal experiment',
}
