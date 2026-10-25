"""Focused R3/R5/R6 verification; synthetic deterministic test values only."""
from w3_reference import *
from collections import Counter
from fractions import Fraction
import json
import random
import time
import platform
import importlib.metadata

RESULTS = []


def check(name, operation):
    start = time.perf_counter()
    try:
        assert operation()
        RESULTS.append({'name': name, 'status': 'PASS', 'seconds': time.perf_counter()-start})
    except Exception as exc:
        RESULTS.append({'name': name, 'status': 'FAIL', 'error': repr(exc)})
        raise


def rejects(operation, exc=ValueError):
    try:
        operation()
    except exc:
        return True
    return False


def sequence(*vals):
    it = iter(vals)
    return lambda width: next(it)


def end_to_end(i, mode):
    rng = random.Random('W3-R6-'+i.kind+mode)
    bits = rng.getrandbits
    c,_ = i.sample_secret(bits)
    u,_ = i.sample_secret(bits)
    service = CertificateService(i,mode,i.sec_encode(c),TestRO(bits=bits))
    request = i.frame(i.mu(u),BitID(13,b'\xa6\x50'),True)
    C,r = service.issue(request,bits)
    s = service.derive(i.sec_encode(u),C,r)
    assert service.verify_preimage(C,s)
    assert not service.verify_preimage(C,s,fresh=True)
    msg = 17 if i.kind == 'PS' else BitID(8,b'\xa6')
    sig = sign(i,s,msg,bits)
    assert verify_signature(i,i.pub_encode(service.recon(C)),msg,sig)
    state = service._last_issuance_state
    assert state['response'] == r and state['C'] == C
    assert all(len(t.export_bits()) == 2*t.width*len(t.blocks)+2 for t in state['consumed_traces'])
    return True


def invalid_before_rng(i):
    zero = (0,0) if i.kind == 'PS' else (Z1,Z2)
    ro = TestRO()
    service = CertificateService(i,'PV',i.sec_encode(zero),ro)
    def forbidden(width):
        raise AssertionError('randomness consumed on invalid request')
    assert rejects(lambda: service.issue(b'invalid',forbidden))
    return not ro.table and not service.issued


def repeat_and_final(i):
    zero = (0,0) if i.kind == 'PS' else (Z1,Z2)
    ro = TestRO(bits=lambda w: 3)
    service = CertificateService(i,'ECQV',i.sec_encode(zero),ro)
    request = i.frame(i.mu(zero),BitID(0,b''),True)
    c1,r1 = service.issue(request,lambda w:0)
    c2,r2 = service.issue(request,lambda w:0)
    assert (c1,r1) == (c2,r2) and len(ro.table)==1 and len(service.issued)==1
    # Fresh certificate with R=identity: a valid preimage may work for every e.
    fresh = i.frame(i.mu(zero),BitID(1,b'\x80'))
    assert fresh not in ro.table
    assert service.verify_preimage(fresh,i.sec_encode(zero),fresh=True)
    assert ro.ordinary_index[fresh] == 2
    return True


def toy_joint_laws():
    # H=Z_5 x Z_2 -> Z_5; shared fixed c=(2,1), nontrivial kernel.
    q=5
    domain=[(a,b) for a in range(q) for b in range(2)]
    c=(2,1)
    for e in (1,2,3,4):
        inv=pow(e,-1,q)
        bcoef=(1-e*inv)//q  # lift T(Y)=(0,0), public exponent m=5
        assert e*inv + bcoef*q == 1
        pv_real=Counter(((k[0],((k[0]+e*c[0])%q,(k[1]+e*c[1])%2))) for k in domain)
        pv_sim=Counter((((z[0]-e*c[0])%q,z)) for z in domain)
        assert pv_real==pv_sim
        ec_real=Counter((k[0],((e*k[0]+c[0])%q,(e*k[1]+c[1])%2)) for k in domain)
        ec_sim=Counter(((z[0]-inv*c[0])%q,((e*z[0])%q,(e*z[1])%2)) for z in domain)
        tv=Fraction(sum(abs(ec_real[k]-ec_sim[k]) for k in ec_real.keys()|ec_sim.keys()),2*len(domain))
        assert tv==(0 if e%2 else 1)
    # The stopped distribution has a shared hit atom, so TV shrinks by fresh mass.
    e=2; inv=3
    def stop(key): return ('STOP',) if key[0] in (0,1) else key
    real=Counter(); sim=Counter()
    for k in domain: real[stop((k[0],((e*k[0]+c[0])%q,(e*k[1]+c[1])%2)))]+=1
    for z in domain: sim[stop(((z[0]-inv*c[0])%q,((e*z[0])%q,(e*z[1])%2)))]+=1
    tv=Fraction(sum(abs(real[k]-sim[k]) for k in real.keys()|sim.keys()),2*len(domain))
    return tv==Fraction(3,5)


def main():
    ps=Instance('PS')
    wt=setup_waters(8,random.Random('W3-global-setup-test-only').getrandbits)
    for group, points in ((1,(G1,Z1)),(2,(G2,Z2))):
        for j,p in enumerate(points):
            check(f'G{group} canonical roundtrip {j}',lambda p=p,group=group:eq(dec_point(enc_point(p,group),group),p))
        check(f'G{group} reject wrong length',lambda group=group:rejects(lambda:dec_point(b'\0'*(48*group-1),group)))
        check(f'G{group} reject infinity sign flag',lambda group=group:rejects(lambda:dec_point(bytes([0xe0])+b'\0'*(48*group-1),group)))
    check('scalar q rejected not reduced',lambda:rejects(lambda:dec_scalar(Q.to_bytes(32,'big'))))
    check('scalar zero retained',lambda:dec_scalar(bytes(32))==0)
    # (0,2) lies on y^2=x^3+4 but has order 3, outside the q subgroup.
    torsion=(1<<383).to_bytes(48,'big')
    # x=0 is interpreted as infinity and rejected by the library flags; use x=4
    # and search a deterministic on-curve, non-subgroup encoding for coverage.
    candidates=[]
    for x in range(1,100):
        raw=((1<<383)+x).to_bytes(48,'big')
        try:
            p=decompress_G1(int.from_bytes(raw,'big'))
            if not is_inf(multiply(p,Q)):
                candidates.append(raw); break
        except ValueError:
            pass
    check('actual on-curve G1 nonsubgroup rejected',lambda:bool(candidates) and rejects(lambda:dec_point(candidates[0],1)))
    check('Waters mixed identity rejected',lambda:rejects(lambda:wt.sec_decode(enc_point(Z1,1)+enc_point(G2,2))))
    check('Waters relation mismatch rejected',lambda:rejects(lambda:wt.sec_decode(enc_point(wt.h,1)+enc_point(multiply(G2,2),2))))
    check('Waters full identity accepted',lambda:eq(wt.sec_decode(enc_point(Z1,1)+enc_point(Z2,2))[0],Z1))
    check('reject nonminimal Nat',lambda:rejects(lambda:read_nat(b'\x80\x00',0)))
    check('reject unterminated Nat',lambda:rejects(lambda:read_nat(b'\x80',0)))
    check('reject nonzero id padding',lambda:rejects(lambda:BitID(1,b'\x81')))
    for i in (ps,wt):
        zero=(0,0) if i.kind=='PS' else (Z1,Z2)
        frame=i.frame(i.mu(zero),BitID(0,b''))
        check(i.kind+' trailing bytes rejected',lambda i=i,frame=frame:rejects(lambda:i.parse(frame+b'\0')))
        check(i.kind+' invalid request before RNG/H',lambda i=i:invalid_before_rng(i))
        check(i.kind+' real collision and final no-query lookup',lambda i=i:repeat_and_final(i))
        for mode in ('ECQV','PV'):
            check(i.kind+' '+mode+' certificate and signature correctness',lambda i=i,mode=mode:end_to_end(i,mode))
    def trace_test():
        a,t=sample(5,sequence(7,6,0))
        return a==0 and t.blocks==(7,6,0) and len(t.export_bits())==20
    check('all rejected and accepted blocks retained',trace_test)
    check('cap last permitted proposal accepted',lambda:sample(5,sequence(7,4),proposal_cap=2)[0]==4)
    check('cap exhausted aborts',lambda:rejects(lambda:sample(5,sequence(7,7,4),proposal_cap=2),TimeoutError))
    check('nonzero operation sampler rejects zero',lambda:sample(5,sequence(0,3),nonzero=True)[0]==3)
    check('exhaustive fixed-c noninjective joint laws and stopped TV',toy_joint_laws)
    def program_test():
        ro=TestRO(bits=lambda width:2)
        ro.program_fresh(b'a',4)
        assert ro(b'a')==4 and not ro.ordinary_index
        assert rejects(lambda:ro.program_fresh(b'a',1),RuntimeError)
        assert ro(b'b')==3 and ro.ordinary_index[b'b']==1
        return True
    check('programmed entries versus ordinary indices',program_test)
    report={'python':platform.python_version(),'platform':platform.platform(),
            'provider':importlib.metadata.version('py-ecc'),'tests':RESULTS,
            'passed':len(RESULTS),'scope':'research diagnostics; not a security proof; no full game/fork harness'}
    Path(__file__).with_name('verification_results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'passed':len(RESULTS),'failed':0}))


if __name__=='__main__':
    main()
