"""Additional unresolved contract checks identified in the reviewer pass."""
from check_reference import check, rejects, RESULTS, sequence
from w3_reference import *
import json
import random


def main():
    def g2_subgroup():
        for x in range(1,100):
            a=(1<<383)+x
            try:
                p=decompress_G2((a,0))
            except (ValueError,ZeroDivisionError):
                continue
            if not is_inf(multiply(p,Q)):
                return rejects(lambda:dec_point(a.to_bytes(48,'big')+bytes(48),2))
        return False
    check('actual on-curve G2 nonsubgroup rejected',g2_subgroup)
    def bits_domain():
        ro=TestRO(bits=sequence(0,1,2))
        assert ro(b'\x80')==ro(BitID(8,b'\x80'))==1
        assert ro(BitID(1,b'\x80'))==2
        assert ro(BitID(2,b'\x80'))==3
        return len(ro.table)==3 and 1<=FixedHash()(BitID(1,b'\x80'))<=2**128
    check('RO arbitrary bitstrings and byte aliases',bits_domain)
    ps=Instance('PS')
    wt=setup_waters(0,random.Random('W3-extra-boundary').getrandbits)
    def zero_keys():
        for secret in ((0,0),(0,7),(11,0)):
            raw=ps.sec_encode(secret)
            sig=sign(ps,raw,0,lambda width:1)
            assert verify_signature(ps,ps.pub_encode(ps.mu(secret)),0,sig)
        # Verify permits the t=0 Waters point although Sign excludes it.
        s=wt.secret_from_scalar(3)
        sig=enc_point(s[0],1)+enc_point(Z2,2)+enc_point(Z1,1)
        return verify_signature(wt,wt.pub_encode(s[1]),BitID(0,b''),sig)
    check('zero PS coordinates and Waters Verify-only nonce zero',zero_keys)
    def arbitrary_request():
        for i in (ps,wt):
            zero=(0,0) if i.kind=='PS' else (Z1,Z2)
            public=(G2,multiply(G2,2)) if i.kind=='PS' else multiply(G2,3)
            service=CertificateService(i,'PV',i.sec_encode(zero),lambda c:1)
            C,r=service.issue(i.frame(public,BitID(0,b''),True),lambda w:0)
            assert i.pub_encode(service.recon(C))==i.pub_encode(public)
        return True
    check('arbitrary legal request no preimage or PoP input',arbitrary_request)
    def fixed_h():
        for i in (ps,wt):
            s=(2,3) if i.kind=='PS' else i.secret_from_scalar(2)
            zero=(0,0) if i.kind=='PS' else (Z1,Z2)
            for mode in ('ECQV','PV'):
                service=CertificateService(i,mode,i.sec_encode(zero),lambda c:1)
                C,r=service.issue(i.frame(i.mu(s),BitID(0,b''),True),lambda w:0)
                derived=service.derive(i.sec_encode(s),C,r)
                assert service.verify_preimage(C,derived)
        return True
    check('constant fixed H correctness in all four configurations',fixed_h)
    Path(__file__).with_name('boundary_results.json').write_text(json.dumps({'tests':RESULTS,'passed':len(RESULTS)},indent=2),encoding='utf-8')
    print(json.dumps({'additional_passed':len(RESULTS)}))


if __name__=='__main__':
    main()
