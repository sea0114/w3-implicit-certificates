"""Small reproducibility pilot, not comparative performance evidence."""
import time
IMPORT_START=time.perf_counter()
from w3_reference import *
IMPORT_SECONDS=time.perf_counter()-IMPORT_START
import random
import statistics
import platform
import os
import json


def timed(operation, count=5):
    samples=[]
    result=None
    for _ in range(count):
        start=time.perf_counter()
        result=operation()
        samples.append(time.perf_counter()-start)
    return result, {'samples_seconds':samples,'median':statistics.median(samples),
                    'min':min(samples),'max':max(samples),'sample_stdev':statistics.stdev(samples)}


def main():
    rng=random.Random('W3-benchmark-synthetic-only')
    bits=rng.getrandbits
    wt,setup_stats=timed(lambda:setup_waters(8,bits),3)
    rows=[]
    for i in (Instance('PS'),wt):
        for mode in ('ECQV','PV'):
            c,_=i.sample_secret(bits); u,_=i.sample_secret(bits)
            service, ca_stats=timed(lambda:CertificateService(i,mode,i.sec_encode(c),FixedHash()))
            request=i.frame(i.mu(u),BitID(128,bytes(range(16))),True)
            pair,iss_stats=timed(lambda:service.issue(request,bits))
            C,r=pair
            s,der_stats=timed(lambda:service.derive(i.sec_encode(u),C,r))
            pk,rec_stats=timed(lambda:service.recon(C))
            valid,guard_stats=timed(lambda:service.verify_preimage(C,s))
            assert valid
            msg=17 if i.kind=='PS' else BitID(8,b'\xa6')
            sig,sign_stats=timed(lambda:sign(i,s,msg,bits))
            valid,ver_stats=timed(lambda:verify_signature(i,i.pub_encode(pk),msg,sig))
            assert valid
            shared_points=0 if i.kind=='PS' else 48*(1+len(i.U))
            rows.append({'instance':i.kind,'mode':mode,'samples_per_operation':5,
                'ca_constructor_existing_secret':ca_stats,'issuance':iss_stats,'derive':der_stats,
                'public_reconstruction':rec_stats,'verify_preimage':guard_stats,
                'sign_separate':sign_stats,'verify_signature_separate':ver_stats,
                'bytes':{'id_bits':128,'certificate':len(C),'response':len(r),'secret':len(s),
                         'public_key':len(i.pub_encode(pk)),'signature':len(sig),
                         'shared_additional_Waters_points':shared_points,
                         'base_generators_g1_g2':144},
                'cache':'no application point-validation/pairing/hash cache; interpreter/provider warm; same pp within row'})
    out={'python':platform.python_version(),'platform':platform.platform(),
         'processor':os.environ.get('PROCESSOR_IDENTIFIER',platform.processor()),
         'provider_import_new_process_seconds':IMPORT_SECONDS,
         'cold_scope':'new Python process; OS disk/page cache not flushed',
         'Waters_global_setup_n8_three_samples':setup_stats,
         'scope':'single-machine pilot, no competing baseline, no strict worst-case claim',
         'rows':rows}
    Path(__file__).with_name('benchmark_results.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
    print(json.dumps({'configurations':len(rows),'samples':5,'import_seconds':IMPORT_SECONDS}))


if __name__=='__main__':
    main()
