"""Focused control acceptance; fake clocks only, no other configuration trials."""
from pathlib import Path
import json
import benchmark_p256_rep_control as bench
import benchmark_comparison as base
import comparison_harness as h
from p256_rep_control import P256JacobianControl, ControlSession, CONFIGURATIONS, POLICY, point_policy
from scalar_reference import ScalarInstance, ScalarFixedHash, CertificateService, PointJacobi, Point, INFINITY
from w3_reference import BitID, nat

RESULTS=[]
ID=BitID(13,b'\xa6\x50')
D=1<<128

def require(value,message):
    if not value:raise RuntimeError(message)

def reject(operation,types=(ValueError,TypeError)):
    try:operation()
    except types:return
    raise RuntimeError('invalid input accepted')

class Tape:
    def __init__(self,*values):self.values=list(values);self.calls=0
    def __call__(self,width):
        self.calls+=1
        require(bool(self.values),'tape exhausted')
        value=self.values.pop(0)
        require(type(value) is int and 0<=value<1<<width,'tape block')
        return value

class Probe:
    def __init__(self,value):self.value=value;self.calls=0
    def __call__(self,C):self.calls+=1;return self.value

def check(label,operation):
    try:RESULTS.append({'id':label,'status':'PASS','evidence':operation()})
    except Exception as e:RESULTS.append({'id':label,'status':'FAIL','error':type(e).__name__+': '+str(e)})

def transcript(instance,mode,c,u,k,challenge):
    ca=h.phase_ca_keygen(instance,Tape(c))
    H=ScalarFixedHash(instance) if challenge is None else Probe(challenge)
    service=CertificateService(instance,mode,ca.secret,H,lam=128)
    user=h.phase_user_prepare(instance,ID,Tape(u))
    C,r=service.issue(user.request,Tape(k))
    s=service.derive(user.secret,C,r)
    public=h.phase_reconstruction(service,C)
    require(service.verify_preimage(C,s),'valid secret rejected')
    require(not service.verify_preimage(C,s,fresh=True),'freshness bypass')
    require(public==instance.pub_encode(instance.mu(instance.sec_decode(s))),'mu equality')
    return {'ca_secret':ca.secret,'ca_public':ca.public,'ca_traces':ca.traces,
            'user_secret':user.secret,'request':user.request,'user_traces':user.traces,
            'C':C,'r':r,'s':s,'public':public,'private_state':service._last_issuance_state}

def equivalence(mode):
    old=ScalarInstance('P256');new=P256JacobianControl();q=new.q
    cases=((3,5,7),(0,0,0),(1,1,1),(q-1,q-1,q-1),(0,1,q-1),(1,q-1,1))
    for c,u,k in cases:
        for challenge in (None,1,D):
            require(transcript(old,mode,c,u,k,challenge)==transcript(new,mode,c,u,k,challenge),
                    'old/control byte or complete private-state mismatch')
    return {'paired_functional_fixtures':18,'equal_full_transcript_and_traces':True,
            'includes':'zero, one, q-1, R identity, fixed SHAKE, challenge endpoints; synthetic, untimed'}

def representation(mode):
    i=P256JacobianControl();q=i.q
    for s in (0,1,2,q-1):
        Y=i.mu(s);R=i.pub_decode(i.pub_encode(Y))
        require(point_policy(Y)['aligned'] and point_policy(R)['aligned'],'mu/decoded input policy')
        if s:
            require(Y is not i.P and R is not i.P,'generator alias escaped')
            for e in (1,2,D):
                result=i.pub_mul(Y,e)
                require(result==INFINITY or (type(result) is PointJacobi and not result._PointJacobi__generator
                        and not result._PointJacobi__precompute),'variable result precomputed')
            require(point_policy(Y)['aligned'],'variable multiply grew a precompute table')
        service=CertificateService(i,mode,i.sec_encode(s),ScalarFixedHash(i))
        require(point_policy(service.Y)['aligned'],'CA import policy')
    require(i.P._PointJacobi__generator and i.P._PointJacobi__precompute,'shared fixed-generator warm path')
    require(not point_policy(Point(i.P.curve(),i.P.x(),i.P.y(),i.q))['aligned'],'diagnostic misses affine')
    return {'mu_one_detached_from_generator':True,'variable_precompute_disabled':True,
            'identity_retained':True,'CA_and_decoded_Z1':True}

def traces(mode):
    i=P256JacobianControl();blocks=((1<<256)-1,i.q,0)
    ca=h.phase_ca_keygen(i,Tape(*blocks));u=h.phase_user_prepare(i,ID,Tape(*blocks))
    service=CertificateService(i,mode,ca.secret,Probe(1))
    C,r=service.issue(u.request,Tape(*blocks))
    for ts in (ca.traces,u.traces,service._last_issuance_state['consumed_traces']):
        require(len(ts)==1 and ts[0].blocks==blocks and ts[0].width==256,'full reject/accept trace')
    require(service.verify_preimage(C,service.derive(u.secret,C,r)),'zero flow')
    return {'three_roles':'all rejected blocks plus accepted zero retained','cap':None}

def wire_validation(mode):
    i=P256JacobianControl();p=i.field_modulus
    nonresidue=next(x for x in range(100) if pow((x**3+i.P.curve().a()*x+i.P.curve().b())%p,(p-1)//2,p)==p-1)
    badpoints=[b'',b'\x00\x00',b'\x01',b'\x04'+bytes(64),b'\x02'+p.to_bytes(32,'big'),
               b'\x02'+nonresidue.to_bytes(32,'big'),bytearray(b'\x00'),None]
    for raw in badpoints:reject(lambda raw=raw:i.pub_decode(raw))
    good=i.frame(i.mu(7),ID)
    badframes=[b'X'+good[1:],good[:4]+b'\x02'+good[5:],i.frame(i.mu(7),ID,True),good+b'\x00',good[:-1],
               good[:-1]+bytes([good[-1]|1]),good[:7]+b'\x80'+good[7:]]
    for raw in badframes:reject(lambda raw=raw:i.parse(raw))
    probe=Probe(1);service=CertificateService(i,mode,i.sec_encode(3),probe);tape=Tape(7)
    for raw in (good,b'X',i.frame(i.mu(5),ID,True)+b'\x00'):
        reject(lambda raw=raw:service.issue(raw,tape))
    require(tape.calls==probe.calls==0 and not service.issued and not hasattr(service,'_last_issuance_state'),
            'invalid request consumed bits/hash or committed state')
    return {'invalid_point_cases':len(badpoints),'invalid_frame_cases':len(badframes),
            'pre_nonce_pre_hash_rejection':True,'non_byte_identity_frame':True}

def domain_validation(mode):
    i=P256JacobianControl()
    for v in (-1,i.q,True,1.0):reject(lambda v=v:i.mu(v))
    for raw in (b'',bytes(31),bytes(33),i.q.to_bytes(32,'big')):reject(lambda raw=raw:i.sec_decode(raw))
    reject(lambda:CertificateService(i,mode,i.sec_encode(3),ScalarFixedHash(i),lam=127))
    request=i.frame(i.mu(5),ID,True)
    for e in (0,D+1,True,1.0):
        service=CertificateService(i,mode,i.sec_encode(3),Probe(e),lam=128)
        reject(lambda:service.issue(request,Tape(7)))
        require(not service.issued and not hasattr(service,'_last_issuance_state'),'bad challenge committed state')
    service=CertificateService(i,mode,i.sec_encode(3),ScalarFixedHash(i))
    C,r=service.issue(request,Tape(7));s=service.derive(i.sec_encode(5),C,r)
    wrong=i.sec_encode((i.sec_decode(s)+1)%i.q)
    require(not service.verify_preimage(C,wrong) and not service.verify_preimage(C,i.q.to_bytes(32,'big')),'bad secret accepted')
    return {'full_scalar_domain':True,'malformed_secret_and_hash_guards':True,'wrong_preimage_rejected':True}

def conversions(mode):
    class Counted(P256JacobianControl):
        def __init__(self):super().__init__();self.count={'D':0,'N':0}
        def pub_decode(self,raw):
            value=super().pub_decode(raw)
            if value!=INFINITY:self.count['D']+=1
            return value
        def mu(self,s):
            value=super().mu(s)
            if value!=INFINITY:self.count['N']+=1
            return value
    i=Counted();c=next(c for c in CONFIGURATIONS if c.mode==mode);got={'group_setup':dict(i.count)};a={}
    operations=[('ca_keygen','ca',lambda:h.phase_ca_keygen(i,Tape(3))),
                ('ca_import','service',lambda:h.phase_ca_import(i,c,a['ca'].secret)),
                ('user_prepare','user',lambda:h.phase_user_prepare(i,ID,Tape(5))),
                ('issue','issuance',lambda:h.phase_issue(a['service'],a['user'].request,Tape(7))),
                ('completion','s',lambda:h.phase_completion(a['service'],a['user'].secret,*a['issuance'])),
                ('reconstruction','public',lambda:h.phase_reconstruction(a['service'],a['issuance'][0])),
                ('preimage_validation','valid',lambda:h.phase_preimage_validation(a['service'],a['issuance'][0],a['s']))]
    for phase,key,fn in operations:
        before=dict(i.count);a[key]=fn();got[phase]={k:i.count[k]-before[k] for k in before}
    require(a['valid'] and got==POLICY['conversion_operations_by_phase'],'conversion accounting mismatch')
    return {'actual_nonidentity_functional_counts':got,'instrumentation':'test-only, absent from timed adapter'}

def integrated(mode):
    c=next(c for c in CONFIGURATIONS if c.mode==mode)
    ticks=iter(range(0,10000,125));runner=base.TimedRunner(lambda:next(ticks))
    row=bench.run_one(c,'fake-clock',0,0,0,runner,h.ScopedSyntheticBits(b'P256-rep-test'))
    require(row['success'] and all(t['elapsed_ns']==125 for t in row['timings']),'integrated flow/fake timer')
    require([t['phase'] for t in row['timings']]==list(base.PHASES),'phase order')
    require(all(v['aligned'] for v in row['representation_diagnostics'].values()),'representation diagnostics')
    require(json.loads(json.dumps(row))['success'],'serialization')
    return {'all_eight_phases':True,'timings':'fake only','no_other_configuration':True}

def failures(mode):
    c=next(c for c in CONFIGURATIONS if c.mode==mode)
    ticks=iter(range(1000));timer=base.TimedRunner(lambda:next(ticks))
    def fault(ctx,op):
        def bad():raise ValueError('injected failure')
        return timer(ctx,bad if ctx.phase=='issue' else op)
    session=ControlSession(c,runner=fault,bits_factory=h.ScopedSyntheticBits(b'P256-rep-failure'))
    session.setup();r=session.run_trial(0)
    require(not r.success and r.ledger[3]['status']=='failed','failure not retained')
    require(all(x['status']=='skipped' for x in r.ledger[4:]),'dependent phases not skipped')
    require(timer.records[-1]['call_status']=='raised' and len(timer.records)==5,'failed timing lost')
    reject(lambda:session.setup(),(RuntimeError,));reject(lambda:session.run_trial(0),(RuntimeError,))
    return {'failed_time_retained':True,'three_successors_skipped':True,'reuse_rejected':True}

def scheduling():
    plan=list(bench.schedule(20,200))
    require(len(plan)==440 and len(CONFIGURATIONS)==2,'budget/config count')
    for c in CONFIGURATIONS:
        require(sum(x[0]=='warmup' and x[3]==c for x in plan)==20,'warmup count')
        require(all(sum(x[0]=='formal' and x[2]==pos and x[3]==c for x in plan)==100 for pos in (0,1)),'positions')
    for c in h.CONFIGURATIONS[2:]:reject(lambda c=c:ControlSession(c))
    # Keep the harmless fixture inside the workspace: the host's sandbox
    # Windows temporary-directory lifecycle may reject access/cleanup.
    d=Path(__file__).parent/'p256_rep_control_overwrite_fixture'
    d.mkdir(exist_ok=True)
    marker=d/'keep.txt'
    if not marker.exists():marker.write_text('original',encoding='utf-8')
    require(marker.read_text(encoding='utf-8')=='original','fixture altered before check')
    reject(lambda:bench.run(d,Path(__file__).parent/'comparison_benchmark_20261024_run01'),(FileExistsError,))
    require(marker.read_text(encoding='utf-8')=='original','existing output modified')
    return {'only_two_configs':True,'records':440,'formal_position_balance':100,'no_overwrite':True}

def main():
    for mode in ('ECQV','PV'):
        for name,fn in (('equivalence',equivalence),('representation',representation),('trace',traces),
                        ('wire',wire_validation),('domain',domain_validation),('conversion_counts',conversions),
                        ('integration',integrated),('failure',failures)):
            check(mode+'/'+name,lambda fn=fn,mode=mode:fn(mode))
    check('schedule_and_scope',scheduling)
    failed=sum(x['status']!='PASS' for x in RESULTS)
    result={'task':'W3-P256-REP-CONTROL-acceptance','checks':RESULTS,'total':len(RESULTS),
            'passed':len(RESULTS)-failed,'failed':failed,'formal_measurement':False,
            'old_full_suites_executed':False,'other_configuration_trials':0}
    Path(__file__).with_name('p256_rep_control_verification_results.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result));return int(bool(failed))

if __name__=='__main__':raise SystemExit(main())
