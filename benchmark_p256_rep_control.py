"""Two P-256 configurations only, fresh independent run, no legacy mutation."""
from pathlib import Path
import argparse
import hashlib
import json
import benchmark_comparison as base
from p256_rep_control import ControlSession, CONFIGURATIONS, POLICY, point_policy


def schedule(warmups, trials):
    if type(warmups) is not int or warmups < 0 or type(trials) is not int or trials < 1:
        raise ValueError('nonnegative warmups and positive formal trials required')
    for partition,count in (('warmup',warmups),('formal',trials)):
        for index in range(count):
            offset=index % len(CONFIGURATIONS)
            order=CONFIGURATIONS[offset:]+CONFIGURATIONS[:offset]
            for position,config in enumerate(order):
                yield partition,index,position,config


def run_one(config, partition, index, position, sequence, runner=None, bits_factory=None):
    runner=base.TimedRunner() if runner is None else runner
    session_id=f'P256-REP/{partition}/{index}/{config.id}'
    session=ControlSession(config,session_id=session_id,runner=runner,
                           bits_factory=base.h.OSBits() if bits_factory is None else bits_factory)
    row={'schema':'W3-COMP-sample-v1','implementation_id':POLICY['implementation_id'],
         'sequence':sequence,'partition':partition,'round':index,'position':position,
         'config_id':config.id,'session_id':session_id,'started_utc':base.utc()}
    result=None
    try:
        session.setup()
        result=session.run_trial(0)
        row['trial']=result.summary()
        row['diagnostics']=base.diagnostics(session,result)
        row['success']=result.success and row['diagnostics']['status']=='ok'
        if row['success']:
            service=result.artifacts['service']
            C=result.artifacts['issuance'][0]
            R,_=session.instance.parse(C)  # Outside timer; no arithmetic cache.
            policy={'CA_Y':point_policy(service.Y),'decoded_R':point_policy(R)}
            row['representation_diagnostics']=policy
            row['success']=all(v['aligned'] for v in policy.values())
    except Exception as exc:
        row.update(success=False,orchestration_error={'type':type(exc).__name__,'message':str(exc)})
        if result is not None:
            row['trial_ledger_fallback']=[dict(v) for v in result.ledger]
    finally:
        row['timings']=runner.records
        row['setup_ledger']=[dict(v) for v in session.setup_ledger]
        row['finished_utc']=base.utc()
    try:
        row['public_setup']=session.public_setup()
        row['public_setup_sha256']=hashlib.sha256(json.dumps(row['public_setup'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
    except Exception as exc:
        row.update(success=False,setup_metadata_error={'type':type(exc).__name__,'message':str(exc)})
    return row


def summarize(rows):
    result=base.summarize(rows)
    result['rows']=[r for r in result['rows'] if r['config_id'] in {c.id for c in CONFIGURATIONS}]
    result['task']='W3-P256-REP-CONTROL'
    return result


def protocol(warmups, trials, baseline):
    result=base.protocol(warmups,trials)
    result.update(task='W3-P256-REP-CONTROL',schema='W3-P256-REP-benchmark-v1',
                  planned_configurations=2,representation_policy=POLICY,
                  benchmark_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  schedule='serial two-config rounds; starting config rotates mod 2; all warmups before formal',
                  trace_policy='complete private traces through trial; counts exported; no private blocks retained in JSON',
                  baseline={'path':str(baseline.resolve()),'raw_sha256':hashlib.sha256((baseline/'raw_samples.jsonl').read_bytes()).hexdigest(),
                            'comparison':'separate runs, independent coins/time/order environment; never pooled or paired'})
    result['harness_manifest']['configurations']=[x for x in result['harness_manifest']['configurations'] if x['id'] in {c.id for c in CONFIGURATIONS}]
    result['harness_manifest']['execution_kind']='inherited seven-phase harness; isolated control setup subclass; outer timer'
    result['harness_manifest']['scope']['clock']='outer perf_counter_ns; no bit-time guarantee'
    result['harness_manifest']['scope']['control_override']='P256 instance factory only; full original trial methods and codecs inherited'
    result['outside_timer'].append('read-only R/Y representation diagnostics, including extra certificate decode')
    root=Path(__file__).resolve().parent
    result['control_sources']={name:{'path':str((root/name).resolve()),'sha256':hashlib.sha256((root/name).read_bytes()).hexdigest()}
                               for name in ('p256_rep_control.py','benchmark_p256_rep_control.py','benchmark_comparison.py')}
    return result


def run(output, baseline, warmups=20, trials=200):
    plan=list(schedule(warmups,trials))
    baseline=Path(baseline)
    old=json.loads((baseline/'run_metadata.json').read_text(encoding='utf-8'))
    if old['status']!='completed':raise ValueError('completed baseline required')
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    metadata=protocol(warmups,trials,baseline)
    metadata.update(status='running',started_utc=base.utc())
    base.write_json(output/'run_metadata.json',metadata)
    rows=[];failures=0
    try:
        with (output/'raw_samples.jsonl').open('x',encoding='utf-8') as stream:
            for seq,(partition,index,position,config) in enumerate(plan):
                row=run_one(config,partition,index,position,seq)
                stream.write(json.dumps(row,ensure_ascii=False,separators=(',',':'))+'\n');stream.flush()
                rows.append(row);failures+=not row['success']
                if position==1 and (index+1)%20==0:
                    progress={'partition':partition,'rounds_completed':index+1,'records_saved':len(rows),'failed_trials':failures}
                    base.write_json(output/'progress.json',progress);print(json.dumps(progress),flush=True)
    except BaseException as exc:
        metadata.update(status='interrupted',interruption={'type':type(exc).__name__,'message':str(exc)})
        raise
    else:metadata['status']='completed'
    finally:
        metadata.update(finished_utc=base.utc(),records_saved=len(rows),failed_trials=failures)
        base.write_json(output/'summary.json',summarize(rows));base.write_json(output/'run_metadata.json',metadata)
    return int(bool(failures))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True)
    parser.add_argument('--baseline',default='comparison_benchmark_20261024_run01')
    parser.add_argument('--warmups',type=int,default=20)
    parser.add_argument('--trials',type=int,default=200)
    args=parser.parse_args()
    raise SystemExit(run(args.output,args.baseline,args.warmups,args.trials))
