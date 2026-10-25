"""Post-run completeness and independent arithmetic review; never runs trials."""
from pathlib import Path
import argparse
import hashlib
import json
import math
import statistics


def require(value, message):
    if not value:
        raise ValueError(message)


def stats(values):
    if not values:
        return {"n":0,"mean_ns":None,"sample_sd_ns":None,"median_ns":None,
                "min_ns":None,"max_ns":None,"p95_ns":None}
    mean = sum(values)/len(values)
    variance = sum((x-mean)**2 for x in values)/(len(values)-1) if len(values)>1 else None
    ordered=sorted(values); index=(len(ordered)-1)*95/100
    lower=math.floor(index); fraction=index-lower
    percentile=ordered[lower]*(1-fraction)+ordered[min(lower+1,len(ordered)-1)]*fraction
    return {"n":len(values),"mean_ns":mean,"sample_sd_ns":math.sqrt(variance) if variance is not None else None,
            "median_ns":statistics.median(values),"min_ns":ordered[0],"max_ns":ordered[-1],"p95_ns":percentile}


def analyze(directory):
    d=Path(directory)
    metadata=json.loads((d/'run_metadata.json').read_text(encoding='utf-8'))
    require(metadata['status']=='completed','run must finish before final analysis')
    rows=[json.loads(line) for line in (d/'raw_samples.jsonl').read_text(encoding='utf-8').splitlines()]
    summary=json.loads((d/'summary.json').read_text(encoding='utf-8'))
    configs=[x['id'] for x in metadata['harness_manifest']['configurations']]
    phases=metadata['harness_manifest']['phase_order']
    counts={'warmup':metadata['planned_warmups_per_config'],'formal':metadata['planned_formal_trials_per_config']}
    require(len(rows)==sum(counts.values())*len(configs)==metadata['records_saved']==summary['records'],'record count')
    require([r['sequence'] for r in rows]==list(range(len(rows))),'sequence continuity')
    require(all(r['partition']==('warmup' if n<counts['warmup']*len(configs) else 'formal')
                for n,r in enumerate(rows)),'all warmup rows precede formal rows')
    require(len({r['session_id'] for r in rows})==len(rows),'fresh explicit session per trial')
    by_id={r['config_id']:r for r in summary['rows']}
    failures=[{'sequence':r['sequence'],'partition':r['partition'],'config_id':r['config_id'],
               'setup_ledger':r['setup_ledger'],'trial':r.get('trial'),'error':r.get('orchestration_error')}
              for r in rows if not r['success']]
    for row in rows:
        require(row['config_id'] in configs and row['partition'] in counts,'known record domain')
        require(row['position']==(configs.index(row['config_id'])-row['round'])%len(configs),'rotating schedule position')
        if 'public_setup' in row:
            digest=hashlib.sha256(json.dumps(row['public_setup'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
            require(digest==row['public_setup_sha256'],'public setup snapshot digest')
        require(row['started_utc']<=row['finished_utc'],'ordered UTC markers')
        require(len({t['phase'] for t in row['timings']})==len(row['timings']),'unique phase timings')
        for t in row['timings']:
            require(t['phase'] in phases and type(t['elapsed_ns']) is int and t['elapsed_ns']>=0,'valid elapsed time')
        if row['success']:
            require(row['setup_ledger']==[{'phase':'group_setup','status':'ok'}],'successful setup ledger')
            require([t['phase'] for t in row['timings']]==phases,'all eight phases executed')
            require(all(t['call_status']=='returned' for t in row['timings']),'no exception in success')
            require(row['diagnostics']['status']=='ok' and all(row['diagnostics']['checks'].values()),'diagnostics success')
            require(all(t['status']=='ok' for t in row['trial']['phases']),'harness ledger success')
            expected=2 if row['config_id'].startswith(('PS-','Okamoto-')) else 1
            for role in ('ca','user','nonce'):
                traces=row['trial']['private_trace_summary'][role]
                require(len(traces)==expected,'trace multiplicity')
                require(all(t['proposals']>=1 and t['consumed_bits']==t['width']*t['proposals'] for t in traces),'complete trace summary arithmetic')
    drift=[];flows=[];independent_cells=0
    for config in configs:
        for partition,count in counts.items():
            selected=[r for r in rows if r['config_id']==config and r['partition']==partition]
            require(len(selected)==count and sorted(r['round'] for r in selected)==list(range(count)),'round completeness/config')
        formal=[r for r in rows if r['config_id']==config and r['partition']=='formal']
        require(sum(r['success'] for r in formal)==by_id[config]['formal_success'],'reported success count')
        require(sum(not r['success'] for r in formal)==by_id[config]['formal_failed'],'reported failure count')
        if counts['formal'] % len(configs)==0:
            require(all(sum(r['position']==p for r in formal)==counts['formal']//len(configs) for p in range(len(configs))),'position balance')
        for phase in phases:
            attempted=[t['elapsed_ns'] for r in formal for t in r['timings'] if t['phase']==phase]
            good=[t['elapsed_ns'] for r in formal if r['success'] for t in r['timings'] if t['phase']==phase]
            failed=[t['elapsed_ns'] for r in formal if not r['success'] for t in r['timings'] if t['phase']==phase]
            cell=by_id[config]['phases'][phase]
            require(cell['scheduled']==counts['formal'] and cell['attempted']==len(attempted) and cell['not_timed']==counts['formal']-len(attempted),'counts by phase')
            for population,values in (('all_attempted_samples',attempted),('successful_trial_samples',good),('failed_trial_attempt_samples',failed)):
                independent=stats(values);saved=cell[population]
                for key,value in independent.items():
                    if value is None:require(saved[key] is None,'null stats')
                    else:require(math.isclose(value,saved[key],rel_tol=1e-12,abs_tol=1e-5),'independent stats '+config+'/'+phase+'/'+key)
                independent_cells+=1
            halves=[]
            for lower,upper in ((0,counts['formal']//2),(counts['formal']//2,counts['formal'])):
                v=[t['elapsed_ns'] for r in formal if r['success'] and lower<=r['round']<upper for t in r['timings'] if t['phase']==phase]
                halves.append(statistics.median(v) if v else None)
            ratio=halves[1]/halves[0] if halves[0] and halves[1] is not None else None
            drift.append({'config_id':config,'phase':phase,'first_half_median_ns':halves[0],
                          'second_half_median_ns':halves[1],'second_over_first':ratio})
        for verifier in ('reconstruction','preimage_validation'):
            include=('ca_keygen','ca_import','user_prepare','issue','completion',verifier)
            totals=[sum(t['elapsed_ns'] for t in r['timings'] if t['phase'] in include) for r in formal if r['success']]
            flows.append({'config_id':config,'path':'fresh_service_plus_certificate_'+verifier,
                          'included_phases':include,'excluded':'setup, other verifier path, diagnostics/logging/control overhead',
                          'statistics':stats(totals)})
    ratios=[]
    for ec in configs:
        if not ec.endswith('-ECQV'):continue
        pv=ec[:-4]+'PV'
        for phase in phases:
            e=by_id[ec]['phases'][phase]['successful_trial_samples']['median_ns']
            p=by_id[pv]['phases'][phase]['successful_trial_samples']['median_ns']
            ratios.append({'family':ec[:-5],'phase':phase,'PV_over_ECQV_median':p/e if e and p is not None else None})
    analysis={'task':'W3-COMP-BENCH-analysis','verdict':'sample completeness and independent descriptive statistics verified',
              'records':len(rows),'warmup_records':sum(r['partition']=='warmup' for r in rows),
              'formal_records':sum(r['partition']=='formal' for r in rows),'failed_records':len(failures),
              'failures':failures,'independently_checked_populations':independent_cells,
              'descriptive_mode_ratios':ratios,'split_half_diagnostic':drift,'workflow_phase_sums':flows,
              'inference_limit':'No significance, causal heat attribution or equal-security superiority claim; split halves are diagnostics only.',
              'raw_sha256':hashlib.sha256((d/'raw_samples.jsonl').read_bytes()).hexdigest()}
    (d/'analysis.json').write_text(json.dumps(analysis,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    lines=['每格為 **mean ± sample SD（median）**，單位ms；完整精度、min／max／p95見summary.json。','']
    for label, subset in [('Setup與CA階段',phases[:3]),('使用者與簽發階段',phases[3:6]),('公開重建與完整驗證',phases[6:])]:
        lines += ['### '+label,'','| 配置 | '+' | '.join(subset)+' |','| --- | '+' | '.join(['---:']*len(subset))+' |']
        for config in configs:
            cells=[]
            for phase in subset:
                s=by_id[config]['phases'][phase]['successful_trial_samples']
                if s['n']:
                    sd='NA' if s['sample_sd_ns'] is None else f"{s['sample_sd_ns']/1e6:.4g}"
                    cells.append(f"{s['mean_ns']/1e6:.4g} ± {sd}（{s['median_ns']/1e6:.4g}）")
                else:cells.append('無成功樣本')
            lines.append('| '+config+' | '+' | '.join(cells)+' |')
        lines.append('')
    (d/'results_tables.md').write_text('\n'.join(lines),encoding='utf-8')
    print(json.dumps({k:analysis[k] for k in ('records','formal_records','warmup_records','failed_records','independently_checked_populations')}))
    return analysis


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory')
    analyze(parser.parse_args().directory)
