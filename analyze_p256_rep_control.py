"""Read-only baseline comparison, with independent arithmetic on both raw sets.

Reuses the generic raw auditor only on the NEW output directory. No trials,
imports of the cryptographic providers, baseline writes or sample pooling.
"""
from pathlib import Path
import argparse
import hashlib
import json
import math
from analyze_comparison_benchmark import analyze, stats, require


def read(path):return json.loads(path.read_text(encoding='utf-8'))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def compare(directory, baseline):
    d=Path(directory);old=Path(baseline)
    require(d.resolve()!=old.resolve(),'new and old runs must remain separate')
    metadata=read(d/'run_metadata.json');previous=read(old/'run_metadata.json')
    require(metadata['task']=='W3-P256-REP-CONTROL','control run required')
    require(metadata['planned_configurations']==2 and metadata['planned_warmups_per_config']==20
            and metadata['planned_formal_trials_per_config']==200,'authorized protocol count')
    require(metadata['baseline']['raw_sha256']==sha(old/'raw_samples.jsonl'),'baseline hash')
    before={p.name:sha(p) for p in old.iterdir() if p.is_file()}
    audit=analyze(d)
    rows=[json.loads(line) for line in (d/'raw_samples.jsonl').read_text(encoding='utf-8').splitlines()]
    oldrows=[json.loads(line) for line in (old/'raw_samples.jsonl').read_text(encoding='utf-8').splitlines()]
    configs=[x['id'] for x in metadata['harness_manifest']['configurations']]
    phases=metadata['harness_manifest']['phase_order']
    require(configs==['scalar-P256-ECQV','scalar-P256-PV'],'exact control configurations')
    require(audit['records']==440 and audit['independently_checked_populations']==48,'raw audit budget')
    for row in rows:
        require(row['implementation_id']==metadata['representation_policy']['implementation_id'],'variant label')
        if row['success']:
            require(all(x['aligned'] for x in row['representation_diagnostics'].values()),'point policy')
            for info in row['representation_diagnostics'].values():
                require(info['identity'] or (info['class']=='PointJacobi' and info['z_is_one']
                        and not info['generator_flag'] and info['precompute_entries']==0),'actual representation properties')
    for name,e in metadata['harness_manifest']['sources'].items():
        require(e['sha256']==previous['harness_manifest']['sources'][name]['sha256'],'shared source changed: '+name)
        require(sha(Path(e['path']))==e['sha256'],'measured source not preserved')
    for e in metadata['control_sources'].values():require(sha(Path(e['path']))==e['sha256'],'control source changed')
    require(metadata['environment']==previous['environment'],'reported environment differs')
    for key in ('default_identity','lambda','hash'):
        require(metadata['harness_manifest'][key]==previous['harness_manifest'][key],'input/hash mismatch')
    newsummary={x['config_id']:x for x in read(d/'summary.json')['rows']}
    oldsummary={x['config_id']:x for x in read(old/'summary.json')['rows']}
    cells=[]
    for config in configs:
        for phase in phases:
            values=[t['elapsed_ns'] for r in oldrows if r['partition']=='formal' and r['config_id']==config
                    and r['success'] for t in r['timings'] if t['phase']==phase]
            reference=stats(values);saved=oldsummary[config]['phases'][phase]['successful_trial_samples']
            require(reference['n']==200,'baseline sample count')
            for key,value in reference.items():require(math.isclose(value,saved[key],rel_tol=1e-12,abs_tol=1e-5),'baseline arithmetic')
            new=newsummary[config]['phases'][phase]['successful_trial_samples']
            cells.append({'config_id':config,'phase':phase,'baseline_successful_statistics':saved,
                          'control_successful_statistics':new,
                          'control_over_baseline_median':new['median_ns']/saved['median_ns'] if new['median_ns'] is not None else None})
    mode_ratios=[]
    for phase in phases:
        ec,pv=configs
        oldratio=oldsummary[pv]['phases'][phase]['successful_trial_samples']['median_ns']/oldsummary[ec]['phases'][phase]['successful_trial_samples']['median_ns']
        em=newsummary[ec]['phases'][phase]['successful_trial_samples']['median_ns']
        pm=newsummary[pv]['phases'][phase]['successful_trial_samples']['median_ns']
        mode_ratios.append({'phase':phase,'baseline_PV_over_ECQV_median':oldratio,
                            'control_PV_over_ECQV_median':pm/em if em and pm is not None else None})
    require(before=={p.name:sha(p) for p in old.iterdir() if p.is_file()},'baseline was modified')
    result={'task':'W3-P256-REP-CONTROL-comparison','raw_audit':{k:audit[k] for k in ('records','formal_records','warmup_records','failed_records','independently_checked_populations')},
            'old_raw_cells_independently_checked':len(cells),'mode_ratios':mode_ratios,'per_phase_comparison':cells,
            'baseline_files_sha256':before,'control_raw_sha256':sha(d/'raw_samples.jsonl'),
            'policy_diagnostics_checked':len(rows),'same_reported_environment':True,'same_shared_sources':True,
            'independence_limit':'old mixed ten-config run and new two-config run have independent randomness, different time and workload; no paired causal effect or significance estimate',
            'conversion_cost':'D/N counts validated in acceptance; actual work included in containing phase; no isolated suboperation time or overhead subtraction'}
    (d/'comparison.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    lines=['| 配置 | 階段 | 原run median ms | 控制run mean ± SD ms | 控制run median ms | 控制／原 median |',
           '| --- | --- | ---: | ---: | ---: | ---: |']
    for cell in cells:
        n=cell['control_successful_statistics'];o=cell['baseline_successful_statistics']
        if n['n']:
            lines.append(f"| {cell['config_id']} | {cell['phase']} | {o['median_ns']/1e6:.5g} | {n['mean_ns']/1e6:.5g} ± {n['sample_sd_ns']/1e6:.4g} | {n['median_ns']/1e6:.5g} | {cell['control_over_baseline_median']:.5g} |")
        else:lines.append(f"| {cell['config_id']} | {cell['phase']} | {o['median_ns']/1e6:.5g} | 無成功樣本 | NA | NA |")
    lines+=['','跨run比值僅為分開呈現的描述性觀測；非相同coins配對、單一轉換耗時或顯著性結論。','',
            '| 階段 | 原run PV／ECQV median | 控制run PV／ECQV median |','| --- | ---: | ---: |']
    for x in mode_ratios:
        ratio='NA' if x['control_PV_over_ECQV_median'] is None else f"{x['control_PV_over_ECQV_median']:.5g}"
        lines.append(f"| {x['phase']} | {x['baseline_PV_over_ECQV_median']:.5g} | {ratio} |")
    (d/'comparison_tables.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps({'task':result['task'],**result['raw_audit'],'old_raw_cells_checked':len(cells),'baseline_unchanged':True}))
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory');parser.add_argument('--baseline',default='comparison_benchmark_20261024_run01')
    args=parser.parse_args();compare(args.directory,args.baseline)
