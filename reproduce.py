"""Safe release entry point: verify saved data or run checks in a fresh copy.

Never launches a performance benchmark. Original research modules remain unchanged.
"""
from pathlib import Path
import argparse, hashlib, json, os, shutil, subprocess, sys

ROOT=Path(__file__).resolve().parent
COMMON='comparison_benchmark_20261024_run01'
CONTROL='p256_rep_control_20261024_run01'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def integrity():
    manifest=json.loads((ROOT/'release_manifest.json').read_text('utf-8'))
    bad=[name for name,h in manifest['files'].items() if not (ROOT/name).is_file() or sha(ROOT/name)!=h]
    if bad:raise ValueError('Release files changed or missing: '+', '.join(bad))
    return len(manifest['files'])
def fresh(path):
    p=Path(path).resolve()
    for name in (COMMON,CONTROL,'vendor'):
        protected=(ROOT/name).resolve()
        if p==protected or protected in p.parents:raise ValueError('Output cannot be inside preserved inputs')
    p.mkdir(parents=True,exist_ok=False)
    return p
def verify(output,providers=False):
    count=integrity(); out=fresh(output)
    from analyze_comparison_benchmark import analyze
    for name in (COMMON,CONTROL):shutil.copytree(ROOT/name,out/name)
    reports={name:analyze(out/name) for name in (COMMON,CONTROL)}
    metadata=json.loads((ROOT/CONTROL/'run_metadata.json').read_text('utf-8'))
    if metadata['baseline']['raw_sha256']!=sha(ROOT/COMMON/'raw_samples.jsonl'):
        raise ValueError('Control baseline raw hash mismatch')
    source_checks=[]
    for group in [metadata['harness_manifest']['sources'],metadata['control_sources']]:
        for name,entry in group.items():
            if not providers and entry['path'].replace('\\','/').startswith('vendor/'):continue
            if sha(ROOT/entry['path'])!=entry['sha256']:raise ValueError('Measured source differs: '+name)
            source_checks.append(name)
    if providers:
        from analyze_p256_rep_control import compare
        compare(out/CONTROL,out/COMMON)
    if integrity()!=count:raise ValueError('Original release changed')
    result={'release_integrity':'PASS','files_checked':count,
        'records':{k:v['records'] for k,v in reports.items()},
        'statistical_populations':{k:v['independently_checked_populations'] for k,v in reports.items()},
        'source_entries_checked':source_checks,'provider_hashes_checked':providers,
        'new_measurements':False,'published_inputs_modified':False}
    (out/'verification.json').write_text(json.dumps(result,indent=2)+'\n','utf-8')
    print(json.dumps(result))
def checks(output,suite):
    integrity(); out=fresh(output)
    # Historical check scripts write beside themselves; execute copies only.
    for p in ROOT.iterdir():
        if p.is_file() and p.suffix in ('.py','.json','.txt'):shutil.copyfile(p,out/p.name)
    for name in (COMMON,CONTROL):shutil.copytree(ROOT/name,out/name)
    env=os.environ.copy()
    env['PYTHONPATH']=str(ROOT/'vendor')+os.pathsep+env.get('PYTHONPATH','')
    scripts={'harness':['check_comparison_harness.py'],
      'all':['check_reference.py','check_boundaries.py','check_scalar.py','check_okamoto.py',
             'check_comparison_harness.py','check_comparison_benchmark.py','check_p256_rep_control.py']}[suite]
    for script in scripts:
        completed=subprocess.run([sys.executable,'-X','utf8',script],cwd=out,env=env,
                                 text=True,encoding='utf-8',capture_output=True)
        (out/(script+'.log')).write_text(completed.stdout+completed.stderr,'utf-8')
        print(json.dumps({'script':script,'exit_code':completed.returncode}))
        if completed.returncode:raise SystemExit(completed.returncode)
    integrity()
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    v=sub.add_parser('verify');v.add_argument('--output',required=True);v.add_argument('--providers',action='store_true')
    c=sub.add_parser('checks');c.add_argument('--output',required=True);c.add_argument('--suite',choices=['harness','all'],default='harness')
    args=parser.parse_args();os.chdir(ROOT)
    if args.command=='verify':verify(args.output,args.providers)
    else:checks(args.output,args.suite)
