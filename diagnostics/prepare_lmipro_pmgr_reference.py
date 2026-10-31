"""Prepare only this CI run's reference inputs for the pinned PMGR audit."""
from pathlib import Path
import argparse, hashlib, json, shutil, subprocess, sys

ap=argparse.ArgumentParser()
ap.add_argument('--work',type=Path,required=True)
ap.add_argument('--cache',type=Path,required=True)
ap.add_argument('--out',type=Path,required=True)
a=ap.parse_args()
tree=a.work/'tree'
assert 'CONFIG_XNU_SHENG_PMGR=y' not in (a.work/'.config').read_text()
candidate=a.work/'kernel/kernel.macho'
plan=candidate.with_suffix('.json')
assert candidate.is_file() and plan.is_file()
cache_sha=hashlib.sha256(a.cache.read_bytes()).hexdigest()
assert cache_sha=='f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7'
reference=tree/'build/pmgr-reference/lmipro-reference.macho'
reference.parent.mkdir(parents=True,exist_ok=True)
shutil.copyfile(candidate,reference)
shutil.copyfile(plan,reference.with_suffix('.json'))
original=tree/'.cache/firmware/kernelcache.macho/kernelcache.release.ipad7.decompressed'
original.parent.mkdir(parents=True,exist_ok=True)
shutil.copyfile(a.cache,original)
assert hashlib.sha256(original.read_bytes()).hexdigest()==cache_sha
subprocess.run([sys.executable,str(tree/'scripts/audit-amfi-pmgr-contract.py'),
                '--candidate',str(reference)],check=True)
a.out.mkdir(parents=True,exist_ok=True)
shutil.copyfile(tree/'build/amfi-pmgr-contract/report.json',a.out/'reference-amfi-pmgr-audit.json')
report=dict(fresh_reference_from_current_job=True,
            reference_sha256=hashlib.sha256(reference.read_bytes()).hexdigest(),
            reference_json_sha256=hashlib.sha256(reference.with_suffix('.json').read_bytes()).hexdigest(),
            original_cache_sha256=cache_sha,reference_pmgr_mode=0,
            original_executable_modified=False,hardware_execution=False)
(a.out/'reference-inputs.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
