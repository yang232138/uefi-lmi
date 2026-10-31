"""Check actual link inputs, original executables and the guarded PMGR hook."""
from pathlib import Path
import argparse, hashlib, json, shutil, subprocess, sys

ap=argparse.ArgumentParser()
ap.add_argument('--work',type=Path,required=True)
ap.add_argument('--out',type=Path,required=True)
ap.add_argument('--device-revision',required=True)
a=ap.parse_args()
tree=a.work/'tree';a.out.mkdir(parents=True,exist_ok=True)
config=(a.work/'.config').read_text()
assert 'CONFIG_XNU_SHENG_PMGR=y' in config and 'CONFIG_XNU_DT_PANIC_REGION=y' in config
obj=tree/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
assert (obj/'.sheng-pmgr-mode').read_text().strip()=='1'
assert (obj/'.dt-panic-region-mode').read_text().strip()=='1'
kernel=a.work/'kernel/kernel.macho';data=kernel.read_bytes()
assert b'LMIPRO PMGR LIFECYCLE PASS' in data
nm=shutil.which('llvm-nm');dump=shutil.which('llvm-objdump');assert nm and dump
text=subprocess.run([nm,'-n','--defined-only',str(kernel)],check=True,capture_output=True,text=True).stdout
symbols={}
for line in text.splitlines():
    p=line.split()
    if len(p)==3:symbols.setdefault(int(p[0],16),p[2])
names={name:va for va,name in symbols.items()}
for name in ['_lmipro_pmgr_run','_sheng_pmgr_run','_sheng_pmgr_observation','__ZTV18ShengPlatformPower']:
    assert name in names,name
lo=names['_bsd_init'];hi=next(v for v in sorted(symbols) if v>lo)
disassembly=subprocess.run([dump,'-d',f'--start-address={lo:#x}',f'--stop-address={hi:#x}',str(kernel)],
                           check=True,capture_output=True,text=True).stdout
assert '<_lmipro_pmgr_run>' in disassembly and '<_lmipro_ufs_handoff_probe>' in disassembly
(a.out/'pmgr-hook-disassembly.txt').write_text(disassembly)
build=tree/'build/sheng-platform-power'
report=json.loads((build/'build-report.json').read_text())
assert report['virtual_entries']==340 and not report['original_executable_modified']
archive=build/'libShengPlatformPower.a'
archive_sha=hashlib.sha256(archive.read_bytes()).hexdigest()
assert archive_sha==report['archive_sha256']
assert archive_sha in (obj/'.native-aes-link-input').read_text()
subprocess.run([sys.executable,str(tree/'scripts/audit-amfi-pmgr-contract.py'),
                '--candidate',str(kernel)],check=True)
shutil.copyfile(tree/'build/amfi-pmgr-contract/report.json',a.out/'final-amfi-pmgr-audit.json')
shutil.copyfile(build/'build-report.json',a.out/'pmgr-archive-proof.json')
shutil.copyfile(kernel,a.out/'kernel-original.macho')
shutil.copyfile(kernel.with_suffix('.json'),a.out/'kernel-prelink.json')
shutil.copyfile(a.work/'.config',a.out/'kernel.config')
proof=dict(unixnu_revision='ee472385743ebd16941ab14892dcb9d02e219d15',
           device_revision=a.device_revision,
           kernel_sha256=hashlib.sha256(data).hexdigest(),kernel_bytes=len(data),
           pmgr_archive_sha256=archive_sha,pmgr_virtual_entries=340,
           pmgr_mode_compiled=1,dt_panic_mode_compiled=1,bsd_hook_verified=True,
           original_amfi_and_pmgr_executables_verified_unchanged=True,
           runtime_mode_default=0,test_runtime_mode=1,
           functional_power_backend=False,lifecycle_pass_observed=False,
           service_publication_observed=False,hardware_test='pending')
(a.out/'kernel-build-proof.json').write_text(json.dumps(proof,indent=2)+'\n')

observer=json.loads((tree/'build/lmipro-ufs-handoff/build-proof.json').read_text())
assert observer['combined_archive_sha256']==archive_sha
assert not observer['hardware_register_writes'] and not observer['storage_commands_submitted']
assert not observer['clock_power_or_smmu_state_changed'] and observer['runtime_default']==0 and observer['test_mode']==1
assert observer['source_sha256']==hashlib.sha256((tree/'kits/lmipro/LmiproUfsHandoff.cpp').read_bytes()).hexdigest()
assert names['_lmipro_ufs_handoff_probe'] and names['_lmipro_ufs_handoff_observation']
shutil.copyfile(tree/'build/lmipro-ufs-handoff/build-proof.json',a.out/'ufs-handoff-build-proof.json')

print(json.dumps(proof,indent=2))
