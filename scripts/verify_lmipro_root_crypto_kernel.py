"""Require exact compiled crypto inputs and retain original root trust refusal."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,struct,subprocess,sys
ap=argparse.ArgumentParser();ap.add_argument('--work',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);ap.add_argument('--device-revision',required=True)
a=ap.parse_args()
subprocess.run([sys.executable,str(Path(__file__).with_name('verify_lmipro_ram_root_kernel.py')),'--work',str(a.work),'--out',str(a.out),'--device-revision',a.device_revision],check=True)
config=(a.work/'.config').read_text();assert 'CONFIG_XNU_VERIFIED_ROOT_PROBE=y' in config
for flag in ['CONFIG_XNU_OWNER_ROOT_AUDIT=y','CONFIG_XNU_OWNER_ROOT_TRUST=y','CONFIG_XNU_NATIVE_VIRTIO_BLOCK=y']:assert flag not in config
tree=a.work/'tree';compiled=tree/'build/verified-root-xnu';policy=Path(os.environ['LMIPRO_ROOT_POLICY_DIR'])
proof=json.loads((compiled/'inputs.json').read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert not proof['boot_root_authenticated'] and not proof['owner_root_trust_enabled']
assert proof['official_probe_source_unmodified'] and proof['host_checks_passed']==7
assert proof['strict_werror']
assert all(value.endswith('/EXPORT_HDRS/libsa') for value in proof['absent_optional_libsa_include_dirs'])
assert proof['archive_sha256']==sha(compiled/'libVerifiedRootProbe.a')
assert proof['archive_sha256'] in (tree/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/.native-aes-link-input').read_text()
assert proof['manifest_sha256']==sha(policy/'manifest.bin')=='8d8836c00d21b290c13b87ce9913d9f93d0cbf3a88d8d156f2511af7f031e229'
assert proof['trusted_key_sha256']==sha(policy/'trusted-key.bin')=='95b218c864db0787a303ec5540c51660e8ed2348f43157ae683f349be2cf5105'
sys.path.insert(0,str(tree/'kits/XnuPrelink'))
from native_prelink import macho,backed_offset,exports
kernel=a.out/'kernel-original.macho';data=kernel.read_bytes();meta=macho(data)
names={n:va for va,values in exports(data,meta).items() for n in values}
for name in ['_native_verified_root_probe','_native_verified_root_status','_native_verified_root_results','_vr_xnu_crypto','_vr_open','_vr_verify_block']:assert name in names,name
def read(name,size):
    at=backed_offset(meta['segments'],names[name],size,len(data));return data[at:at+size]
for name,file in [('_verified_root_manifest','manifest.bin'),('_verified_root_key','trusted-key.bin'),('_verified_root_samples','samples.bin')]:
    blob=(policy/file).read_bytes();assert read(name,len(blob))==blob
assert struct.unpack('<Q',read('_verified_root_manifest_bytes',8))[0]==proof['manifest_bytes']
assert struct.unpack('<4Q',read('_verified_root_sample_indices',32))==tuple(proof['actual_sample_indices'])
assert struct.unpack('<4Q',read('_verified_root_sample_lengths',32))==(4096,)*4
status=names['_native_verified_root_status']
sections=[s for segment in meta['segments'] for s in segment['sections'] if s['va']<=status and status+4<=s['va']+s['size']]
assert len(sections)==1
assert struct.unpack_from('<I',data,sections[0]['command_offset']+64)[0]&0xff==1
assert sections[0]['fileoff']==0, 'Initial status must be in actual Mach-O S_ZEROFILL, initialized to zero by loader'
assert b'LMIPRO ROOT fs=%s crypto=%u\n' in data
source=(tree/'.cache/xnu-work/bsd/kern/bsd_init.c').read_text()
assert 'if (autherr && !owner_authorized)' in source and 'FSIOC_KERNEL_ROOTAUTH' in source
assert 'vfs_statfs(vnode_mount(rootvnode))->f_fstypename' in source
assert 'native_verified_root_results[7], autherr' in source
out_policy=a.out/'root-policy';out_policy.mkdir(exist_ok=True)
for file in ['manifest.bin','trusted-key.bin','manifest.json','verification.json','samples.bin','host-checks.json']:shutil.copyfile(policy/file,out_policy/file)
shutil.copyfile(compiled/'inputs.json',a.out/'root-crypto-inputs.json')
report=json.loads((a.out/'kernel-build-proof.json').read_text())
report.update(root_crypto_probe_compiled=True,root_crypto_archive_sha256=proof['archive_sha256'],
    exact_crypto_policy_embedded=True,root_authentication_refusal_retained=True,
    owner_root_trust_enabled=False,real_xnu_crypto_observed=False,complete_os=False)
(a.out/'kernel-build-proof.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: exact real-crypto inputs and official probe linked; root-authentication refusal and original Apple executables retained')
