from pathlib import Path
import hashlib,importlib.util,json,os,shutil,struct,subprocess,tomllib,zlib
root=Path('unixnu/out/lmipro/ipados-17.7.11-21H461/lmipro');out=Path('output');out.mkdir(exist_ok=True)
raw=root/'kernel/kernel.macho';volume=root/'payload/payload.img';report=json.loads((root/'payload/payload.json').read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert report['panic_screen'] is True and report['kernel_sha256']==sha(raw)
assert report['payload_kernel_sha256']!=sha(raw)

pmgr=json.loads((out/'kernel-build-proof.json').read_text())
assert pmgr['kernel_sha256']==sha(raw) and pmgr['bsd_hook_verified']
assert pmgr['pmgr_mode_compiled']==pmgr['dt_panic_mode_compiled']==1 and pmgr['pmgr_virtual_entries']==340
assert pmgr['original_amfi_and_pmgr_executables_verified_unchanged']
assert report['kernel_args']=='-v serial=3 boot-progress=2 sheng-pmgr=2'
cfg=(root/'.config').read_text();assert 'CONFIG_XNU_SHENG_PMGR=y' in cfg
assert 'CONFIG_XNU_NATIVE_UFS=y' not in cfg

subprocess.run(['mcopy','-o','-i',str(volume),'::EFI/UniXNU/Payloads/kernel.macho',str(out/'kernel-probed.macho')],check=True)
patched=(out/'kernel-probed.macho').read_bytes();assert hashlib.sha256(patched).hexdigest()==report['payload_kernel_sha256']
script=Path('unixnu/scripts/patch-xnu-entry-probe.py')
assert sha(script)=='159eb1ea8d6c1da30f26913a281f46e21d940a1ae7886656529907ec3edf96ad'
spec=importlib.util.spec_from_file_location('official_entry',script);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
d=raw.read_bytes();assert len(d)==len(patched);m.load_segments(d);names=m.rebase(raw,d)
word=lambda va:struct.unpack_from('<I',patched,m.file_offset(va))[0]
symbols=m.kernel_symbols(raw)

import sys
sys.path.insert(0,str(Path('unixnu/scripts').resolve()))
from unixnu.config import parse_config
assert parse_config((root/'.config').read_text())['XNU_DT_PANIC_REGION'] is True
inputs=json.loads((root/'kernel/dt-panic-inputs.json').read_text())
assert inputs['kernel_sha256']==sha(raw)
record=inputs['record']
assert inputs['dt_panic_build_mode']=='1'
text=inputs['source_text']
assert hashlib.sha256(text.encode()).hexdigest()==inputs['source_sha256']
assert '#if defined(PLATFORM_PANIC_LOG_PADDR) && !(defined(XNU_DT_PANIC_REGION) && XNU_DT_PANIC_REGION)' in text
lo,hi=m.function_range(symbols,'_PE_create_console')
body=d[m.file_offset(lo):m.file_offset(hi-4)+4]
assert struct.pack('<2I',0x52980000,0x72a781e0) not in body,'Fixed BCM2837 panic mapping remained'
dtproof=dict(config_enabled=True,build_script_mode_seen=True,per_file_flag_in_compile_record=any(v=='-DXNU_DT_PANIC_REGION=1' or (v=='XNU_DT_PANIC_REGION=1' and i>0 and record['arguments'][i-1]=='-D') for i,v in enumerate(record['arguments'])),official_dt_guard_seen=True,
 actual_console_fixed_panic_mapping_removed=True,source_sha256=inputs['source_sha256'],
 compile_record=record,original_kernel_sha256=sha(raw),hardware_tested=False)
assert dtproof['per_file_flag_in_compile_record']
(out/'dt-panic-compile-proof.json').write_text(json.dumps(dtproof,indent=2)+'\n')

for site,stage in [(m.ENTRY_VA,1),(m.MMU_ENABLE_VA,2)]:assert word(site)==m.branch(site,m.CAVES[stage])
def target(va):
 value=word(va);assert value>>26==0b000101
 n=value&0x3ffffff
 if n&(1<<25):n-=1<<26
 return va+n*4
panic_lo,panic_hi=m.CAVES[2]+m.CAVE_SIZE,m.PANIC_CAVE_END
common=names['_panic_trap_to_debugger']
assert not any(d[m.file_offset(panic_lo):m.file_offset(panic_hi)])
for site in [m.PANIC_VA,common]:assert panic_lo<=target(site)<panic_hi
assert word(m.AFTER_MMU_VA)==struct.unpack_from('<I',d,m.file_offset(m.AFTER_MMU_VA))[0]
normalized=bytearray(patched)
regions=[(m.ENTRY_VA,4),(m.MMU_ENABLE_VA,4),(m.PANIC_VA,4),(common,4),*((m.CAVES[s],m.CAVE_SIZE) for s in (1,2)),(panic_lo,panic_hi-panic_lo)]
for va,size in regions:
 at=m.file_offset(va);normalized[at:at+size]=d[at:at+size]
assert bytes(normalized)==d,'Unexpected executable changes outside the official entry/reset/panic hooks'
# Replay the exact official no-reset invocation and compare the complete kernel.
replay=out/'kernel-replay.macho';shutil.copyfile(raw,replay)
os.environ['UNIXNU_UEFI']=str(Path('uefi').resolve())
subprocess.run(['python3',str(script),str(replay),'--panic-screen','--no-reset'],check=True)
assert replay.read_bytes()==patched
replay.unlink()
for file in ['boot.img']:
 candidate=root/'boot'/file
 assert candidate.is_file(),file
 shutil.copyfile(candidate,out/file)
shutil.copyfile(raw,out/'kernel-original.macho');shutil.copyfile(volume,out/'payload.img')
shutil.copyfile(root/'payload/payload.json',out/'payload.json')
shutil.copyfile('lmipro/board.toml',out/'test-board.toml');shutil.copyfile(root/'.config',out/'kernel.config')
fd=next(Path('artifact').rglob('SILICIUM_UEFI.fd'));shutil.copyfile(fd,out/fd.name)
shutil.copyfile('overlay/DeviceTree/lmi.dtb',out/'firmware.dtb')
for file in ['payload-patch.log','kernel.log']:
 f=root/'logs'/file
 if f.exists():shutil.copyfile(f,out/file)
boot=(out/'boot.img').read_bytes();ksize,kaddr,rd,_,second,_,tags,page,version,_=struct.unpack_from('<10I',boot,8)
assert boot[:8]==b'ANDROID!' and (rd,second,tags,page,version)==(0,0,0x100,4096,1)
z=zlib.decompressobj(31);back=z.decompress(boot[page:page+ksize]);assert z.eof
firmware=fd.read_bytes();shim=back.find(firmware);assert 0<shim<4096
assert back[shim+len(firmware):]==b'XNUP'+struct.pack('<I',volume.stat().st_size)+volume.read_bytes()
assert z.unused_data==Path('overlay/DeviceTree/lmi.dtb').read_bytes()
meta=dict(image_sha256=sha(out/'boot.img'),shim_bytes=shim,firmware_sha256=sha(fd),payload_sha256=sha(volume),header_version=version,page_bytes=page,report_source='parsed actual packed image and round-tripped exact inputs')
(out/'boot.json').write_text(json.dumps(meta,indent=2)+'\n')
proof=dict(boot_sha256=sha(out/'boot.img'),kernel_sha256=sha(raw),payload_kernel_sha256=hashlib.sha256(patched).hexdigest(),
 fd_sha256=sha(fd),dt_panic_region_enabled=True,fixed_bcm_panic_mapping_removed=True,pmgr_mode_compiled=1,pmgr_runtime_mode=2,pmgr_virtual_entries=340,pmgr_bsd_hook_verified=True,original_amfi_and_pmgr_executables_unchanged=True,functional_power_backend=False,entry_hooks_verified=True,panic_hooks_verified=True,other_kernel_bytes_unchanged=True,
 official_probe_replay_identical=True,reset_delay_seconds=0,timed_reset=False,reset_checkpoint='none; continue normal execution and display actual panic',
 framework_revision=subprocess.check_output(['git','-C','unixnu','rev-parse','HEAD'],text=True).strip(),
 device_revision=subprocess.check_output(['git','-C','lmipro','rev-parse','HEAD'],text=True).strip(),
 firmware_source='identical photo-qualified FD720481eb preserved as a pinned compressed branch input',complete_os_qualified=False,userdata_written=False,hardware_test='pending temporary handset test')
(out/'verification.json').write_text(json.dumps(proof,indent=2)+'\n')
(out/'SHA256SUMS').write_text(''.join(sha(out/f)+'  '+f+'\n' for f in ['boot.img','kernel-original.macho','kernel-probed.macho','SILICIUM_UEFI.fd']))
print(json.dumps(proof,indent=2))
