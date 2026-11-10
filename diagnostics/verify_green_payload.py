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
assert any(x.startswith('lmipro-ufs-') for x in report['kernel_args'].split())
cfg=(root/'.config').read_text();assert 'CONFIG_XNU_SHENG_PMGR=y' in cfg
# CONFIG_XNU_NATIVE_UFS is a selected board capability; the block driver may publish windows.

subprocess.run(['mcopy','-o','-i',str(volume),'::EFI/UniXNU/Payloads/kernel.macho',str(out/'kernel-probed.macho')],check=True)
patched=(out/'kernel-probed.macho').read_bytes();assert hashlib.sha256(patched).hexdigest()==report['payload_kernel_sha256']
script=Path('unixnu/scripts/patch-xnu-entry-probe.py')
assert sha(script)=='159eb1ea8d6c1da30f26913a281f46e21d940a1ae7886656529907ec3edf96ad'
spec=importlib.util.spec_from_file_location('official_entry',script);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
d=raw.read_bytes();assert len(d)==len(patched);m.load_segments(d);names=m.rebase(raw,d)
word=lambda va:struct.unpack_from('<I',patched,m.file_offset(va))[0]
symbols=m.kernel_symbols(raw)
for required in ['_lmipro_capture_mount_output','_lmipro_mount_output','_lmipro_publish_boot_identity']:
    assert required in symbols.values(), 'Missing recovery implementation: '+required
assert b'MOUNT LOG v1 signal=%d exit=%d bytes=%u' in d
assert b'LMIPRO boot identity publication failed' in d
assert b'Lmipro.SHNGROOT.ImageSet.v1' in d
assert 'CONFIG_XNU_OWNER_CACHE_STARTUP=y' in cfg
assert 'CONFIG_XNU_OWNER_UNION_SYSTEMOS=y' in cfg
assert 'CONFIG_XNU_OWNER_DATA_MOUNT=y' not in cfg
assert 'CONFIG_XNU_NATIVE_RAM_BLOCK=y' in cfg
recovery=dict(mount_output_capture=True,boot_identity_namespace='Lmipro.SHNGROOT.ImageSet.v1',
    raw_kernel_sha256=sha(raw),device_revision=os.environ['DEVICE_REF'],framework_revision=os.environ['UNIXNU_REF'],
    data_enabled=True,hardware_tested=False)
(out/'mount-recovery-proof.json').write_text(json.dumps(recovery,indent=2)+'\n')


observer=json.loads((out/'ufs-handoff-build-proof.json').read_text())
archive=json.loads((out/'pmgr-archive-proof.json').read_text())
assert observer['combined_archive_sha256']==archive['archive_sha256']==pmgr['pmgr_archive_sha256']
assert not observer['hardware_register_writes'] and not observer['storage_commands_submitted'] and not observer['clock_power_or_smmu_state_changed']
pmgr_call,_=m.find_call(d,symbols,'_bsd_init','_lmipro_pmgr_run',1)
observer_call,_=m.find_call(d,symbols,'_bsd_init','_lmipro_ufs_handoff_probe',1)
assert observer_call<pmgr_call
board=tomllib.loads(Path('lmipro/board.toml').read_text())
assert board['payload']['adt']['root_match_volume_uuid']=='04769D26-2CA0-4825-B443-E2E5F88300F2'


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
 fd_sha256=sha(fd),dt_panic_region_enabled=True,fixed_bcm_panic_mapping_removed=True,ufs_handoff_mode=1,hardware_register_writes=False,storage_commands_submitted=False,pmgr_mode_compiled=1,pmgr_runtime_mode=2,pmgr_virtual_entries=340,pmgr_bsd_hook_verified=True,original_amfi_and_pmgr_executables_unchanged=True,functional_power_backend=False,entry_hooks_verified=True,panic_hooks_verified=True,other_kernel_bytes_unchanged=True,
 official_probe_replay_identical=True,reset_delay_seconds=0,timed_reset=False,reset_checkpoint='none; continue normal execution and display actual panic',
 framework_revision=subprocess.check_output(['git','-C','unixnu','rev-parse','HEAD'],text=True).strip(),
 device_revision=subprocess.check_output(['git','-C','lmipro','rev-parse','HEAD'],text=True).strip(),
 firmware_source='identical photo-qualified FD720481eb preserved as a pinned compressed branch input',complete_os_qualified=False,userdata_written=False,hardware_test='pending temporary handset test')
# Inspect the actual linked transport and payload; never infer a mounted Data from a build.
seed=json.loads((out/'data-seed.json').read_text())
assert report['data_ramdisk_sha256']==seed['packed_sha256']
assert not seed['persistent'] and seed['bytes']==33554432
for name in ['_native_ram_block_volume_seed','_native_ram_block_ready','_lmipro_data_status','_lmipro_data_stage']:
    assert name in symbols.values(),name
assert seed['volume_uuid'].encode()+b'\0' in d and bytes.fromhex(seed['sha256']) in d
assert b'LMIPRO Data mount failed' in d
assert (b'LMIPRO writable RAM Data mounted' in d)==('CONFIG_XNU_BOOT_PROGRESS=y' in cfg)
# Verify pure-RAM selection and refusal in the actual linked ARM64 code.
byname={name:va for va,name in symbols.items()}
for name,value in [('mode',0),('read',0),('write',0),('sync',0),('gpt_check',255)]:
    va=byname['_native_ufs_store_'+name]
    assert struct.unpack_from('<2I',d,m.file_offset(va))==(0x52800000|(value<<5),0xd65f03c0),name
assert '_native_ufs_store_open' in byname

for leaf in ['scratch-data.img','kernel.macho.adt']:
    subprocess.run(['mcopy','-o','-i',str(volume),'::EFI/UniXNU/Payloads/'+leaf,str(out/leaf)],check=True)
assert sha(out/'scratch-data.img')==seed['packed_sha256']
assert b'PackedRAMDisk' in (out/'kernel.macho.adt').read_bytes()
bindings=root/'tree/build/ram-block/lmipro-bindings.json'
assert bindings.is_file()
binding_proof=json.loads(bindings.read_text())
assert binding_proof['persistence_mode']==0 and binding_proof['persistence_io_result']==0
assert binding_proof['volatile_provider_sha256']==sha(Path('lmipro/package/LmiproVolatileStore.c'))
shutil.copyfile(bindings,out/'ram-block-bindings.json')
proof.update(volatile_data=True,data_seed=seed,data_mounted_on_handset=False,userdata_reflash_required=False)

assert 'lmipro-data-watch=120' in report['kernel_args'].split()
assert b'LMIPRO DATA CHECKPOINT timeout=%u' in d
assert any('lmiproDataWatchThread' in name for name in symbols.values())
assert struct.unpack_from('<i',d,m.file_offset(byname['_lmipro_data_stage']))[0]==-2
watch_build=json.loads((root/'tree/build/lmipro-ufs-block/build-proof.json').read_text())
watch_header=sha(Path('lmipro/package/LmiproDataWatch.h'))
assert watch_build['data_watch_header_sha256']==watch_header
# Prove that the linked timer does not silently filter successful stage 4.
watch_name=next(name for name in symbols.values() if name.endswith('lmiproDataWatchThreadPvi'))
watch_lo,watch_hi=m.function_range(symbols,watch_name)
def conditional_branch(word):
    return (word & 0xff000010)==0x54000000 or (word & 0x7e000000) in (0x34000000,0x36000000)
watch_words=[struct.unpack_from('<I',d,m.file_offset(va))[0] for va in range(watch_lo,watch_hi,4)]
assert not any(map(conditional_branch,watch_words)), 'A conditional silent-success path remains in the watch thread'
proof['watch_snapshots_success_stage']=True
(out/'data-watch-proof.json').write_text(json.dumps(dict(header_sha256=watch_header,
    kernel_sha256=sha(raw),initial_data_stage=-2,delay_seconds=120,default_off=True,
    actual_watch_thread_linked=True,snapshots_success_stage=True,conditional_free_watch=True,hardware_checkpoint_observed=False),indent=2)+'\n')

# Check the actual post-Data diagnostics and original API calls in this kernel.
for name in ['_lmipro_init_stage','_lmipro_init_error','_lmipro_init_path','_proc_name']:
    assert name in byname,name
sample_name=next(name for name in symbols.values() if 'lmiproSampleProcesses' in name and '.cold' not in name)
sample_call,_=m.find_call(d,symbols,watch_name,sample_name,1)
proc_name_call,_=m.find_call(d,symbols,sample_name,'_proc_name',1)
exec_spec=importlib.util.spec_from_file_location('exec_forwarding',Path(__file__).with_name('exec-forwarding-check.py'))
exec_check=importlib.util.module_from_spec(exec_spec);exec_spec.loader.exec_module(exec_check)
exec_path=exec_check.audit_exec_path(d,symbols,m)
exec_call=int(exec_path['actual_original_execve_call'],16)
assert b'initStage=%d execError=%d path=%s' in d and b'process sample pid<=64:' in d
patch=Path('lmipro/patches/xnu/lmipro-userspace-checkpoint.patch')
shutil.copyfile(patch,out/'rendered-lmipro-userspace-checkpoint.patch')
userproof=dict(kernel_sha256=sha(raw),patch_sha256=sha(patch),watch_header_sha256=watch_header,
    actual_original_execve_call=hex(exec_call),actual_timer_sample_call=hex(sample_call),
    actual_proc_name_call=hex(proc_name_call),pid_sample_upper_bound=64,
    original_execve_result_preserved=True,hardware_observed=False)
userproof.update(exec_path)
(out/'userspace-checkpoint-proof.json').write_text(json.dumps(userproof,indent=2)+'\n')
proof['post_data_userspace_diagnostic']=True
# Actual PID1 trace callbacks and two explicit final-mode compile records.
trace_header=Path('lmipro/package/LmiproUserTrace.h')
assert watch_build['user_trace_header_sha256']==sha(trace_header)
assert '_lmipro_user_trace_event' in byname and b'PID1 svcIn=%llu' in d
trace_sites={}
for owner in ['_sleh_synchronous','_unix_syscall_return']:
    site,_=m.find_call(d,symbols,owner,'_lmipro_user_trace_event',1)
    trace_sites[owner]=hex(site)
pid_site,_=m.find_call(d,symbols,'_lmipro_user_trace_event','_proc_selfpid',1)
formatter=next(name for name in symbols.values() if 'lmiproFormatUserTrace' in name and '.cold' not in name)
format_site,_=m.find_call(d,symbols,watch_name,formatter,1)
records={}
for area,stem in [('osfmk','sleh'),('bsd','systemcalls')]:
    p=root/f'tree/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/{area}/DEVELOPMENT/{stem}.o.json'
    rec=json.loads(p.read_text().strip().rstrip(','));args=rec['arguments']
    assert any(a=='-DLMIPRO_USER_TRACE=1' or (a=='LMIPRO_USER_TRACE=1' and i and args[i-1]=='-D') for i,a in enumerate(args))
    s=Path(rec['file']).read_bytes();assert b'LMIPRO_USER_EVENT' in s
    records[stem]=dict(compile_record=rec,source_sha256=hashlib.sha256(s).hexdigest(),per_file_flag1_verified=True)
flags=json.loads(Path('unixnu/build/lmipro-user-trace-flags.json').read_text())
assert flags['reference_mode']==0 and flags['final_mode']==1 and flags['uses_existing_mode_stamp']
trace_patch=Path('lmipro/patches/xnu/lmipro-pid1-trace.patch')
shutil.copyfile(trace_patch,out/'rendered-lmipro-pid1-trace.patch')
traceproof=dict(kernel_sha256=sha(raw),trace_header_sha256=sha(trace_header),trace_patch_sha256=sha(trace_patch),
    callback_sites=trace_sites,actual_proc_selfpid_call=hex(pid_site),actual_timer_formatter_call=hex(format_site),
    compile_records=records,build_flags_adaptation=flags,default_runtime_off=True,pid_filter=1,
    preserves_original_dispatch_and_return_registers=True,hardware_observed=False)
(out/'pid1-trace-proof.json').write_text(json.dumps(traceproof,indent=2)+'\n')
proof['pid1_runtime_trace_verified']=True
(out/'verification.json').write_text(json.dumps(proof,indent=2)+'\n')
(out/'SHA256SUMS').write_text(''.join(sha(out/f)+'  '+f+'\n' for f in ['boot.img','kernel-original.macho','kernel-probed.macho','SILICIUM_UEFI.fd']))
print(json.dumps(proof,indent=2))
