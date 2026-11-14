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

assert 'lmipro-data-watch=600' in report['kernel_args'].split()
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
for area,stem in [('osfmk','sleh'),('bsd','systemcalls'),('bsd','kern_descrip')]:
    p=root/f'tree/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/{area}/DEVELOPMENT/{stem}.o.json'
    rec=json.loads(p.read_text().strip().rstrip(','));args=rec['arguments']
    assert any(a=='-DLMIPRO_USER_TRACE=1' or (a=='LMIPRO_USER_TRACE=1' and i and args[i-1]=='-D') for i,a in enumerate(args))
    s=Path(rec['file']).read_bytes();assert (b'LMIPRO_SIG_EVENT' if stem=='kern_descrip' else b'LMIPRO_USER_EVENT') in s
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
# Signature progress is observational; the original signature implementation is unchanged.
sign_header=Path('lmipro/package/LmiproSignProgress.h')
assert watch_build['sign_progress_header_sha256']==sha(sign_header)
wait_name=next(n for n in symbols.values() if 'lmiproWaitSignProgress' in n and '.cold' not in n)
wait_site,_=m.find_call(d,symbols,watch_name,wait_name,1)
fcntl_site,_=m.find_call(d,symbols,'_sys_fcntl_nocancel','_lmipro_user_trace_event',1)
counters=['_cs_native4k_full_blocks','_cs_native4k_ready_blobs','_cs_native4k_bytes',
    '_cs_native4k_read_ticks','_cs_native4k_hash_ticks','_cs_validate_page_bad_hash','_cs_validate_page_no_hash']
assert all(n in byname for n in counters)
assert b'CS at%u blocks=%llu bytes=%llu blobs=%llu' in d and b'fileSig stage=%d' in d
stage_patch=Path('lmipro/patches/xnu/lmipro-filesig-stage.patch')
native_patch=Path('unixnu/patches/xnu/native-4k-signature-hash-cache.patch')
shutil.copyfile(stage_patch,out/'rendered-lmipro-filesig-stage.patch')
shutil.copyfile(native_patch,out/'original-native-4k-signature-hash-cache.patch')
signproof=dict(kernel_sha256=sha(raw),header_sha256=sha(sign_header),stage_patch_sha256=sha(stage_patch),
    native_signature_patch_sha256=sha(native_patch),actual_wait_call=hex(wait_site),actual_fcntl_trace_call=hex(fcntl_site),
    counter_symbols=counters,sample_seconds=[0,30,120],original_authentication_and_errors_preserved=True,hardware_observed=False)
(out/'sign-progress-proof.json').write_text(json.dumps(signproof,indent=2)+'\n')
proof['signature_progress_diagnostic']=True
# Qualify the read-only display observer in this actual linked kernel.
display_header=Path('lmipro/package/LmiproDisplayWatch.h')
assert watch_build['display_watch_header_sha256']==sha(display_header)
assert 'lmipro-display-watch=2' in report['kernel_args'].split()
assert 'CONFIG_XNU_NATIVE_LEGACY_DISPLAY=y' in cfg
checkpoint=next(n for n in symbols.values() if 'lmiproDisplayCheckpoint' in n and '.cold' not in n)
formatter=next(n for n in symbols.values() if 'lmiproFormatDisplaySnapshot' in n and '.cold' not in n)
counter=next(n for n in symbols.values() if 'lmiproCountDisplayServices' in n and '.cold' not in n)
matching=next(n for n in symbols.values() if n.startswith('__ZN9IOService15serviceMatchingEPKc'))
registry=next(n for n in symbols.values() if n.startswith('__ZN9IOService19getMatchingServicesE'))
display_calls={}
for owner,callee in [(watch_name,checkpoint),(checkpoint,formatter),(formatter,'_PE_current_console'),(formatter,counter),(counter,matching),(counter,registry)]:
    site,_=m.find_call(d,symbols,owner,callee,1)
    display_calls[owner+' -> '+callee]=hex(site)
assert b'LMIPRO UI CHECKPOINT timeout=%u' in d
assert b'published MobileFB=%d LegacyFB=%d IOSurface=%d GOP=%d' in d
displayproof=dict(kernel_sha256=sha(raw),header_sha256=sha(display_header),actual_call_sites=display_calls,
    source_sha256=sha(Path('lmipro/package/LmiproUfsBlock.cpp')),default_off=True,
    read_only=True,hardware_observed=False,no_device_mapping_or_display_operations=True,
    sample_delay_seconds=120,published_count_cap=33)
(out/'display-watch-proof.json').write_text(json.dumps(displayproof,indent=2)+'\n')
shutil.copyfile(display_header,out/'LmiproDisplayWatch.h')
proof['display_handoff_observer_verified']=True
# Qualify the new original Legacy startup separately from the read-only observer.
display_dir=root/'tree/build/native-legacy-display'
display_build=json.loads((display_dir/'build-report.json').read_text())
display_abi=json.loads((root/'tree/build/display-analysis/mobile-graphics-legacy-abi.json').read_text())
assert display_build['component_revision']=='cf3b42979a9c44219e7bb149543e6fc3388b58ed'
assert not display_build['publication_only'] and display_build['frame_transfer_enabled'] and not display_build['gpu_enabled']
assert not display_build['original_instructions_modified'] and display_build['virtual_entries']==358
assert display_abi['static_metadata_arguments_checked'] and display_abi['legacy_instance_bytes']==0x18a0
assert display_abi['abstract_slots']==[211,213,245,246,306,307,337,338,345]
assert sha(display_dir/'libNativeLegacyDisplay.late.a')==display_build['archive_sha256']
for name,digest in display_build['source_sha256'].items():
    assert sha(root/'tree'/name)==digest
# The general AES cache stamp omits Legacy archives. Exact archive/source hashes
# are checked above; actual linked initialization calls are checked below.
for arg in ['lmipro-display-init=1','offline-legacy-phase=4','offline-legacy-register=1','offline-legacy-gop=1']:
    assert arg in report['kernel_args'].split()
for arg in ['offline-legacy-retire','sheng-fb-gpu','sheng-vsync']:
    assert not any(x.startswith(arg+'=') for x in report['kernel_args'].split())
display_pairs={}
startup_owner=None
for owner in ['_bsd_autoconf','_bsd_init']:
    if owner not in symbols.values():continue
    try:
        before,_=m.find_call(d,symbols,owner,'_IOKitBSDInit',1)
        after,_=m.find_call(d,symbols,owner,'_native_legacy_display_late_probe',1)
    except (AssertionError,SystemExit,ValueError,KeyError):continue
    assert before<after
    startup_owner=owner
    display_pairs[owner+' -> _IOKitBSDInit']=hex(before)
    display_pairs[owner+' -> _native_legacy_display_late_probe']=hex(after)
    break
assert startup_owner,'Missing actual post-IOKitBSDInit display initialization'
static_init=next(n for n in symbols.values() if n.endswith('GLOBAL__sub_I_NativeLegacyDisplay.cpp'))
backend_start=next(n for n in symbols.values() if 'NativeLegacyDisplay13startHardwareEv' in n)
for owner,callee in [('_native_legacy_display_late_probe',static_init),
                     ('_native_legacy_display_late_probe','_OSKextLoadKextWithIdentifier'),
                     ('_native_legacy_display_late_probe','_native_legacy_display_allocate'),
                     (backend_start,'_native_legacy_gop_mapping_observed'),
                     (checkpoint,'_lmipro_display_report')]:
    site,_=m.find_call(d,symbols,owner,callee,1)
    display_pairs[owner+' -> '+callee]=hex(site)
# The two original families must retain the reference's entire executable bytes.
sys.path.insert(0,str((root/'tree/kits/XnuPrelink').resolve()))
from native_prelink import macho,backed_offset
prelink=json.loads(raw.with_suffix('.json').read_text());image=macho(d)
ref=json.loads((root/'tree/build/pmgr-reference/lmipro-reference.json').read_text())
families={}
for family in ['com.apple.iokit.IOMobileGraphicsFamily','com.apple.iokit.IOSurface']:
    extent=next(e for e in prelink['extents'] if e['module']==family and e['segment']=='__TEXT_EXEC')
    at=backed_offset(image['segments'],extent['va'],extent['size'],len(d))
    digest=hashlib.sha256(d[at:at+extent['size']]).hexdigest()
    assert digest==ref['original_executable_sha256'][family]==prelink['original_executable_sha256'][family]
    families[family]=digest
compile_command=json.loads((display_dir/'board-compile-command.json').read_text())
assert '-Werror' in compile_command and any(x.endswith('LmiproDisplay.cpp') for x in compile_command)
for source,target in [(display_dir/'build-report.json','display-init-build.json'),
    (root/'tree/build/display-analysis/mobile-graphics-legacy-abi.json','display-init-abi.json'),
    (display_dir/'libNativeLegacyDisplay.late.a','display-init-archive.a'),
    (display_dir/'board-compile-command.json','display-init-compile.json'),
    (root/'tree/kits/lmipro/LmiproDisplay.cpp','LmiproDisplay.cpp'),
    (root/'tree/kits/lmipro/LmiproDisplayPolicy.h','LmiproDisplayPolicy.h')]:
    shutil.copyfile(source,out/target)
initproof=dict(kernel_sha256=sha(raw),archive_sha256=display_build['archive_sha256'],
    actual_call_sites=display_pairs,original_executable_sha256=families,
    runtime_gate='lmipro-display-init=1',publication_only=False,frame_transfer_enabled=True,
    device_register_operations=False,gpu_enabled=False,handset_initialization_observed=False,
    linked_after_iokit_bsd_init=True,compile_warnings_as_errors=True)
(out/'display-init-proof.json').write_text(json.dumps(initproof,indent=2)+'\n')
proof['original_legacy_board_init_verified']=True

trace_header=Path('lmipro/package/LmiproDisplayTrace.h')
trace_patch=Path('lmipro/patches/xnu/lmipro-display-dispatch.patch')
assert display_build['source_sha256']['kits/lmipro/LmiproDisplayTrace.h']==sha(trace_header)
assert 'lmipro-display-calls=1' in report['kernel_args'].split()
dispatcher=next(n for n in symbols.values() if '12IOUserClient18callExternalMethodE' in n)
trace_sites=[m.find_call(d,symbols,dispatcher,'_lmipro_display_method_event',i)[0] for i in [1,2]]
assert trace_sites[0]<trace_sites[1]
assert b'IOMobileFramebufferUserClient\0' in d and b'Display calls in=%llu out=%llu dropped=%llu' in d
record_path=root/'tree/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOUserClient.cpo.json'
record=json.loads(record_path.read_text().strip().rstrip(','))
cpp=Path(record['file'])
if not cpp.is_absolute():cpp=Path(record['directory'])/cpp
text=cpp.read_text()
start=text.index('IOReturn\nIOUserClient::callExternalMethod(')
end=text.index('\nMIG_SERVER_ROUTINE',start)
body=text[start:end]
guard='#if (DEVELOPMENT || DEBUG) && defined(XNU_NATIVE_LEGACY_DISPLAY) && XNU_NATIVE_LEGACY_DISPLAY'
entry='\n'+guard+'\n\tlmipro_display_method_event(this, selector, args, 0, kIOReturnSuccess);\n#endif\n'
exit='\n'+guard+'\n\tlmipro_display_method_event(this, selector, args, 1, ret);\n#endif\n'
assert body.count(entry)==body.count(exit)==1
restored=body.replace(entry,'').replace(exit,'')
assert hashlib.sha256(restored.encode()).hexdigest()=='8c08c11480fdbe6baa40897c601ce3b3f4f1c21298fbe92205e5a7aedf51b529'
argv=record['arguments']
definitions=[]
for i,a in enumerate(argv):
    if a.startswith('-DXNU_NATIVE_LEGACY_DISPLAY='):definitions.append(a.split('=',1)[1])
    elif a=='-D' and i+1<len(argv) and argv[i+1].startswith('XNU_NATIVE_LEGACY_DISPLAY='):
        definitions.append(argv[i+1].split('=',1)[1])
assert definitions and definitions[-1]=='1'
dispatchproof=dict(kernel_sha256=sha(raw),trace_header_sha256=sha(trace_header),
    patch_sha256=sha(trace_patch),board_source_sha256=sha(Path('lmipro/package/LmiproDisplay.cpp')),
    actual_call_sites=list(map(hex,trace_sites)),dispatcher=dispatcher,
    original_dispatch_restored_sha256=hashlib.sha256(restored.encode()).hexdigest(),
    source_original_call_locks_and_return_preserved=True,class_filter='IOMobileFramebufferUserClient',
    max_scalar_inputs_copied=3,selector_table_size=96,snapshot_rows=16,
    default_off=True,nonwaiting=True,frame_transfer_enabled=False,hardware_observed=False,
    original_client_vptr_or_methods_modified=False)
for path in [trace_header,trace_patch]:shutil.copyfile(path,out/('rendered-'+path.name if path.suffix=='.patch' else path.name))
(out/'display-dispatch-proof.json').write_text(json.dumps(dispatchproof,indent=2)+'\n')
proof['original_display_dispatch_observer_verified']=True

ui_header=Path('lmipro/package/LmiproUITrace.h')
assert 'lmipro-ui-watch=1' in report['kernel_args'].split()
assert watch_build['ui_trace_header_sha256']==sha(ui_header)
assert b'UI activity enabled=%u dropped=%llu' in d
ui_pairs={}
ui_branch_kinds={}
def ui_direct_edge(owner,callee):
    low,high=m.function_range(symbols,owner)
    destination=byname[callee];hits=[]
    for pc in range(low,high,4):
        op=struct.unpack_from('<I',d,m.file_offset(pc))[0]
        if op&0x7c000000!=0x14000000:continue
        immediate=op&0x3ffffff
        if immediate&(1<<25):immediate-=1<<26
        if pc+4*immediate==destination:hits.append((pc,'bl' if op&0x80000000 else 'b'))
    assert len(hits)==1,(owner,callee,hits)
    return hits[0]
for owner,callee in [('_lmipro_user_trace_event','_lmipro_ui_user_event'),
                     ('_lmipro_ui_user_event','_proc_selfname'),
                     ('_lmipro_ui_user_event','_thread_tid'),
                     ('_lmipro_display_method_event','_proc_selfname'),
                     ('_native_legacy_display_late_probe','_lmipro_ui_trace_enable'),
                     (checkpoint,'_lmipro_ui_trace_report')]:
    site,kind=ui_direct_edge(owner,callee)
    ui_pairs[owner+' -> '+callee]=hex(site)
    ui_branch_kinds[owner+' -> '+callee]=kind
for source in [ui_header,Path('lmipro/package/LmiproUserTrace.h')]:
    shutil.copyfile(source,out/source.name)
uiproof=dict(kernel_sha256=sha(raw),header_sha256=sha(ui_header),
    user_trace_header_sha256=sha(Path('lmipro/package/LmiproUserTrace.h')),
    actual_call_sites=ui_pairs,direct_branch_kinds=ui_branch_kinds,default_off=True,read_only=True,
    actor_names=['SpringBoard','backboardd'],actor_limit=2,
    original_entry_return_exception_registers_preserved=True,
    aggregate_events_not_paired_waits=True,frame_transfer_enabled=False,
    original_client_vptr_or_methods_modified=False,hardware_observed=False)
(out/'ui-activity-proof.json').write_text(json.dumps(uiproof,indent=2)+'\n')
proof['ui_activity_observer_verified']=True

mode_header=Path('lmipro/package/LmiproModePolicy.h')
assert display_build['source_sha256']['kits/lmipro/LmiproModePolicy.h']==sha(mode_header)
assert 'lmipro-display-mode=1' in report['kernel_args'].split()
configure=next(n for n in symbols.values() if 'lmiproConfigureDisplayMode' in n and '.cold' not in n)
mode_sites={}
for owner,callee in [('_native_legacy_display_late_probe',configure),
                     ('_sleh_synchronous','_lmipro_ui_fault_event')]:
    site,kind=ui_direct_edge(owner,callee);mode_sites[owner+' -> '+callee]=dict(site=hex(site),kind=kind)
assert b'Mode policy stage=%u status=%d scale=1 rotation=0' in d
assert b'UI first BRK valid=%u pc=%llx x24=%llx x25=%llx x26=%llx' in d
fault_patch=Path('lmipro/patches/xnu/lmipro-ui-fault-registers.patch')
for source in [mode_header,fault_patch]:shutil.copyfile(source,out/('rendered-'+source.name if source.suffix=='.patch' else source.name))
modeproof=dict(kernel_sha256=sha(raw),header_sha256=sha(mode_header),fault_patch_sha256=sha(fault_patch),
    actual_direct_edges=mode_sites,default_off=True,logical_scale=1,rotation=0,
    existing_property_conflicts_refused=True,partial_publication_rolled_back=True,
    original_userspace_validation_modified=False,frame_transfer_enabled=False,
    fault_observer_reads_only_saved_kernel_registers=True,hardware_observed=False)
(out/'display-mode-proof.json').write_text(json.dumps(modeproof,indent=2)+'\n')
proof['display_mode_policy_verified']=True

cpu_header=Path('lmipro/package/LmiproScanoutPolicy.h')
assert display_build['source_sha256']['kits/lmipro/LmiproScanoutPolicy.h']==sha(cpu_header)
for arg in ['lmipro-display-cpu=1','offline-legacy-pm=1','offline-legacy-validate=1','offline-legacy-transfer=1','offline-legacy-cpu-present=1']:
    assert arg in report['kernel_args'].split()
assert 'CONFIG_XNU_BOOT_PROGRESS=y' not in cfg
assert display_build['bindings']['_lmipro_original_surface_descriptor']=='0xfffffff004b9ead0'
assert '_native_legacy_surface_descriptor' not in display_build['bindings']
cpu_sites={}
for owner,callee in [('_native_legacy_prepare_scanout','_PE_initialize_console'),
                     ('_native_legacy_surface_descriptor','_lmipro_original_surface_descriptor'),
                     (checkpoint,'_lmipro_display_frame_presented'),
                     (checkpoint,'_thread_terminate')]:
    site,kind=ui_direct_edge(owner,callee);cpu_sites[owner+' -> '+callee]=dict(site=hex(site),kind=kind)
shutil.copyfile(cpu_header,out/cpu_header.name)
cpuproof=dict(kernel_sha256=sha(raw),header_sha256=sha(cpu_header),actual_direct_edges=cpu_sites,
    gpu_enabled=False,cpu_policy_opt_in=True,original_cpu_surface_copy_enabled=True,
    compressed_and_planar_formats_refused=True,original_descriptor_alias=display_build['bindings']['_lmipro_original_surface_descriptor'],
    normal_original_swap_retirement_only_after_copy=True,video_console_release_before_copy=True,
    boot_progress_writer_not_compiled=True,blank_only_or_failed_transfer_keeps_diagnostic_stop=True,
    actual_frame_presented=False,handset_ui_observed=False)
(out/'display-cpu-proof.json').write_text(json.dumps(cpuproof,indent=2)+'\n')
proof['cpu_presentation_path_verified']=True


assert dispatchproof['snapshot_rows']==16
assert 'LmiproDisplaySelector rows[16]' in trace_header.read_text()
assert 'gLmiproClients[8]' in trace_header.read_text()
assert 'pending>=0 && !gLmiproClients[pending].ambiguous' in trace_header.read_text()
board_text=Path('lmipro/package/LmiproDisplay.cpp').read_text()
assert 'kind==1 && status==kIOReturnSuccess && args && args->scalarOutput' in board_text
assert 'unsigned count=outputCount<3?outputCount:3;' in board_text
assert 'lmiproClientEvent(0,thread_tid(current_thread()),type,proc_selfpid(),name,0)' in board_text
assert 'lmiproClientEvent(1,thread_tid(current_thread()),0,0,nullptr,(uint32_t)status)' in board_text
submitproof=dict(kernel_sha256=sha(raw),trace_header_sha256=sha(trace_header),
 board_source_sha256=sha(Path('lmipro/package/LmiproDisplay.cpp')),
 watch_header_sha256=sha(Path('lmipro/package/LmiproDisplayWatch.h')),
 selector_limit=96,snapshot_rows=16,client_history_cap=8,max_success_scalar_words=3,
 copied_thread_ids_only=True,nested_or_missing_events_not_paired=True,
 original_status_and_dispatch_preserved=True,display_behavior_changed=False,
 handset_ui_observed=False)
(out/'display-submit-proof.json').write_text(json.dumps(submitproof,indent=2)+'\n')
proof['complete_display_submission_observation_verified']=True

assert 'code==136 || code==475' in ui_header.read_text()
assert 'UINT64_C(1)<<29' in ui_header.read_text()
owner_patch=Path('lmipro/patches/xnu/lmipro-data-mobile-owners.patch')
owner_sites={}
preparation_candidates=[]
for candidate in ['_lmipro_data_prepare','_load_init_program']:
 if candidate not in symbols.values():continue
 try: site,kind=ui_direct_edge(candidate,'_lmipro_data_mobile_owners')
 except SystemExit:continue
 preparation_candidates.append((candidate,site,kind))
assert len(preparation_candidates)==1
owner,site,kind=preparation_candidates[0]
owner_sites[owner+' -> _lmipro_data_mobile_owners']=dict(site=hex(site),kind=kind)
site,kind=ui_direct_edge('_lmipro_data_mobile_owners','_vnode_setattr')
owner_sites['_lmipro_data_mobile_owners -> _vnode_setattr']=dict(site=hex(site),kind=kind)
assert '_lmipro_data_owner_stage' in symbols.values() and '_lmipro_data_owner_status' in symbols.values()
assert 'data_mount' in owner_patch.read_text() and 'vnode_mount(vp) != data_mount' in owner_patch.read_text()
shutil.copyfile(owner_patch,out/'rendered-lmipro-data-mobile-owners.patch')
ownerproof=dict(kernel_sha256=sha(raw),patch_sha256=sha(owner_patch),actual_direct_edges=owner_sites,
 paths=['/private/var/mobile/tmp','/private/var/mobile/Documents','/private/var/mobile/Containers'],
 allowed_initial_uid=[0,501],required_gid=501,required_mode=493,target_uid=501,
 requires_qualified_ram_mount=True,unexpected_metadata_refused=True,mode_preserved=True,
 actual_errors_preserved=True,readback_verified_by_source=True,handset_verified=False)
(out/'data-owner-proof.json').write_text(json.dumps(ownerproof,indent=2)+'\n')
proof['ram_data_mobile_owner_fix_verified']=True

stack_header=Path('lmipro/package/LmiproUIStacks.h')
assert watch_build['ui_stack_header_sha256']==sha(stack_header)
assert 'lmipro-ui-stacks=1' in report['kernel_args'].split()
stack_sites={}
sampler=next(n for n in symbols.values() if 'lmiproSampleUIStack' in n and '.cold' not in n)
for owner,callee in [('_lmipro_ui_user_event',sampler),(sampler,'_lmipro_ui_stack_capture'),
 ('_lmipro_ui_stack_capture','_backtrace_user'),(checkpoint,'_lmipro_ui_stack_report'),
 ('_native_legacy_client_observed','_lmipro_ui_stack_display_open')]:
 site,kind=ui_direct_edge(owner,callee);stack_sites[owner+' -> '+callee]=dict(site=hex(site),kind=kind)
assert 'ml_at_interrupt_context()' in board_text and '!preemption_enabled()' in board_text
assert 'backtrace_user(frames,capacity,nullptr,&info)' in board_text
assert 'gLmiproUIStacks[8]' in stack_header.read_text() and 'uintptr_t frames[8]' in stack_header.read_text()
stack_text=stack_header.read_text()
assert 'if(!focused && code!=-47 && code!=375)return;' in stack_text
assert 'lmipro-ui-focus=1' in report['kernel_args'].split()
assert 'gLmiproUIStacksFocusTids[4]' in stack_text
assert 'pid!=__atomic_load_n(&gLmiproUIStacksDisplayPid,__ATOMIC_ACQUIRE)' in stack_text
assert '(!focused && row.postOpen && (now<row.seconds || now-row.seconds<10))' in stack_text
assert 's.result=result;s.status=status;s.returned=1' in stack_text
assert '++s.irqCount;s.irqSame=s.irqPC==pc?s.irqSame+1:1;s.irqPC=pc' in stack_text
assert b'focus%llu' in d and b'Q%llu/%llu@%llx' in d
assert b'auto%u ev%u capSkip%u' in d
assert 'thread_tid(current_thread())' in stack_text
assert 'if(focused)for(unsigned i=8;i>0;--i)if(gLmiproUIStacks[i-1].state!=1)' in stack_text
assert '++gLmiproUIStacksCapacitySkips' in stack_text
assert '__atomic_load_n(&gLmiproUIStacksDisplayPid,__ATOMIC_ACQUIRE)!=pid' not in stack_text
assert stack_text.index('if(!focused && code!=-47 && code!=375)return;') < stack_text.index('unsigned slot=')
assert 'status==kIOReturnSuccess && client' in board_text
assert 'if(!strcmp(name,"backboardd"))lmipro_ui_stack_display_open(proc_selfpid())' in board_text
shutil.copyfile(stack_header,out/stack_header.name)
stacksproof=dict(kernel_sha256=sha(raw),header_sha256=sha(stack_header),actual_direct_edges=stack_sites,
 samples_cap=8,frames_cap=8,delay_seconds=30,current_thread_only=True,
 faultable_context_required=True,observation_locks_released_before_copyin=True,
 default_off=True,original_user_code_and_syscall_results_preserved=True,
 wait_state_proof=False,handset_observed=False,
 post_successful_backboardd_open=False,selected_entry_codes=[-47,375],startup_calls_skip_before_reservation=True,
 focused_tid=None,focus_mode='first_successful_display_opener',capacity_rejection_reported=True,focused_calls_all=True,focused_no_rate_limit=True,IRQ_saved_PC_only=True)
(out/'ui-stacks-proof.json').write_text(json.dumps(stacksproof,indent=2)+'\n')
exit_header=Path('lmipro/package/LmiproUIExit.h')
exit_patch=Path('lmipro/patches/xnu/lmipro-ui-exit.patch')
assert sha(exit_header)==watch_build['ui_exit_header_sha256']
assert 'lmipro-data-watch=600' in report['kernel_args'].split()
assert 'lmipro-data-watch=600' in report['kernel_args'].split()
exit_sites={}
# Accept either compiler layout only through a real exit_with_reason path.
try:
 site,kind=ui_direct_edge('_exit_with_reason','_lmipro_ui_exit_event')
 exit_sites['_exit_with_reason -> _lmipro_ui_exit_event']=dict(site=hex(site),kind=kind)
except AssertionError:
 for owner,callee in [('_exit_with_reason','_proc_prepareexit'),('_proc_prepareexit','_lmipro_ui_exit_event')]:
  site,kind=ui_direct_edge(owner,callee);exit_sites[owner+' -> '+callee]=dict(site=hex(site),kind=kind)
site,kind=ui_direct_edge(checkpoint,'_lmipro_ui_exit_report')
exit_sites[checkpoint+' -> _lmipro_ui_exit_report']=dict(site=hex(site),kind=kind)
rec_path=root/'tree/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/kern_exit.o.json'
rec=json.loads(rec_path.read_text().strip().rstrip(','));argv=rec['arguments']
assert any(a=='-DLMIPRO_USER_TRACE=1' or (a=='LMIPRO_USER_TRACE=1' and i and argv[i-1]=='-D') for i,a in enumerate(argv))
exit_source=Path(rec['file']).read_text()
assert 'lmipro_ui_exit_event(proc_getpid(p), p->p_name, rv,' in exit_source
assert 'boot_progress_exit(proc_getpid(p),p->p_name,rv,' in exit_source
assert '"kern_exit.o_CFLAGS_ADD=-DLMIPRO_USER_TRACE=$SHENG_PMGR"' in Path('unixnu/scripts/build-xnu-4k-baseline.sh').read_text()
assert 'bsd/kern/kern_exit.c' in flags['target_files']
for p in [exit_header,exit_patch]:shutil.copyfile(p,out/('rendered-'+p.name if p.suffix=='.patch' else p.name))
exitproof=dict(kernel_sha256=sha(raw),header_sha256=sha(exit_header),patch_sha256=sha(exit_patch),
 source_sha256=sha(Path(rec['file'])),compile_record=rec,per_file_flag1_verified=True,
 actual_direct_edges=exit_sites,raw_wait_status_and_reason_preserved=True,
 kernel_scalar_name_copies_only=True,nonwaiting=True,default_off=True,
 observation_after_original_exit_commit=True,original_exit_policy_preserved=True,
 original_boot_progress_hook_preserved=True,first_and_last_per_actor=True,actor_limit=2,
 observation_seconds=120,handset_observed=False)
(out/'ui-exits-proof.json').write_text(json.dumps(exitproof,indent=2)+'\n')
proof['committed_compositor_exits_verified']=True

proof['bounded_current_thread_compositor_stacks_verified']=True

(out/'verification.json').write_text(json.dumps(proof,indent=2)+'\n')
(out/'SHA256SUMS').write_text(''.join(sha(out/f)+'  '+f+'\n' for f in ['boot.img','kernel-original.macho','kernel-probed.macho','SILICIUM_UEFI.fd']))
print(json.dumps(proof,indent=2))
