"""Qualify an immutable, already built image; never rebuild or boot a device."""
from pathlib import Path
import argparse, hashlib, importlib.util, json, struct, zipfile, zlib
from pyfatfs.PyFatFS import PyFatFS

p=argparse.ArgumentParser()
p.add_argument('archive',type=Path);p.add_argument('manifest',type=Path)
p.add_argument('entry_script',type=Path);p.add_argument('output',type=Path)
a=p.parse_args();expected=json.loads(a.manifest.read_text());out=a.output;out.mkdir(parents=True,exist_ok=True)
sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(a.archive.read_bytes())==expected['artifact_sha256']
assert sha(a.entry_script.read_bytes())=='159eb1ea8d6c1da30f26913a281f46e21d940a1ae7886656529907ec3edf96ad'
with zipfile.ZipFile(a.archive) as z:
    for name in z.namelist():
        if name.startswith('output/') and not name.endswith('/'):
            (out/Path(name).name).write_bytes(z.read(name))
    binding_name=next((n for n in z.namelist() if n.endswith('/ram-block/lmipro-bindings.json')), 'output/ram-block-bindings.json')
    bindings=json.loads(z.read(binding_name))
    provider_name=next((n for n in z.namelist() if n.endswith('/ram-block/LmiproVolatileStore.o')), 'output/LmiproVolatileStore.o')
    assert sha(z.read(provider_name))==bindings['volatile_provider_object_sha256']
(out/'ram-block-bindings.json').write_text(json.dumps(bindings,indent=2)+'\n')
readj=lambda n:json.loads((out/n).read_text())
payload=readj('payload.json');bootproof=readj('boot.json');identity=readj('mount-recovery-proof.json')
raw=(out/'kernel-original.macho').read_bytes();boot=(out/'boot.img').read_bytes();cfg=(out/'kernel.config').read_text()
assert sha(boot)==expected['boot_sha256']==bootproof['image_sha256']
assert sha(raw)==payload['kernel_sha256']==identity['raw_kernel_sha256']
assert identity['device_revision']==expected['device_commit'] and identity['framework_revision']==expected['framework_commit']
assert identity['mount_output_capture'] and identity['data_enabled']
for key in ['OWNER_CACHE_MOUNT','OWNER_CACHE_STARTUP','OWNER_UNION_SYSTEMOS','NATIVE_RAM_BLOCK']:
    assert 'CONFIG_XNU_'+key+'=y' in cfg,key
for key in ['OWNER_DATA_MOUNT','OWNER_BOOT_MANIFEST']:
    assert 'CONFIG_XNU_'+key+'=y' not in cfg,key
assert raw[:4]==bytes.fromhex('cffaedfe')
cursor=32;segments=[]
for _ in range(struct.unpack_from('<I',raw,16)[0]):
    cmd,size=struct.unpack_from('<II',raw,cursor)
    if cmd==25:
        va,vs,fo,fs=struct.unpack_from('<4Q',raw,cursor+24);segments.append((va,fo,fs))
    if cmd==2:so,n,st,ss=struct.unpack_from('<4I',raw,cursor+8)
    cursor+=size
symbols={}
for i in range(n):
    ix,typ,sec,desc,va=struct.unpack_from('<IBBHQ',raw,so+16*i)
    if not ix or ix>=ss or typ&0xe0:continue
    name=raw[st+ix:raw.find(b'\0',st+ix)].decode(errors='replace')
    symbols[name]=(va,typ,desc)
def off(address):
    va,fo,fs=next(s for s in segments if s[0]<=address<s[0]+s[2]);return fo+address-va
def calls(name,target):
    lo=symbols[name][0];hi=min(v[0] for v in symbols.values() if v[0]>lo);hits=[]
    for at in range(lo,hi,4):
        word=struct.unpack_from('<I',raw,off(at))[0]
        if word>>26!=37:continue
        delta=word&0x3ffffff
        if delta&(1<<25):delta-=1<<26
        if at+delta*4==symbols[target][0]:hits.append(at)
    return hits
va,typ,desc=symbols['_lmipro_publish_boot_identity'];assert typ&14==14 and not desc&128
identity_calls=calls('_load_init_program','_lmipro_publish_boot_identity')
seed_calls=calls('_load_init_program','_native_ram_block_volume_seed')
mount_calls=calls('_load_init_program','_mount')
exec_calls=calls('_load_init_program','_load_init_program_at_path')
assert len(identity_calls)==len(seed_calls)==1
assert any(identity_calls[0]<seed_calls[0]<v<min(exec_calls) for v in mount_calls)
for name in ['_lmipro_capture_mount_output','_lmipro_mount_output','_lmipro_data_status','_lmipro_data_stage','_native_ram_block_ready']:
    assert name in symbols,name
for text in [b'MOUNT LOG v1 signal=%d exit=%d bytes=%u',b'END MOUNT LOG',b'LMIPRO boot identity publication failed',b'Lmipro.SHNGROOT.ImageSet.v1',b'LMIPRO Data mount failed: error=%d stage=%d readonly=%d']:
    assert text in raw,text
progress='CONFIG_XNU_BOOT_PROGRESS=y' in cfg
assert (b'LMIPRO writable RAM Data mounted' in raw)==progress
for name,value in [('mode',0),('read',0),('write',0),('sync',0),('gpt_check',255)]:
    assert struct.unpack_from('<2I',raw,off(symbols['_native_ufs_store_'+name][0]))==(0x52800000|(value<<5),0xd65f03c0),name
assert '_native_ufs_store_open' in symbols
assert bindings['persistence_mode']==bindings['persistence_io_result']==0
assert bindings['volatile_provider_sha256']==expected['volatile_provider_sha256']
for name,value in bindings['bindings'].items():
    assert value==(int(expected['storage_bindings']['addresses'][name],16)+int(expected['storage_bindings']['slide']))&0xffffffffffffffff
    assert symbols[name][0]==value,name
observer=readj('ufs-handoff-build-proof.json');pmgr=readj('kernel-build-proof.json');archive=readj('pmgr-archive-proof.json')
assert observer['auxiliary_readonly_ufs_block']['source_sha256']==expected['ufs_source_sha256']
assert observer['combined_archive_sha256']==archive['archive_sha256']==pmgr['pmgr_archive_sha256']
assert pmgr['kernel_sha256']==sha(raw) and pmgr['bsd_hook_verified'] and pmgr['original_amfi_and_pmgr_executables_verified_unchanged']
assert not observer['hardware_register_writes'] and not observer['storage_commands_submitted']
assert boot[:8]==b'ANDROID!'
ksize,_,rd,_,second,_,tags,page,version,_=struct.unpack_from('<10I',boot,8)
assert (rd,second,tags,page,version)==(0,0,0x100,4096,1)
z=zlib.decompressobj(31);bundle=z.decompress(boot[page:page+ksize]);assert z.eof
assert z.unused_data==(out/'firmware.dtb').read_bytes()
firmware=(out/'SILICIUM_UEFI.fd').read_bytes()
assert sha(firmware)=='f95578af73b83c818ab07dc2210e0a435cbb4c9a9a962de3405d5da05921624b'
assert bundle[368:368+len(firmware)]==firmware
at=368+len(firmware);assert bundle[at:at+4]==b'XNUP'
fat=bundle[at+8:];assert len(fat)==struct.unpack_from('<I',bundle,at+4)[0]
assert sha(fat)==payload['payload_sha256']==bootproof['payload_sha256']
volume=out/'payload.img';volume.write_bytes(fat)
with PyFatFS(str(volume),read_only=True) as fs:
    kernel=fs.readbytes('/EFI/UniXNU/Payloads/kernel.macho')
    seed=fs.readbytes('/EFI/UniXNU/Payloads/scratch-data.img')
    adt=fs.readbytes('/EFI/UniXNU/Payloads/kernel.macho.adt')
assert sha(kernel)==payload['payload_kernel_sha256'] and len(kernel)==len(raw)
assert sha(adt)==payload['adt_sha256'] and b'PackedRAMDisk' in adt
seedmeta=readj('data-seed.json')
assert sha(seed)==payload['data_ramdisk_sha256']==seedmeta['packed_sha256']=='2434ed1fdfc09f518fd6b18e6ef77ea94aff5090ed98a8d29018dc013cb42c13'
assert seedmeta['bytes']==33554432 and not seedmeta['persistent']
assert seedmeta['sha256']=='8e9ff98f62a4dfc5f8e82ef30f435cfe035ab9830fac59210f8f6a67a5ef097c'
assert seedmeta['volume_uuid']=='32EC6E37-C75B-4305-AA27-C2FEA4E67F30'
assert bytes.fromhex(seedmeta['sha256']) in raw and seedmeta['volume_uuid'].encode()+b'\0' in raw
assert sha((out/'rendered-lmipro-data-mount.patch').read_bytes())==expected['data_patch_sha256']==seedmeta['rendered_patch_sha256']
# Preserve exact original diagnostic patch boundaries, without rebuilding a kernel.
spec=importlib.util.spec_from_file_location('entry',a.entry_script);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.kernel_symbols=lambda _: {v[0]:name for name,v in symbols.items()}
m.load_segments(raw);m.rebase(None,raw)
common=symbols['_panic_trap_to_debugger'][0];lo=m.CAVES[2]+m.CAVE_SIZE;hi=m.PANIC_CAVE_END
def branch_target(address):
    word=struct.unpack_from('<I',kernel,off(address))[0];assert word>>26==5
    delta=word&0x3ffffff
    if delta&(1<<25):delta-=1<<26
    return address+delta*4
for stage,site in [(1,m.ENTRY_VA),(2,m.MMU_ENABLE_VA)]:assert branch_target(site)==m.CAVES[stage]
for site in [m.PANIC_VA,common]:assert lo<=branch_target(site)<hi
assert not any(raw[off(lo):off(hi-4)+4])
normal=bytearray(kernel)
for va,size in [(m.ENTRY_VA,4),(m.MMU_ENABLE_VA,4),(m.PANIC_VA,4),(common,4),*((m.CAVES[s],m.CAVE_SIZE) for s in (1,2)),(lo,hi-lo)]:
    normal[off(va):off(va)+size]=raw[off(va):off(va)+size]
assert bytes(normal)==raw,'Unexpected payload kernel changes or reset probe'
result=dict(boot_sha256=sha(boot),raw_kernel_sha256=sha(raw),payload_kernel_sha256=sha(kernel),
    source_build_run=expected['source_build_run'],device_commit=expected['device_commit'],framework_commit=expected['framework_commit'],
    source_build_verifier_failure='Expected an optional boot_progress string despite disabled XNU_BOOT_PROGRESS',
    actual_identity_seed_mount_exec_order=True,call_sites=dict(identity=list(map(hex,identity_calls)),seed=list(map(hex,seed_calls)),mount=list(map(hex,mount_calls))),
    strong_board_identity=True,mount_output_capture=True,volatile_provider_refuses_io=True,ram_bindings_verified=len(bindings['bindings']),
    exact_embedded_payload_checked=True,entry_panic_hooks_only=True,boot_progress_compiled=progress,
    seed_bytes=seedmeta['bytes'],seed_packed_sha256=sha(seed),seed_logical_sha256=seedmeta['sha256'],
    firmware_sha256=sha(firmware),hardware_tested=False,mount_passed_on_handset=False,tzinit_resumed_on_handset=False,data_mounted_on_handset=False,launchd_startup_qualified=False)
(out/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
(out/'SHA256SUMS').write_text(''.join(sha((out/f).read_bytes())+'  '+f+'\n' for f in ['boot.img','kernel-original.macho','SILICIUM_UEFI.fd']))
print(json.dumps(result,indent=2))
