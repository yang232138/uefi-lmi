"""Pack two fresh payloads and read back every changed boot-chain component."""
from pathlib import Path
import gzip, hashlib, json, os, shutil, struct, subprocess, sys, tomllib, uuid, zlib
from pyfatfs.PyFatFS import PyFatFS

ROOT = Path.cwd()
out = ROOT/'output'
out.mkdir(exist_ok=True)
sha = lambda b: hashlib.sha256(b).hexdigest()
pins = json.loads((ROOT/'qualified-inputs/manifest.json').read_text())
for relative,digest in pins.items():
    assert sha((ROOT/'qualified-inputs'/relative).read_bytes())==digest,relative
firmware = (ROOT/'qualified-inputs/firmware/SILICIUM_UEFI.fd').read_bytes()
shim = (ROOT/'qualified-inputs/shim/shim.bin').read_bytes()
tree = (ROOT/'overlay/DeviceTree/lmi.dtb').read_bytes()
assert len(firmware)==0x300000 and sha(firmware)=='720481eb15e6cb3a6552c717ee6e912649a9c81eef18c95ab00dff7627530ee6'
assert len(shim)==368 and sha(shim)=='fca5c1e7fd9b455c27c4039a66c27792c0f475a515b0e4f3bf0a088fcf256195'
assert sha(tree)=='bb52bbbf97601450dbdca9a020145ebe7ea816a94418155919c139ba27d39529'
seed = json.loads((ROOT/'root-seed/seed-proof.json').read_text())
init = json.loads((ROOT/'root-seed/mininit-proof.json').read_text())
board = ROOT/'lmipro/board.toml'
text = board.read_text()
assert tomllib.loads(text)['payload']['kernel_args']==['-v','serial=3']
text = text.replace('kernel_args = ["-v", "serial=3"]', 'kernel_args = ["-v", "serial=3", "sheng-pmgr=2", "offline-owner-root-check=1"]')
assert text.count('[payload]\n')==text.count('[payload.adt]\n')==1
text = text.replace('[payload]\n', '[payload]\npanic_screen = true\ntrust_cache_sha256 = ["'+init['trust_cache_sha256']+'"]\n',1)
text = text.replace('[payload.adt]\n', '[payload.adt]\npacked_data_ramdisk = true\nroot_match_volume_uuid = "'+seed['volume_uuid']+'"\n',1)
board.write_text(text)
work = ROOT/'unixnu/out/lmipro/ipados-17.7.11-21H461/lmipro'
reports=[]
for flavor,extra in [('miniram',[]),('miniram-proof',['--kernel-arg=-s'])]:
    command=['./unixnu','build','payload','-D','../lmipro','--kernel','../output/kernel-original.macho',
        '--data-ramdisk','../root-seed/test-root.dbrdisk','--trust-cache','../root-seed/miniram.trustcache',
        '--uefi','../uefi','--unique-chip-id','0x8011',*extra]
    subprocess.run(command,cwd=ROOT/'unixnu',check=True)
    payload=(work/'payload/payload.img').read_bytes()
    meta=json.loads((work/'payload/payload.json').read_text())
    assert len(payload)==0x4000000 and sha(payload)==meta['payload_sha256']
    assert meta['data_ramdisk_sha256']==seed['encoded_sha256']
    assert meta['trust_cache_sha256']==init['trust_cache_sha256']
    args='-v serial=3 sheng-pmgr=2 offline-owner-root-check=1'+(' -s' if extra else '')
    assert meta['kernel_args']==args,meta['kernel_args']
    assert 'lmipro-ufs-handoff' not in args and 'native-ufs-root' not in args
    fs=PyFatFS(str(work/'payload/payload.img'),read_only=True)
    try:
        cfg=tomllib.loads(fs.readtext('/EFI/UniXNU/unixnu.toml'))
        kernel=fs.readbytes('/EFI/UniXNU/Payloads/kernel.macho')
        adt=fs.readbytes('/EFI/UniXNU/Payloads/kernel.macho.adt')
        ram=fs.readbytes('/EFI/UniXNU/Payloads/scratch-data.img')
        trust=fs.readbytes('/EFI/UniXNU/Payloads/kernel.macho.trustcache')
    finally: fs.close()
    assert sha(kernel)==meta['payload_kernel_sha256'] and sha(adt)==meta['adt_sha256']
    assert sha(ram)==seed['encoded_sha256'] and sha(trust)==init['trust_cache_sha256']
    entry,=[e for e in cfg['entry'] if e['id']=='xnu']
    assert entry['args']==args and entry['initrd']=='Payloads/scratch-data.img'
    assert meta['kernel_sha256']==sha((out/'kernel-original.macho').read_bytes()) and meta['panic_screen']
    assert b'PackedRAMDisk\0' in adt and b'TrustCache\0' in adt and b'root-matching\0' in adt
    assert seed['volume_uuid'].encode() in adt
    combined=shim+firmware+b'XNUP'+struct.pack('<I',len(payload))+payload
    staging=ROOT/'pack-staging'
    staging.mkdir(exist_ok=True)
    gz=staging/'Image.gz-dtb'
    gz.write_bytes(gzip.compress(combined,mtime=0)+tree)
    (staging/'ramdisk').write_bytes(b'')
    target=out/('boot-'+flavor+'.img')
    cfg=tomllib.loads((ROOT/'uefi/Resources/Configs/lmi.toml').read_text())
    image=dict(base=0,header_version=0,kernel_offset=0x8000,tags_offset=0x1e00000,pagesize=4096)
    image.update(cfg.get('boot_image',{}))
    cmd=[sys.executable,str(ROOT/'uefi/Resources/Scripts/mkbootimg.py'),'--kernel',str(gz),'--ramdisk',str(staging/'ramdisk'),'-o',str(target)]
    for k in ('base','kernel_offset','tags_offset','pagesize','header_version','ramdisk_offset'):
        if k in image: cmd+=['--'+k,str(image[k])]
    subprocess.run(cmd,check=True)
    boot=target.read_bytes()
    size,addr,rd,_,second,_,tags,page,version,_=struct.unpack_from('<10I',boot,8)
    assert boot[:8]==b'ANDROID!' and (addr,rd,second,tags,page,version)==(0x8000,0,0,0x100,4096,1)
    decoder=zlib.decompressobj(31)
    actual=decoder.decompress(boot[page:page+size])
    assert decoder.eof and actual==combined and decoder.unused_data==tree and len(boot)<0x8000000
    report=dict(image=target.name,image_sha256=sha(boot),image_bytes=len(boot),kernel_args=args,
        unpatched_kernel_sha256=meta['kernel_sha256'],payload_kernel_sha256=meta['payload_kernel_sha256'],
        firmware_sha256=sha(firmware),shim_sha256=sha(shim),dtb_sha256=sha(tree),
        payload_sha256=sha(payload),root_seed_sha256=sha(ram),root_volume_uuid=seed['volume_uuid'],
        static_pid1_sha256=init['process_sha256'],trust_cache_sha256=sha(trust),
        packed_roundtrip_verified=True,all_boot_parts_read_back=True,native_ufs_enabled=False,
        persistent_storage_enabled=False,complete_ipados=False,interactive_shell=False,
        owner_root_trust_compiled=True,hardware_tested=False,pid1_runtime_observed=False,
        intentional_userspace_panic=bool(extra))
    (out/('boot-'+flavor+'.json')).write_text(json.dumps(report,indent=2)+'\n')
    shutil.copyfile(work/'payload/payload.json',out/('payload-'+flavor+'.json'))
    shutil.copyfile(work/'logs/payload-patch.log',out/('payload-'+flavor+'-patch.log'))
    reports.append(report)
for file in ['seed-proof.json','mininit-proof.json','input-pins.json','miniram.trustcache','test-root.dbrdisk','launchd']:
    shutil.copyfile(ROOT/'root-seed'/file,out/file)
shutil.copyfile(board,out/'test-board.toml')
(out/'verification.json').write_text(json.dumps(dict(images=reports,host_validation_passed=True,hardware_tested=False,pid1_runtime_observed=False),indent=2)+'\n')
(out/'SHA256SUMS').write_text(''.join(r['image_sha256']+'  '+r['image']+'\n' for r in reports))
print('PASS: two newly built RAM-root images read back; actual device boot and PID 1 execution remain unqualified')
