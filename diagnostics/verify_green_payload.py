from pathlib import Path
import hashlib,importlib.util,json,os,shutil,struct,subprocess,tomllib
root=Path('unixnu/out/lmipro/ipados-17.7.11-21H461/lmipro');out=Path('output');out.mkdir(exist_ok=True)
raw=root/'kernel/kernel.macho';volume=root/'payload/payload.img';report=json.loads((root/'payload/payload.json').read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert report['panic_screen'] is True and report['kernel_sha256']==sha(raw)
assert report['payload_kernel_sha256']!=sha(raw)
subprocess.run(['mcopy','-o','-i',str(volume),'::kernel.macho',str(out/'kernel-probed.macho')],check=True)
patched=(out/'kernel-probed.macho').read_bytes();assert hashlib.sha256(patched).hexdigest()==report['payload_kernel_sha256']
script=Path('unixnu/scripts/patch-xnu-entry-probe.py')
assert sha(script)=='159eb1ea8d6c1da30f26913a281f46e21d940a1ae7886656529907ec3edf96ad'
spec=importlib.util.spec_from_file_location('official_entry',script);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
d=raw.read_bytes();assert len(d)==len(patched);m.load_segments(d);names=m.rebase(raw,d)
word=lambda va:struct.unpack_from('<I',patched,m.file_offset(va))[0]
for site,stage in [(m.ENTRY_VA,1),(m.MMU_ENABLE_VA,2),(m.AFTER_MMU_VA,3)]:assert word(site)==m.branch(site,m.CAVES[stage])
lo,hi=m.CAVES[3]+m.CAVE_SIZE,m.PANIC_CAVE_END
assert not any(d[m.file_offset(lo):m.file_offset(hi)])
def target(va):
 value=word(va);assert value>>26==0b000101
 n=value&0x3ffffff
 if n&(1<<25):n-=1<<26
 return va+n*4
common=names['_panic_trap_to_debugger']
for site in [m.PANIC_VA,common]:assert lo<=target(site)<hi
normalized=bytearray(patched)
regions=[(m.ENTRY_VA,4),(m.MMU_ENABLE_VA,4),(m.AFTER_MMU_VA,4),(m.PANIC_VA,4),(common,4),*( (m.CAVES[s],m.CAVE_SIZE) for s in (1,2,3)),(lo,hi-lo)]
for va,size in regions:
 at=m.file_offset(va);normalized[at:at+size]=d[at:at+size]
assert bytes(normalized)==d,'Unexpected executable changes outside the official entry/reset/panic hooks'
# Replay the exact official invocation to qualify the real six-second reset,
# not merely the presence of a branch into the reset cave.
replay=out/'kernel-replay.macho';shutil.copyfile(raw,replay)
os.environ['UNIXNU_UEFI']=str(Path('uefi').resolve())
subprocess.run(['python3',str(script),str(replay),'--panic-screen','--reset-delay','6'],check=True)
assert replay.read_bytes()==patched
replay.unlink()
for file in ['boot.img','boot.json']:
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
meta=json.loads((out/'boot.json').read_text());assert meta['image_sha256']==sha(out/'boot.img')
proof=dict(boot_sha256=sha(out/'boot.img'),kernel_sha256=sha(raw),payload_kernel_sha256=hashlib.sha256(patched).hexdigest(),
 fd_sha256=sha(fd),entry_hooks_verified=True,panic_hooks_verified=True,other_kernel_bytes_unchanged=True,
 official_probe_replay_identical=True,reset_delay_seconds=6,reset_checkpoint='immediately after enabling MMU, before platform/storage initialization',
 framework_revision=subprocess.check_output(['git','-C','unixnu','rev-parse','HEAD'],text=True).strip(),
 device_revision=subprocess.check_output(['git','-C','lmipro','rev-parse','HEAD'],text=True).strip(),
 firmware_source='qualified artifact40877381481 with exact FD digest',complete_os_qualified=False,userdata_written=False,hardware_test='pending temporary handset test')
(out/'verification.json').write_text(json.dumps(proof,indent=2)+'\n')
(out/'SHA256SUMS').write_text(''.join(sha(out/f)+'  '+f+'\n' for f in ['boot.img','kernel-original.macho','kernel-probed.macho','SILICIUM_UEFI.fd']))
print(json.dumps(proof,indent=2))
