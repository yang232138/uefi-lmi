"""Build a real small APFS root, signed PID 1, and independently signed blocks."""
from pathlib import Path
import hashlib, importlib.util, json, os, plistlib, re, shutil, struct, subprocess, sys, uuid

ROOT = Path.cwd()
out = ROOT/'root-seed'
out.mkdir(exist_ok=True)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
def run(*args):
    result = subprocess.run(list(map(str,args)), capture_output=True)
    with (out/'creation.log').open('ab') as log:
        log.write(('COMMAND: '+' '.join(map(str,args))+'\n').encode()+result.stdout+result.stderr)
    if result.returncode:
        sys.stderr.buffer.write(result.stdout+result.stderr)
        result.check_returncode()
    return result.stdout

source = ROOT/'overlay/miniram/mininit.S'
sdk = subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'], text=True).strip()
run('xcrun','clang','-target','arm64-apple-ios17.0','-isysroot',sdk,'-c',source,'-o',out/'mininit.o')
run('xcrun','ld','-arch','arm64','-static','-e','_start','-platform_version','ios','17.0','17.0',out/'mininit.o','-o',out/'mininit-static')
program = out/'launchd'
run('xcrun','vtool','-set-build-version','ios','17.0','17.0','-replace','-output',program,out/'mininit-static')
run('codesign','--force','--sign','-','--pagesize','4096','--identifier','org.unixnu.lmipro.miniram',program)
run('codesign','--verify','--strict',program)
details = subprocess.run(['codesign','--display','--verbose=4',program], capture_output=True,text=True,check=True).stderr
match = re.search(r'^CDHash=([0-9a-f]{40})$',details,re.M)
assert match and re.search(r'^Page size=4096$',details,re.M)
cdhash = bytes.fromhex(match[1])
binary = program.read_bytes()
assert struct.unpack_from('<4I',binary)==(0xfeedfacf,0x100000c,0,2)
at = 32
commands = []
directories = []
for _ in range(struct.unpack_from('<I',binary,16)[0]):
    cmd,size = struct.unpack_from('<II',binary,at)
    assert size>=8 and at+size<=len(binary)
    commands.append(cmd)
    if cmd == 0x1d:
        start,length = struct.unpack_from('<II',binary,at+8)
        signature = binary[start:start+length]
        assert struct.unpack_from('>I',signature)[0]==0xfade0cc0
        for i in range(struct.unpack_from('>I',signature,8)[0]):
            _,offset = struct.unpack_from('>II',signature,12+8*i)
            magic,n = struct.unpack_from('>II',signature,offset)
            if magic == 0xfade0c02: directories.append(signature[offset:offset+n])
    at += size
assert 5 in commands and 0xc not in commands and 0xe not in commands and 0x80000028 not in commands
assert len(directories)==1
directory = directories[0]
assert directory[37]==2 and directory[39]==12
assert hashlib.sha256(directory).digest()[:20]==cdhash
hash_offset,slots,limit = struct.unpack_from('>I',directory,16)[0],struct.unpack_from('>I',directory,28)[0],struct.unpack_from('>I',directory,32)[0]
assert slots == (limit+4095)//4096
for i in range(slots):
    assert hashlib.sha256(binary[i*4096:min(limit,(i+1)*4096)]).digest()==directory[hash_offset+32*i:hash_offset+32*(i+1)]
identifier = uuid.uuid5(uuid.NAMESPACE_URL,'org.unixnu.lmipro.miniram:'+cdhash.hex())
module = struct.pack('<I16sI',2,identifier.bytes,1)+cdhash+bytes([2,0,0,0])
bundle = struct.pack('<2I',1,8)+module
(out/'miniram.trustcache').write_bytes(bundle)
(out/'mininit-proof.json').write_text(json.dumps(dict(
    source_sha256=sha(source),process_sha256=sha(program),cdhash=cdhash.hex(),
    trust_cache_sha256=hashlib.sha256(bundle).hexdigest(),code_signature_page_bytes=4096,
    all_code_pages_verified=True,static_unixthread=True,dynamic_libraries=[],
    entry_at_el0_observed=False,pid1_observed=False,hardware_tested=False,
    proof_mode='-s requests real userspace reboot(RB_PANIC|RB_QUICK) after getpid()==1',
    running_mode='without -s: write console heartbeat and select timeout loop',
),indent=2)+'\n')

# This is exclusively a newly created workspace disk image. No physical disk
# paths are accepted, and no mount/format command is sent to the handset.
image = out/'test-root.dmg'
mount = out/'mount'
mount.mkdir(exist_ok=True)
assert not image.exists()
run('hdiutil','create','-size','256m','-fs','APFS','-layout','GPTSPUD','-volname','LMIPRO_MINIRAM',image)
attached = False
try:
    plistlib.loads(run('hdiutil','attach','-plist','-nobrowse','-mountpoint',mount,image))
    attached = True
    info = plistlib.loads(run('diskutil','info','-plist',mount))
    assert info['FilesystemType']=='apfs' and info['MountPoint']==str(mount)
    volume = str(uuid.UUID(info['VolumeUUID'])).upper()
    for name in ('sbin','dev','tmp','private','etc'):
        (mount/name).mkdir(exist_ok=True)
    shutil.copyfile(program,mount/'sbin/launchd')
    (mount/'sbin/launchd').chmod(0o755)
    assert sha(mount/'sbin/launchd')==sha(program)
    (mount/'MINIRAM-README.txt').write_text('Experimental RAM-only APFS root and static PID 1. No iPadOS desktop, shell, UFS, or persistence.\n')
    (out/'volume-info.json').write_text(json.dumps(info,indent=2,default=str)+'\n')
finally:
    if attached: run('hdiutil','detach',mount)
run('hdiutil','convert',image,'-format','UDTO','-o',out/'test-root-raw')
disk = (out/'test-root-raw.cdr').read_bytes()
assert disk[512:520]==b'EFI PART'
lba,count,entry_size = struct.unpack_from('<QII',disk,584)
assert 0<count<=256 and entry_size==128
parts = []
for i in range(count):
    at=lba*512+i*entry_size
    if str(uuid.UUID(bytes_le=disk[at:at+16])).upper()=='7C3457EF-0000-11AA-AA11-00306543ECAC':
        first,last=struct.unpack_from('<QQ',disk,at+32)
        assert first<=last and (last+1)*512<=len(disk)
        parts.append(disk[first*512:(last+1)*512])
assert len(parts)==1
data=parts[0]
assert data[32:36]==b'NXSB'
block,blocks=struct.unpack_from('<IQ',data,36)
size=block*blocks
assert block==4096 and size==268394496 and not any(data[size:])
raw=out/'test-root.raw'
raw.write_bytes(data[:size])
spec=importlib.util.spec_from_file_location('packed_ramdisk',ROOT/'DarwinBoot/Test/packed_ramdisk.py')
packed=importlib.util.module_from_spec(spec)
spec.loader.exec_module(packed)
proof=packed.pack(raw,out/'test-root.dbrdisk')
assert proof['encoded_bytes']<=8*1024**2 and proof['sha256']==sha(raw)
logical,extents=packed.regions((out/'test-root.dbrdisk').read_bytes())
decoded=bytearray(logical)
for offset,chunk in extents: decoded[offset:offset+len(chunk)]=chunk
assert hashlib.sha256(decoded).hexdigest()==sha(raw)
proof.update(volume_uuid=volume,filesystem='APFS',complete_os=False,launchd_present=True,
    launchd_is_test_instrument=True,internal_storage_access=False,process_sha256=sha(program),
    bytes=size,purpose='minimal static PID 1 with genuine read-only signed RAM-root enforcement',
    darwinboot_revision='3325e352d7df68a9f9ad74832ed94a6acbbd7390',hardware_tested=False)
(out/'seed-proof.json').write_text(json.dumps(proof,indent=2)+'\n')

# Generate disposable owner keys inside the build runner; only the public
# anchor, signed manifest and verification results leave that runner.
prefix=subprocess.check_output(['brew','--prefix','openssl@3'],text=True).strip()
run(sys.executable,ROOT/'VerifiedRoot/tests/check.py','--output',ROOT/'host-checks','--openssl-prefix',prefix)
policy=ROOT/'root-policy'
policy.mkdir(exist_ok=True)
keys=ROOT/'host-checks/keys'
run(sys.executable,ROOT/'VerifiedRoot/tools/manifest.py','--image',raw,
    '--private-key',keys/'owner.pem','--public-key',keys/'owner-public.pem',
    '--volume-uuid',volume,'--generation','1','--output',policy)
run(sys.executable,ROOT/'VerifiedRoot/tools/verify_image.py','--library',ROOT/'host-checks/verified-root.dylib',
    '--manifest',policy/'manifest.bin','--trusted-key',policy/'trusted-key.bin',
    '--image',raw,'--volume-uuid',volume,'--minimum-generation','1','--output',policy/'verification.json')
meta=json.loads((policy/'verification.json').read_text())
assert meta['real_c_signature_and_block_verification'] and meta['blocks_verified']==65526
assert meta['image_sha256']==proof['sha256'] and meta['image_bytes']==size
indices=[0,1,32763,65525]
with raw.open('rb') as stream,(policy/'samples.bin').open('xb') as target:
    for index in indices:
        stream.seek(index*4096)
        chunk=stream.read(4096)
        assert len(chunk)==4096
        target.write(chunk)
meta.update(actual_sample_indices=indices,actual_sample_lengths=[4096]*4,
    seed_sha256=proof['encoded_sha256'],complete_os=False,boot_root_authenticated=False,
    hardware_tested=False,verified_root_revision='def026642c6c6e71be0dea267d989df1d29ddc64',
    manifest_sha256=sha(policy/'manifest.bin'),samples_sha256=sha(policy/'samples.bin'))
(policy/'verification.json').write_text(json.dumps(meta,indent=2)+'\n')
shutil.copyfile(ROOT/'host-checks/checks.json',policy/'host-checks.json')
for private in keys.glob('*.pem'):
    if 'public' not in private.name: private.unlink()
env={
    'LMIPRO_PACKED_SEED_SHA256':proof['encoded_sha256'],
    'LMIPRO_SIGNED_IMAGE_SHA256':proof['sha256'],
    'LMIPRO_TRUSTED_KEY_SHA256':sha(policy/'trusted-key.bin'),
    'LMIPRO_MANIFEST_SHA256':sha(policy/'manifest.bin'),
}
with Path(os.environ['GITHUB_ENV']).open('a') as stream:
    for k,v in env.items(): stream.write(k+'='+v+'\n')
(out/'input-pins.json').write_text(json.dumps(env,indent=2)+'\n')
print(json.dumps(dict(root_bytes=size,packed_bytes=proof['encoded_bytes'],minimal_init_present=True,complete_os=False,hardware_tested=False)))
