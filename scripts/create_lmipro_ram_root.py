"""Create a disposable APFS virtual disk, then use DarwinBoot's pinned packer."""
from pathlib import Path
import hashlib, importlib.util, json, plistlib, struct, subprocess, sys, uuid

out=Path('root-seed').resolve();out.mkdir(exist_ok=True)
image=out/'test-root.dmg';mount=out/'mount';mount.mkdir(exist_ok=True)
assert not image.exists()
def run(*args):
    result=subprocess.run(list(map(str,args)),check=True,capture_output=True)
    with (out/'creation.log').open('ab') as log:
        log.write(('COMMAND: '+' '.join(map(str,args))+'\n').encode()+result.stdout+result.stderr)
    return result.stdout
run('hdiutil','create','-size','256m','-fs','APFS','-layout','NONE','-format','UDRW','-volname','LMIPRO_RAM_ROOT',image)
attached=False
try:
    attach=plistlib.loads(run('hdiutil','attach','-plist','-nobrowse','-mountpoint',mount,image));attached=True
    info=plistlib.loads(run('diskutil','info','-plist',mount))
    volume=str(uuid.UUID(info['VolumeUUID'])).upper()
    assert info['FilesystemType']=='apfs' and info['MountPoint']==str(mount)
    (mount/'LMIPRO-RAM-ROOT-TEST.txt').write_text('Temporary RAM-only APFS root discovery/mount test. No complete OS or launchd. No persistent phone storage.\n')
    (out/'volume-info.json').write_text(json.dumps(info,indent=2,default=str)+'\n')
finally:
    if attached:run('hdiutil','detach',mount)
run('hdiutil','convert',image,'-format','UDTO','-o',out/'test-root-raw')
cdr=out/'test-root-raw.cdr';data=cdr.read_bytes()
assert data[32:36]==b'NXSB','Expected APFS container without a partition table'
block,blocks=struct.unpack_from('<IQ',data,36);assert block==4096
size=block*blocks;assert 128*1024**2<=size<=256*1024**2 and size<=len(data)
assert not any(data[size:]),'Unexpected nonzero trailing virtual-disk data'
raw=out/'test-root.raw';raw.write_bytes(data[:size])
spec=importlib.util.spec_from_file_location('packed_ramdisk','DarwinBoot/Test/packed_ramdisk.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
packed=out/'test-root.dbrdisk';proof=module.pack(raw,packed)
assert proof['encoded_bytes']<=8*1024**2,'Packed test root exceeds current FAT payload budget'
assert proof['sha256']==hashlib.sha256(raw.read_bytes()).hexdigest()
proof.update(volume_uuid=volume,filesystem='APFS',container_bytes=size,
             purpose='volatile root device discovery and mount smoke test',
             complete_os=False,launchd_present=False,internal_storage_access=False,
             darwinboot_revision='3325e352d7df68a9f9ad74832ed94a6acbbd7390',
             volume_creation_host=sys.platform)
(out/'seed-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
print(json.dumps(proof,indent=2))
