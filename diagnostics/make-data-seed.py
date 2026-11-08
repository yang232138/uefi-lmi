#!/usr/bin/env python3
"""Build a volatile APFS Data input on macOS, from the exact original OS var tree."""
from pathlib import Path
import hashlib, json, os, plistlib, re, shutil, stat, subprocess, sys

root=Path.cwd();framework=root/'unixnu';device=root/'lmipro';out=root/'output';out.mkdir(exist_ok=True)
work=out/'data-seed';work.mkdir()
metadata=[]
for p in (framework/'out/ipsw/21H461').glob('*.json'):
 try: d=json.loads(p.read_text())
 except (ValueError,UnicodeError): continue
 if d.get('component')=='OS': metadata.append(p)
assert len(metadata)==1, metadata
image=metadata[0].with_suffix('')
assert image.is_file()
source=work/'os';source.mkdir()
def plist(args):return plistlib.loads(subprocess.check_output(args))
attached=plist(['hdiutil','attach','-readonly','-nobrowse','-owners','on','-mountpoint',str(source),'-plist',str(image)])
osdev=attached['system-entities'][0]['dev-entry']
raw=work/'data-32.cdr';target=work/'data';target.mkdir()
datadev=None
try:
 mounts=[e for e in attached['system-entities'] if e.get('mount-point')==str(source)]
 assert len(mounts)==1
 info=plist(['diskutil','info','-plist',mounts[0]['dev-entry']])
 assert info['VolumeUUID'].upper()=='04769D26-2CA0-4825-B443-E2E5F88300F2'
 launchd=hashlib.sha256((source/'sbin/launchd').read_bytes()).hexdigest()
 assert launchd=='8cec9a3c44a443b08e977ccc5d577850316ad428c575dc01f09b018dbd5b6a25'
 subprocess.run(['hdiutil','create','-size','32m','-layout','NONE','-fs','APFS','-volname','LmiproData','-type','UDTO',str(raw)],check=True)
 attached_data=plist(['hdiutil','attach','-nobrowse','-owners','on','-mountpoint',str(target),'-plist',str(raw)])
 datadev=attached_data['system-entities'][0]['dev-entry']
 dm=[e for e in attached_data['system-entities'] if e.get('mount-point')==str(target)];assert len(dm)==1
 uuid=plist(['diskutil','info','-plist',dm[0]['dev-entry']])['VolumeUUID'].upper()
 assert re.fullmatch('[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}',uuid)
 # ditto preserves modes, ownership, symlinks and xattrs; exclude staged app payloads.
 var=source/'private/var';assert var.is_dir() and not var.is_symlink()
 count=0
 for src in var.iterdir():
  if src.name=='staged_system_apps':continue
  subprocess.run(['sudo','ditto','--rsrc','--extattr',str(src),str(target/src.name)],check=True)
  count+=1
 # Only empty directory provisioning, as in prepare-offline-data.py.
 directories=['keybags','mobile/tmp','tmp','run','db/timezone','db/dslocal/nodes/Default/users',
              'db/dslocal/nodes/Default/groups','db/dslocal/nodes/Default/config',
              'containers/Data/System','containers/Data/Application','containers/Shared/SystemGroup',
              'PersonaVolumes','preboot','root','Library','mobile/Library/Preferences',
              'mobile/Library/Caches','mobile/Library/Logs','mobile/Containers','mobile/Documents','mobile/Media']
 for name in directories:subprocess.run(['sudo','mkdir','-p',str(target/name)],check=True)
 subprocess.run(['sudo','chmod','1777',str(target/'tmp')],check=True)
 # Exercise the originally failing write on the scratch seed, then remove test link.
 probe=target/'db/timezone/.lmipro-probe'
 subprocess.run(['sudo','ln','-s','/usr/share/zoneinfo.default',str(probe)],check=True)
 assert probe.is_symlink() and os.readlink(probe)=='/usr/share/zoneinfo.default'
 subprocess.run(['sudo','rm',str(probe)],check=True)
finally:
 if datadev:subprocess.run(['hdiutil','detach',datadev],check=True)
 subprocess.run(['hdiutil','detach',osdev],check=True)
blob=raw.read_bytes();assert len(blob)==33554432 and blob[32:36]==b'NXSB'
digest=hashlib.sha256(blob).hexdigest()
sys.path.insert(0,str(framework/'out/lmipro/ipados-17.7.11-21H461/lmipro/tree/drivers/DarwinBoot/Test'))
# Fetched component location precedes materialized build tree on a cold build.
if not any((Path(p)/'packed_ramdisk.py').is_file() for p in sys.path):
 candidates=list(framework.rglob('packed_ramdisk.py'));assert len(candidates)==1,candidates
 sys.path.insert(0,str(candidates[0].parent))
import packed_ramdisk
packed=work/'data-32.dbr';packed_meta=packed_ramdisk.pack(raw,packed)
logical,extents=packed_ramdisk.regions(packed.read_bytes());assert logical==len(blob)
assert packed.stat().st_size<10*1024**2, 'Keep 64 MiB payload budget'
p=device/'patches/xnu/lmipro-data-mount.patch';s=p.read_text()
assert s.count('LMIPRO_DATA_UUID_REQUIRED')==s.count('LMIPRO_DATA_HASH_REQUIRED')==1
s=s.replace('LMIPRO_DATA_UUID_REQUIRED',uuid).replace('LMIPRO_DATA_HASH_REQUIRED',','.join('0x'+digest[i:i+2] for i in range(0,64,2)))
p.write_text(s);(out/'rendered-lmipro-data-mount.patch').write_text(s)
report=dict(volume_uuid=uuid,bytes=len(blob),sha256=digest,packed_sha256=hashlib.sha256(packed.read_bytes()).hexdigest(),
            packed_bytes=packed.stat().st_size,source_launchd_sha256=launchd,source_os_uuid=info['VolumeUUID'],
            copied_top_level_entries=count,host_timezone_write_probe=True,guest_hardware_verified=False,
            persistent=False,rendered_patch_sha256=hashlib.sha256(s.encode()).hexdigest())
(out/'data-seed.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
