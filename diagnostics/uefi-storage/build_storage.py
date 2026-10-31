from pathlib import Path
import gzip,hashlib,json,os,shutil,subprocess,sys
from verify_image import FD_SHA,verify,sha
src=Path(__file__).resolve().parent
overlay=src.parents[1];workspace=overlay.parent;out=workspace/'artifact';out.mkdir(exist_ok=True)
headers=workspace/'basecore/MdePkg/Include';uefi=workspace/'uefi'
def run(*cmd): subprocess.run([str(x) for x in cmd],check=True)
run(sys.executable,src/'test_core.py')
flags=['--target=aarch64-pc-windows-msvc','-ffreestanding','-fno-builtin','-fshort-wchar','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-mno-outline-atomics','-O2','-Wall','-Wextra','-Werror','-I',headers,'-I',headers/'AArch64']
for name in ['UefiStorage','StorageCore']: run('clang',*flags,'-c',src/(name+'.c'),'-o',out/(name+'.obj'))
run('lld-link','/subsystem:efi_application','/entry:UefiMain','/nodefaultlib','/machine:arm64','/base:0','/filealign:512','/timestamp:0','/opt:ref','/out:'+str(out/'UefiStorage.efi'),out/'UefiStorage.obj',out/'StorageCore.obj')
fd=gzip.decompress((overlay/'diagnostics/qualified-SILICIUM_UEFI.fd.gz').read_bytes())
assert len(fd)==0x300000 and sha(fd)==FD_SHA
(out/'SILICIUM_UEFI.fd').write_bytes(fd)
payload=out/'payload.img'
with payload.open('wb') as f: f.truncate(64*1024*1024)
run('mformat','-i',payload,'-F','-v','LMIPROESP','::')
for d in ['EFI','EFI/UniXNU','EFI/UniXNU/Payloads']: run('mmd','-i',payload,'::/'+d)
run('mcopy','-i',payload,src/'unixnu.toml','::/EFI/UniXNU/unixnu.toml')
run('mcopy','-i',payload,out/'UefiStorage.efi','::/EFI/UniXNU/Payloads/UefiStorage.efi')
run(sys.executable,overlay/'scripts/pack_bootimg.py','--uefi',uefi,'--fd',out/'SILICIUM_UEFI.fd','--payload',payload,'--dtb',overlay/'DeviceTree/lmi.dtb','--out',out/'boot.img')
v=verify(out,src);v['source_commit']=os.environ['GITHUB_SHA'];v['build_run']=os.environ['GITHUB_SERVER_URL']+'/'+os.environ['GITHUB_REPOSITORY']+'/actions/runs/'+os.environ['GITHUB_RUN_ID']
(out/'verification.json').write_text(json.dumps(v,indent=2)+'\n')
(out/'boot.json').write_text(json.dumps(dict(sha256=v['boot_sha256'],bytes=v['boot_bytes'],temporary_boot_only=True,contains_xnu=False,contains_os=False,userdata_written=False),indent=2)+'\n')
for name in ['expected-metadata.json','core-test-results.json','unixnu.toml','porting.toml','README.md','verify_image.py']:
    shutil.copyfile(src/name,out/name)
provenance={p.name:sha(p.read_bytes()) for p in src.iterdir() if p.suffix in ('.c','.h','.py','.toml','.json','.md') and p.name!='core-test-results.json'}
(out/'source-sha256.json').write_text(json.dumps(provenance,indent=2)+'\n')
(out/'SHA256SUMS').write_text(''.join(sha(p.read_bytes())+'  '+p.name+'\n' for p in sorted(out.iterdir()) if p.is_file() and p.suffix!='.obj' and p.name!='SHA256SUMS'))
print(json.dumps(v,indent=2))
