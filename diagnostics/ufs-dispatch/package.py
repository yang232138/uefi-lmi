"""Build viewer and validate the new firmware and complete temporary boot image."""
from pathlib import Path
import contextlib, hashlib, io, json, os, shutil, subprocess, uuid, zipfile
from uefi_firmware.uefi import FirmwareVolume, FirmwareFile, FirmwareFileSystemSection
from verify import verify, sha

src=Path(__file__).resolve().parent
overlay=src.parents[1];workspace=overlay.parent;uefi=workspace/'uefi'
out=workspace/'output';out.mkdir(exist_ok=True)
headers=uefi/'Mu_Basecore/MdePkg/Include'
def run(*args):subprocess.run([str(a) for a in args],check=True)
assert sha((overlay/'Binaries-lmi.zip').read_bytes())=='9c76bc298053228969d2aac4b215aaaadc302ceb793d3f811a284156dcb623f4'
z=zipfile.ZipFile(overlay/'Binaries-lmi.zip')
vendor=z.read('QcomPkg/Drivers/UFSDxe/UFSDxe.efi')
assert sha(vendor)=='ffeaed467f8251b7e30a45075da84a1c563e2bac7dc4be0f79f0ed49a88b8dc9'
fds=list((uefi/'Build/lmiPkg').glob('**/FV/SILICIUM_UEFI.fd'));assert len(fds)==1
fd=fds[0].read_bytes();assert len(fd)==0x300000
(out/'SILICIUM_UEFI.fd').write_bytes(fd)

def walk(obj):
    yield obj
    for child in getattr(obj,'objects',[]) or []:yield from walk(child)
volume=FirmwareVolume(fd)
with contextlib.redirect_stdout(io.StringIO()):assert volume.process()
modules={}
for f in walk(volume):
    if not isinstance(f,FirmwareFile):continue
    guid=str(uuid.UUID(bytes_le=f.guid))
    pes=[s.data for s in walk(f) if isinstance(s,FirmwareFileSystemSection) and s.type==0x10]
    if pes: modules.setdefault(guid,[]).extend(pes)
ufs=modules['0d35cd8e-97ea-4f9a-96af-0f0d89f76567'];assert len(ufs)==1 and ufs[0]==vendor
core=modules['d6a2cb7f-6a18-4e2f-b43b-9920a733700a'];assert len(core)==1
assert b'LMI-UFS-TRACE-v1' in core[0] and b'LMI-UFS-ORIGINAL' in core[0]
assert b'LMI UFS Serial Log v1' in core[0]
sec=list((uefi/'Build/lmiPkg').glob('**/AARCH64/Sec.efi'));assert len(sec)==1
assert b'LMI UFS Serial Log v1' in sec[0].read_bytes()
(out/'Sec.efi').write_bytes(sec[0].read_bytes())
(out/'DxeCore.efi').write_bytes(core[0])
flags=['--target=aarch64-pc-windows-msvc','-ffreestanding','-fno-builtin','-fshort-wchar',
 '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-mno-outline-atomics',
 '-O2','-Wall','-Wextra','-Werror','-I',headers,'-I',headers/'AArch64']
run('clang',*flags,'-c',src/'TraceView.c','-o',out/'TraceView.obj')
run('lld-link','/subsystem:efi_application','/entry:UefiMain','/nodefaultlib','/machine:arm64',
 '/base:0','/filealign:512','/timestamp:0','/opt:ref','/out:'+str(out/'TraceView.efi'),out/'TraceView.obj')
payload=out/'payload.img'
with payload.open('wb') as f:f.truncate(64*1024*1024)
run('mformat','-i',payload,'-F','-v','LMIPROTRACE','::')
for d in ['EFI','EFI/UniXNU','EFI/UniXNU/Payloads']:run('mmd','-i',payload,'::/'+d)
run('mcopy','-i',payload,src/'unixnu.toml','::/EFI/UniXNU/unixnu.toml')
run('mcopy','-i',payload,out/'TraceView.efi','::/EFI/UniXNU/Payloads/TraceView.efi')
run('python3',overlay/'scripts/pack_bootimg.py','--uefi',uefi,'--fd',out/'SILICIUM_UEFI.fd',
 '--payload',payload,'--dtb',overlay/'DeviceTree/lmi.dtb','--out',out/'boot.img')
report=verify(out,src)
report.update(source_commit=os.environ['GITHUB_SHA'],build_run=os.environ['GITHUB_SERVER_URL']+'/'+os.environ['GITHUB_REPOSITORY']+'/actions/runs/'+os.environ['GITHUB_RUN_ID'],
 vendor_ufs_byte_identical=True,vendor_ufs_sha256=sha(vendor),dxe_core_sha256=sha(core[0]),compiled_trace_markers=True,
 normal_dispatch_only=True,new_firmware_requires_hardware_qualification=True,
 serial_capture_window='original UFS CoreStartImage only',serial_forwarding_preserved=True,
 sec_sha256=sha(sec[0].read_bytes()))
(out/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
for name in ['README.md','unixnu.toml','verify.py','UfsDispatchTrace.h','DispatcherTrace.inc','TraceView.c','instrument.py','test_trace.c','UfsSerialLog.h','SerialCapture.inc','SerialBridge.inc','LogText.inc','patch_dtb.py','IortProbe.h','IortProbe.c']:
    shutil.copyfile(src/name,out/name)
(out/'source-sha256.json').write_text(json.dumps({p.name:sha(p.read_bytes()) for p in src.iterdir() if p.is_file()},indent=2)+'\n')
payload.unlink();(out/'TraceView.obj').unlink()
(out/'SHA256SUMS').write_text(''.join(sha(p.read_bytes())+'  '+p.name+'\n' for p in sorted(out.iterdir()) if p.is_file() and p.name!='SHA256SUMS'))
print(json.dumps(report,indent=2))
