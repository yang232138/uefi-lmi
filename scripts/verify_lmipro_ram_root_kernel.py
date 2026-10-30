"""Verify final RAM transport link inputs and unchanged original storage code."""
from pathlib import Path
import argparse,hashlib,json,shutil,subprocess,sys
ap=argparse.ArgumentParser();ap.add_argument('--work',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);ap.add_argument('--device-revision',required=True)
a=ap.parse_args()
subprocess.run([sys.executable,str(Path(__file__).with_name('verify_lmipro_pmgr_kernel.py')),'--work',str(a.work),'--out',str(a.out),'--device-revision',a.device_revision],check=True)
tree=a.work/'tree';obj=tree/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
assert 'CONFIG_XNU_NATIVE_RAM_BLOCK=y' in (a.work/'.config').read_text()
driver=tree/'build/ram-block';archive=driver/'libRamBlock.a'
binding=json.loads((driver/'bindings.json').read_text());abi=json.loads((driver/'interface-audit.json').read_text())
assert binding['virtual_methods_checked']==190 and not binding['original_code_modified']
assert not binding['actual_io_qualified'] and not abi['live_metadata_observed']
assert binding['compiled_object_sha256']==hashlib.sha256((driver/'NativeRamBlock.o').read_bytes()).hexdigest()
assert abi['compiled_public_class_size']==abi['static_original_class_size']==0x90
assert abi['method_slots']==190 and abi['static_parent_class']=='IOService'
assert binding['ram_only_store_mode']==0 and not binding['persistent_io_available']
assert binding['ram_only_store_object_sha256']==hashlib.sha256((driver/'LmiproRamOnlyStore.o').read_bytes()).hexdigest()
archive_sha=hashlib.sha256(archive.read_bytes()).hexdigest()
assert archive_sha in (obj/'.native-aes-link-input').read_text()
kernel=a.out/'kernel-original.macho'
nm=subprocess.run([shutil.which('llvm-nm'),'--defined-only',str(kernel)],check=True,capture_output=True,text=True).stdout
for symbol in ['_native_ram_block_ready','_native_ram_block_reads','__ZTV14NativeRamBlock']:
    assert symbol in nm,symbol
assert b'NativeRamBlock\0' in kernel.read_bytes()
sys.path.insert(0,str(tree/'kits/XnuPrelink'))
from native_prelink import macho,backed_offset,exports
data=kernel.read_bytes();meta=macho(data);plan=json.loads((a.out/'kernel-prelink.json').read_text())
names={n:va for va,values in exports(data,meta).items() for n in values}
for name in binding['ram_only_store_callbacks']:assert name in names,name
mode_at=backed_offset(meta['segments'],names['_native_ufs_store_mode'],8,len(data))
import struct
assert struct.unpack_from('<2I',data,mode_at) in ((0x52800000,0xd65f03c0),(0x2a1f03e0,0xd65f03c0))
extent,=[e for e in plan['extents'] if e['module']=='com.apple.iokit.IOStorageFamily' and e['segment']=='__TEXT_EXEC']
at=backed_offset(meta['segments'],extent['va'],extent['size'],len(data))
assert hashlib.sha256(data[at:at+extent['size']]).hexdigest()==plan['original_executable_sha256']['com.apple.iokit.IOStorageFamily']
for file in ['interface-audit.json','bindings.json','compile-command.json']:
    shutil.copyfile(driver/file,a.out/('ram-block-'+file))
shutil.copyfile(tree/'build/pmgr-reference/reference-inputs.json',a.out/'reference-inputs.json')
report=json.loads((a.out/'kernel-build-proof.json').read_text())
report.update(test_runtime_mode=2,ram_block_archive_sha256=archive_sha,
              ram_block_virtual_slots=190,ram_block_compiled=True,
              original_storage_executable_unchanged=True,storage_live_metadata_observed=False,
              actual_ram_block_io_observed=False,root_mount_observed=False,
              persistent_storage=False,persistent_store_mode=0,complete_os=False)
(a.out/'kernel-build-proof.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: real RamBlock object/archive linked, 190 slots audited; original storage executable unchanged')
