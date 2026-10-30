"""Sign the exact previously tested RAM image and verify every real block."""
from pathlib import Path
import hashlib,importlib.util,json,struct,subprocess,sys,uuid
ROOT=Path.cwd();out=ROOT/'root-policy';out.mkdir(exist_ok=True)
seed=ROOT/'root-seed/test-root.dbrdisk';proof=json.loads((seed.parent/'seed-proof.json').read_text())
assert hashlib.sha256(seed.read_bytes()).hexdigest()=='64a0b51fcdd7b026675633d42321fe594d93a7d4b27c9c4c9755201f3b743676'
spec=importlib.util.spec_from_file_location('packed_ramdisk',ROOT/'DarwinBoot/Test/packed_ramdisk.py')
packed=importlib.util.module_from_spec(spec);spec.loader.exec_module(packed)
logical,extents=packed.regions(seed.read_bytes());assert logical==268394496
raw=out/'root.raw'
with raw.open('xb') as stream:
    stream.truncate(logical)
    for offset,data in extents:stream.seek(offset);stream.write(data)
assert hashlib.sha256(raw.read_bytes()).hexdigest()=='ba060c84ae26166f3068dcb8a5b338b6ddeb539f872f40d46482639b74997557'
volume='B76FFF45-A38F-4850-B66C-A5B6547A77D7';assert proof['volume_uuid']==volume
kit=ROOT/'VerifiedRoot';keys=ROOT/'host-checks/keys'
subprocess.run([sys.executable,str(kit/'tools/manifest.py'),'--image',str(raw),
 '--private-key',str(keys/'owner.pem'),'--public-key',str(keys/'owner-public.pem'),
 '--volume-uuid',volume,'--generation','1','--output',str(out)],check=True)
subprocess.run([sys.executable,str(kit/'tools/verify_image.py'),'--library',str(ROOT/'host-checks/verified-root.dylib'),
 '--manifest',str(out/'manifest.bin'),'--trusted-key',str(out/'trusted-key.bin'),'--image',str(raw),
 '--volume-uuid',volume,'--minimum-generation','1','--output',str(out/'verification.json')],check=True)
meta=json.loads((out/'verification.json').read_text())
assert meta['real_c_signature_and_block_verification'] and meta['blocks_verified']==65526
indices=[0,1,meta['blocks_verified']//2,meta['blocks_verified']-1]
with raw.open('rb') as stream,(out/'samples.bin').open('xb') as target:
    for index in indices:
        stream.seek(index*4096);data=stream.read(4096);assert len(data)==4096;target.write(data)
meta.update(actual_sample_indices=indices,actual_sample_lengths=[4096]*4,
            seed_sha256=proof['encoded_sha256'],full_test_image=True,complete_os=False,
            boot_root_authenticated=False,hardware_tested=False,
            verified_root_revision='def026642c6c6e71be0dea267d989df1d29ddc64',
            samples_sha256=hashlib.sha256((out/'samples.bin').read_bytes()).hexdigest(),
            manifest_sha256=hashlib.sha256((out/'manifest.bin').read_bytes()).hexdigest())
(out/'verification.json').write_text(json.dumps(meta,indent=2)+'\n')
print('PASS: actual complete RAM-test image signed and all 65526 blocks verified; no root authorization enabled')
