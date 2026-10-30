"""Select the measured temporary root UUID and official packed sidecar."""
from pathlib import Path
import hashlib,json,tomllib,uuid
p=Path('lmipro/board.toml');s=p.read_text()
proof=json.loads(Path('root-seed/seed-proof.json').read_text())
seed=Path('root-seed/test-root.dbrdisk').read_bytes()
assert hashlib.sha256(seed).hexdigest()==proof['encoded_sha256']
assert len(seed)==proof['encoded_bytes']<=8*1024**2
assert proof['packed'] and not proof['complete_os'] and not proof['internal_storage_access']
volume=str(uuid.UUID(proof['volume_uuid'])).upper()
assert s.count('[payload]\n')==s.count('[payload.adt]\n')==1
assert tomllib.loads(s)['payload']['kernel_args']==['-v','serial=3']
s=s.replace('[payload]\n','[payload]\npanic_screen = true\n',1)
s=s.replace('kernel_args = ["-v", "serial=3"]','kernel_args = ["-v", "serial=3", "sheng-pmgr=2"]')
s=s.replace('[payload.adt]\n','[payload.adt]\npacked_data_ramdisk = true\nroot_match_volume_uuid = "'+volume+'"\n',1)
assert tomllib.loads(s)['payload']['adt']['root_match_volume_uuid']==volume
p.write_text(s)
print('Selected verified volatile APFS seed UUID',volume)
