from pathlib import Path
import subprocess,sys,tomllib
subprocess.run([sys.executable,str(Path(__file__).with_name('select_lmipro_ram_root_payload.py'))],check=True)
p=Path('lmipro/board.toml');s=p.read_text()
assert tomllib.loads(s)['payload']['kernel_args']==['-v','serial=3','sheng-pmgr=2']
old='kernel_args = ["-v", "serial=3", "sheng-pmgr=2"]';assert s.count(old)==1
s=s.replace(old,'kernel_args = ["-v", "serial=3", "sheng-pmgr=2", "offline-owner-root-check=1"]')
p.write_text(s)
print('Selected official eight-control crypto instrument; root acceptance remains disabled')
