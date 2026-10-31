from pathlib import Path
import argparse,json,os,subprocess
p=argparse.ArgumentParser();p.add_argument('--headers',type=Path,required=True);a=p.parse_args()
src=Path(__file__).resolve().parent;out=src/('test_loader_path.exe' if os.name=='nt' else 'test_loader_path')
subprocess.run([os.environ.get('CC','cc'),'-O2','-fshort-wchar','-fno-builtin','-I',str(a.headers),'-I',str(a.headers/'AArch64'),str(src/'test_loader_path.c'),str(src/'StorageCore.c'),'-o',str(out)],check=True)
r=subprocess.run([str(out)],capture_output=True,text=True,check=True);print(r.stdout,end='')
assert 'passed: 10;' in r.stdout
(src/'loader-path-tests.json').write_text(json.dumps(dict(passed=10,real_c_builder=True,uses_firmware=False))+'\n')
