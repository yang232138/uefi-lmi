"""Add the Qualcomm SM8250 UFS-card stream bindings to the board DTB.

The original board DTB describes ufshc_card but leaves it disabled and without
its two SMMU stream IDs. The vendor UFS module's read-only setup then cannot
attach ARID 0. This patch changes only that node; it does not touch registers,
memory windows, vendor firmware or the UFS controller driver.
"""
from pathlib import Path
import argparse, subprocess, tempfile, shutil

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--input',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--dtc',default='dtc')
    a=ap.parse_args()
    dtc=a.dtc
    if shutil.which(dtc) is None and Path('C:/msys64/ucrt64/bin/dtc.exe').exists(): dtc='C:/msys64/ucrt64/bin/dtc.exe'
    with tempfile.TemporaryDirectory() as d:
        d=Path(d);src=d/'in.dts';out=d/'out.dtb'
        subprocess.run([dtc,'-I','dtb','-O','dts','-o',str(src),str(a.input)],check=True,stdout=subprocess.DEVNULL)
        s=src.read_text()
        marker='ufshc_card: ufshc_card@1da4000 {'
        if marker not in s: marker='ufshc_card@1da4000 {'
        start=s.find(marker);assert start>=0,'ufshc_card node missing'
        brace=s.find('{',start);depth=0;end=None
        for i in range(brace,len(s)):
            if s[i]=='{': depth+=1
            elif s[i]=='}':
                depth-=1
                if depth==0: end=i+1;break
        assert end is not None
        node=s[start:end]
        assert node.count('status = "disabled";')==1
        assert 'iommus =' not in node
        node=node.replace('status = "disabled";','iommus = <0x47 0x0e0 0>, <0x47 0x4e0 0>;\n\t\t\tstatus = "okay";',1)
        s=s[:start]+node+s[end:]
        src.write_text(s)
        subprocess.run([dtc,'-I','dts','-O','dtb','-o',str(out),str(src)],check=True,stdout=subprocess.DEVNULL)
        data=out.read_bytes();assert len(data)>0
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(data)
        print(f'patched UFS card DTB: {len(a.input.read_bytes())} -> {len(data)} bytes')
if __name__=='__main__': main()
