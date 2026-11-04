#!/usr/bin/env python3
"""Exercise both adapters from the same pristine upstream ramdisk source."""
import argparse
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--unixnu', required=True, type=Path)
args = parser.parse_args()
scripts = Path(__file__).resolve().parent
adapter = runpy.run_path(str(scripts / 'adapt.py'))
driver = Path('package/UniXNUPkg/Driver/UniXNURamDiskDxe/UniXNURamDiskDxe.c')
source = (args.unixnu / driver).read_bytes()
with tempfile.TemporaryDirectory() as tmp:
    for size in (0x4000000, 0x5600000):
        root = Path(tmp) / str(size)
        (root / driver).parent.mkdir(parents=True)
        (root / driver).write_bytes(source)
        adapter['patch_ramdisk'](root, size)
        adapter['patch_ramdisk'](root, size)
        subprocess.run([sys.executable, str(scripts / 'test-ramdisk-guard.py'),
                        '--unixnu', str(root), '--payload-bytes', hex(size)], check=True)
print('Both memory-map adapters, idempotence and compiled C guards passed')
