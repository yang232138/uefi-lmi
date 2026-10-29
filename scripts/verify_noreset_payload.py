#!/usr/bin/env python3
"""Bind the new firmware to the immutable entry/panic payload with no reset."""
import argparse
import hashlib
import json
import struct
import tomllib
import zlib
from pathlib import Path
from pyfatfs.PyFatFS import PyFatFS

PAYLOAD = '0991926ae4d69121ceeb8133c3fdcf179e889e7163acfbe78dda28d091df9071'
KERNEL = 'c05fbb93252ddbe2c230a7a1c7769bd55b28dda0f4b25a823bf36e1eec900fcd'
ADT = '5575c17a5bdcd5c442f5d4dd7a006ccc7b38bd1c912f1bc5a1803e05c1d0011e'

def sha(b):
    return hashlib.sha256(b).hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--payload', type=Path, required=True)
    args = ap.parse_args()
    out = args.out
    meta = json.loads((out/'boot.json').read_text())
    report = json.loads((out/'payload.json').read_text())
    proof = json.loads((out/'source-probe-verification.json').read_text())
    assert proof['timed_reset'] is False and proof['panic_screen'] is True
    assert proof['boot_sha256'] == '961a5e1c764f206d5e08f0bebf62247eb6dbf7425d9a0e07ed67e4f172893a4d'
    assert 'no reset probe, panic screen' in (out/'payload-patch.log').read_text()
    assert report['payload_sha256'] == PAYLOAD
    assert report['payload_kernel_sha256'] == KERNEL and report['adt_sha256'] == ADT
    payload = args.payload.read_bytes()
    assert len(payload) == 0x4000000 and sha(payload) == PAYLOAD == meta['payload_sha256']
    fs = PyFatFS(str(args.payload), read_only=True)
    try:
        assert sha(fs.readbytes('/EFI/UniXNU/Payloads/kernel.macho')) == KERNEL
        assert sha(fs.readbytes('/EFI/UniXNU/Payloads/kernel.macho.adt')) == ADT
        cfg = tomllib.loads(fs.readtext('/EFI/UniXNU/unixnu.toml'))
        assert any(e.get('id') == 'xnu' and e.get('title') == 'Redmi K30 Pro' for e in cfg['entry'])
    finally:
        fs.close()
    b = (out/'boot.img').read_bytes()
    assert sha(b) == meta['image_sha256']
    p = struct.unpack_from('<I', b, 36)[0]
    k = struct.unpack_from('<I', b, 8)[0]
    d = zlib.decompressobj(31)
    raw = d.decompress(b[p:p+k])
    assert d.eof and sha(d.unused_data) == meta['dtb_sha256']
    fd = (out/'SILICIUM_UEFI.fd').read_bytes()
    assert len(fd) == 0x300000 and sha(fd) == meta['fd_sha256']
    s = meta['shim_bytes']
    assert raw[s:s+len(fd)] == fd
    assert raw[s+len(fd):] == b'XNUP' + struct.pack('<I', len(payload)) + payload
    v = dict(boot_sha256=meta['image_sha256'], payload_sha256=PAYLOAD,
             payload_kernel_sha256=KERNEL, adt_sha256=ADT,
             entry_probe=True, panic_screen=True, timed_reset=False,
             source_payload_run=40843353220, original_kernel_rebuilt=False,
             source_firmware_menu_photo='1793273617545.jpg',
             hardware_test='pending')
    (out/'integration-verification.json').write_text(json.dumps(v, indent=2)+'\n')
    print(json.dumps(v, indent=2))

if __name__ == '__main__':
    main()
