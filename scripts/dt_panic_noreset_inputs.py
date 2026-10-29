#!/usr/bin/env python3
"""Verify the menu-tested image and recover only its original kernel/ADT."""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path
from pyfatfs.PyFatFS import PyFatFS

SOURCE_IMAGE_SHA = 'e8dd31ab3389595dc0c27b3a8d3b68f36a542f0672173597d0dc11ce742cb7d0'
SOURCE_KERNEL_SHA = 'fa73fcb3a811ba2133ce2753e3292bc0757166b5903f791e3ecd32a319aa9026'
SOURCE_ADT_SHA = '4b7ae5dba0dc94951e5710037540cc900838397e6542e459eef539e2f0a58d6e'
SOURCE_PAYLOAD_SHA = '5f8d7580d545e0ef9f5d147fe181184e3813eab2dbda7b2914c203fb00f93031'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source', required=True, type=Path)
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--board', required=True, type=Path)
    args = ap.parse_args()
    boot = (args.source / 'boot.img').read_bytes()
    meta = json.loads((args.source / 'boot.json').read_text())
    assert sha(boot) == SOURCE_IMAGE_SHA == meta['image_sha256']
    assert boot[:8] == b'ANDROID!'
    page = struct.unpack_from('<I', boot, 36)[0]
    size = struct.unpack_from('<I', boot, 8)[0]
    d = zlib.decompressobj(31)
    raw = d.decompress(boot[page:page + size])
    assert d.eof and sha(d.unused_data) == meta['dtb_sha256']
    shim_size = meta['shim_bytes']
    fd = (args.source / 'SILICIUM_UEFI.fd').read_bytes()
    assert len(fd) == 0x300000
    assert sha(fd) == meta['fd_sha256'] and raw[shim_size:shim_size + len(fd)] == fd
    tag = shim_size + len(fd)
    assert raw[tag:tag + 8] == b'XNUP' + struct.pack('<I', 0x4000000)
    payload = raw[tag + 8:]
    assert len(payload) == 0x4000000 and sha(payload) == SOURCE_PAYLOAD_SHA
    args.out.mkdir(parents=True, exist_ok=True)
    image = args.out / 'source-payload.img'
    image.write_bytes(payload)
    fs = PyFatFS(str(image), read_only=True)
    try:
        kernel = (args.source / 'kernel-original.macho').read_bytes()
        adt = fs.readbytes('/EFI/UniXNU/Payloads/kernel.macho.adt')
    finally:
        fs.close()
    assert sha(kernel) == SOURCE_KERNEL_SHA and sha(adt) == SOURCE_ADT_SHA
    proof = json.loads((args.source / 'kernel-build-proof.json').read_text())
    assert proof['compiled_mode'] == 1 and proof['kernel_sha256'] == SOURCE_KERNEL_SHA
    (args.out / 'kernel.macho').write_bytes(kernel)
    (args.out / 'kernel.macho.adt').write_bytes(adt)
    # Match the official payload path: panic_screen adds the entry probes and
    # panic renderer to a COPY. No timed reset and no other board changes.
    text = args.board.read_text()
    assert text.count('[payload]\n') == 1 and 'panic_screen' not in text
    args.board.write_text(text.replace('[payload]\n', '[payload]\npanic_screen = true\n', 1))
    print('Verified menu-tested FD, original kernel and ADT; enabled documented panic_screen')

if __name__ == '__main__':
    main()
