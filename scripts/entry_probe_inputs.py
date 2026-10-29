#!/usr/bin/env python3
"""Verify the menu-tested image and recover only its original kernel/ADT."""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path
from pyfatfs.PyFatFS import PyFatFS

SOURCE_IMAGE_SHA = 'c955c448a5240b9b5186ed87f5e7e00af65fcede6332439ddf30fc7c6ce28295'
SOURCE_KERNEL_SHA = '3d3482ae0edd15dbc0fc4c0ba339a64f77c0699f4a9480168fd151c7c139d0f8'
SOURCE_ADT_SHA = '24dcaf989d5a94631affcbc74110f769c8906551349555e2187617428a1a019e'
SOURCE_PAYLOAD_SHA = 'b9b383161b0e4f20dcedcd98892712400e6d1c0d4686ad6c8a9d26abda86ae13'

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
        kernel = fs.readbytes('/EFI/UniXNU/Payloads/kernel.macho')
        adt = fs.readbytes('/EFI/UniXNU/Payloads/kernel.macho.adt')
    finally:
        fs.close()
    assert sha(kernel) == SOURCE_KERNEL_SHA and sha(adt) == SOURCE_ADT_SHA
    (args.out / 'kernel.macho').write_bytes(kernel)
    (args.out / 'kernel.macho.adt').write_bytes(adt)
    # The official payload path adds the two color probes and the stage-3
    # 6-second reset after PE_init_printf to a COPY. Omit the panic renderer for cave capacity.
    text = args.board.read_text()
    assert text.count('[payload]\n') == 1 and 'panic_screen' not in text
    args.board.write_text(text.replace('[payload]\n', '[payload]\npanic_screen = false\nentry_probe_reset_delay = 6\nentry_probe_reset_after = "_PE_init_printf"\nentry_probe_reset_occurrence = 1\n', 1))
    print('Verified menu-tested FD, original kernel and ADT; enabled documented post-early-startup checkpoint')

if __name__ == '__main__':
    main()
