#!/usr/bin/env python3
"""Verify the menu-tested image and recover only its original kernel/ADT."""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path
from pyfatfs.PyFatFS import PyFatFS

SOURCE_IMAGE_SHA = '00818dc3beabe08a0b1884286ceb43c401461375d8dff5c0b300b618e3528a31'
SOURCE_KERNEL_SHA = '49334c982a4029097f841d234cd03bd2cd3d9d017d067ce79cef88c719ca613c'
SOURCE_ADT_SHA = 'bb9513968a1bc6675e192ab279d45f698ee05a36f57ab21c539780056e5918cb'
SOURCE_PAYLOAD_SHA = 'ccec510636f920bb114acc8805c2aeb914b57e0ffa31a0f0987d03df56663566'

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
    assert proof['pmgr_mode_compiled'] == proof['dt_panic_mode_compiled'] == 1 and proof['kernel_sha256'] == SOURCE_KERNEL_SHA
    assert proof['pmgr_virtual_entries'] == 340 and proof['original_amfi_and_pmgr_executables_verified_unchanged']
    (args.out / 'kernel.macho').write_bytes(kernel)
    (args.out / 'kernel.macho.adt').write_bytes(adt)
    # Match the official payload path: panic_screen adds the entry probes and
    # panic renderer to a COPY. No timed reset and no other board changes.
    text = args.board.read_text()
    assert text.count('[payload]\n') == 1 and 'panic_screen' not in text
    text = text.replace('[payload]\n', '[payload]\npanic_screen = true\n', 1)
    assert 'kernel_args = ["-v", "serial=3"]' in text
    text = text.replace('kernel_args = ["-v", "serial=3"]', 'kernel_args = ["-v", "serial=3", "sheng-pmgr=2"]')
    args.board.write_text(text)
    print('Verified menu-tested FD, original kernel and ADT; enabled documented panic_screen')

if __name__ == '__main__':
    main()
