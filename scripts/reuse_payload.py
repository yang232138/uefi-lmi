#!/usr/bin/env python3
"""Reuse the verified FAT payload, never the old failing firmware/shim.

Input: lmi-boot-payload from run 40824751238. No kernel rebuild or OS install.
"""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path

IMAGE_SHA = 'aa16708be837d46a20ce4d682819da15d6cb2f501eb38a95117e02074edd2d17'
PAYLOAD_SHA = 'b9b383161b0e4f20dcedcd98892712400e6d1c0d4686ad6c8a9d26abda86ae13'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--boot', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    data = args.boot.read_bytes()
    if hashlib.sha256(data).hexdigest() != IMAGE_SHA:
        raise SystemExit('source boot image hash mismatch')
    size = struct.unpack_from('<I', data, 8)[0]
    page = struct.unpack_from('<I', data, 36)[0]
    decoder = zlib.decompressobj(31)
    raw = decoder.decompress(data[page:page + size], 72 * 1024 * 1024)
    if not decoder.eof:
        raise SystemExit('incomplete/oversized gzip')
    tag = raw.find(b'XNUP', 0x300000, 0x300400)
    if tag < 0:
        raise SystemExit('XNUP missing')
    length = struct.unpack_from('<I', raw, tag + 4)[0]
    payload = raw[tag + 8:]
    if length != 0x04000000 or len(payload) != length:
        raise SystemExit('wrong XNUP length')
    if hashlib.sha256(payload).hexdigest() != PAYLOAD_SHA:
        raise SystemExit('payload hash mismatch')
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'payload.img').write_bytes(payload)
    (args.out / 'reuse.json').write_text(json.dumps({
        'run_id': 40824751238, 'source_image_sha256': IMAGE_SHA,
        'payload_sha256': PAYLOAD_SHA, 'payload_bytes': length,
        'kernel_rebuilt': False,
    }, indent=2) + '\n')
    print(f'verified and reused {length} bytes of FAT payload')


if __name__ == '__main__':
    main()
