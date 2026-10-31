#!/usr/bin/env python3
"""Assemble the payload trust-cache bundle from the two extracted IPSW modules.

The payload step only accepts a bundle whose SHA-256 is pinned in
``board.toml [payload] trust_cache_sha256``. The bundle carries exactly the two
modules the OS profile lists under ``fetch``:

    StaticTrustCache           a version-2 trust module, copied verbatim
    Cryptex1,SystemTrustCache  an IM4P DER blob wrapping the system module

Layout (little endian, as UniXNU's DarwinBoot validates it):

    u32 version = 2
    u32 offset  = 12
    u32 first_module_end = 12 + len(static)
    static module bytes
    system module bytes

The inputs are the files `unixnu fetch` leaves under out/ipsw/<build>/, so this
never needs the whole IPSW.

Usage:
    python3 build-trust-bundle.py --static <static file> --system <im4p file> \
        --output <bundle>
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


def der(data, at):
    """Read one DER TLV; return (tag, value, next offset)."""
    if at + 2 > len(data):
        raise SystemExit('truncated DER')
    tag, size = data[at:at + 2]
    at += 2
    if size & 0x80:
        count = size & 0x7F
        if not 0 < count <= 4 or at + count > len(data):
            raise SystemExit('invalid DER length')
        size = int.from_bytes(data[at:at + count], 'big')
        at += count
    if at + size > len(data):
        raise SystemExit('DER exceeds input')
    return tag, data[at:at + size], at + size


def im4p_payload(blob):
    """Return the OCTET STRING payload of an IM4P blob."""
    tag, sequence, end = der(blob, 0)
    if tag != 0x30 or end != len(blob):
        raise SystemExit('require the original IM4P sequence')
    fields, cursor = [], 0
    while cursor < len(sequence):
        kind, data, cursor = der(sequence, cursor)
        fields.append((kind, data))
    if not fields or fields[0][0] != 0x16 or fields[0][1] != b'IM4P':
        raise SystemExit('require the original IM4P header')
    return fields[-1][1]


def module_ok(module):
    """A version-2 trust module: u32 version, u32 count, then 24-byte entries."""
    if len(module) < 24:
        return False
    version, count = struct.unpack_from('<II', module, 0)
    return version == 2 and len(module) == 24 + count * 24


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--static', required=True, type=Path)
    parser.add_argument('--system', required=True, type=Path, help='Cryptex1,SystemTrustCache (IM4P)')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()

    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

    static = args.static.read_bytes()
    cryptex = args.system.read_bytes()

    # The IPSW ships both as IM4P blobs (the static one too on this build);
    # unwrap whichever is not already a bare version-2 module.
    if not module_ok(static):
        static = im4p_payload(static)
    system = im4p_payload(cryptex)

    if not module_ok(static):
        print(f'static head: {static[:32].hex()}')
        raise SystemExit(f'static trust module is not version 2: {len(static)} bytes')
    if not module_ok(system):
        print(f'system head: {system[:32].hex()}')
        raise SystemExit(f'system trust module is not version 2: {len(system)} bytes')

    static_count = struct.unpack_from('<I', static, 4)[0]
    system_count = struct.unpack_from('<I', system, 4)[0]

    bundle = struct.pack('<3I', 2, 12, 12 + len(static)) + static + system
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(bundle)
    digest = hashlib.sha256(bundle).hexdigest()

    print(f'static: {len(static)} bytes, {static_count} entries')
    print(f'system: {len(system)} bytes, {system_count} entries')
    print(f'bundle: {len(bundle)} bytes sha256 {digest}')
    print(f'PIN: [payload] trust_cache_sha256 = ["{digest}"]')

    if args.report:
        args.report.write_text(json.dumps({
            'static_sha256': hashlib.sha256(static).hexdigest(),
            'system_sha256': hashlib.sha256(system).hexdigest(),
            'bundle_sha256': digest,
            'bundle_bytes': len(bundle),
            'static_entries': static_count,
            'system_entries': system_count,
        }, indent=2) + '\n')


if __name__ == '__main__':
    main()
