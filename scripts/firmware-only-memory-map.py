#!/usr/bin/env python3
"""Apply or report the lmi memory map used by the firmware build."""
import argparse
import json
from pathlib import Path
import re
import shutil
import tempfile

PAYLOAD_86 = '  {"Payload Ramdisk",   0x93200000, 0x05600000, AddMem, SYS_MEM, SYS_MEM_CAP, Reserv, WRITE_BACK_XN},'
PAYLOAD_64 = '  {"Payload Ramdisk",   0x93200000, 0x04000000, AddMem, SYS_MEM, SYS_MEM_CAP, Reserv, WRITE_BACK_XN},'
SPARE_23 = '  {"RAM Partition",     0x97200000, 0x01700000, AddMem, SYS_MEM, SYS_MEM_CAP, Conv,   WRITE_BACK_XN},'


def transform(source):
    if source.count(PAYLOAD_86) != 1 or '0x97200000, 0x01700000' in source:
        raise ValueError('source memory map does not match the expected full-payload layout')
    return source.replace(PAYLOAD_86, PAYLOAD_64 + '\n' + SPARE_23)


def validate(source, firmware_only):
    payload_line = PAYLOAD_64 if firmware_only else PAYLOAD_86
    if source.count(payload_line) != 1:
        raise ValueError('payload reservation does not match build mode')
    spare = source.count(SPARE_23)
    if spare != int(firmware_only):
        raise ValueError('23 MiB DXE expansion does not match build mode')
    descriptors = []
    for line in source.splitlines():
        match = re.search(r'\{"[^"]+",\s*(0x[0-9A-Fa-f]+),\s*(0x[0-9A-Fa-f]+),', line)
        if match:
            base, size = (int(value, 16) for value in match.groups())
            if base >= 0x80000000:
                descriptors.append((base, base + size, line.strip()))
    for left, right in zip(sorted(descriptors), sorted(descriptors)[1:]):
        if left[1] > right[0]:
            raise ValueError(f'overlapping memory descriptors: {left[2]} / {right[2]}')
    payload_bytes = 0x04000000 if firmware_only else 0x05600000
    dxe_heap_bytes = 0x03300000 + (0x01700000 if firmware_only else 0)
    return {
        'mode': 'firmware_only' if firmware_only else 'payload',
        'payload_base': '0x93200000',
        'payload_reserved_bytes': payload_bytes,
        'dxe_conventional_bytes': dxe_heap_bytes,
        'additional_dxe_ram_bytes': 0x01700000 if firmware_only else 0,
        'map_intervals_non_overlapping': True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if bool(args.apply) == bool(args.report):
        parser.error('provide exactly one of --apply or --report')
    if args.apply:
        path = args.apply
        original = path.read_text(encoding='utf-8')
        updated = transform(original)
        validate(updated, firmware_only=True)
        path.write_text(updated, encoding='utf-8')
        print('firmware-only memory map: payload 64 MiB, DXE conventional RAM 74 MiB')
    else:
        source = args.report.read_text(encoding='utf-8')
        firmware_only = '0x97200000, 0x01700000' in source
        print(json.dumps(validate(source, firmware_only), indent=2))


if __name__ == '__main__':
    main()
