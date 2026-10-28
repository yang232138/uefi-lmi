#!/usr/bin/env python3
"""Point the pinned upstreams at the lmi boot chain.

One upstream behaviour does not describe this handset:

``unixnu bootimg`` requires the ARM64 header ``image_size`` to be
``len(shim) + FD size``. The lmi ABL rejects such an image with "Load Error", so
``BootShim/BootShim.S`` reports the bare volume size. Accept both values instead
of only the one unixnu compiles in.

Nothing else is patched: ``Resources/Configs/lmi.toml`` uses header v1, so
mkbootimg's empty-DTB guard for header v2 is never reached.
"""
import argparse
import sys
from pathlib import Path

IMAGE_SIZE_OLD = (
    "    if requires_header and (shim[56:60] != b'ARM\\x64' or struct.unpack_from('<QQ', shim, 8) != (base, len(shim) + size)):\n"
)
IMAGE_SIZE_NEW = (
    "    # The lmi ABL rejects image_size = shim + FD (Load Error), so BootShim.S\n"
    "    # reports the bare volume size. Accept either value.\n"
    "    if requires_header and (shim[56:60] != b'ARM\\x64'\n"
    "                            or struct.unpack_from('<QQ', shim, 8)[0] != base\n"
    "                            or struct.unpack_from('<QQ', shim, 8)[1] not in (size, len(shim) + size)):\n"
)


def edit(path, old, new, label):
    if not path.is_file():
        sys.exit(f'{label}: {path} is missing')
    text = path.read_text(encoding='utf-8')
    count = text.count(old)
    if count == 0 and new in text:
        print(f'{label}: already applied ({path})')
        return
    if count == 0:
        sys.exit(f'{label}: pattern not found in {path}; the pinned upstream moved')
    path.write_text(text.replace(old, new), encoding='utf-8')
    print(f'{label}: applied {count} occurrence(s) ({path})')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unixnu', required=True, type=Path, help='UniXNU checkout')
    args = parser.parse_args()

    edit(args.unixnu / 'scripts/unixnu/bootimg.py', IMAGE_SIZE_OLD, IMAGE_SIZE_NEW,
         'bootimg image_size')


if __name__ == '__main__':
    main()
