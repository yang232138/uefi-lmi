#!/usr/bin/env python3
"""Point the pinned upstreams at the lmi boot chain.

Two upstream behaviours do not describe this handset:

1. ``unixnu bootimg`` requires the ARM64 header ``image_size`` to be
   ``len(shim) + FD size``. The lmi ABL rejects such an image with "Load Error",
   so ``BootShim/BootShim.S`` reports the bare volume size. Accept both values
   instead of only the one unixnu compiles in.
2. Mu-Silicium ``mkbootimg.py`` raises on an empty DTB for header v2. unixnu does
   not pass ``--dtb``; it appends the device tree to the kernel field
   (``append_dtb = true`` in ``Resources/Configs/lmi.toml``). Allow the empty DTB.

Both edits are idempotent and fail loudly when the pinned source has drifted, so
a silent upstream change cannot produce an image the bootloader rejects.
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

DTB_OLD = "raise ValueError('DTB image must not be empty.')"
DTB_NEW = "pass  # unixnu appends the device tree to the kernel field"


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
    # The guard appears twice in mkbootimg.py (vendor boot header and header v2);
    # both paths must stop rejecting an empty DTB.
    path.write_text(text.replace(old, new), encoding='utf-8')
    print(f'{label}: applied {count} occurrence(s) ({path})')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unixnu', required=True, type=Path, help='UniXNU checkout')
    parser.add_argument('--uefi', required=True, type=Path, help='Mu-Silicium checkout')
    args = parser.parse_args()

    edit(args.unixnu / 'scripts/unixnu/bootimg.py', IMAGE_SIZE_OLD, IMAGE_SIZE_NEW,
         'bootimg image_size')
    edit(args.uefi / 'Resources/Scripts/mkbootimg.py', DTB_OLD, DTB_NEW,
         'mkbootimg empty dtb')


if __name__ == '__main__':
    main()
