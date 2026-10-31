#!/usr/bin/env python3
"""Point the pinned upstreams at the lmi boot chain.

Two upstream behaviours do not describe this handset:

1. ``unixnu bootimg`` requires the ARM64 header ``image_size`` to be
   ``len(shim) + FD size``. The lmi ABL rejects such an image with "Load Error",
   so ``BootShim/BootShim.S`` reports the bare volume size. Accept both values
   instead of only the one unixnu compiles in.

2. Project-Silicium v4.0 overwrites x0 (the DT pointer the boot loader hands
   over) in ``ModuleEntryPoint.S`` before any C code runs, so the DAEE82E6
   entry-argument HOB that ``UniXNURamDiskDxe`` reads is never built and the
   payload FAT volume is never published (the menu comes up without an xnu
   entry). Keep x0 and build the HOB after ``PlatformPeim``, which is what
   UniXNU/uefi-sheng's sheng branch does.

Both edits are idempotent, work with LF or CRLF checkouts, and fail loudly when
the pinned source has drifted.
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


def text_edit(path, old, new, label, required=True):
    """Replace ``old`` once, tolerating the checkout's line endings."""
    if not path.is_file():
        sys.exit(f'{label}: {path} is missing')
    text = path.read_text(encoding='utf-8')
    nl = '\r\n' if '\r\n' in text else '\n'
    old, new = old.replace('\n', nl), new.replace('\n', nl)
    if new in text:
        print(f'{label}: already applied ({path.name})')
        return
    if old not in text:
        if required:
            sys.exit(f'{label}: pattern not found in {path}; the pinned upstream moved')
        print(f'{label}: skipped, pattern absent ({path.name})')
        return
    path.write_text(text.replace(old, new, 1), encoding='utf-8')
    print(f'{label}: applied ({path.name})')


def patch_entry_arg(uefi):
    """Keep x0 in gSecEntryArg0 and turn it into the DAEE82E6 HOB."""
    sec = uefi / 'Silicon/Silicium/SiliciumPkg/Sec'
    text_edit(
        sec / 'AArch64/ModuleEntryPoint.S',
        'ASM_FUNC (_ModuleEntryPoint)\n  // Do Platform Specific Initialization\n',
        'ASM_FUNC (_ModuleEntryPoint)\n'
        '  // Keep the DT pointer a Linux-style boot loader hands over in x0. The\n'
        '  // slot is in this section, which is in RAM here, so it survives until\n'
        '  // Sec.c runs.\n'
        '  adr   x1, ASM_PFX (gSecEntryArg0)\n'
        '  str   x0, [x1]\n\n'
        '  // Do Platform Specific Initialization\n',
        'SEC: keep x0')
    text_edit(
        sec / 'AArch64/ModuleEntryPoint.S',
        '  // Do Infinite Spin\n  b     .\n',
        '  // Do Infinite Spin\n  b     .\n\n'
        '  // First argument (x0) of the previous stage, written once at entry.\n'
        '  .align 3\n'
        '  .global ASM_PFX (gSecEntryArg0)\n'
        'ASM_PFX (gSecEntryArg0):\n'
        '  .quad 0\n',
        'SEC: gSecEntryArg0 slot')
    text_edit(
        sec / 'Sec.c',
        '#include "Sec.h"\n',
        '#include "Sec.h"\n\n'
        '// First argument (x0) of the previous stage, saved by ModuleEntryPoint.S\n'
        'extern UINT64  gSecEntryArg0;\n',
        'SEC: extern')
    text_edit(
        sec / 'Sec.c',
        '  // Run Library Cconstructors\n',
        '  // Pass on what the previous stage handed over in x0 (a DT address for a\n'
        '  // Linux-style boot loader), so a DXE driver can use it.\n'
        '  {\n'
        '    UINT64  EntryArg = gSecEntryArg0;\n\n'
        '    BuildGuidDataHob (&gSiliciumEntryArgHobGuid, &EntryArg, sizeof (EntryArg));\n'
        '  }\n\n'
        '  // Run Library Cconstructors\n',
        'SEC: build HOB')
    text_edit(
        sec / 'Sec.inf',
        '[Guids]\n  gArmMpCoreInfoGuid\n',
        '[Guids]\n  gArmMpCoreInfoGuid\n  gSiliciumEntryArgHobGuid\n',
        'SEC: inf guid')
    text_edit(
        uefi / 'Silicon/Silicium/SiliciumPkg/SiliciumPkg.dec',
        '  gSiliciumPkgTokenSpaceGuid          = { 0x055720A6, 0xA739, 0x0047, { 0xBE, 0xC1, 0x67, 0xFC, 0x38, 0x34, 0x54, 0x53 } }\n',
        '  gSiliciumPkgTokenSpaceGuid          = { 0x055720A6, 0xA739, 0x0047, { 0xBE, 0xC1, 0x67, 0xFC, 0x38, 0x34, 0x54, 0x53 } }\n'
        '  # Entry argument handoff: the previous stage\'s x0 (a DT address for a\n'
        '  # Linux-style boot loader), consumed by e.g. UniXNURamDiskDxe.\n'
        '  gSiliciumEntryArgHobGuid            = { 0xDAEE82E6, 0x8090, 0x4E72, { 0xBF, 0xB9, 0x78, 0xC1, 0x3C, 0xD4, 0xE3, 0x59 } }\n',
        'SEC: dec guid')


def patch_ramdisk(unixnu):
    """Fall back to the reserved window when the boot loader's initrd is unusable.

    The lmi boot loader reports an initrd address outside the RAM the firmware
    maps, and reading it faults (ArmCpuDxe reports a second-level translation
    fault). lmi.toml asks for ramdisk_addr 0x93200000 and MemoryMapLib reserves
    exactly that 64 MiB, so use it whenever the reported value cannot work.
    """
    text_edit(
        unixnu / 'package/UniXNUPkg/Driver/UniXNURamDiskDxe/UniXNURamDiskDxe.c',
        '  StartProp = FdtGetProp (Fdt, Chosen, "linux,initrd-start", &StartLength);\n'
        '  EndProp   = FdtGetProp (Fdt, Chosen, "linux,initrd-end", &EndLength);\n'
        '  if ((StartProp == NULL) || (EndProp == NULL) ||\n'
        '      ((StartLength != 4) && (StartLength != 8)) || ((EndLength != 4) && (EndLength != 8)))\n'
        '  {\n'
        '    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: no initrd in /chosen\\n"));\n'
        '    return;\n'
        '  }\n'
        '\n'
        '  Start = ReadCells (StartProp, StartLength / 4);\n'
        '  End   = ReadCells (EndProp, EndLength / 4);\n',
        '  StartProp = FdtGetProp (Fdt, Chosen, "linux,initrd-start", &StartLength);\n'
        '  EndProp   = FdtGetProp (Fdt, Chosen, "linux,initrd-end", &EndLength);\n'
        '  if ((StartProp == NULL) || (EndProp == NULL) ||\n'
        '      ((StartLength != 4) && (StartLength != 8)) || ((EndLength != 4) && (EndLength != 8)))\n'
        '  {\n'
        '    // lmi: no initrd was reported; use the window the boot image header asks\n'
        '    // for and the firmware memory map reserves for it.\n'
        '    Start = 0x93200000ULL;\n'
        '    End   = Start + 0x5600000ULL;\n'
        '    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: no initrd in /chosen; using 0x%lx\\n", Start));\n'
        '  } else {\n'
        '    Start = ReadCells (StartProp, StartLength / 4);\n'
        '    End   = ReadCells (EndProp, EndLength / 4);\n'
        '    if ((Start < 0x80000000ULL) || ((End - Start) != 0x5600000ULL)) {\n'
        '      // lmi: the reported range is outside the mapped RAM or the wrong size.\n'
        '      DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: initrd 0x%lx-0x%lx unusable; using 0x93200000\\n", Start, End));\n'
        '      Start = 0x93200000ULL;\n'
        '      End   = Start + 0x5600000ULL;\n'
        '    }\n'
        '  }\n',
        'ramdisk fallback window')

    # The boot loader's x0 is not a usable FDT on this board: it points outside
    # the RAM the firmware maps (ArmCpuDxe reports a second-level translation
    # fault with FAR equal to that pointer). Never dereference it in that case;
    # publish the reserved window the boot image asked for.
    text_edit(
        unixnu / 'package/UniXNUPkg/Driver/UniXNURamDiskDxe/UniXNURamDiskDxe.c',
        '  DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: initrd block device 0x%lx size 0x%lx %r\\n", Start, End - Start, Status));\n'
        '}\n',
        '  DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: initrd block device 0x%lx size 0x%lx %r\\n", Start, End - Start, Status));\n'
        '}\n'
        '\n'
        'STATIC\n'
        'VOID\n'
        'PublishWindow (\n'
        '  VOID\n'
        '  )\n'
        '{\n'
        '  EFI_STATUS  Status;\n'
        '  EFI_HANDLE  Handle;\n'
        '\n'
        '  mRamBase                = (UINT8 *)(UINTN)0x93200000ULL;\n'
        '  mMedia.MediaId          = 1;\n'
        '  mMedia.RemovableMedia   = FALSE;\n'
        '  mMedia.MediaPresent     = TRUE;\n'
        '  mMedia.LogicalPartition = TRUE;\n'
        '  mMedia.ReadOnly         = TRUE;\n'
        '  mMedia.WriteCaching     = FALSE;\n'
        '  mMedia.BlockSize        = RAM_BLOCK_SIZE;\n'
        '  mMedia.IoAlign          = 1;\n'
        '  mMedia.LastBlock        = (0x5600000ULL / RAM_BLOCK_SIZE) - 1;\n'
        '\n'
        '  Handle = NULL;\n'
        '  Status = gBS->InstallMultipleProtocolInterfaces (\n'
        '                  &Handle,\n'
        '                  &gEfiDevicePathProtocolGuid,\n'
        '                  &mDevicePath,\n'
        '                  &gEfiBlockIoProtocolGuid,\n'
        '                  &mBlockIo,\n'
        '                  NULL\n'
        '                  );\n'
        '  DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: reserved window 0x93200000 size 0x4000000 %r\\n", Status));\n'
        '}\n',
        'ramdisk publish window')
    text_edit(
        unixnu / 'package/UniXNUPkg/Driver/UniXNURamDiskDxe/UniXNURamDiskDxe.c',
        '  Dtb = ReadUnaligned64 ((CONST UINT64 *)GET_GUID_HOB_DATA (Hob));\n',
        '  Dtb = ReadUnaligned64 ((CONST UINT64 *)GET_GUID_HOB_DATA (Hob));\n'
        '  if ((Dtb < 0x80000000ULL) || (Dtb >= 0x9FF00000ULL)) {\n'
        '    // lmi: the boot loader\'s FDT pointer is outside the RAM the firmware\n'
        '    // maps; dereferencing it faults. Use the reserved window instead.\n'
        '    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: x0 0x%lx is not in mapped RAM; using the reserved window\\n", Dtb));\n'
        '    PublishWindow ();\n'
        '    return EFI_SUCCESS;\n'
        '  }\n',
        'ramdisk fdt range')

    # The prebuilt PartitionDxe from Binaries/lmi faults while scanning this
    # volume (translation fault at FAR 0x119, third level). Publishing the block
    # device as a partition makes PartitionDxe skip it; EnhancedFatDxe then
    # mounts the volume directly.
    text_edit(
        unixnu / 'package/UniXNUPkg/Driver/UniXNURamDiskDxe/UniXNURamDiskDxe.c',
        '  mMedia.LogicalPartition = FALSE;\n',
        '  mMedia.LogicalPartition = TRUE;\n',
        'ramdisk logical partition')


def patch_userdata_chunk(unixnu):
    """Read the attached disk image in smaller blocks.

    ``userdata.py`` reads 8 MiB at a time from /dev/rdiskN; macOS 26 answers
    EINVAL for reads that large on a raw disk device, which aborted the
    userdata build after the IPSW had already been extracted.
    """
    text_edit(
        unixnu / 'scripts/unixnu/userdata.py',
        'CHUNK = 8 * MIB\n',
        'CHUNK = 1 * MIB  # lmi: /dev/rdiskN rejects 8 MiB reads on macOS 26 (EINVAL)\n',
        'userdata chunk')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unixnu', required=True, type=Path, help='UniXNU checkout')
    parser.add_argument('--uefi', type=Path, help='Mu-Silicium checkout (SEC handoff)')
    args = parser.parse_args()

    text_edit(args.unixnu / 'scripts/unixnu/bootimg.py',
              IMAGE_SIZE_OLD.replace('\n', '\n'), IMAGE_SIZE_NEW,
              'bootimg image_size')
    patch_ramdisk(args.unixnu)
    patch_userdata_chunk(args.unixnu)
    if args.uefi:
        patch_entry_arg(args.uefi)


if __name__ == '__main__':
    main()
