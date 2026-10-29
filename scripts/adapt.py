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
        '  if ((Dtb == 0) || ((Dtb & 3) != 0) || (FdtCheckHeader ((VOID *)(UINTN)Dtb) != 0)) {\n',
        '  // Board-only: BootShim copies the live FDT into this mapped reservation.\n'
        '  if ((Dtb != 0x9F300000ULL) || (FdtCheckHeader ((VOID *)(UINTN)Dtb) != 0)) {\n',
        'ramdisk reserved FDT guard')
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
        '    End   = Start + 0x04000000ULL;\n'
        '    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: no initrd in /chosen; using 0x%lx\\n", Start));\n'
        '  } else {\n'
        '    Start = ReadCells (StartProp, StartLength / 4);\n'
        '    End   = ReadCells (EndProp, EndLength / 4);\n'
        '    if ((Start != 0x93200000ULL) || (End != 0x97200000ULL)) {\n'
        '      // Only BootShim\'s exact reserved XNUP window is valid on this board.\n'
        '      DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: initrd 0x%lx-0x%lx unusable; using 0x93200000\\n", Start, End));\n'
        '      Start = 0x93200000ULL;\n'
        '      End   = Start + 0x04000000ULL;\n'
        '    }\n'
        '  }\n',
        'ramdisk fallback window')

    # The prebuilt PartitionDxe from Binaries/lmi faults while scanning this
    # volume (translation fault at FAR 0x119, third level). Publishing the block
    # device as a partition makes PartitionDxe skip it; EnhancedFatDxe then
    # mounts the volume directly.
    text_edit(
        unixnu / 'package/UniXNUPkg/Driver/UniXNURamDiskDxe/UniXNURamDiskDxe.c',
        '  mMedia.LogicalPartition = FALSE;\n',
        '  mMedia.LogicalPartition = TRUE;\n',
        'ramdisk logical partition')



def patch_exception_footer(edk2):
    """Add a short fault footer without changing CPU/MMU behavior."""
    text_edit(
        edk2 / "UefiCpuPkg/Library/CpuExceptionHandlerLib/AArch64/CpuExceptionHandlerLib.c",
        "  LogToConsole (UnicodeBuffer);\n\n  ASSERT (FALSE);\n",
        "  LogToConsole (UnicodeBuffer);\n\n" + '  // LMI-DIAG2: repeat the useful values after the long stack dump.\n  // EC=0 means instruction fetch completed; never probe ELR for data aborts.\n  DEBUG_CODE_BEGIN ();\n  {\n    UINTN  FaultPc;\n    UINTN  FaultImageBase;\n    UINTN  FaultHeaderSize;\n    CHAR8  *FaultPdb;\n\n    FaultPc = (UINTN)SystemContext.SystemContextAArch64->ELR;\n    FaultPdb = GetImageName (FaultPc, &FaultImageBase, &FaultHeaderSize);\n    DEBUG ((DEBUG_ERROR, "\\nLMI-DIAG3-FWONLY: no XNU payload\\n"));\n    DEBUG ((DEBUG_ERROR, "EL=%lx SCTLR=%lx TTBR0=%lx MIDR=%x\\n",\n      (UINT64)ArmReadCurrentEL (), (UINT64)ArmReadSctlr (),\n      (UINT64)ArmGetTTBR0BaseAddress (), ArmReadMidr ()));\n    DEBUG ((DEBUG_ERROR, "ESR=%lx PC=%lx LR=%lx\\n",\n      SystemContext.SystemContextAArch64->ESR, (UINT64)FaultPc,\n      SystemContext.SystemContextAArch64->LR));\n    if (FaultPdb != NULL) {\n      DEBUG ((DEBUG_ERROR, "IMAGE=%a BASE=%lx OFF=%lx\\n",\n        BaseName (FaultPdb), (UINT64)FaultImageBase,\n        (UINT64)(FaultPc - FaultImageBase)));\n      if (((SystemContext.SystemContextAArch64->ESR >> 26) == 0) &&\n          ((FaultPc & 3) == 0) && (FaultPc >= 0x80000000ULL) &&\n          (FaultPc <= 0x9FFFFFFCULL)) {\n        DEBUG ((DEBUG_ERROR, "OP=%08x\\n", *(volatile UINT32 *)FaultPc));\n      }\n    }\n    DEBUG ((DEBUG_ERROR, "X0=%lx X1=%lx X2=%lx\\n",\n      SystemContext.SystemContextAArch64->X0,\n      SystemContext.SystemContextAArch64->X1,\n      SystemContext.SystemContextAArch64->X2));\n  }\n  DEBUG_CODE_END ();\n' + "\n  ASSERT (FALSE);\n",
        "LMI-DIAG2 exception footer")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unixnu', required=True, type=Path, help='UniXNU checkout')
    parser.add_argument('--uefi', type=Path, help='Mu-Silicium checkout (SEC handoff)')
    parser.add_argument('--edk2', type=Path, help='Resolved shared edk2 feed actually used by the builder')
    args = parser.parse_args()

    text_edit(args.unixnu / 'scripts/unixnu/bootimg.py',
              IMAGE_SIZE_OLD.replace('\n', '\n'), IMAGE_SIZE_NEW,
              'bootimg image_size')
    patch_ramdisk(args.unixnu)
    if args.uefi:
        patch_entry_arg(args.uefi)
    if args.edk2:
        patch_exception_footer(args.edk2)


if __name__ == '__main__':
    main()
