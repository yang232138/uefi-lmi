#!/usr/bin/env python3
"""Add photographable, automatic loader checkpoints for temporary LMIPRO boots.

Only runs when explicitly selected by the workflow. No disk writes, reset hooks,
kernel patches, or calls to boot services after ExitBootServices are added.
"""
import argparse
from pathlib import Path
from adapt import text_edit


def patch(tree):
    loader = tree / 'drivers/DarwinBoot/DarwinBootPkg/Driver/DarwinBoot.c'
    helper = '''STATIC
VOID
LmiCheckpoint (CONST CHAR16 *Stage, UINTN Seconds)
{
  DEBUG ((DEBUG_ERROR, "LMIPRO BOOT STAGES v1: %s\\n", Stage));
  DiagDraw (L"LMIPRO BOOT STAGES v1", 0);
  DiagDraw (L"                                            ", 1);
  DiagDraw (Stage, 1);
  // This runs only before ExitBootServices; the map is refreshed afterwards.
  gBS->Stall (Seconds * 1000000);
}

'''
    text_edit(loader, 'STATIC\nEFI_STATUS\nAllocateWindow (',
              helper + 'STATIC\nEFI_STATUS\nAllocateWindow (', 'loader checkpoint helper')
    text_edit(loader, '  (VOID)This;\n',
              '  LmiCheckpoint (L"01 LOADER REQUEST", 3);\n  (VOID)This;\n', 'loader request')
    text_edit(loader, '  Length = StrSize (Request->KernelPath);\n',
              '  LmiCheckpoint (L"02 KERNEL PARSED", 3);\n  Length = StrSize (Request->KernelPath);\n', 'kernel parsed')
    text_edit(loader, '  Status = AllocateWindow (&Kernel, WindowSize, &Address);\n',
              '  LmiCheckpoint (L"03 ALLOCATING KERNEL WINDOW", 3);\n'
              '  Status = AllocateWindow (&Kernel, WindowSize, &Address);\n', 'kernel allocation')
    text_edit(loader, '  ZeroMem ((VOID *)(UINTN)Address, (UINTN)Used);\n',
              '  LmiCheckpoint (L"04 COPYING KERNEL AND INPUTS", 3);\n'
              '  ZeroMem ((VOID *)(UINTN)Address, (UINTN)Used);\n', 'kernel copy')
    # GetMap has the same retry-loop header. Include the boot loop's body so
    # this cannot insert a delay into the earlier memory-map helper.
    text_edit(loader, '  for (Attempt = 0; Attempt < 3; Attempt++) {\n    MapSize = Capacity;\n',
              '  // The green bar is drawn by the original assembly handoff.\n'
              '  // This checkpoint does NOT establish that XNU has executed.\n'
              '  LmiCheckpoint (L"05 BEFORE EXIT BOOT SERVICES", 20);\n'
              '  for (Attempt = 0; Attempt < 3; Attempt++) {\n'
              '    MapSize = Capacity;\n', 'before handoff')
    text_edit(loader, '  Print (L"DARWINBOOT: boot refused: %r; firmware retained\\n", Status);\n',
              '  Print (L"DARWINBOOT: boot refused: %r; firmware retained\\n", Status);\n'
              '  {\n'
              '    CHAR16 ErrorLine[64];\n'
              '    UnicodeSPrint (ErrorLine, sizeof (ErrorLine), L"ERROR %r", Status);\n'
              '    DiagDraw (ErrorLine, 3);\n'
              '    LmiCheckpoint (L"LOADER REFUSED - NO KERNEL ENTRY", 60);\n'
              '  }\n', 'loader failure')
    main = tree / 'package/UniXNUPkg/Library/UniXNULib/Main.c'
    text_edit(main, '    Status = UniXNUBootEntry (ImageHandle, &Config, &BootCopy);\n',
              '    Status = UniXNUBootEntry (ImageHandle, &Config, &BootCopy);\n'
              '    DEBUG ((DEBUG_ERROR, "\\fLMIPRO BOOT STAGES v1\\nBOOT ENTRY RETURNED: %r\\nNo keyboard required; holding for 60 seconds.\\n", Status));\n'
              '    gBS->Stall (60 * 1000000);\n', 'returned entry hold')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unixnu', required=True, type=Path)
    patch(parser.parse_args().unixnu)
