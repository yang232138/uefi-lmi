#!/usr/bin/env python3
"""Opt-in SEC checkpoints using its existing debug console and TimerLib."""
import argparse
from pathlib import Path

SEC = Path('Silicon/Silicium/SiliciumPkg/Sec/Sec.c')
HELPER = '''STATIC
VOID
LmiEarlyCheckpoint (CONST CHAR8 *Stage, EFI_STATUS Status)
{
  DEBUG ((DEBUG_ERROR, "\\nLMIPRO EARLY v1: %a status=%r\\n", Stage, Status));
  // Short pause only: hardware watchdog behavior is not changed.
  MicroSecondDelay (500000);
}

'''
EDITS = [
    ('STATIC\nVOID\nSecMain (VOID)\n', HELPER + 'STATIC\nVOID\nSecMain (VOID)\n'),
    ('  PrintFirmwareVersion ();\n', '  PrintFirmwareVersion ();\n'
     '  LmiEarlyCheckpoint ("E1 PLATFORM AND DEBUG CONSOLE", EFI_SUCCESS);\n'),
    ('  Status = InitializeMemory ();\n', '  Status = InitializeMemory ();\n'
     '  LmiEarlyCheckpoint ("E2 MEMORY INIT RETURNED", Status);\n'),
    ('  Status = PlatformPeim ();\n', '  Status = PlatformPeim ();\n'
     '  LmiEarlyCheckpoint ("E3 PLATFORM HOBS RETURNED", Status);\n'),
    ('  Status = DecompressFirstFv ();\n', '  Status = DecompressFirstFv ();\n'
     '  LmiEarlyCheckpoint ("E4 FV DECOMPRESSION RETURNED", Status);\n'),
    ('  Status = LoadDxeCoreFromFv (NULL, 0);\n',
     '  LmiEarlyCheckpoint ("E5 BEFORE DXE CORE", EFI_SUCCESS);\n'
     '  Status = LoadDxeCoreFromFv (NULL, 0);\n'
     '  LmiEarlyCheckpoint ("DXE CORE RETURNED", Status);\n'),
]


def patch_text(source):
    for old, new in EDITS:
        if new in source:
            continue
        if source.count(old) != 1:
            raise ValueError('SEC source changed or ambiguous: ' + old.strip())
        source = source.replace(old, new, 1)
    return source


def self_test(source):
    # Exercise actual fetched SEC source; preserve all original control flow.
    for newline in ('\n', '\r\n'):
        original = source.replace('\n', newline)
        normalized = original.replace('\r\n', '\n')
        patched = patch_text(normalized)
        assert patch_text(patched) == patched
        restored = patched
        for old, new in reversed(EDITS):
            assert restored.count(new) == 1
            restored = restored.replace(new, old, 1)
        assert restored == normalized
        last = -1
        for label in ('E1 PLATFORM', 'E2 MEMORY', 'E3 PLATFORM', 'E4 FV', 'E5 BEFORE'):
            position = patched.index('LmiEarlyCheckpoint ("' + label)
            assert position > last
            last = position
        assert patched.index('LmiEarlyCheckpoint (CONST') < patched.index('SecMain (VOID)')
        assert patched.index('SerialPortInitialize ();') < patched.index('LmiEarlyCheckpoint ("E1')
        assert patched.index('LmiEarlyCheckpoint ("E5') < patched.index('Status = LoadDxeCoreFromFv')
        assert 'LmiEarlyCheckpoint' not in patched[patched.index('SecEntry (VOID)'):]
    try:
        patch_text(source.replace('  Status = InitializeMemory ();\n', ''))
    except ValueError:
        pass
    else:
        raise AssertionError('Source drift was not rejected')
    print('SEC checkpoint checks passed: placement, unchanged control flow, idempotence, line endings, source drift')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uefi', required=True, type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    path = args.uefi / SEC
    source = path.read_text(encoding='utf-8')
    if args.check:
        self_test(source)
    else:
        path.write_text(patch_text(source), encoding='utf-8')
        print('SEC early checkpoints applied')
