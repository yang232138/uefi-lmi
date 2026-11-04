#!/usr/bin/env python3
"""Do not publish lmi's reserved RAM as a disk without a bounded FAT payload."""
import argparse
from pathlib import Path

DRIVER = Path('package/UniXNUPkg/Driver/UniXNURamDiskDxe/UniXNURamDiskDxe.c')
GUARD = '''STATIC
BOOLEAN
LmiPayloadPresent (UINT64 Start, UINT64 End)
{
  CONST UINT8 *Boot;
  UINT32       Sectors;
  UINT32       FatSectors;
  UINT32       Reserved;
  UINT32       RootSectors;

  // Only this entire, mapped, reserved window may be read by the lmi adapter.
  // Reject addresses from the boot loader before dereferencing any bytes.
  if ((Start != 0x93200000ULL) || (End != 0x98800000ULL)) {
    return FALSE;
  }

  Boot = (CONST UINT8 *)(UINTN)Start;
  if ((Boot[510] != 0x55) || (Boot[511] != 0xAA) ||
      ((Boot[0] != 0xEB) && (Boot[0] != 0xE9)) ||
      (ReadUnaligned16 ((CONST UINT16 *)(Boot + 11)) != RAM_BLOCK_SIZE) ||
      (Boot[13] == 0) || (Boot[13] > 128) ||
      ((Boot[13] & (Boot[13] - 1)) != 0) ||
      ((Boot[16] != 1) && (Boot[16] != 2))) {
    return FALSE;
  }

  Reserved = ReadUnaligned16 ((CONST UINT16 *)(Boot + 14));
  Sectors = ReadUnaligned16 ((CONST UINT16 *)(Boot + 19));
  if (Sectors == 0) {
    Sectors = ReadUnaligned32 ((CONST UINT32 *)(Boot + 32));
  }
  FatSectors = ReadUnaligned16 ((CONST UINT16 *)(Boot + 22));
  if (FatSectors == 0) {
    FatSectors = ReadUnaligned32 ((CONST UINT32 *)(Boot + 36));
  }
  RootSectors = (ReadUnaligned16 ((CONST UINT16 *)(Boot + 17)) * 32U + 511U) / 512U;
  // Geometry checks use division/subtraction to avoid overflow on corrupt RAM.
  if ((Sectors != (End - Start) / RAM_BLOCK_SIZE) ||
      (Reserved == 0) || (Reserved >= Sectors) ||
      (RootSectors >= Sectors - Reserved) || (FatSectors == 0) ||
      (FatSectors > (Sectors - Reserved - RootSectors - 1) / Boot[16])) {
    return FALSE;
  }
  return TRUE;
}

'''


def guard(payload_bytes):
    if payload_bytes not in (0x4000000, 0x5600000):
        raise ValueError('unsupported lmi payload reservation')
    return GUARD.replace('0x98800000ULL', f'0x{0x93200000 + payload_bytes:x}ULL')


def patch(source, payload_bytes=0x5600000):
    selected = guard(payload_bytes)
    if 'LmiPayloadPresent (' in source and selected not in source:
        raise ValueError('ramdisk guard was generated for a different window')
    if selected not in source:
        anchor = 'STATIC\nVOID\nPublishInitrd (\n'
        if source.count(anchor) != 1:
            raise ValueError('Ramdisk driver changed: PublishInitrd')
        source = source.replace(anchor, selected + anchor, 1)
    for address, limits in [('Start', 'Start, End'),
                            ('0x93200000ULL', f'0x93200000ULL, 0x{0x93200000 + payload_bytes:x}ULL')]:
        anchor = f'  mRamBase                = (UINT8 *)(UINTN){address};\n'
        replacement = ('  if (!LmiPayloadPresent (' + limits + ')) {\n'
                       '    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: no valid bounded FAT payload; skipping RAM disk\\n"));\n'
                       '    return;\n'
                       '  }\n\n' + anchor)
        if replacement in source:
            continue
        if source.count(anchor) != 1:
            raise ValueError('Ramdisk driver changed: ' + address)
        source = source.replace(anchor, replacement, 1)
    return source


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unixnu', required=True, type=Path)
    parser.add_argument('--payload-bytes', type=lambda value: int(value, 0),
                        choices=(0x4000000, 0x5600000), default=0x5600000)
    args = parser.parse_args()
    path = args.unixnu / DRIVER
    path.write_text(patch(path.read_text(encoding='utf-8'), args.payload_bytes), encoding='utf-8')
    print('lmi reserved payload bounds and FAT header guard applied')
