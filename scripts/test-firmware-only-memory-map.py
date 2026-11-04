#!/usr/bin/env python3
"""Check the empty-payload DXE memory-map variant and its full-payload guard."""
import importlib.util
from pathlib import Path
import tempfile

root = Path(__file__).resolve().parents[1]
module_path = root / 'scripts/firmware-only-memory-map.py'
spec = importlib.util.spec_from_file_location('firmware_only_memory_map', module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
memory_map = root / 'Platforms/Xiaomi/lmiPkg/Library/MemoryMapLib/MemoryMapLib.c'
original = memory_map.read_text(encoding='utf-8')
module.validate(original, firmware_only=False)
changed = module.transform(original)
result = module.validate(changed, firmware_only=True)
assert result['payload_reserved_bytes'] == 0x04000000
assert result['dxe_conventional_bytes'] == 0x04A00000
assert result['additional_dxe_ram_bytes'] == 0x01700000
assert memory_map.read_text(encoding='utf-8') == original
try:
    module.validate(changed, firmware_only=False)
except ValueError:
    pass
else:
    raise AssertionError('firmware-only map was accepted as a payload map')
print('firmware-only map passes; full-payload map remains unchanged')
