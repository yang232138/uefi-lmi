#!/usr/bin/env python3
"""Execute the ARM64 shim: valid payloads, mismatched sizes and stale RAM."""
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0

ROOT = Path(__file__).resolve().parents[1]
BIN = Path('C:/msys64/ucrt64/bin')
def tool(name):
    return shutil.which(name) or str(BIN / (name + '.exe'))

SOURCE, FD, PAYLOAD = 0x84000000, 0x9fc00000, 0x93200000
FD_BYTES = 4096  # The copy semantics do not depend on the volume's contents.
with tempfile.TemporaryDirectory() as temporary:
    tmp = Path(temporary)
    for limit in (0x4000000, 0x5600000):
        obj, binary = tmp / 'shim.o', tmp / 'shim.bin'
        subprocess.run([tool('clang'), '--target=aarch64-none-elf', '-c',
                        f'-DFD_BASE={FD}', f'-DFD_SIZE={FD_BYTES}',
                        '-DREQUIRES_KERNEL_HEADER=1', f'-DPAYLOAD_BASE={PAYLOAD}',
                        f'-DPAYLOAD_SIZE={limit}', str(ROOT / 'BootShim/BootShim.S'),
                        '-o', str(obj)], check=True)
        subprocess.run([tool('llvm-objcopy'), '-O', 'binary', str(obj), str(binary)], check=True)
        shim = binary.read_bytes()
        symbols = subprocess.check_output([tool('llvm-nm'), '-n', str(obj)], text=True)
        offset = next(int(s.split()[0], 16) for s in symbols.splitlines() if s.endswith(' _Payload'))
        assert len(shim) == offset
        for claimed in (limit, 0, limit + 16, limit - 16, 0xffffffff, None):
            valid = claimed == limit
            disk = bytes([0xa5]) * (limit if valid else 512)
            tail = (b'XNUP' + struct.pack('<I', claimed)) if claimed is not None else bytes(8)
            volume = bytes([0x7c]) * FD_BYTES
            combined = shim + volume + tail + disk
            emu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            emu.mem_map(SOURCE, (len(combined) + 4095) & ~4095)
            emu.mem_write(SOURCE, combined)
            emu.mem_map(FD, FD_BYTES)
            emu.mem_map(PAYLOAD, limit + 4096)
            emu.mem_write(PAYLOAD, bytes([0xcc]) * 512)
            emu.mem_write(PAYLOAD + limit, bytes([0x6d]) * 4096)
            emu.reg_write(UC_ARM64_REG_X0, 0)  # No FDT in this isolated payload test.
            emu.emu_start(SOURCE, FD, count=40000000)
            assert emu.reg_read(UC_ARM64_REG_PC) == FD
            assert bytes(emu.mem_read(FD, FD_BYTES)) == volume
            assert bytes(emu.mem_read(PAYLOAD, limit if valid else 512)) == (disk if valid else bytes(512))
            assert bytes(emu.mem_read(PAYLOAD + limit, 4096)) == bytes([0x6d]) * 4096
            print(f'ARM64 shim: limit={limit:#x}, claimed={claimed}, copy/clear and adjacent RAM verified')
print('Actual ARM64 shim payload safety tests passed')
