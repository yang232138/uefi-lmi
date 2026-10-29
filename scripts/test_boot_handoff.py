#!/usr/bin/env python3
"""Execute the assembled AArch64 shim with unmapped-source handoff cases.

This does not emulate SEC/DXE or establish hardware success.
pip install unicorn
"""
import importlib.util
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pack_bootimg', ROOT / 'scripts/pack_bootimg.py')
pack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pack)
FD = 0x9FC00000
FD_SIZE = 0x300000
PAYLOAD = 0x93200000
PAYLOAD_SIZE = 0x4000000
FDT = 0x9F300000
SOURCE = 0xB8000000


def run(shim, dead, dtb, *, inplace=False, bad_magic=False, bad_size=False,
        payload_size=PAYLOAD_SIZE):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(FD, FD_SIZE)
    uc.mem_map(FDT, 0x100000)
    uc.mem_map(PAYLOAD, PAYLOAD_SIZE)
    fd_bytes = b'0123456789ABCDEF' * (FD_SIZE // 16)
    assert len(fd_bytes) == FD_SIZE
    payload_bytes = b'FEDCBA9876543210' * (PAYLOAD_SIZE // 16)
    body = fd_bytes + b'XNUP' + struct.pack('<I', payload_size) + payload_bytes
    image = shim + body
    if inplace:
        # The FD starts at its final address; the shim immediately precedes it.
        start = FD - len(shim)
        uc.mem_map(FD - 0x1000, 0x1000)
        uc.mem_map(FD + FD_SIZE, PAYLOAD_SIZE + 0x1000)
    else:
        start = SOURCE
        uc.mem_map(start, (len(image) + 0xFFF) & ~0xFFF)
    uc.mem_write(start, image)
    tree = bytearray((ROOT / 'DeviceTree/lmi.dtb').read_bytes())
    if bad_magic:
        tree[:4] = b'FAIL'
    if bad_size:
        struct.pack_into('>I', tree, 4, 0x100001)
    if dtb:
        page = dtb & ~0xFFF
        if not (FDT <= page < FDT + 0x100000):
            uc.mem_map(page, (dtb - page + len(tree) + 0xFFF) & ~0xFFF)
        uc.mem_write(dtb, bytes(tree))
    uc.reg_write(UC_ARM64_REG_X0, dtb)
    stopped = []
    def stop_at_dead(emu, address, size, user):
        stopped.append(True)
        emu.emu_stop()
    uc.hook_add(UC_HOOK_CODE, stop_at_dead, begin=start + dead, end=start + dead)
    uc.emu_start(start, FD, count=40000000)
    if payload_size != PAYLOAD_SIZE:
        assert stopped, 'invalid payload did not fail closed'
        return
    assert not stopped
    assert bytes(uc.mem_read(FD, FD_SIZE)) == fd_bytes
    assert bytes(uc.mem_read(PAYLOAD, PAYLOAD_SIZE)) == payload_bytes
    if not dtb or bad_magic or bad_size:
        assert uc.reg_read(UC_ARM64_REG_X0) == 0
    else:
        assert uc.reg_read(UC_ARM64_REG_X0) == FDT
        assert bytes(uc.mem_read(FDT, len(tree))) == bytes(tree)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp)
        shim = pack.compile_shim(ROOT, FD, FD_SIZE, True, PAYLOAD, scratch)
        symbols = subprocess.check_output([pack.tool('llvm-nm'), '-n', str(scratch / 'shim.o')], text=True)
        dead = next(int(x.split()[0], 16) for x in symbols.splitlines() if x.endswith(' _Dead'))
        cases = [
            ('bootloader FDT outside original map', 0xA9DFE000, {}),
            ('FDT already reserved', FDT, {}),
            ('overlapping FDT copy', FDT + 0x1000, {}),
            ('no FDT', 0, {}),
            ('bad FDT magic', 0xA9DFE000, {'bad_magic': True}),
            ('oversized FDT', 0xA9DFE000, {'bad_size': True}),
            ('FD already relocated', 0xA9DFE000, {'inplace': True}),
            ('zero XNUP size', 0xA9DFE000, {'payload_size': 0}),
            ('oversized XNUP', 0xA9DFE000, {'payload_size': PAYLOAD_SIZE + 16}),
        ]
        for label, address, kwargs in cases:
            run(shim, dead, address, **kwargs)
            print('PASS:', label)
    memory_map = (ROOT / 'Platforms/Xiaomi/lmiPkg/Library/MemoryMapLib/MemoryMapLib.c').read_text()
    assert re.search(r'"Boot FDT"\s*,\s*0x9F300000,\s*0x00100000,\s*AddMem,.*Reserv,\s*WRITE_BACK_XN', memory_map)
    print(json.dumps({'shim_bytes': len(shim), 'executed_cases': len(cases), 'hardware_tested': False}))


if __name__ == '__main__':
    main()
