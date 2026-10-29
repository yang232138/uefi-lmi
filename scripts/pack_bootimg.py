#!/usr/bin/env python3
"""Pack the boot image with the payload embedded in the kernel image.

The lmi boot loader behaves like the 3a's in UniXNU's asteroids record: it takes
the initrd from its own vendor_boot/init_boot ramdisks and ignores the boot
image's ramdisk, so a payload passed as --ramdisk never reaches the firmware.

Mu-Silicium's BootShim already understands a payload appended after the firmware
volume when it is built with -DPAYLOAD_BASE: a "XNUP" tag and a 32-bit size,
which it copies to that address as it boots. UniXNURamDiskDxe then publishes the
same window (lmi.toml asks for 0x93200000 and MemoryMapLib reserves 64 MiB
there), and its own fallback ignores whatever unusable initrd the boot loader
reported.

kernel field = gzip(BootShim + FD + XNUP + payload) + device tree, ramdisk empty.
"""
import argparse
import gzip
import struct
import subprocess
import sys
import tempfile
import tomllib
import zlib
from pathlib import Path

PAGE = 4096
XNUP = b'XNUP'


def tool(name):
    from shutil import which
    path = which(name)
    if not path:
        sys.exit(f'{name} not found in PATH')
    return path


def config(uefi):
    data = tomllib.loads((uefi / 'Resources/Configs/lmi.toml').read_text(encoding='utf-8'))
    return data


def compile_shim(uefi, base, size, requires_header, payload_base, scratch):
    source = uefi / 'BootShim/BootShim.S'
    if not source.is_file():
        sys.exit(f'{source} missing')
    obj = scratch / 'shim.o'
    subprocess.run([
        tool('clang'), '--target=aarch64-none-elf', '-c',
        f'-DFD_BASE={base}', f'-DFD_SIZE={size}',
        f'-DREQUIRES_KERNEL_HEADER={int(requires_header)}',
        f'-DPAYLOAD_BASE={payload_base}',
        str(source), '-o', str(obj),
    ], check=True)
    subprocess.run([tool('llvm-objcopy'), '-O', 'binary', str(obj), str(scratch / 'shim.bin')], check=True)
    shim = (scratch / 'shim.bin').read_bytes()
    symbols = subprocess.run([tool('llvm-nm'), '-n', str(obj)], capture_output=True, text=True, check=True).stdout
    offset = next((int(line.split()[0], 16) for line in symbols.splitlines() if line.endswith(' _Payload')), None)
    if offset != len(shim):
        sys.exit('a literal pool or padding separates the _Payload label from the volume')
    return shim


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--uefi', required=True, type=Path)
    ap.add_argument('--fd', required=True, type=Path)
    ap.add_argument('--payload', required=True, type=Path)
    ap.add_argument('--dtb', required=True, type=Path)
    ap.add_argument('--payload-base', default='0x93200000')
    ap.add_argument('--out', required=True, type=Path)
    args = ap.parse_args()

    cfg = config(args.uefi)
    base = cfg['uefi_fd']['base']
    size = cfg['uefi_fd']['size']
    image = dict(base=0, header_version=0, kernel_offset=0x8000, tags_offset=0x1e00000, pagesize=PAGE)
    image.update(cfg.get('boot_image', {}))
    requires_header = cfg.get('boot_shim', {}).get('requires_kernel_header', True)
    payload_base = int(args.payload_base, 16)

    firmware = args.fd.read_bytes()
    if len(firmware) != size:
        sys.exit(f'firmware volume is {len(firmware):#x} bytes, the config says {size:#x}')
    payload = args.payload.read_bytes()
    tree = args.dtb.read_bytes()
    if tree[:4] != b'\xd0\x0d\xfe\xed' or struct.unpack_from('>I', tree, 4)[0] != len(tree):
        sys.exit('invalid compiled device tree')

    with tempfile.TemporaryDirectory(prefix='pack-bootimg-') as tmp:
        scratch = Path(tmp)
        shim = compile_shim(args.uefi, base, size, requires_header, payload_base, scratch)
        combined = shim + firmware + XNUP + struct.pack('<I', len(payload)) + payload
        kernel_bytes = gzip.compress(combined, mtime=0) + tree
        kernel_path = scratch / 'Image.gz-dtb'
        kernel_path.write_bytes(kernel_bytes)
        ramdisk_path = scratch / 'ramdisk'
        ramdisk_path.write_bytes(b'')

        args.out.parent.mkdir(parents=True, exist_ok=True)
        command = [
            sys.executable, str(args.uefi / 'Resources/Scripts/mkbootimg.py'),
            '--kernel', str(kernel_path), '--ramdisk', str(ramdisk_path), '-o', str(args.out),
        ]
        for key in ('base', 'kernel_offset', 'tags_offset', 'pagesize', 'header_version', 'ramdisk_offset'):
            if key in image:
                command += [f'--{key}', str(image[key])]
        subprocess.run(command, check=True)

        # Unpack and compare every part with its input.
        data = args.out.read_bytes()
        ksize, kaddr, rsize, _, ssize, _, tags, page, version, _ = struct.unpack_from('<10I', data, 8)
        if data[:8] != b'ANDROID!' or version != image['header_version'] or page != image['pagesize']:
            sys.exit('boot image header does not match the requested parameters')
        if rsize != 0 or ssize != 0:
            sys.exit('ramdisk/second must be empty with the payload in the kernel')
        kernel = data[page:page + ksize]
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        back = d.decompress(kernel)
        if back != combined or not d.eof or d.unused_data != tree:
            sys.exit('gzip, firmware, payload and device tree do not round-trip')
        print(f'shim {len(shim)} bytes, firmware {len(firmware)} bytes, payload {len(payload)} bytes at {payload_base:#x}')
        print(f'image {args.out} ({len(data)} bytes), kernel field {ksize}, header v{version}')


if __name__ == '__main__':
    main()
