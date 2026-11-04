"""Validate a freshly compiled ARM64 Mach-O and record its pinned build inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess


def revision(path):
    return subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()


def inspect_kernel(data):
    if len(data) < 32:
        raise ValueError('Truncated Mach-O header')
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from('<8I', data)
    if magic != 0xfeedfacf or cpu != 0x100000c or kind != 2:
        raise ValueError('Expected an ARM64 Mach-O executable')
    end = 32 + size
    if end > len(data):
        raise ValueError('Truncated load commands')
    cursor, entry, segments = 32, None, []
    for _ in range(count):
        if cursor + 8 > end:
            raise ValueError('Missing load command')
        command, length = struct.unpack_from('<II', data, cursor)
        if length < 8 or length % 4 or cursor + length > end:
            raise ValueError('Invalid load command bounds')
        if command == 0x19:
            if length < 72:
                raise ValueError('Truncated segment')
            name = data[cursor+8:cursor+24].split(b'\0')[0].decode('ascii')
            va, vm_size, offset, file_size, maxprot, initprot = struct.unpack_from('<4Q2I', data, cursor+24)
            if file_size > vm_size or offset + file_size > len(data):
                raise ValueError('Invalid segment bounds')
            segments.append(dict(name=name, va=va, vm_size=vm_size, offset=offset,
                                 file_size=file_size, initprot=initprot))
        elif command == 5:
            if entry is not None or length < 288:
                raise ValueError('Invalid ARM64 thread state')
            flavor, words = struct.unpack_from('<II', data, cursor+8)
            if flavor != 6 or words != 68:
                raise ValueError('Unexpected thread flavor')
            entry = struct.unpack_from('<Q', data, cursor+16+32*8)[0]
        cursor += length
    if cursor != end or entry is None:
        raise ValueError('Missing entry or inconsistent command count')
    matches = [s for s in segments if s['va'] <= entry < s['va'] + s['file_size'] and s['initprot'] & 4]
    if len(matches) != 1:
        raise ValueError('Entry must belong to exactly one file-backed executable segment')
    s = matches[0]
    word = struct.unpack_from('<I', data, s['offset'] + entry - s['va'])[0]
    if word >> 26 != 0b000101:
        raise ValueError('Expected the native entry branch, without a binary probe')
    return dict(entry_va=hex(entry), entry_word=hex(word), segments=segments)


def main():
    parser = argparse.ArgumentParser()
    for name in ['unixnu', 'device', 'out']:
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    kernel, = args.unixnu.glob('out/**/kernel/kernel.macho')
    data = kernel.read_bytes()
    report = inspect_kernel(data)
    args.out.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(kernel, args.out / 'kernel.macho')
    shutil.copyfile(args.device / 'board.toml', args.out / 'board.toml')
    shutil.copyfile(args.device / 'configs/lmipro_defconfig', args.out / 'lmipro_defconfig')
    shutil.copyfile('resolved-kernel.json', args.out / 'resolved-kernel.json')
    for lock in args.unixnu.glob('out/**/unixnu.lock'):
        target = args.out / 'locks' / lock.relative_to(args.unixnu)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(lock, target)
    report.update(kernel_bytes=len(data), kernel_sha256=hashlib.sha256(data).hexdigest(),
                  unixnu_commit=revision(args.unixnu), device_commit=revision(args.device),
                  workflow_commit=os.environ['GITHUB_SHA'], run_id=int(os.environ['GITHUB_RUN_ID']),
                  fresh_build_no_cache=True, binary_entry_probe_applied=False,
                  hardware_tested=False, system_boot_confirmed=False)
    (args.out / 'kernel-build.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'segments'}, indent=2))


if __name__ == '__main__':
    main()
