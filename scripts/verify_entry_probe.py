#!/usr/bin/env python3
"""Verify the official payload result and unchanged menu-tested firmware."""
import argparse
import hashlib
import json
import struct
import tomllib
import zlib
from pathlib import Path
from pyfatfs.PyFatFS import PyFatFS
from entry_probe_inputs import SOURCE_ADT_SHA, SOURCE_IMAGE_SHA, SOURCE_KERNEL_SHA

def sha(data):
    return hashlib.sha256(data).hexdigest()

def verify_adt(old, new):
    """The generator refreshes only /chosen/random-seed on each build."""
    assert sha(old) == SOURCE_ADT_SHA and len(old) == len(new)
    spans = []
    def node(data, at, parent):
        count, children = struct.unpack_from('<II', data, at)
        at += 8
        properties = {}
        for _ in range(count):
            assert at + 36 <= len(data)
            name = data[at:at + 32].split(b'\0')[0].decode('ascii')
            size = struct.unpack_from('<I', data, at + 32)[0] & 0x7fffffff
            at += 36
            assert at + size <= len(data)
            properties[name] = (at, size)
            at += (size + 3) & ~3
        start, size = properties['name']
        name = data[start:start + size].split(b'\0')[0].decode('ascii')
        path = parent + '/' + name
        if path == '/device-tree/chosen':
            spans.append(properties['random-seed'])
        for _ in range(children):
            at = node(data, at, path)
        return at
    assert node(old, 0, '') == len(old)
    old_spans = list(spans)
    spans.clear()
    assert node(new, 0, '') == len(new)
    assert spans == old_spans and len(spans) == 1
    offset, size = spans[0]
    assert size == 64
    normalized = bytearray(new)
    normalized[offset:offset + size] = old[offset:offset + size]
    assert bytes(normalized) == old, 'ADT differs beyond the regenerated random seed'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', required=True, type=Path)
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--payload', required=True, type=Path)
    ap.add_argument('--log', required=True, type=Path)
    ap.add_argument('--probe-script', required=True, type=Path)
    ap.add_argument('--source-adt', required=True, type=Path)
    args = ap.parse_args()
    out = args.out
    meta = json.loads((out / 'boot.json').read_text())
    source = json.loads((args.source / 'boot.json').read_text())
    report = json.loads((out / 'payload.json').read_text())
    assert report['kernel_sha256'] == SOURCE_KERNEL_SHA
    assert report['payload_kernel_sha256'] != SOURCE_KERNEL_SHA
    assert report['panic_screen'] is False and report['kernel_args'] == '-v serial=3'
    assert report['trust_cache_sha256'] is None and report['data_ramdisk_sha256'] is None
    log = args.log.read_text()
    assert 'stage 1 blue bar, stage 2 magenta bar, stage 4 reset after call #1 to _kprintf in _arm_init' in log
    fd = (out / 'SILICIUM_UEFI.fd').read_bytes()
    assert sha(fd) == meta['fd_sha256'] == source['fd_sha256']
    assert meta['shim_sha256'] == source['shim_sha256']
    assert meta['dtb_sha256'] == source['dtb_sha256']
    boot = (out / 'boot.img').read_bytes()
    assert sha(boot) == meta['image_sha256']
    p = struct.unpack_from('<I', boot, 36)[0]
    k = struct.unpack_from('<I', boot, 8)[0]
    d = zlib.decompressobj(31)
    raw = d.decompress(boot[p:p + k])
    s = meta['shim_bytes']
    payload = args.payload.read_bytes()
    assert d.eof and sha(d.unused_data) == source['dtb_sha256']
    assert raw[s:s + len(fd)] == fd and raw[s + len(fd):s + len(fd) + 8] == b'XNUP' + struct.pack('<I', len(payload))
    assert raw[s + len(fd) + 8:] == payload
    assert sha(payload) == report['payload_sha256'] == meta['payload_sha256']
    fs = PyFatFS(str(args.payload), read_only=True)
    try:
        cfg = tomllib.loads(fs.readtext('/EFI/UniXNU/unixnu.toml'))
        kernel = fs.readbytes('/EFI/UniXNU/Payloads/kernel.macho')
        adt = fs.readbytes('/EFI/UniXNU/Payloads/kernel.macho.adt')
    finally:
        fs.close()
    assert sha(kernel) == report['payload_kernel_sha256'] and sha(adt) == report['adt_sha256']
    verify_adt(args.source_adt.read_bytes(), adt)
    assert any(e.get('id') == 'xnu' and e.get('args') == '-v serial=3' for e in cfg['entry'])
    check = dict(documentation='https://unixnu.com/zh/guide/debugging#交接时的绿色条',
                 source_image_sha256=SOURCE_IMAGE_SHA, source_run=40840362988,
                 official_probe_revision='ee472385743ebd16941ab14892dcb9d02e219d15',
                 official_probe_script_sha256=sha(args.probe_script.read_bytes()),
                 unchanged_firmware=True, unchanged_shim=True, unchanged_dtb=True,
                 adt_equivalent_except_random_seed=True, adt_random_seed_bytes=64,
                 source_adt_sha256=SOURCE_ADT_SHA, payload_adt_sha256=sha(adt),
                 original_kernel_rebuilt=False,
                 entry_probe=True, panic_screen=False, timed_reset=True, reset_delay_seconds=6, reset_after="_kprintf", reset_in="_arm_init", reset_occurrence=1,
                 source_observation='Under FD 720481eb15e6cb3a6552c717ee6e912649a9c81eef18c95ab00dff7627530ee6, post-startup reset passed and post-PE_init_printf reset did not occur; check first kprintf next',
                 hardware_test='pending', boot_sha256=meta['image_sha256'])
    (out / 'probe-verification.json').write_text(json.dumps(check, indent=2) + '\n')
    print(json.dumps(check, indent=2))

if __name__ == '__main__':
    main()
