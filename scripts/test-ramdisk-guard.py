#!/usr/bin/env python3
"""Compile the actual payload guard and reject corrupt/out-of-window inputs."""
import argparse
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--unixnu', required=True, type=Path)
parser.add_argument('--payload-sector', type=Path, help='Optional real payload boot sector')
args = parser.parse_args()
adapter = runpy.run_path(str(Path(__file__).with_name('ramdisk-guard.py')))
source = (args.unixnu / adapter['DRIVER']).read_text(encoding='utf-8')
patched = adapter['patch'](source)
assert adapter['patch'](patched) == patched
assert adapter['patch'](source.replace('\n', '\r\n').replace('\r\n', '\n')) == patched
assert patched.count('if (!LmiPayloadPresent (') == 2
for name in ('PublishInitrd', 'PublishWindow'):
    body = patched[patched.index('\n' + name + ' ('):]
    body = body[:body.index('\n}\n')]
    assert body.index('if (!LmiPayloadPresent (') < body.index('mRamBase ')
    assert body.index('if (!LmiPayloadPresent (') < body.index('InstallMultipleProtocolInterfaces')

# Redirect only the validated physical window to a host buffer. The range check
# remains unchanged, so an invalid pointer crashes the test if read too early.
guard = adapter['GUARD'].replace('Boot = (CONST UINT8 *)(UINTN)Start;', 'Boot = Sector;')
harness = r'''
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
typedef uint8_t UINT8; typedef uint16_t UINT16; typedef uint32_t UINT32;
typedef uint64_t UINT64; typedef uintptr_t UINTN; typedef int BOOLEAN;
#define STATIC static
#define CONST const
#define TRUE 1
#define FALSE 0
#define RAM_BLOCK_SIZE 512
static UINT8 Sector[512];
static UINT16 ReadUnaligned16(const UINT16 *p) {UINT16 n;memcpy(&n,p,2);return n;}
static UINT32 ReadUnaligned32(const UINT32 *p) {UINT32 n;memcpy(&n,p,4);return n;}
'''
harness += guard
harness += r'''
static void put16(int p,UINT16 n) {memcpy(Sector+p,&n,2);}
static void put32(int p,UINT32 n) {memcpy(Sector+p,&n,4);}
static int present(void) {return LmiPayloadPresent(0x93200000ULL,0x98800000ULL);}
static void valid(void) {
 memset(Sector,0,sizeof(Sector));Sector[0]=0xeb;Sector[510]=0x55;Sector[511]=0xaa;
 put16(11,512);Sector[13]=4;put16(14,1);Sector[16]=2;
 put16(17,512);put32(32,0x5600000/512);put16(22,256);
}
int main(int argc,char **argv) {
 assert(!present()); memset(Sector,0xff,sizeof(Sector));assert(!present());
 valid();assert(present());
 assert(!LmiPayloadPresent(1,0x5600001));
 assert(!LmiPayloadPresent(0x93200000ULL,0));
 assert(!LmiPayloadPresent(0x93200000ULL,UINT64_MAX));
 Sector[511]=0;assert(!present());valid();put16(11,4096);assert(!present());
 valid();Sector[13]=3;assert(!present());valid();Sector[13]=0;assert(!present());
 valid();put16(14,0);assert(!present());valid();Sector[16]=0;assert(!present());
 valid();put32(32,0xffffffff);assert(!present());
 valid();put16(22,0);put32(36,0xffffffff);assert(!present());
 valid();put16(22,0);put16(17,0);put16(14,32);put32(36,400);assert(present());
 if(argc==2) {FILE *f=fopen(argv[1],"rb");assert(f);assert(fread(Sector,1,512,f)==512);fclose(f);assert(present());}
 puts("RAM disk guard: valid FAT16/FAT32, absent/corrupt payload, exact bounds, overflow cases passed");
 return 0;
}
'''
compiler = shutil.which('cc') or shutil.which('clang') or shutil.which('gcc')
if not compiler:
    fallback = Path('C:/msys64/ucrt64/bin/clang.exe')
    if fallback.is_file():
        compiler = str(fallback)
if not compiler:
    raise SystemExit('A host C compiler is required to test the actual guard')
with tempfile.TemporaryDirectory() as tmp:
    folder = Path(tmp)
    src, exe = folder / 'guard.c', folder / 'guard.exe'
    src.write_text(harness, encoding='utf-8')
    subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)] + ([str(args.payload_sector.resolve())] if args.payload_sector else []), check=True)
print('Payload guard placement and patch idempotence passed')
