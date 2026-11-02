"""Repair the pinned driver's bootstrap readiness check, preserving link checks."""
import argparse
from pathlib import Path

OLD = '''    record = ctx.tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/osfmk/DEVELOPMENT/startup.o.json'
    if not record.is_file():
'''
NEW = '''    record = ctx.tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/osfmk/DEVELOPMENT/startup.o.json'
    def bootstrap_ready():
        # Mode changes can remove objects while leaving their compile records.
        # Archive builders need the actual objects to discover kernel symbols.
        filelist = record.parents[2] / 'link.filelist'
        if not record.is_file() or not record.with_suffix('').is_file() or not filelist.is_file():
            return False
        objects = [Path(line.strip()) for line in filelist.read_text().splitlines() if line.strip()]
        return bool(objects) and all((p if p.is_absolute() else ctx.tree / p).is_file() for p in objects)
    if not bootstrap_ready():
'''
OLD_AFTER = '''        except Error:
            if not record.is_file():
                raise
    storage = ctx.tree / 'build/storage-abi/include/IOKit/storage'
'''
NEW_AFTER = '''        except Error:
            if not bootstrap_ready():
                raise
        if not bootstrap_ready():
            raise Error('kernel bootstrap did not produce all required objects and compile records')
    storage = ctx.tree / 'build/storage-abi/include/IOKit/storage'
'''


def patch(path):
    source = path.read_text(encoding='utf-8')
    if NEW in source and NEW_AFTER in source:
        print('miniram bootstrap readiness: already applied')
        return
    if source.count(OLD) != 1 or source.count(OLD_AFTER) != 1:
        raise SystemExit('Pinned kernel driver changed; refusing to patch')
    source = source.replace(OLD, NEW, 1).replace(OLD_AFTER, NEW_AFTER, 1)
    compile(source, str(path), 'exec')
    path.write_text(source, encoding='utf-8')
    print('miniram bootstrap readiness: actual objects and records required')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unixnu', required=True, type=Path)
    args = parser.parse_args()
    patch(args.unixnu / 'scripts/unixnu/kernel.py')
