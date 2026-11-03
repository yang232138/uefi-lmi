#!/usr/bin/env python3
"""Check diagnostics placement against fetched upstream C, before firmware build."""
import argparse
import contextlib
import io
from pathlib import Path
import runpy
import tempfile
import unittest

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--unixnu', required=True, type=Path)
args = parser.parse_args()
patch = runpy.run_path(str(Path(__file__).with_name('boot-stage-diagnostics.py')))['patch']
LOADER = Path('drivers/DarwinBoot/DarwinBootPkg/Driver/DarwinBoot.c')
MAIN = Path('package/UniXNUPkg/Library/UniXNULib/Main.c')


def function(source, name):
    start = source.index('\n' + name + ' (')
    return source[start:source.index('\n}\n', start) + 3]


class BootStages(unittest.TestCase):
    def check_source(self, newline):
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp)
            originals = {}
            for rel in (LOADER, MAIN):
                originals[rel] = (args.unixnu / rel).read_text(encoding='utf-8')
                dest = tree / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(originals[rel].replace('\n', newline).encode('utf-8'))
            with contextlib.redirect_stdout(io.StringIO()):
                patch(tree)
            source = (tree / LOADER).read_text(encoding='utf-8')
            # The failing revision inserted stage 05 in GetMap's retry loop.
            self.assertEqual(function(source, 'GetMap'), function(originals[LOADER], 'GetMap'))
            self.assertEqual(function(source, 'AllocateWindow'), function(originals[LOADER], 'AllocateWindow'))
            boot = function(source, 'Boot')
            stages = [boot.index('L"0' + str(n) + ' ') for n in range(1, 6)]
            self.assertEqual(stages, sorted(stages))
            self.assertLess(boot.index('CopyMem (Args->CommandLine'), stages[-1])
            # Final pause precedes the fresh memory map and ExitBootServices.
            map_read = boot.index('gBS->GetMemoryMap')
            exit_call = boot.index('gBS->ExitBootServices')
            self.assertLess(stages[-1], map_read)
            self.assertLess(map_read, exit_call)
            self.assertNotIn('LmiCheckpoint', boot[map_read:boot.index('Fail:')])
            self.assertEqual(source.count('LmiCheckpoint ('), 7)  # definition + 5 stages + failure
            self.assertLess(source.index('\nLmiCheckpoint ('), source.index('LmiCheckpoint (L"01'))
            snapshot = {rel: (tree / rel).read_bytes() for rel in (LOADER, MAIN)}
            with contextlib.redirect_stdout(io.StringIO()):
                patch(tree)
            self.assertEqual(snapshot, {rel: (tree / rel).read_bytes() for rel in snapshot})

    def test_loader_control_flow_and_idempotence(self):
        self.check_source('\n')

    def test_crlf_input(self):
        self.check_source('\r\n')


unittest.main(argv=[__file__], verbosity=2)
