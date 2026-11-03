#!/usr/bin/env python3
"""Exercise the adapted upstream disk reader without attaching a real disk."""
import argparse
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--unixnu', required=True, type=Path)
args = parser.parse_args()
sys.path.insert(0, str(args.unixnu / 'scripts'))
from unixnu import userdata


class PartialReader(io.BytesIO):
    def read(self, size=-1):
        return super().read(min(size, 32768))


class UserdataReads(unittest.TestCase):
    def run_reader(self, data, expected):
        with patch.object(userdata.platform, 'system', return_value='Darwin'), \
                patch.object(userdata, 'attach', return_value='/dev/disk10'), \
                patch('builtins.open', return_value=PartialReader(data)) as opened, \
                patch.object(userdata.subprocess, 'run') as detached:
            try:
                return b''.join(userdata.disk_blocks(Path('fixture.dmg'), expected))
            finally:
                opened.assert_called_once_with('/dev/disk10', 'rb', buffering=0)
                detached.assert_called_once_with(['hdiutil', 'detach', '/dev/disk10'], capture_output=True)

    def test_partial_reads_and_sector_aligned_tail(self):
        # The failing production read starts at 5796 MiB, with 34,304 bytes
        # remaining in the UDIF disk. Keep that tail but use a small body.
        data = bytes(range(256)) * (2 * 4096) + b't' * 34304
        self.assertEqual(self.run_reader(data, len(data)), data)

    def test_premature_eof_is_rejected_and_detached(self):
        with self.assertRaisesRegex(userdata.Error, 'unexpected EOF.*read 32768 of 34304'):
            self.run_reader(b'x' * 32768, 34304)

    def test_no_read_beyond_declared_size(self):
        self.assertEqual(self.run_reader(b'x' * 4096 + b'extra', 4096), b'x' * 4096)


unittest.main(argv=[sys.argv[0]], verbosity=2)
