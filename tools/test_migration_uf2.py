"""Host-only migration safety regressions: python3 -m unittest discover -s tools -p 'test_*.py'."""

import contextlib
import io
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from migration_uf2 import CF2_MAGIC, FAMILY, LAYOUTS, identity, main, migrate


SOURCE = 0x12097694
TARGET = 0x12097693


def fixture(mcu="nrf52840", extra_entries=()):
    start, config, end, flash, family = LAYOUTS[mcu]
    payloads = {0: bytearray(256), start: bytearray(256), config: bytearray(256), 0x10001000: bytearray(256)}
    struct.pack_into("<2I", payloads[start], 0, 0x20010000, start + 9)
    entries = [(204, flash), (205, 0x20000), (208, TARGET), (209, family), (210, 32)] + list(extra_entries)
    struct.pack_into("<4I", payloads[config], 0, *CF2_MAGIC, len(entries), 100)
    for index, pair in enumerate(entries):
        struct.pack_into("<2I", payloads[config], 16 + index * 8, *pair)
    struct.pack_into("<2I", payloads[0x10001000], 0x14, start, end)
    blocks = []
    for number, (address, payload) in enumerate(sorted(payloads.items())):
        header = struct.pack("<8I", 0x0A324655, 0x9E5D5157, 0x2000, address, 256, number, len(payloads), FAMILY)
        blocks.append(header + payload + bytes(220) + struct.pack("<I", 0x0AB16F30))
    return b"".join(blocks)


def changed(data, offset, value):
    result = bytearray(data)
    struct.pack_into("<I", result, offset, value)
    return bytes(result)


class MigrationTests(unittest.TestCase):
    def test_changes_only_identity_for_both_usb_layouts(self):
        for mcu in LAYOUTS:
            with self.subTest(mcu=mcu):
                original = fixture(mcu)
                offset = 2 * 512 + 32 + 16 + 2 * 8 + 4
                expected = changed(original, offset, SOURCE)
                result = migrate(original, SOURCE, TARGET, mcu)
                self.assertEqual(result, expected)
                self.assertEqual(original[offset:offset + 4], struct.pack("<I", TARGET))
                with self.assertRaisesRegex(ValueError, "identity"):
                    migrate(result, SOURCE, TARGET, mcu)

    def test_rejects_corrupt_or_incompatible_metadata(self):
        original = fixture()
        cf2 = 2 * 512 + 32
        uicr = 3 * 512 + 32
        cases = {
            "magic": (0, 0), "end magic": (508, 0),
            "flags": (8, 0x2001), "family": (28, 0xADA52840),
            "size": (16, 128), "number": (20, 1), "count": (24, 5),
            "unaligned": (12, 1), "application": (12, 0x26000),
            "duplicate address": (512 + 12, 0),
            "boot address": (uicr + 0x14, 0xED000),
            "MBR address": (uicr + 0x18, 0xFF000),
            "vector": (512 + 32 + 4, 0x26001),
            "CF2 magic": (cf2, 0), "CF2 used": (cf2 + 8, 101),
            "CF2 capacity": (cf2 + 12, 256), "CF2 truncated": (cf2 + 8, 40),
            "target identity": (cf2 + 36, SOURCE),
            "missing identity": (cf2 + 32, 207),
            "flash size": (cf2 + 20, 0x80000),
            "application family": (cf2 + 44, 0x621E937A),
            "unused identity": (cf2 + 56, 208),
        }
        for name, (offset, value) in cases.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                migrate(changed(original, offset, value), SOURCE, TARGET, "nrf52840")

    def test_rejects_ambiguous_cf2(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            migrate(fixture(extra_entries=[(208, TARGET)]), SOURCE, TARGET, "nrf52840")
        data = bytearray(fixture())
        struct.pack_into("<2I", data, 32, *CF2_MAGIC)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            migrate(data, SOURCE, TARGET, "nrf52840")

    def test_rejects_missing_data_and_non_usb(self):
        for data in (b"", fixture()[:-1], fixture()[:512]):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                migrate(data, SOURCE, TARGET, "nrf52840")
        with self.assertRaisesRegex(ValueError, "USB MCU"):
            migrate(fixture(), SOURCE, TARGET, "nrf52832")
        with self.assertRaisesRegex(ValueError, "differ"):
            migrate(fixture(), TARGET, TARGET, "nrf52840")
        with self.assertRaises(ValueError):
            migrate(fixture(), SOURCE, TARGET, "nrf52833")

    def test_identity_validation(self):
        self.assertEqual(identity("0x12097694"), SOURCE)
        for text in ("", "12097694", "-1", "0x100000000", "0x00007694", "0x12090000", "0xFFFF7694", "0x1209FFFF", "0x1209769g"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                identity(text)

    def test_cli_rebuilds_migration_without_overwriting_standard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            standard = root / "standard.uf2"
            standard.write_bytes(fixture())
            output = root / "migration-board-from-12097694-to-12097693.uf2"
            argv = ["migration_uf2.py", "--input", str(standard),
                    "--output-dir", str(root), "--board", "board",
                    "--mcu", "nrf52840", "--source-id", "0x12097694",
                    "--target-id", "0x12097693"]
            with patch("sys.argv", argv), contextlib.redirect_stdout(io.StringIO()):
                main()
            self.assertEqual(output.read_bytes(), migrate(fixture(), SOURCE, TARGET, "nrf52840"))
            self.assertEqual(standard.read_bytes(), fixture())
            first_stat = output.stat()
            with patch("sys.argv", argv), contextlib.redirect_stdout(io.StringIO()):
                main()
            self.assertEqual(output.stat().st_mtime_ns, first_stat.st_mtime_ns)
            updated = changed(fixture(), 512 + 32 + 64, 0x12345678)
            standard.write_bytes(updated)
            with patch("sys.argv", argv), contextlib.redirect_stdout(io.StringIO()):
                main()
            self.assertEqual(output.read_bytes(), migrate(updated, SOURCE, TARGET, "nrf52840"))
            self.assertEqual(standard.read_bytes(), updated)
            self.assertEqual(set(root.iterdir()), {standard, output})
            output.unlink()
            output.symlink_to(standard)
            with patch("sys.argv", argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main()
            self.assertEqual(standard.read_bytes(), updated)
            output.unlink()
            os.link(standard, output)
            with patch("sys.argv", argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main()
            self.assertEqual(standard.read_bytes(), updated)
            output.unlink()
            # A regular standard file at the migration path must not be replaced either.
            output.write_bytes(updated)
            with patch("sys.argv", argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main()
            self.assertEqual(output.read_bytes(), updated)
            self.assertEqual(standard.read_bytes(), updated)
            # Input/output alias is rejected even when the input name looks like a migration.
            argv[2] = str(output)
            with patch("sys.argv", argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main()
            self.assertEqual(output.read_bytes(), updated)


if __name__ == "__main__":
    unittest.main()
