#!/usr/bin/env python3
"""Package a one-time USB bootloader identity migration; never alter runtime code."""

import argparse
import os
from pathlib import Path
import re
import stat
import struct
import tempfile


FAMILY = 0xD663823C
CF2_MAGIC = (0x1E9E10F1, 0x20227A79)
# Release linker layouts only. Debug/different-address bootloaders cannot self-update.
LAYOUTS = {
    "nrf52840": (0xF4000, 0xFD800, 0xFE000, 0x100000, 0xADA52840),
    "nrf52833": (0x74000, 0x7D800, 0x7E000, 0x80000, 0x621E937A),
}


def identity(text):
    if not re.fullmatch(r"0[xX][0-9a-fA-F]{8}", text):
        raise ValueError("identity must be 0x followed by eight hexadecimal digits (VID/PID)")
    value = int(text, 16)
    if value >> 16 in (0, 0xFFFF) or value & 0xFFFF in (0, 0xFFFF):
        raise ValueError("identity requires nonzero, non-FFFF USB VID and PID")
    return value


def migrate(data, source_id, target_id, mcu):
    """Return original UF2 bytes with only the verified CF2 key 208 value changed."""
    for value in (source_id, target_id):
        identity(f"0x{value:08x}")
    if source_id == target_id:
        raise ValueError("source and target identities must differ")
    if mcu not in LAYOUTS:
        raise ValueError("migration requires a supported USB MCU (nrf52840 or nrf52833)")
    start, config, end, flash_size, app_family = LAYOUTS[mcu]
    if not data or len(data) % 512:
        raise ValueError("UF2 must contain complete 512-byte blocks")
    blocks = {}
    magic_addresses = []
    count = len(data) // 512
    for index in range(count):
        offset = index * 512
        magic0, magic1, flags, address, size, number, total, family = struct.unpack_from("<8I", data, offset)
        if (magic0, magic1, struct.unpack_from("<I", data, offset + 508)[0]) != (0x0A324655, 0x9E5D5157, 0x0AB16F30):
            raise ValueError("invalid UF2 magic")
        if flags != 0x2000 or family != FAMILY or size != 256:
            raise ValueError("requires ordinary 256-byte bootloader-family UF2 blocks")
        if number != index or total != count or address % 256 or address in blocks:
            raise ValueError("invalid UF2 numbering, alignment, or duplicate address")
        if not (address < 0x1000 or start <= address < end or address == 0x10001000):
            raise ValueError(f"incompatible address 0x{address:08x}; use the standard no-SoftDevice release UF2")
        blocks[address] = offset + 32
        for pos in range(0, 252, 4):
            if struct.unpack_from("<2I", data, offset + 32 + pos) == CF2_MAGIC:
                magic_addresses.append(address + pos)
    if magic_addresses != [config]:
        raise ValueError("missing, misplaced, or ambiguous CF2 header")

    def word(address):
        try:
            return struct.unpack_from("<I", data, blocks[address & ~255] + (address & 255))[0]
        except KeyError:
            raise ValueError(f"missing required data at 0x{address:08x}") from None

    if word(0x10001014) != start or word(0x10001018) != end:
        raise ValueError("UICR bootloader start or MBR parameter address does not match release layout")
    # Require actual bootloader vector data as well as its metadata.
    stack, reset = word(start), word(start + 4)
    if not (0x20000000 < stack <= 0x20000000 + (0x40000 if mcu == "nrf52840" else 0x20000)) or not (reset & 1 and start <= (reset & ~1) < config):
        raise ValueError("invalid bootloader vector table")
    used, capacity = word(config + 8), word(config + 12)
    if not (0 < used <= capacity <= (end - config - 16) // 8):
        raise ValueError("invalid CF2 entry counts")
    entries = {}
    value_address = None
    for index in range(used):
        address = config + 16 + index * 8
        key, value = word(address), word(address + 4)
        if not key or key in entries:
            raise ValueError("invalid or duplicate CF2 key")
        entries[key] = value
        if key == 208:
            value_address = address + 4
    if entries.get(204) != flash_size or entries.get(209) != app_family:
        raise ValueError("CF2 flash size or application family does not match MCU")
    if entries.get(208) != target_id:
        raise ValueError("CF2 identity does not match expected target; wrong input or already migrated")
    # The receiver scans all aligned pairs, not just the CF2 used-entry count.
    matches = []
    for address, offset in blocks.items():
        if config <= address < end:
            for pos in range(0, 256, 8):
                if struct.unpack_from("<I", data, offset + pos)[0] == 208:
                    matches.append(address + pos + 4)
    if matches != [value_address]:
        raise ValueError("ambiguous CF2 identity in receiver-scanned region")
    result = bytearray(data)
    offset = blocks[value_address & ~255] + (value_address & 255)
    struct.pack_into("<I", result, offset, source_id)
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--mcu", required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--target-id", required=True)
    args = parser.parse_args()
    try:
        source, target = identity(args.source_id), identity(args.target_id)
        if not re.fullmatch(r"[A-Za-z0-9_-]+", args.board):
            raise ValueError("invalid board name")
        result = migrate(args.input.read_bytes(), source, target, args.mcu)
        output = args.output_dir / f"migration-{args.board}-from-{source:08x}-to-{target:08x}.uf2"
        if output.resolve() == args.input.resolve():
            raise ValueError("migration output must not replace input")
        args.output_dir.mkdir(parents=True, exist_ok=True)
        if output.is_symlink():
            raise ValueError("migration output must not be a symlink")
        if output.exists():
            metadata = output.stat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or output.samefile(args.input):
                raise ValueError("migration output must be a regular single-link file distinct from input")
            previous = output.read_bytes()
            # Only replace a previously packaged migration for this identity/layout.
            migrate(previous, target, source, args.mcu)
            if previous == result:
                print(f"Up to date: {output}")
                return
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=args.output_dir, prefix=f".{output.name}.", delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(result)
            os.replace(temporary, output)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(f"Created {output}; only CF2 key 208 changed. Runtime identity remains 0x{target:08x}.")


if __name__ == "__main__":
    main()
