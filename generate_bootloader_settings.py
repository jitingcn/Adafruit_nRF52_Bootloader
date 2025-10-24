#!/usr/bin/env python3
"""
Bootloader Settings Generator for nRF52 Adafruit Bootloader

This script generates correct bootloader settings hex file for nRF52 devices
by analyzing an application hex file and calculating the appropriate CRC.

Usage:
    python generate_bootloader_settings.py <application_hex_file> [output_hex_file]

Example:
    python generate_bootloader_settings.py zephyr.hex settings.hex
"""

import sys
import struct
import argparse
from pathlib import Path


def crc16_ccitt(data, length):
    """Calculate CRC16-CCITT checksum for the given data (legacy function)."""
    crc = 0xFFFF
    for i in range(length):
        crc ^= data[i] << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


def parse_intel_hex(hex_file_path):
    """Parse Intel HEX file and return application data and size."""
    print(f"Parsing application hex file: {hex_file_path}")

    # Initialize 64KB buffer (nRF52 application space)
    app_data = bytearray(0x10000)
    max_addr = 0

    try:
        with open(hex_file_path, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: File '{hex_file_path}' not found!")
        return None, 0
    except Exception as e:
        print(f"Error reading file: {e}")
        return None, 0

    extended_addr = 0

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line.startswith(':'):
            continue

        try:
            # Parse Intel HEX record
            byte_count = int(line[1:3], 16)
            address = int(line[3:7], 16)
            record_type = int(line[7:9], 16)

            # Handle extended linear address records
            if record_type == 4:  # Extended Linear Address Record
                extended_addr = int(line[9:13], 16) << 16
                continue
            elif record_type == 1:  # End of file record
                break
            elif record_type != 0:  # Skip non-data records
                continue

            # Data record
            full_address = address + extended_addr

            # Only process data within application space (0x0000 - 0xFFFF)
            if full_address < 0x10000:
                data = bytes.fromhex(line[9:9+byte_count*2])
                app_data[full_address:full_address+len(data)] = data
                max_addr = max(max_addr, full_address + len(data))

        except (ValueError, IndexError) as e:
            print(f"Warning: Invalid hex record at line {line_num}: {line}")
            continue

    # Find actual application size (last non-0xFF byte + 1)
    actual_size = max_addr
    print(f"Max address found: 0x{max_addr:X}")

    # For nRF52 applications, we should use the max_addr as the size
    # since this represents the actual range of the application
    app_size = max_addr

    # If max_addr is 0, means no valid data found
    if app_size == 0:
        print("Warning: No application data found!")

    print(f"Application size: 0x{app_size:X} bytes ({app_size} bytes)")
    print(f"Last used address: 0x{max_addr:X}")

    return app_data, app_size


def generate_intel_hex_record(address, data):
    """Generate an Intel HEX record for given address and data."""
    byte_count = len(data)
    addr_high = (address >> 8) & 0xFF
    addr_low = address & 0xFF
    record_type = 0x00

    # Calculate checksum
    checksum = byte_count + addr_high + addr_low + record_type
    for byte in data:
        checksum += byte
    checksum = (-checksum) & 0xFF

    return f':{byte_count:02X}{address:04X}{record_type:02X}{data.hex().upper()}{checksum:02X}'


def nordic_crc16_compute(data, size, initial_crc=None):
    """
    Calculate CRC16 using Nordic SDK algorithm from crc16.c
    This is the actual algorithm used by the bootloader for validation.
    """
    crc = 0xFFFF if initial_crc is None else initial_crc

    for i in range(size):
        # Step 1: Swap bytes
        crc = (crc >> 8) | (crc << 8)
        crc &= 0xFFFF

        # Step 2: XOR with data byte
        crc ^= data[i]

        # Step 3: XOR with low nibble of low byte shifted right by 4
        crc ^= (crc & 0xFF) >> 4

        # Step 4: XOR with crc << 12
        crc ^= crc << 12
        crc &= 0xFFFF

        # Step 5: XOR with (crc & 0xFF) << 5
        crc ^= (crc & 0xFF) << 5
        crc &= 0xFFFF

    return crc

def generate_bootloader_settings(app_data, app_size, output_file, enable_crc_check=False):
    """Generate bootloader settings hex file."""
    print(f"\nGenerating bootloader settings...")

    if enable_crc_check:
        # Calculate Nordic CRC16 for the application
        app_crc = nordic_crc16_compute(app_data, app_size)
        print(f"Application Nordic CRC16: 0x{app_crc:04X}")
        print(f"CRC checking: ENABLED")
    else:
        # Disable CRC checking by setting CRC to 0
        app_crc = 0x0000
        print(f"Application CRC16: 0x{app_crc:04X} (CRC checking DISABLED)")

    # Create bootloader settings structure (Nordic nRF52 format)
    # typedef struct {
    #     uint16_t bank_0;          // 0x01 = BANK_VALID_APP
    #     uint16_t bank_0_crc;      // Application CRC or 0x0000 to disable checking
    #     uint16_t bank_1;          // 0xFF = BANK_INVALID_APP
    #     uint32_t bank_0_size;     // Size of application
    #     uint32_t sd_image_size;   // SoftDevice size (0 for app-only)
    #     uint32_t bl_image_size;   // Bootloader size (0 for app-only)
    #     uint32_t app_image_size;  // Application size (0 for app-only)
    #     uint32_t sd_image_start;  // SoftDevice start address (0 for app-only)
    # } bootloader_settings_t;     // 28 bytes total

    # Create bootloader settings with explicit padding
    # The C struct has padding after bank_1 to align bank_0_size to 4-byte boundary
    settings_data = struct.pack('<HHH',  # First 3 uint16_t fields
                               0x0001,   # bank_0 = BANK_VALID_APP
                               app_crc,  # bank_0_crc
                               0x00FF)   # bank_1 = BANK_INVALID_APP

    # Add 2 bytes padding for 4-byte alignment
    settings_data += struct.pack('<H', 0x0000)  # padding

    # Add the remaining uint32_t fields
    settings_data += struct.pack('<IIIII',  # 5 uint32_t fields
                                app_size,   # bank_0_size
                                0,          # sd_image_size
                                0,          # bl_image_size
                                0,          # app_image_size
                                0)          # sd_image_start

    settings = settings_data

    # Pad to 32 bytes (bootloader expects this)
    settings += b'\xFF' * (32 - len(settings))

    print(f"Settings data (32 bytes): {settings.hex().upper()}")

    # Generate Intel HEX file for bootloader settings
    # Settings are located at 0xFF000 (with extended address 0x000F0000)
    hex_lines = []

    # Extended Linear Address Record for 0x000F0000
    ext_addr = 0x000F
    ext_data = struct.pack('>H', ext_addr)
    checksum = 2 + 0 + 4 + ext_data[0] + ext_data[1]
    checksum = (-checksum) & 0xFF
    hex_lines.append(f':02000004{ext_addr:04X}{checksum:02X}')

    # Settings data at offset 0xF000 (actual address 0xFF000)
    hex_lines.append(generate_intel_hex_record(0xF000, settings[:16]))
    hex_lines.append(generate_intel_hex_record(0xF010, settings[16:32]))

    # End of file record
    hex_lines.append(':00000001FF')

    hex_content = '\n'.join(hex_lines) + '\n'

    # Write to output file
    try:
        with open(output_file, 'w') as f:
            f.write(hex_content)
        print(f"\n✅ Bootloader settings saved to: {output_file}")
        print(f"Settings address: 0xFF000 (0x000F0000 + 0xF000)")
        print(f"Bank flag: 0x01 (BANK_VALID_APP)")
        print(f"CRC: 0x{app_crc:04X}")

    except Exception as e:
        print(f"Error writing output file: {e}")
        return False

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Generate bootloader settings hex file for nRF52 Adafruit bootloader",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s zephyr.hex                    # Generate settings_zephyr.hex
  %(prog)s app.hex bootloader_cfg.hex    # Generate bootloader_cfg.hex

The generated settings file can be merged with bootloader and application:
  mergehex -m bootloader.hex app.hex settings.hex -o complete.hex
        """
    )

    parser.add_argument('input_hex',
                       help='Input application hex file')
    parser.add_argument('output_hex', nargs='?',
                       help='Output bootloader settings hex file (default: settings_<input_name>.hex)')
    parser.add_argument('--enable-crc', action='store_true',
                       help='Enable CRC checking (default: disabled for compatibility)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')

    args = parser.parse_args()

    # Validate input file
    input_path = Path(args.input_hex)
    if not input_path.exists():
        print(f"Error: Input file '{args.input_hex}' does not exist!")
        return 1

    # Generate output filename if not provided
    if args.output_hex:
        output_path = Path(args.output_hex)
    else:
        output_path = input_path.parent / f"settings_{input_path.stem}.hex"

    print("=" * 60)
    print("nRF52 Bootloader Settings Generator")
    print("=" * 60)

    # Parse application hex file
    app_data, app_size = parse_intel_hex(input_path)
    if app_data is None:
        return 1

    if app_size == 0:
        print("Error: No valid application data found in hex file!")
        return 1

    # Generate bootloader settings
    if not generate_bootloader_settings(app_data, app_size, output_path, args.enable_crc):
        return 1

    print("\n" + "=" * 60)
    print("🚀 Next steps:")
    print(f"1. Merge files: mergehex -m bootloader.hex {input_path.name} {output_path.name} -o firmware.hex")
    print("2. Flash firmware: nrfjprog --log --family nRF52 --program firmware.hex --sectoranduicrerase --verify --reset")

    if args.enable_crc:
        print("\n⚠️  CRC checking is ENABLED. Application must match exactly.")
    else:
        print("\n✅ CRC checking is DISABLED for maximum compatibility.")

    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
