"""Host flash/WDT regressions: python3 -m unittest discover -s tools -p 'test_flash_wdt.py'.

CC selects the host C compiler; BOOTLOADER_SOURCE_ROOT selects source for A/B runs.
Requires POSIX mmap and a free low-address
mapping for the firmware's uint32_t flash addresses. Production C is compiled
unchanged except for replacing its hardware includes with this modeled HAL.
The deterministic 100 ms watchdog, 90 ms erase and 40 ms write durations model
operation boundaries, not hardware timing, interrupt behavior or hardware proof.
"""

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(os.environ.get("BOOTLOADER_SOURCE_ROOT", Path(__file__).resolve().parents[1]))
FLASH = ROOT / "src/flash_nrf5x.c"

HAL = r"""
#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define CODE_PAGE_SIZE 4096u
#define NRFX_CEIL_DIV(a, b) (((a) + (b) - 1) / (b))
#define PRINTF(...) ((void)0)
#define WDT_RUNSTATUS_RUNSTATUS_Running 1u
#define WDT_RR_RR_Reload 0x6e524635u
#define SENTINEL 0x12345678u
static struct { uint32_t RUNSTATUS, RREN, RR[8]; } wdt;
#define NRF_WDT (&wdt)
static uint64_t now, deadline;
static bool expired;
static uint8_t *memory;
static uint32_t base;
#define FLASH_BYTES (8 * CODE_PAGE_SIZE)

/* RR writes are sampled at the next blocking operation, with no modeled
 * elapsed time between the feed and that operation. Every enabled channel
 * must reload; disabled reload registers must remain untouched. */
static void operation(unsigned duration) {
    bool all_reloaded = wdt.RREN != 0;
    for (unsigned i = 0; i < 8; ++i) {
        if (wdt.RUNSTATUS && (wdt.RREN & (1u << i))) {
            all_reloaded &= wdt.RR[i] == WDT_RR_RR_Reload;
        } else {
            assert(wdt.RR[i] == SENTINEL);
        }
    }
    if (wdt.RUNSTATUS && all_reloaded) deadline = now + 100;
    for (unsigned i = 0; i < 8; ++i) wdt.RR[i] = SENTINEL;
    now += duration;
    if (wdt.RUNSTATUS && now >= deadline) expired = true;
}

static void nrfx_nvmc_page_erase(uint32_t address) {
    assert(address >= base && address <= base + FLASH_BYTES - CODE_PAGE_SIZE);
    assert(address % CODE_PAGE_SIZE == 0);
    operation(90);
    memset((void *)(uintptr_t)address, 0xff, CODE_PAGE_SIZE);
}

static void nrfx_nvmc_words_write(uint32_t address, const uint32_t *words,
                                  uint32_t count) {
    assert(address >= base && address <= base + FLASH_BYTES - count * 4);
    operation(40);
    uint8_t *destination = (uint8_t *)(uintptr_t)address;
    const uint8_t *source = (const uint8_t *)words;
    for (unsigned i = 0; i < count * 4; ++i) destination[i] &= source[i];
}
"""

CHECKS = r"""
static void reset(bool running, unsigned mask) {
    memset(memory, 0xff, FLASH_BYTES);
    _fl_addr = FLASH_CACHE_INVALID_ADDR;
    wdt.RUNSTATUS = running;
    wdt.RREN = mask;
    for (unsigned i = 0; i < 8; ++i) wdt.RR[i] = SENTINEL;
    now = 90; /* Only 10 ms remain before the first operation. */
    deadline = 100;
    expired = false;
}

static void check_bytes(const uint8_t *data, unsigned size, uint8_t value) {
    for (unsigned i = 0; i < size; ++i) assert(data[i] == value);
}

static void bulk(bool running, unsigned mask) {
    reset(running, mask);
    memset(memory, 0, FLASH_BYTES);
    /* Exercise alignment and ceiling division as well as multiple pages. */
    flash_nrf5x_erase(base + 4, 3 * CODE_PAGE_SIZE + 1);
    assert(!expired);
    check_bytes(memory, 4 * CODE_PAGE_SIZE, 0xff);
    check_bytes(memory + 4 * CODE_PAGE_SIZE, 4 * CODE_PAGE_SIZE, 0);
}

static void flush(bool running, unsigned mask, bool erase) {
    reset(running, mask);
    uint8_t payload[2 * CODE_PAGE_SIZE];
    memset(payload, 0xa5, sizeof payload);
    if (erase) memset(memory, 0, FLASH_BYTES);
    /* Page transition flushes the first page; explicit flush writes second. */
    flash_nrf5x_write(base, payload, sizeof payload, erase);
    flash_nrf5x_flush(erase);
    assert(!expired);
    assert(memcmp(memory, payload, sizeof payload) == 0);
    check_bytes(memory + sizeof payload, FLASH_BYTES - sizeof payload,
                erase ? 0 : 0xff);
}

static void noops(bool running, unsigned mask) {
    reset(running, mask);
    flash_nrf5x_flush(true); /* Invalid cache. */
    flash_nrf5x_erase(base, 0);
    flash_nrf5x_write(base, memory, 0, true);
    flash_nrf5x_write(base, memory, CODE_PAGE_SIZE, true);
    flash_nrf5x_flush(true); /* Valid but identical cache. */
    flash_nrf5x_flush(false);
    assert(now == 90 && deadline == 100 && !expired);
    for (unsigned i = 0; i < 8; ++i) assert(wdt.RR[i] == SENTINEL);
    check_bytes(memory, FLASH_BYTES, 0xff);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    memory = mmap((void *)0x10000000, FLASH_BYTES, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(memory != MAP_FAILED);
    assert((uintptr_t)memory <= UINT32_MAX - FLASH_BYTES);
    base = (uint32_t)(uintptr_t)memory;
    unsigned mode = (unsigned)atoi(argv[1]);
    /* Includes sparse first/last channels and every single reload channel. */
    static const unsigned masks[] = {0x81, 0x24, 0xff, 1, 2, 4, 8, 16, 32, 64, 128};
    for (unsigned i = 0; i < sizeof masks / sizeof masks[0]; ++i) {
        if (mode == 0) bulk(true, masks[i]);
        if (mode == 1) flush(true, masks[i], true);
        if (mode == 2) flush(true, masks[i], false);
        if (mode == 3) {
            bulk(false, masks[i]);
            flush(false, masks[i], true);
            flush(false, masks[i], false);
        }
        if (mode == 4) {
            noops(true, masks[i]);
            noops(false, masks[i]);
        }
    }
    assert(munmap(memory, FLASH_BYTES) == 0);
    return 0;
}
"""


ABORT_HAL = r"""
static uint32_t m_init_packet_length, m_image_crc, m_image_size, m_data_received;
static unsigned m_dfu_state;
#define DFU_STATE_IDLE 0
static uint32_t dfu_timer_restart(void) { return 0; }
"""

ABORT_CHECKS = r"""
int main(void) {
    memory = mmap((void *)0x10000000, FLASH_BYTES, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(memory != MAP_FAILED);
    assert((uintptr_t)memory <= UINT32_MAX - FLASH_BYTES);
    base = (uint32_t)(uintptr_t)memory;
    memset(memory, 0xff, FLASH_BYTES);
    for (unsigned i = 0; i < 8; ++i) wdt.RR[i] = SENTINEL;
    /* Leave a partially received second page pending in the real cache. */
    uint8_t interrupted[CODE_PAGE_SIZE + 4] = {0};
    flash_nrf5x_write(base, interrupted, sizeof interrupted, false);
    assert(dfu_abort() == 0);
    flash_nrf5x_erase(base, 3 * CODE_PAGE_SIZE);
    uint8_t replacement[3 * CODE_PAGE_SIZE];
    memset(replacement, 0xa5, sizeof replacement);
    memset(replacement + CODE_PAGE_SIZE, 0xff, 4);
    flash_nrf5x_write(base, replacement, sizeof replacement, false);
    flash_nrf5x_flush(false);
    /* NOR programming cannot restore zero bits leaked from the old cache. */
    assert(memcmp(memory, replacement, sizeof replacement) == 0);
    assert(munmap(memory, FLASH_BYTES) == 0);
    return 0;
}
"""


def abort_function(source):
    masked = re.sub(
        r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        lambda match: " " * len(match[0]), source, flags=re.S,
    )
    match = re.search(r"\buint32_t\s+dfu_abort\s*\(void\)\s*\{", masked)
    if match is None:
        raise ValueError("Missing production dfu_abort")
    depth = 1
    for end in range(match.end(), len(masked)):
        depth += (masked[end] == "{") - (masked[end] == "}")
        if depth == 0:
            return source[match.start():end + 1]
    raise ValueError("Unclosed production dfu_abort")


def compile_harness(directory, name, checks):
    source = directory / (name + ".c")
    executable = directory / name
    production = re.sub(r'^\s*#include[^\n]*', '', FLASH.read_text(), flags=re.M)
    source.write_text(HAL + production + checks)
    subprocess.run(
        shlex.split(os.environ.get("CC", "cc"))
        + ["-std=c11", "-Wall", "-Wextra", "-Werror",
           "-Wno-int-to-pointer-cast", str(source), "-o", str(executable)],
        check=True, capture_output=True, text=True,
    )
    return executable


class FlashWatchdogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="flash-wdt-test-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.executable = compile_harness(Path(cls.temp.name), "flash_wdt", CHECKS)

    def run_case(self, mode):
        result = subprocess.run([str(self.executable), str(mode)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_bulk_erase_survives_deadlines(self):
        self.run_case(0)

    def test_dirty_flush_services_erase_write_gap(self):
        self.run_case(1)

    def test_preerased_dirty_flush_survives_deadline(self):
        self.run_case(2)

    def test_disabled_watchdog_preserves_registers_and_flash_results(self):
        self.run_case(3)

    def test_clean_invalid_and_empty_operations_are_noops(self):
        self.run_case(4)

    def test_abort_discards_pending_page(self):
        for bank in ("single", "dual"):
            with self.subTest(bank=bank):
                path = ROOT / "lib/sdk11/components/libraries/bootloader_dfu" / (
                    f"dfu_{bank}_bank.c"
                )
                executable = compile_harness(
                    Path(self.temp.name), f"abort_{bank}",
                    ABORT_HAL + abort_function(path.read_text()) + ABORT_CHECKS,
                )
                result = subprocess.run([str(executable)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)



if __name__ == "__main__":
    unittest.main()
