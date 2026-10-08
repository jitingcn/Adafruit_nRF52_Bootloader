"""Production main/check_dfu_mode regressions, with hardware/DFU leaves modeled.

Run: python3 -m unittest discover -s tools -p 'test_boot_recovery.py'
CC selects the host compiler; BOOT_MAIN_SOURCE selects an alternate main.c.
Only the RESETREAS W1C store is instrumented to emulate Nordic hardware in C.
"""

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "src/main.c"


def function(source, name):
    masked = re.sub(
        r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        lambda match: " " * len(match[0]), source, flags=re.S,
    )
    match = re.search(r"(?:static\s+)?(?:void|int|bool)\s+" + re.escape(name)
                      + r"\s*\([^;{}]*\)\s*\{", masked)
    if match is None:
        raise ValueError(f"Missing production function: {name}")
    depth = 1
    for end in range(match.end(), len(masked)):
        depth += (masked[end] == "{") - (masked[end] == "}")
        if depth == 0:
            return source[match.start():end + 1]
    raise ValueError(f"Unclosed production function: {name}")


def production(source):
    definitions = re.findall(r"^#define (?:DFU_MAGIC_\w+|DFU_DBL_RESET_\w+|DFU_SERIAL_STARTUP_INTERVAL|BOOTLOADER_VERSION_REGISTER)\s+[^\n]+", source, re.M)
    check = function(source, "check_dfu_mode")
    # C volatile memory cannot model write-one-to-clear; translate the hardware
    # store only, leaving its production RHS and all control flow unchanged.
    check = re.sub(r"NRF_POWER->RESETREAS\s*=\s*([^;]+);",
                   r"resetreas_w1c(\1);", check)
    return "\n".join(definitions) + "\n" + check + "\n#define main production_main\n" + function(source, "main") + "\n#undef main\n"


HAL = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#define BOOTLOADER_DFU_START 0xB1
#define POWER_RESETREAS_RESETPIN_Msk 1u
#define POWER_RESETREAS_DOG_Msk 2u
#define POWER_RESETREAS_LOCKUP_Msk 8u
#define SREQ 4u
#define OFF 0x10000u
#define BUTTON_DFU 1
#define BUTTON_DFU_OTA 2
#define STATE_BOOTLOADER_STARTED 1
#define STATE_WRITING_STARTED 2
#define STATE_WRITING_FINISHED 3
#define STATE_BLE_DISCONNECTED 4
#define STATE_USB_UNMOUNTED 5
#define STATE_USB_MOUNTED 6
#define MK_BOOTLOADER_VERSION 123
#define PRINTF(...) ((void)0)
#define APP_ASKS_FOR_SINGLE_TAP_RESET() single_tap
#define NRFX_DELAY_MS(ms) ((void)(ms))
static struct { uint32_t GPREGRET, GPREGRET2, RESETREAS; } power;
#define NRF_POWER (&power)
// TIMER2 capture/compare registers begin at offset 0x540 on nRF52.
static struct { uint32_t reserved[0x540 / 4]; volatile uint32_t CC[4]; } timer2;
#define NRF_TIMER2 (&timer2)
#define RECOVERY_CAPABILITY 0x52435631u
static uint32_t dbl;
static uint32_t *dbl_reset_mem = &dbl;
static bool _ota_dfu, _ota_connected, _ota_was_connected, _sd_inited;
static bool valid_app, single_tap, button, ota_button, must_reenter, sd_progress;
static bool sd_exists, connected, complete, finish_reenter, finish_sd;
static bootloader_status_t m_update_status, finish_status;
bool bootloader_recovery_can_start_app(void);
static unsigned dfu_calls, timeout_ms, writes, usb_calls, mbr_calls, sd_continues;
static uint32_t cleared_bits, handoff_gp;
static bool dfu_ota, timed, usb_serial;
static bool board_torn_down, softdevice_disabled;
static jmp_buf terminal;
enum { APP = 1, RESET, PARK };
static void resetreas_w1c(uint32_t value) {
  ++writes; cleared_bits |= value; power.RESETREAS &= ~value;
}
static bool button_pressed(unsigned id) { return id == 1 ? button : ota_button; }
static bool bootloader_app_is_valid(void) { return valid_app; }
static void board_init(void) {}
static void board_teardown(void) {
  assert(timer2.CC[1] != RECOVERY_CAPABILITY);
  timer2.CC[1] = 0; // Model peripheral cleanup clobbering the capability slot.
  board_torn_down = true;
}
static void bootloader_init(void) {}
static void led_state(unsigned state) { (void)state; }
static bool bootloader_dfu_sd_in_progress(void) { return sd_progress; }
static void bootloader_dfu_sd_update_continue(void) { ++sd_continues; }
static void bootloader_dfu_sd_update_finalize(void) { sd_progress = false; }
static bool bootloader_must_reset_to_self(void) { return must_reenter; }
static bool is_sd_existed(void) { return sd_exists; }
static void mbr_init_sd(void) { ++mbr_calls; }
static void disable_softdevice(void) {
  assert(timer2.CC[1] != RECOVERY_CAPABILITY);
  timer2.CC[1] = 0;
  softdevice_disabled = true;
}
static uint32_t ble_stack_init(void) { return 0; }
#ifdef NRF52832_XXAA
#define usb_init(serial) led_state(STATE_USB_MOUNTED)
#define usb_teardown() ((void)0)
#else
static void usb_init(bool serial) { ++usb_calls; usb_serial = serial; }
static void usb_teardown(void) {}
#endif
static bool use_uf2;
void tud_msc_write10_complete_cb(uint8_t lun);
static void bootloader_dfu_start(bool ota, unsigned timeout, bool automatic) {
  ++dfu_calls; dfu_ota = ota; timeout_ms = timeout; timed = automatic;
  _ota_was_connected = connected;
  if (!complete) longjmp(terminal, PARK);
  must_reenter = finish_reenter; sd_progress = finish_sd;
  m_update_status = finish_status;
  if (use_uf2) {
    m_update_status = BOOTLOADER_UPDATING;
    tud_msc_write10_complete_cb(0);
  }
}
static void bootloader_app_start(void) {
  assert(board_torn_down && (!sd_exists || softdevice_disabled));
  assert(timer2.CC[0] == MK_BOOTLOADER_VERSION);
  assert(timer2.CC[1] == RECOVERY_CAPABILITY);
  handoff_gp = power.GPREGRET; longjmp(terminal, APP);
}
static void __attribute__((noreturn)) NVIC_SystemReset(void) { longjmp(terminal, RESET); }
// UF2 callback dependencies: persistence/CRC/MBR hardware leaves are modeled.
enum { DFU_RESET, DFU_UPDATE_APP_COMPLETE };
typedef struct {
  unsigned status_code, app_size, app_crc;
  bool restart_into_bootloader;
} dfu_update_status_t;
static struct {
  bool aborted, preserve_app_bank, bank_invalidated, update_bootloader;
  unsigned numBlocks, numWritten, app_end;
} _wr_state;
static unsigned uf2_event, uf2_size, uf2_crc;
static uint32_t staged_bl[4], installed_bl[4];
#define BOOTLOADER_ADDR_NEW_RECEIVED staged_bl
#define BOOTLOADER_ADDR_START installed_bl
#define DFU_BL_IMAGE_MAX_SIZE sizeof(staged_bl)
#define DFU_BANK_0_REGION_START 0x1000u
#define SD_MBR_COMMAND_COPY_BL 1
#define PRINT_HEX(x) ((void)(x))
typedef struct {
  unsigned command;
  struct { struct { uint32_t *bl_src; unsigned bl_len; } copy_bl; } params;
} sd_mbr_command_t;
static void sd_mbr_command(sd_mbr_command_t *command) {
  (void)command; longjmp(terminal, RESET);
}
static void uf2_ensure_bank_invalid(void) { _wr_state.bank_invalidated = true; valid_app = false; }
static unsigned crc16_compute(const uint8_t *address, unsigned size, void *initial) {
  (void)address; (void)size; (void)initial; return 0x1234;
}
static void bootloader_dfu_update_process(dfu_update_status_t update) {
  uf2_event = update.status_code; uf2_size = update.app_size; uf2_crc = update.app_crc;
  // Model the synchronous flash settings persistence callback for UF2.
  if (update.status_code == DFU_UPDATE_APP_COMPLETE) {
    m_update_status = BOOTLOADER_COMPLETE;
  } else {
    must_reenter = update.restart_into_bootloader;
    m_update_status = must_reenter ? BOOTLOADER_RESET_TO_SELF : BOOTLOADER_SYS_RESET;
  }
}
"""

CHECKS = r"""
static void setup(uint32_t gp, uint32_t reason) {
  memset(&power, 0, sizeof power);
  memset(&timer2, 0, sizeof timer2);
  timer2.CC[0] = 0xffffffffu;
  timer2.CC[1] = 0x11223344u; // Wrong/non-capability contents must be replaced.
  timer2.CC[2] = 0x22334455u; timer2.CC[3] = 0x33445566u;
  board_torn_down = softdevice_disabled = false;
  power.GPREGRET = gp; power.RESETREAS = reason; power.GPREGRET2 = 0x5A;
  dbl = 0; _ota_dfu = _ota_connected = _ota_was_connected = _sd_inited = false;
  valid_app = true; single_tap = button = ota_button = false;
  must_reenter = sd_progress = sd_exists = connected = complete = false;
  finish_reenter = finish_sd = false;
  m_update_status = BOOTLOADER_UPDATING; finish_status = BOOTLOADER_COMPLETE;
  dfu_calls = timeout_ms = writes = usb_calls = mbr_calls = sd_continues = 0;
  cleared_bits = handoff_gp = 0; dfu_ota = timed = usb_serial = false;
  use_uf2 = false; memset(&_wr_state, 0, sizeof _wr_state);
  uf2_event = uf2_size = uf2_crc = 0;
}
static int run(void) {
  int result = setjmp(terminal);
  if (!result) { production_main(); assert(!"main unexpectedly returned"); }
  assert(power.GPREGRET2 == 0x5A);
  assert(timer2.CC[0] == MK_BOOTLOADER_VERSION);
  assert(timer2.CC[2] == 0x22334455u && timer2.CC[3] == 0x33445566u);
  // Every existing park, abort, invalid-app and reset scenario checks no token.
  assert((timer2.CC[1] == RECOVERY_CAPABILITY) == (result == APP));
  return result;
}
static void parked(void) {
  assert(run() == PARK);
  assert(dfu_calls == 1 && timeout_ms == 0 && !timed);
  assert(power.GPREGRET == DFU_MAGIC_RECOVERY);
#ifdef DEFAULT_TO_OTA_DFU
  assert(dfu_ota);
#endif
}
int main(void) {
  // Handoff capability survives both teardown stages, with or without SD.
  for (unsigned with_sd = 0; with_sd < 2; ++with_sd) {
    setup(DFU_MAGIC_SKIP, SREQ); sd_exists = with_sd;
    assert(run() == APP && board_torn_down);
    assert(softdevice_disabled == (bool)with_sd);
    assert(mbr_calls == with_sd);
  }
  // Three actual main entries, retaining only reset-persistent state.
  uint32_t gp = 0;
  for (unsigned n = 1; n <= 3; ++n) {
    setup(gp, POWER_RESETREAS_DOG_Msk | SREQ | OFF);
    single_tap = true; dbl = DFU_DBL_RESET_APP;
    if (n < 3) {
      assert(run() == APP); assert(!dfu_calls);
      assert(handoff_gp == (n == 1 ? DFU_MAGIC_WDT_FIRST : DFU_MAGIC_WDT_SECOND));
    } else { parked(); }
    assert(writes == 1 && cleared_bits == POWER_RESETREAS_DOG_Msk);
    assert(power.RESETREAS == (SREQ | OFF));
    gp = power.GPREGRET;
  }
  // Latched recovery survives software resets, MakeCode state, and OTA disconnect.
  setup(gp, SREQ); single_tap = true; dbl = DFU_DBL_RESET_APP; parked();
  setup(gp, SREQ); valid_app = false; complete = connected = true;
  assert(run() == RESET && power.GPREGRET == DFU_MAGIC_RECOVERY);
  setup(power.GPREGRET, SREQ); parked();
  // Healthy application acknowledgement clears only retry state (modeled app).
  for (gp = DFU_MAGIC_WDT_FIRST; gp <= DFU_MAGIC_WDT_SECOND; ++gp) {
    setup(gp, POWER_RESETREAS_DOG_Msk);
    power.GPREGRET = 0; // modeled 60-second healthy acknowledgement
    assert(run() == APP && handoff_gp == DFU_MAGIC_WDT_FIRST);
    setup(gp, SREQ); complete = true;
    assert(run() == APP && handoff_gp == 0);
    setup(gp, POWER_RESETREAS_DOG_Msk); button = true;
    assert(run() == PARK && power.GPREGRET == 0 && !timed);
  }
  // A power cycle (retention lost) permits a new attempt.
  setup(0, 0); complete = true; assert(run() == APP && handoff_gp == 0);
  // SREQ alone and OTA debug breadcrumbs are not faults; unknown values survive.
  for (gp = 0xD0; gp <= 0xDE; ++gp) {
    setup(gp, SREQ); complete = true; assert(run() == APP && handoff_gp == gp);
    setup(gp, POWER_RESETREAS_DOG_Msk);
    assert(run() == APP && handoff_gp == DFU_MAGIC_WDT_FIRST);
  }
  setup(0x77, SREQ); complete = true; assert(run() == APP && handoff_gp == 0x77);
  // SKIP never overrides either hardware fault, even simultaneous reset flags.
  setup(DFU_MAGIC_SKIP, SREQ); assert(run() == APP && handoff_gp == 0 && !dfu_calls);
  setup(DFU_MAGIC_SKIP, POWER_RESETREAS_DOG_Msk);
  assert(run() == APP && handoff_gp == DFU_MAGIC_WDT_FIRST);
  const uint32_t states[] = {0, DFU_MAGIC_SKIP, DFU_MAGIC_WDT_FIRST, DFU_MAGIC_WDT_SECOND, DFU_MAGIC_RECOVERY};
  for (unsigned i = 0; i < sizeof states / sizeof states[0]; ++i) {
    setup(states[i], POWER_RESETREAS_LOCKUP_Msk | POWER_RESETREAS_DOG_Msk | SREQ | OFF);
    single_tap = true; parked();
    assert(cleared_bits == (POWER_RESETREAS_LOCKUP_Msk | POWER_RESETREAS_DOG_Msk));
    assert(power.RESETREAS == (SREQ | OFF));
  }
  // Explicit DFU preserves transport and ordinary timeout policy on DOG.
  const uint32_t requests[] = {DFU_MAGIC_UF2_RESET, DFU_MAGIC_SERIAL_ONLY_RESET,
                              DFU_MAGIC_OTA_RESET, DFU_MAGIC_OTA_APPJUM};
  for (unsigned i = 0; i < sizeof requests / sizeof requests[0]; ++i) {
    for (unsigned fault = 0; fault < 3; ++fault) {
      setup(requests[i], fault == 0 ? SREQ : fault == 1 ? POWER_RESETREAS_DOG_Msk : POWER_RESETREAS_LOCKUP_Msk);
      assert(run() == PARK && dfu_calls == 1);
      assert(power.GPREGRET == (fault == 2 ? DFU_MAGIC_RECOVERY : 0));
      assert(timeout_ms == (fault != 2 && i < 2 ? 15000u : 0u));
      assert(timed == (fault != 2 && i < 2));
#ifdef DEFAULT_TO_OTA_DFU
      assert(dfu_ota);
#else
      assert(dfu_ota == (i >= 2));
#ifndef NRF52832_XXAA
      if (i < 2) assert(usb_calls == 1 && usb_serial == (i == 1));
#endif
#endif
      if (i == 3) assert(_sd_inited && mbr_calls == (fault == 0 ? 0u : 1u));
    }
  }
  // Real UF2 completion callback -> modeled settings commit -> real main handoff.
  setup(DFU_MAGIC_RECOVERY, SREQ); complete = use_uf2 = true;
  _wr_state.numBlocks = _wr_state.numWritten = 1;
  _wr_state.app_end = DFU_BANK_0_REGION_START + 256;
  assert(run() == APP && handoff_gp == 0);
  assert(uf2_event == DFU_UPDATE_APP_COMPLETE && uf2_size == 256 && uf2_crc == 0x1234);
  setup(DFU_MAGIC_RECOVERY, SREQ); complete = use_uf2 = true;
  _wr_state.aborted = _wr_state.preserve_app_bank = true;
  assert(run() == RESET && power.GPREGRET == DFU_MAGIC_RECOVERY && valid_app);
  assert(uf2_event == DFU_RESET && must_reenter);
  setup(DFU_MAGIC_RECOVERY, SREQ); complete = use_uf2 = true;
  _wr_state.numBlocks = _wr_state.numWritten = 1; // no bank0 payload
  assert(run() == RESET && power.GPREGRET == DFU_MAGIC_RECOVERY && !valid_app);
  // Actual main handoff clears E3 only for a valid app, not mere DFU entry.
  setup(DFU_MAGIC_RECOVERY, SREQ); complete = true;
  assert(run() == APP && handoff_gp == 0);
  setup(DFU_MAGIC_RECOVERY, SREQ); complete = true; valid_app = false;
  assert(run() == RESET && power.GPREGRET == DFU_MAGIC_RECOVERY);
  setup(DFU_MAGIC_RECOVERY, SREQ); complete = finish_reenter = true;
  assert(run() == RESET && power.GPREGRET == DFU_MAGIC_RECOVERY);
  // Automatic inactivity/abort/disconnect cannot hand off even to a valid app.
  const bootloader_status_t exits[] = {BOOTLOADER_TIMEOUT, BOOTLOADER_SYS_RESET,
                                     BOOTLOADER_RESET_TO_SELF, BOOTLOADER_SETTINGS_SAVING};
  for (unsigned i = 0; i < sizeof exits / sizeof exits[0]; ++i) {
    setup(DFU_MAGIC_RECOVERY, SREQ); complete = connected = true;
    finish_status = exits[i]; finish_reenter = exits[i] == BOOTLOADER_RESET_TO_SELF;
    assert(run() == RESET && power.GPREGRET == DFU_MAGIC_RECOVERY);
  }
  setup(DFU_MAGIC_RECOVERY, SREQ); complete = true; finish_status = BOOTLOADER_USER_EXIT;
  assert(run() == APP && handoff_gp == 0);
  // The SDK sd-in-progress predicate covers both SD and bootloader banks.
  // Only this committed transaction may replace E3 with the OTA reentry marker.
  for (unsigned reenter = 0; reenter < 2; ++reenter) {
    setup(DFU_MAGIC_RECOVERY, SREQ); complete = connected = finish_sd = true;
    finish_reenter = reenter;
    assert(run() == RESET && power.GPREGRET == DFU_MAGIC_OTA_RESET);
    setup(power.GPREGRET, SREQ); sd_progress = complete = true;
    assert(run() == APP && handoff_gp == 0 && sd_continues == 1);
  }
  // Ordinary OTA reset lifecycle unchanged even without a valid application.
  setup(DFU_MAGIC_OTA_RESET, SREQ); valid_app = false; connected = complete = true;
  assert(run() == RESET && power.GPREGRET == DFU_MAGIC_OTA_RESET);
  puts("boot recovery and production main handoff passed");
  return 0;
}
"""


class BootRecoveryTests(unittest.TestCase):
    def test_production_recovery_and_handoff(self):
        source = Path(os.environ.get("BOOT_MAIN_SOURCE", str(SOURCE))).read_text()
        lifecycle = (SOURCE.parent.parent / "lib/sdk11/components/libraries/bootloader_dfu/bootloader.c").read_text()
        uf2 = (SOURCE.parent / "usb/msc_uf2.c").read_text()
        status_enum = re.search(r"typedef enum\s*\{[^}]+\}\s*bootloader_status_t;", lifecycle)
        if status_enum is None:
            raise ValueError("Missing production bootloader status enum")
        harness = (status_enum[0] + HAL
                   + function(lifecycle, "bootloader_recovery_can_start_app")
                   + '\n#pragma GCC diagnostic push\n#pragma GCC diagnostic ignored "-Wunused-parameter"\n'
                   + '#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"\n'
                   + function(uf2, "tud_msc_write10_complete_cb")
                   + '\n#pragma GCC diagnostic pop\n'
                   + production(source) + CHECKS)
        compiler = shlex.split(os.environ.get("CC", "cc"))
        with tempfile.TemporaryDirectory(prefix="boot-recovery-") as directory:
            root = Path(directory)
            c_file = root / "recovery.c"
            binary = root / "recovery"
            c_file.write_text(harness)
            for non_usb in (False, True):
                for default_ota in (False, True):
                    with self.subTest(non_usb=non_usb, default_ota=default_ota):
                        flags = []
                        if non_usb:
                            flags.append("-DNRF52832_XXAA")
                        if default_ota:
                            flags.append("-DDEFAULT_TO_OTA_DFU")
                        result = subprocess.run(compiler + ["-std=c99", "-Wall", "-Wextra", "-Werror"]
                                                + flags + [str(c_file), "-o", str(binary)],
                                                capture_output=True, text=True, check=False)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        result = subprocess.run([str(binary)], capture_output=True, text=True, check=False)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
