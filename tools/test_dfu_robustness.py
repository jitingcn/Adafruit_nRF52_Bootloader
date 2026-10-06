#!/usr/bin/env python3
"""Native production-C DFU regressions; flash/timer/HCI hardware is modeled.

Run: python3 -m unittest discover -s tools -p test_dfu_robustness.py -v
BOOTLOADER_SOURCE_ROOT selects another checkout for failing-before comparisons.
No ARM SDK, submodules, or hardware needed; requires a native C compiler (CC).
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(os.environ.get("BOOTLOADER_SOURCE_ROOT", Path(__file__).resolve().parents[1]))
BASE = Path("lib/sdk11/components/libraries/bootloader_dfu")


def function(path, name):
    """Extract a complete function, respecting comments and string literals."""
    text = path.read_text()
    match = re.search(
        r"^[ \t]*(?:(?:static|inline|__INLINE)[ \t]+)*"
        r"(?:void|bool|uint(?:8|16|32)_t)[ \t]+" + re.escape(name)
        + r"\s*\([^;{}]*\)\s*\{", text, re.M,
    )
    if not match:
        raise ValueError(f"Function not found: {path}:{name}")
    depth = 0
    tokens = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)
    for token in tokens.finditer(text, text.index("{", match.start())):
        if token.group() == "{":
            depth += 1
        elif token.group() == "}":
            depth -= 1
            if depth == 0:
                line = text.count("\n", 0, match.start()) + 1
                return f'\n#line {line} "{path}"\n' + text[match.start():token.end()] + "\n"
    raise ValueError(f"Unclosed function: {path}:{name}")


def generate_c(root=ROOT, abort_bank="dual"):
    base = root / BASE
    dual, serial, boot = (base / name for name in ("dfu_dual_bank.c", "dfu_transport_serial.c", "bootloader.c"))
    types = (base / "dfu_types.h").read_text()
    settings = (base / "bootloader_types.h").read_text()
    init = (base / "dfu_init.h").read_text()
    queue = serial.read_text()
    internal = (base / "dfu_bank_internal.h").read_text()
    parts = [PRELUDE,
             types[types.index("typedef struct"):types.index("/**@brief Update complete handler type.")],
             settings[settings.index("typedef enum"):settings.index("#endif")],
             init[init.index("typedef struct"):init.index("/**@brief Structure holding basic")],
             internal[internal.index("/**@brief States"):internal.index("#endif")],
             queue[queue.index("#define MAX_BUFFERS"):queue.index("/**@brief Initializes an element")],
             HARDWARE]
    for path, names in [
        (root / "lib/sdk/components/libraries/crc16/crc16.c", ["crc16_compute"]),
        (root / "lib/sdk/components/libraries/util/app_util.h", ["uint16_decode"]),
        (root / "src/dfu_init.c", ["dfu_init_prevalidate", "dfu_init_postvalidate"]),
        (base / "bootloader_settings.c", ["bootloader_util_settings_get"]),
    ]:
        parts.extend(function(path, name) for name in names)
    parts.append(function(boot, "pstorage_callback_handler").replace("pstorage_callback_handler(", "settings_callback_handler("))
    parts.append(function(boot, "bootloader_settings_save").replace("pstorage_callback_handler(", "settings_callback_handler("))
    parts.extend(function(boot, name) for name in ["bootloader_dfu_update_process", "bootloader_dfu_activity_mark", "bootloader_app_is_valid"])
    parts.extend(function(dual, name) for name in [
        "pstorage_callback_handler", "dfu_timer_restart", "dfu_prepare_func_app_erase",
        "dfu_prepare_func_swap_erase", "dfu_cleared_func_swap", "dfu_cleared_func_app",
        "dfu_activate_sd", "dfu_activate_app", "dfu_activate_bl", "dfu_start_pkt_handle",
        "dfu_data_pkt_handle", "dfu_init_pkt_complete", "dfu_init_pkt_handle",
        "dfu_image_validate", "dfu_image_activate",
    ])
    # Old source has no abort API and its serial consumer never calls one.
    # Do not add a stand-in: baseline must fail on its observable STOP behavior.
    abort_source = base / f"dfu_{abort_bank}_bank.c"
    if re.search(r"\bdfu_abort\s*\(", abort_source.read_text()):
        parts.append(function(abort_source, "dfu_abort"))
    parts.extend(function(serial, name) for name in [
        "data_queue_element_init", "data_queue_init", "data_queue_element_free",
        "data_queue_flush", "dfu_transport_serial_close", "process_dfu_packet",
    ])
    return "\n".join(parts + [SCENARIOS])


PRELUDE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __INLINE inline
#define NRF_SUCCESS 0
#define NRF_ERROR_NO_MEM 4
#define NRF_ERROR_NOT_FOUND 5
#define NRF_ERROR_INVALID_PARAM 7
#define NRF_ERROR_INVALID_STATE 8
#define NRF_ERROR_INVALID_DATA 11
#define NRF_ERROR_DATA_SIZE 12
#define NRF_ERROR_INVALID_LENGTH 13
#define NRF_ERROR_INVALID_ADDR 14
#define NRF_ERROR_NOT_SUPPORTED 15
#define NRF_ERROR_FORBIDDEN 16
#define PSTORAGE_CLEAR_OP_CODE 1
#define PSTORAGE_STORE_OP_CODE 2
#define APP_ERROR_CHECK(x) do { unsigned rc_=(x); if(rc_) { fprintf(stderr,"error %u at %s:%d\n",rc_,__FILE__,__LINE__); abort(); } } while(0)
#define VERIFY_SUCCESS(x) do { if((x)!=NRF_SUCCESS) return (x); } while(0)
#define VERIFY_PARAM_NOT_NULL(x) assert(x)
#define APP_TIMER_TICKS(x) (x)
#define INVALID_PACKET 0
#define INIT_PACKET 1
#define START_PACKET 3
#define DATA_PACKET 4
#define STOP_DATA_PACKET 5
#define DFU_UPDATE_SD 1
#define DFU_UPDATE_BL 2
#define DFU_UPDATE_APP 4
#define STATE_WRITING_STARTED 1
#define STATE_WRITING_FINISHED 2
#define DFU_BL_IMAGE_MAX_SIZE 64
#define DFU_IMAGE_MAX_SIZE_FULL 128
#define DFU_IMAGE_MAX_SIZE_BANKED 64
#define ADAFRUIT_DEVICE_TYPE 0x52
#define ADAFRUIT_DEV_REV 52840
#define DFU_INIT_PACKET_EXT_LENGTH_MIN 2
#define DFU_SOFTDEVICE_ANY 0xfffe
#define MBR_SIZE 4096
#define SD_FWID_GET(x) 0x1234
'''

HARDWARE = r'''
enum { BOOTLOADER_UPDATING, BOOTLOADER_SETTINGS_SAVING, BOOTLOADER_COMPLETE,
       BOOTLOADER_TIMEOUT, BOOTLOADER_SYS_RESET, BOOTLOADER_RESET_TO_SELF };
typedef struct { uintptr_t block_id; } pstorage_handle_t;
static _Alignas(4) uint8_t bank0[64], bank1[64], image[64], old_image[64];
static _Alignas(4) uint8_t m_boot_settings[4096];
#define settings_flash (*(bootloader_settings_t *)m_boot_settings)
#define BOOTLOADER_SETTINGS_ADDRESS ((uintptr_t)m_boot_settings)
#define DFU_BANK_0_REGION_START ((uintptr_t)bank0)
#define DFU_BANK_1_REGION_START ((uintptr_t)bank1)
#define BOOTLOADER_REGION_START ((uintptr_t)bank0 + sizeof bank0)
static struct { struct { uint32_t RAM; } INFO; } ficr = {{64}};
#define NRF_FICR (&ficr)
static dfu_state_t m_dfu_state;
static uint32_t m_image_size;
static uint16_t m_image_crc;
static uint8_t m_init_packet[128], m_init_packet_length;
static uint8_t m_extended_packet[104], m_extended_packet_length;
static dfu_start_packet_t m_start_packet;
static pstorage_handle_t m_storage_handle_app, m_storage_handle_swap, m_bootsettings_handle;
static pstorage_handle_t *mp_storage_handle_active;
static void (*m_data_pkt_cb)(uint32_t,uint32_t,uint8_t*);
static dfu_bank_func_t m_functions;
static bool m_dfu_timed_out, m_startup_dfu_has_activity;
static int m_dfu_timer_id, m_update_status;
static bool timer_running, corrupt_copy;
static unsigned invalidation_fault, bank0_erases, consumes, led, settings_writes;
static bool is_ota(void) { return false; }
static bool is_word_aligned(const void *p) { return ((uintptr_t)p & 3)==0; }
static uint32_t app_timer_stop(int id) { (void)id; timer_running=false; return 0; }
static uint32_t app_timer_start(int id,unsigned ticks,void *p) { (void)id;(void)ticks;(void)p;timer_running=true;return 0; }
static void flash_nrf5x_erase(uintptr_t addr,unsigned len) {
  if(addr==(uintptr_t)bank0) {
    // A reset at the first destructive operation must not boot the old settings.
    assert(settings_flash.bank_0==BANK_INVALID_APP);
    bank0_erases++;
  }
  memset((void*)addr,255,len);
}
static void flash_nrf5x_write(uintptr_t addr,const void *src,unsigned len,bool sync) {
  (void)sync; memcpy((void*)addr,src,len);
  if(corrupt_copy && addr==(uintptr_t)bank0) ((uint8_t*)addr)[17]^=1;
}
static void flash_nrf5x_flush(bool sync) { (void)sync; }
// This model writes through; test_flash_wdt exercises the production page cache.
static void flash_nrf5x_discard(void) {}
static void nrfx_nvmc_page_erase(uintptr_t addr) {
  assert(addr==(uintptr_t)m_boot_settings);
  if(invalidation_fault!=1) memset(m_boot_settings,255,sizeof m_boot_settings);
}
static void nrfx_nvmc_words_write(uintptr_t addr,const uint32_t *src,unsigned words) {
  assert(addr==(uintptr_t)m_boot_settings); settings_writes++;
  if(!invalidation_fault) memcpy((void*)addr,src,words*4);
}
static uint32_t pstorage_clear(pstorage_handle_t *h,unsigned len) { (void)h;(void)len;abort(); }
static uint32_t pstorage_store(pstorage_handle_t *h,uint8_t *p,unsigned n,unsigned off) { (void)h;(void)p;(void)n;(void)off;abort(); }
static uint32_t proc_soc(void) { abort(); }
static void led_state(unsigned value) { led=value; }
static uint32_t hci_transport_rx_pkt_consume(uint8_t *p) { (void)p; consumes++;return 0; }
static uint32_t hci_transport_close(void) { return 0; }
static uint32_t dfu_transport_ble_close(void) { abort(); }
void bootloader_dfu_update_process(dfu_update_status_t status);
uint32_t dfu_transport_serial_close(void);
'''

SCENARIOS = r'''
#line 1 "dfu_behavior_scenarios"
static void enqueue(unsigned slot,unsigned type,uint32_t *payload,unsigned words) {
  m_data_queue.data_packet[slot].packet_type=type;
  m_data_queue.data_packet[slot].params.data_packet.p_data_packet=payload;
  m_data_queue.data_packet[slot].params.data_packet.packet_length=words;
  m_data_queue.count++;
}
static void send(unsigned type,uint32_t *payload,unsigned words) {
  enqueue(0,type,payload,words); process_dfu_packet(NULL,0);
}
static void receive_image(bool bad_crc) {
  static struct { uint32_t opcode; dfu_start_packet_t start; } start;
  static uint32_t init_words[5], data_words[17];
  start.start=(dfu_start_packet_t){.dfu_update_mode=DFU_UPDATE_APP,.app_image_size=64};
  send(START_PACKET,(uint32_t*)&start.start,sizeof start.start/4);
  assert(m_dfu_state==DFU_STATE_RDY);
  memset(init_words,0,sizeof init_words);
  dfu_init_packet_t *init=(dfu_init_packet_t*)&init_words[1];
  init->device_type=ADAFRUIT_DEVICE_TYPE;init->softdevice_len=1;init->softdevice[0]=DFU_SOFTDEVICE_ANY;
  uint16_t crc=crc16_compute(image,sizeof image,NULL) ^ (bad_crc ? 1 : 0);
  memcpy(&init->softdevice[1],&crc,sizeof crc);
  send(INIT_PACKET,&init_words[1],4);
  assert(m_dfu_state==DFU_STATE_RX_DATA_PKT);
  memcpy(&data_words[1],image,sizeof image);
  send(DATA_PACKET,&data_words[1],16);
  assert(m_data_received==sizeof image);
}
static void stop_with_stale_data(void) {
  static uint32_t stop[2], stale[2];
  enqueue(0,STOP_DATA_PACKET,&stop[1],0);
  enqueue(1,DATA_PACKET,&stale[1],1);
  unsigned before=consumes;
  process_dfu_packet(NULL,0);
  assert(m_data_queue.count==0 && consumes==before+2);
}
static void assert_failed(void) {
  assert(m_dfu_state==DFU_STATE_IDLE && timer_running);
  assert(led!=STATE_WRITING_FINISHED && m_update_status!=BOOTLOADER_COMPLETE);
  unsigned erased=bank0_erases, saved=settings_writes;
  process_dfu_packet(NULL,0); // Already scheduled callbacks cannot replay STOP.
  assert(bank0_erases==erased && settings_writes==saved);
}
static void vectors(void) {
  const uint16_t flags[]={BANK_VALID_APP,0xffff,BANK_INVALID_APP,BANK_VALID_SD,BANK_VALID_BOOT,BANK_ERASED};
  const uint32_t ram_sizes[]={0,64,256};
  for(unsigned r=0;r<3;r++) {
    ficr.INFO.RAM=ram_sizes[r];
    uint32_t end=0x20000000u+((ram_sizes[r]?ram_sizes[r]:64)*1024);
    const uint32_t sp[]={0x1ffffffc,0x20000000,end,end+4,0x20000002,0xffffffff};
    const uint32_t pc[]={(uint32_t)(uintptr_t)bank0-1,(uint32_t)(uintptr_t)bank0,
      (uint32_t)(uintptr_t)bank0+1,(uint32_t)BOOTLOADER_REGION_START-1,
      (uint32_t)BOOTLOADER_REGION_START+1,0xffffffff};
    for(unsigned f=0;f<6;f++) for(unsigned s=0;s<6;s++) for(unsigned p=0;p<6;p++) {
      settings_flash.bank_0=flags[f];settings_flash.bank_0_crc=0;
      ((uint32_t*)bank0)[0]=sp[s];((uint32_t*)bank0)[1]=pc[p];
      bool expected=(f<2)&&(s==1||s==2)&&(p==2||p==3);
      assert(bootloader_app_is_valid()==expected);
    }
  }
  memcpy(bank0,image,sizeof image);settings_flash.bank_0=BANK_VALID_APP;
  settings_flash.bank_0_size=sizeof image;
  settings_flash.bank_0_crc=crc16_compute(bank0,sizeof bank0,NULL);
  assert(settings_flash.bank_0_crc!=0 && bootloader_app_is_valid());
  bank0[17]^=1;assert(!bootloader_app_is_valid());
}
int main(int argc,char **argv) {
  assert(argc==2);
  for(unsigned i=0;i<sizeof image;i++) image[i]=(uint8_t)(i*3+7);
  ((uint32_t*)image)[0]=0x20010000u;((uint32_t*)image)[1]=(uint32_t)(uintptr_t)bank0+33;
  memcpy(old_image,image,sizeof image);old_image[20]^=2;
  memcpy(bank0,old_image,sizeof bank0);
  settings_flash.bank_0=BANK_VALID_APP;settings_flash.bank_0_crc=0;settings_flash.bank_0_size=64;
  m_storage_handle_app.block_id=(uintptr_t)bank0;m_storage_handle_swap.block_id=(uintptr_t)bank1;
  m_dfu_state=DFU_STATE_IDLE;timer_running=true;m_update_status=BOOTLOADER_UPDATING;
  data_queue_init();
  if(!strcmp(argv[1],"vectors")) { vectors();return 0; }
  bool validation_failure=!strcmp(argv[1],"validation");
  corrupt_copy=!strcmp(argv[1],"copy");
  invalidation_fault=!strcmp(argv[1],"settings_unchanged")?1:!strcmp(argv[1],"settings_erased")?2:0;
  receive_image(validation_failure);
  stop_with_stale_data();
  if(validation_failure||corrupt_copy||invalidation_fault) {
    assert_failed();
    if(validation_failure || invalidation_fault) {
      assert(bank0_erases==0 && !memcmp(bank0,old_image,sizeof bank0));
      if(validation_failure) assert(settings_writes==0 && bootloader_app_is_valid());
    } else {
      assert(bank0_erases==1 && memcmp(bank0,image,sizeof bank0));
      assert(settings_flash.bank_0==BANK_INVALID_APP && !bootloader_app_is_valid());
    }
    corrupt_copy=false;invalidation_fault=0;
    receive_image(false);stop_with_stale_data();
  }
  assert(!memcmp(bank0,image,sizeof bank0));
  assert(settings_flash.bank_0==BANK_VALID_APP && settings_flash.bank_0_size==sizeof image);
  assert(bootloader_app_is_valid());
  assert(m_update_status==BOOTLOADER_COMPLETE && led==STATE_WRITING_FINISHED);
  puts("PASS");return 0;
}
'''


class DfuRobustnessTests(unittest.TestCase):
    def test_serial_dfu_and_vectors(self):
        with tempfile.TemporaryDirectory(prefix="dfu-robustness-") as tmp:
            source, binary = Path(tmp) / "dfu.c", Path(tmp) / "dfu"
            for abort_bank in ("dual", "single"):
                source.write_text(generate_c(abort_bank=abort_bank))
                compiled = subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
                    "-std=c11", "-O0", "-g", "-no-pie", "-Wall", "-Wextra",
                    "-Wno-unused-parameter", "-Wno-pointer-to-int-cast", "-Wno-int-to-pointer-cast",
                    str(source), "-o", str(binary)], capture_output=True, text=True)
                self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                for case in ("success", "validation", "copy", "settings_unchanged", "settings_erased", "vectors"):
                    with self.subTest(abort_bank=abort_bank, case=case):
                        result = subprocess.run([str(binary), case], capture_output=True, text=True)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
