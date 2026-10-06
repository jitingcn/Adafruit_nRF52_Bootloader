"""Host PWM regressions: python3 -m unittest discover -s tools -p 'test_led_pwm.py'.

Requires Python and a host C compiler only. CC selects the compiler;
BOARDS_SOURCE optionally selects a different boards.c for before/after checks.
The tested function bodies are extracted unchanged from production C.
"""

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


BOARDS = Path(__file__).resolve().parents[1] / "src/boards/boards.c"
RGB_SECTION = "#if defined(LED_RGB_RED_PIN) && defined(LED_RGB_GREEN_PIN) && defined(LED_RGB_BLUE_PIN)"


def function(source, name):
    """Extract a definition, ignoring braces inside comments and literals."""
    masked = re.sub(
        r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        lambda match: " " * len(match[0]), source, flags=re.S,
    )
    match = re.search(r"\bvoid\s+" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", masked)
    if match is None:
        raise ValueError(f"Missing production function: {name}")
    depth = 1
    for end in range(match.end(), len(masked)):
        depth += (masked[end] == "{") - (masked[end] == "}")
        if depth == 0:
            return source[match.start():end + 1]
    raise ValueError(f"Unclosed production function: {name}")


def production(source):
    rgb = source[source.index(RGB_SECTION):]
    definitions = []
    for name in ("LED_RGB_RED", "LED_RGB_GREEN", "LED_RGB_BLUE"):
        match = re.search(r"^#define\s+" + name + r"\s+[^\n]+", rgb, re.M)
        if match is None:
            raise ValueError(f"Missing production channel: {name}")
        definitions.append(match[0])
    return "\n".join(definitions + [
        function(source, "led_pwm_duty_cycle"),
        function(source, "led_tick"),
        function(rgb, "neopixel_write"),
    ])


HAL = r"""
#include <assert.h>
#include <stdint.h>
#include <string.h>

#define LEDS_NUMBER 1
#define LED_PRIMARY 0
#define PWM0_CH_NUM 4
#define NRF_PWM0 ((void *)1)
#define NRF_PWM_EVENT_SEQEND0 1
#define NRF_PWM_TASK_SEQSTART0 2

static uint16_t led_duty_cycles[PWM0_CH_NUM];
static uint32_t _systick_count;
static uint32_t primary_cycle_length;

static void nrf_pwm_event_clear(void *pwm, unsigned event) {
  (void)pwm;
  (void)event;
}

static void nrf_pwm_task_trigger(void *pwm, unsigned task) {
  (void)pwm;
  (void)task;
}
"""


CHECKS = r"""
static uint16_t expected_rgb(uint8_t value) {
#ifdef LED_RGB_COMMON_CATHODE
  return 255 - value;
#else
  return value;
#endif
}

static void check_rgb(const uint8_t color[3]) {
  assert(led_duty_cycles[LED_RGB_RED] == expected_rgb(color[2]));
  assert(led_duty_cycles[LED_RGB_GREEN] == expected_rgb(color[1]));
  assert(led_duty_cycles[LED_RGB_BLUE] == expected_rgb(color[0]));
}

static void write_rgb(const uint8_t color[3]) {
  uint8_t pixels[3];
  memcpy(pixels, color, sizeof pixels);
  uint16_t primary = led_duty_cycles[LED_PRIMARY];
  neopixel_write(pixels);
  assert(memcmp(pixels, color, sizeof pixels) == 0);
  assert(led_duty_cycles[LED_PRIMARY] == primary);
  check_rgb(color);
}

int main(void) {
  /* Each color channel spans every byte value, with distinct mixed inputs. */
  for (unsigned value = 0; value <= 255; ++value) {
    uint8_t color[3] = {value, value + 85, value + 170};
    write_rgb(color);
  }
  static const uint8_t endpoints[][3] = {
    {0, 0, 0}, {255, 255, 255},
    {255, 0, 0}, {0, 255, 0}, {0, 0, 255},
    {0, 255, 255}, {255, 0, 255}, {255, 255, 0},
  };
  for (unsigned i = 0; i < sizeof endpoints / sizeof endpoints[0]; ++i) {
    write_rgb(endpoints[i]);
  }

  /* Both bootloader and mounted cadences, including the wrap to phase zero. */
  static const unsigned periods[] = {300, 3000};
  for (unsigned p = 0; p < sizeof periods / sizeof periods[0]; ++p) {
    primary_cycle_length = periods[p];
    unsigned half = periods[p] / 2;
    for (unsigned tick = 0; tick <= periods[p]; ++tick) {
      uint8_t color[3] = {tick, tick + 85, tick + 170};
      write_rgb(color);
      _systick_count = tick;
      led_tick();
      unsigned distance = tick <= half ? tick : periods[p] - tick;
      unsigned expected = 79 * distance / half;
      if (LED_STATE_ON == 1) expected = 255 - expected;
      assert(led_duty_cycles[LED_PRIMARY] == expected);
      check_rgb(color);
      /* Exercise RGB off at every primary level without disturbing it. */
      write_rgb(endpoints[0]);
    }
  }
  return 0;
}
"""


class LedPwmTests(unittest.TestCase):
    def test_rgb_polarity_preserves_primary_breathing(self):
        source = Path(os.environ.get("BOARDS_SOURCE", str(BOARDS))).read_text()
        harness = HAL + "\n" + production(source) + "\n" + CHECKS
        compiler = shlex.split(os.environ.get("CC", "cc"))
        with tempfile.TemporaryDirectory(prefix="led-pwm-") as directory:
            root = Path(directory)
            c_file = root / "led_pwm.c"
            binary = root / "led_pwm"
            c_file.write_text(harness)
            for common_cathode in (False, True):
                for state_on in (0, 1):
                    with self.subTest(common_cathode=common_cathode, LED_STATE_ON=state_on):
                        command = compiler + ["-std=c99", "-Wall", "-Wextra", "-Werror",
                                              f"-DLED_STATE_ON={state_on}"]
                        if common_cathode:
                            command.append("-DLED_RGB_COMMON_CATHODE")
                        result = subprocess.run(
                            command + [str(c_file), "-o", str(binary)],
                            capture_output=True, text=True, timeout=30,
                        )
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        result = subprocess.run(
                            [str(binary)], capture_output=True, text=True, timeout=10,
                            cwd=root,
                        )
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
