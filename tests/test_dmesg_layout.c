// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parser unit tests for dmesg_mem_init_kernel_layout.
//
// The riscv print_vm_layout() dump's "kernel : 0x<virt_addr> - 0x<end>" line
// reports kernel_map.virt_addr (where _start/_stext land) directly, so its low
// edge is a pos=base kernel-text pin. These tests exercise the static parser
// (on_match() + the entries table) by #including the component with its main
// renamed, capturing the emitted P/V/S wire lines. Addresses derive from the
// arch's KERNEL_VIRT_TEXT_MIN, so the suite is valid on every width/endianness
// under tests/test-cross.
// ---
// <bcoles@gmail.com>

/* Rename the component's main so its parser/table link into this test TU. The
 * forward declaration keeps -Wmissing-prototypes quiet for the renamed symbol.
 */
int dmesg_layout_component_main(void);
#define main dmesg_layout_component_main
#include "../src/components/dmesg_mem_init_kernel_layout.c"
#undef main

#include "test_harness.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Run one log line through the parser, capturing the component's stdout (the
 * P/V/S wire lines) into buf so the emitted result can be asserted. */
static void parse_capture(const char *line, char *buf, size_t bufsz) {
  fflush(stdout);
  int saved = dup(STDOUT_FILENO);
  FILE *tmp = tmpfile();
  assert(saved >= 0 && tmp);
  dup2(fileno(tmp), STDOUT_FILENO);
  /* Silence the component's stderr diagnostics (the kasld_info/_found
   * data-echo) for the duration of the call so they don't leak into the test
   * runner; we assert only on the stdout wire line. */
  fflush(stderr);
  int saved_err = dup(STDERR_FILENO);
  int devnull = open("/dev/null", O_WRONLY);
  assert(saved_err >= 0 && devnull >= 0);
  dup2(devnull, STDERR_FILENO);
  struct search_ctx ctx = {0};
  on_match(line, &ctx);
  fflush(stdout);
  dup2(saved, STDOUT_FILENO);
  close(saved);
  fflush(stderr);
  dup2(saved_err, STDERR_FILENO);
  close(saved_err);
  close(devnull);
  rewind(tmp);
  size_t n = fread(buf, 1, bufsz - 1, tmp);
  buf[n] = '\0';
  fclose(tmp);
}

static char cap[8192];

/* The "kernel" line reports _start (kernel_map.virt_addr, the image LOAD
 * address). The engine's image base is _text, IMAGE_BASE_OFFSET above _start on
 * a head-gap arch, so the emitted pos=base KERNEL_IMAGE value is projected up
 * by IMAGE_BASE_OFFSET (a no-op on arches where it is 0, e.g. the x86_64 host).
 */
static void test_kernel_line_pins_text_base(void) {
  unsigned long start = (unsigned long)KERNEL_VIRT_TEXT_MIN;
  unsigned long image_base = start + (unsigned long)IMAGE_BASE_OFFSET;
  char line[256], want[64];
  snprintf(line, sizeof(line),
           "      kernel : 0x%lx - 0xffffffffffffffff   (   2 GB)", start);
  parse_capture(line, cap, sizeof(cap));
  /* REGION_KERNEL_IMAGE, not KERNEL_TEXT (which the engine treats as _stext and
   * shifts down by the head gap). */
  assert(strstr(cap, "V kernel_image pos=base") != NULL);
  snprintf(want, sizeof(want), "lo=0x%lx",
           image_base); /* _start + head = _text */
  assert(strstr(cap, want) != NULL);
}

/* An address below the kernel-text window is rejected by the section gate, so
 * the broad "kernel : 0x" needle cannot false-match an unrelated log line. */
static void test_kernel_line_below_text_rejected(void) {
  parse_capture("      kernel : 0x1000 - 0xffffffffffffffff", cap, sizeof(cap));
  assert(strstr(cap, "kernel_text") == NULL);
}

int main(void) {
  TEST_SUITE("test_dmesg_layout");
  BEGIN_CATEGORY("riscv layout-dump kernel line");
  RUN(test_kernel_line_pins_text_base);
  RUN(test_kernel_line_below_text_rejected);
  return TEST_DONE();
}
