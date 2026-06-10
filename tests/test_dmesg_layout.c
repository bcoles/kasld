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
  struct search_ctx ctx = {0};
  on_match(line, &ctx);
  fflush(stdout);
  dup2(saved, STDOUT_FILENO);
  close(saved);
  rewind(tmp);
  size_t n = fread(buf, 1, bufsz - 1, tmp);
  buf[n] = '\0';
  fclose(tmp);
}

static char cap[8192];

/* The "kernel" line pins the text base: the low edge becomes a pos=base
 * KERNEL_TEXT result (the high edge, a fixed VAS end, is ignored by LK_BASE).
 */
static void test_kernel_line_pins_text_base(void) {
  unsigned long base = (unsigned long)KERNEL_VIRT_TEXT_MIN;
  char line[256], want[64];
  snprintf(line, sizeof(line),
           "      kernel : 0x%lx - 0xffffffffffffffff   (   2 GB)", base);
  parse_capture(line, cap, sizeof(cap));
  assert(strstr(cap, "V kernel_text pos=base") != NULL);
  snprintf(want, sizeof(want), "lo=0x%lx", base);
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
