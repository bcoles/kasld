// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for ptdump_kernel_page_tables. The component is #included with its main
// renamed, then driven end-to-end over a staged KASLD_SYSROOT
// /sys/kernel/debug/page_tables/kernel.
//
// The behaviour under test: in the "High Kernel Mapping" region an unmapped gap
// (no protection flags) precedes the mapped kernel image, so the first run
// carrying a protection flag begins at _text. The parser must skip the gap and
// pin that first mapped run as the image base, and must decline where the
// region marker is absent. Synthetic addresses are built from the arch's own
// text window so the assertion holds on every arch where the component fires
// (TEXT_TRACKS_DIRECTMAP == 0); on coupled-text arches it is inert.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

/* The component's main() signature is arch-dependent (int main(void) on
 * coupled-text arches, int main(int, char **) elsewhere), so it is not
 * forward-declared here — the include below defines the renamed function. */
#define main ptdump_main
#include "../src/components/ptdump_kernel_page_tables.c"
#undef main

#include "test_harness.h"
#include "test_sysroot.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if !TEXT_TRACKS_DIRECTMAP

static char cap[8192];

/* Run the component, capturing its stdout (the wire channel) into `cap`; stderr
 * diagnostics are silenced. */
static void run_capture(void) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_ptdump_capXXXXXX";
  int fd = mkstemp(tmpl);
  assert(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);

  char arg0[] = "ptdump_kernel_page_tables";
  char *argv[] = {arg0, NULL};
  ptdump_main(1, argv);

  fflush(stdout);
  fflush(stderr);
  dup2(saved, 1);
  close(saved);
  dup2(saved_err, 2);
  close(saved_err);
  if (devnull >= 0)
    close(devnull);
  lseek(fd, 0, SEEK_SET);
  ssize_t r = read(fd, cap, sizeof(cap) - 1);
  cap[r > 0 ? r : 0] = '\0';
  close(fd);
  unlink(tmpl);
}

/* The unmapped gap is skipped and the first mapped run is pinned as the image
 * base. `_text` sits an offset into the arch's text window; the gap line below
 * it carries no protection flag, the image line carries "ro". */
static void test_recovers_image_base(void) {
  unsigned long text = (unsigned long)KERNEL_VIRT_TEXT_MIN + 0x200000;
  unsigned long gap = (unsigned long)KERNEL_VIRT_TEXT_MIN;
  char fx[512];
  snprintf(fx, sizeof(fx),
           "---[ High Kernel Mapping ]---\n"
           "0x%016lx-0x%016lx           2M                               pmd\n"
           "0x%016lx-0x%016lx          18M     ro         PSE     GLB x  pmd\n"
           "---[ Modules ]---\n",
           gap, text, text, text + 0x1200000);
  th_sysroot_write("/sys/kernel/debug/page_tables/kernel", fx);
  run_capture();
  char want[64];
  snprintf(want, sizeof(want), "lo=0x%lx", text);
  assert(strstr(cap, "kernel_image") != NULL);
  assert(strstr(cap, want) != NULL);
}

/* A dump without the "High Kernel Mapping" region pins nothing (the arm64
 * shape, where the image has no distinct header). */
static void test_no_marker_declines(void) {
  th_sysroot_write(
      "/sys/kernel/debug/page_tables/kernel",
      "---[ vmalloc() Area ]---\n"
      "0xffffc90000000000-0xffffc90000001000   4K   RW         GLB NX pte\n");
  run_capture();
  assert(strstr(cap, "kernel_image") == NULL);
}

#else /* coupled-text arch: the component is inert. */

static void test_inert_on_coupled(void) { assert(ptdump_main() == 0); }

#endif

int main(void) {
  th_sysroot_init("ptdump");

  TEST_SUITE("test_ptdump");
#if !TEXT_TRACKS_DIRECTMAP
  BEGIN_CATEGORY("page-table dump parse");
  RUN(test_recovers_image_base);
  RUN(test_no_marker_declines);
#else
  BEGIN_CATEGORY("inert on coupled-text arches");
  RUN(test_inert_on_coupled);
#endif
  return TEST_DONE();
}
