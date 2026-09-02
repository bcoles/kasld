// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for proc_iomem_kernel. The component is #included with its main
// renamed, then driven end-to-end over a staged KASLD_SYSROOT /proc/iomem.
//
// The branch worth guarding is the masking one. /proc/iomem is world-readable,
// but without CAP_SYS_ADMIN the kernel's r_show() prints every address as zero,
// and that is independent of kptr_restrict — the file looks present and
// well-formed while carrying nothing. Emitting from it would pin the physical
// image base at 0, which is not a wide answer but a wrong one, so the component
// must report access-denied rather than parse what it read. The rest of the
// surface is the label mapping (only the three "Kernel *" labels name a region)
// and the line rejections that keep a half-parsed range off the wire.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int proc_iomem_kernel_main(void);
#define main proc_iomem_kernel_main
#include "../src/components/proc_iomem_kernel.c"
#undef main

#include "test_component.h"
#include "test_harness.h"
#include "test_sysroot.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* The shape the component documents, indentation and all. */
static const char *const IOMEM_REAL = "00000000-00000fff : Reserved\n"
                                      "80000000-bfffffff : System RAM\n"
                                      "  1bc00000-1d336cef : Kernel code\n"
                                      "  1e600000-1ead557f : Kernel data\n"
                                      "  1f047000-1f5fffff : Kernel bss\n"
                                      "c0000000-c0003fff : PCI Bus 0000:00\n";

static void test_emits_each_kernel_extent(void) {
  th_sysroot_write("/proc/iomem", IOMEM_REAL);
  int rc;
  TH_RUN_COMPONENT(rc, proc_iomem_kernel_main());
  assert(rc == 0);
  /* Both edges on the wire, as a range, at parsed confidence. The image base
   * is the one the engine pins Q_PHYS_IMAGE_BASE from, so its low edge is the
   * value that matters. */
  assert(strstr(th_cap, "lo=0x1bc00000") != NULL);
  assert(strstr(th_cap, "hi=0x1d336cef") != NULL);
  /* Region AND name, as one token. Each line carries both, and they read alike
   * here, so matching the name alone would still pass with every label mapped
   * to the wrong region. */
  assert(strstr(th_cap, "kernel_image:kernel_code") != NULL);
  assert(strstr(th_cap, "kernel_data:kernel_data") != NULL);
  assert(strstr(th_cap, "kernel_bss:kernel_bss") != NULL);
  assert(strstr(th_cap, "conf=parsed") != NULL);
  /* Physical, never virtual: these are __pa_symbol() values. */
  assert(strstr(th_cap, "V ") == NULL);
}

/* Masked by the absence of CAP_SYS_ADMIN: every address reads as zero. The
 * file parses perfectly, so nothing but this check stops a pin at 0. */
static void test_masked_file_emits_nothing(void) {
  th_sysroot_write("/proc/iomem", "00000000-00000000 : System RAM\n"
                                  "  00000000-00000000 : Kernel code\n"
                                  "  00000000-00000000 : Kernel data\n"
                                  "  00000000-00000000 : Kernel bss\n");
  int rc;
  TH_RUN_COMPONENT(rc, proc_iomem_kernel_main());
  assert(th_cap[0] == '\0');
  /* Access denied, not source absent: the file is there and the caller lacks
   * the capability that fills it in. */
  assert(rc == KASLD_EXIT_NOPERM);
}

/* A single real address anywhere in the scanned prefix proves the file is not
 * masked, even when the kernel extents themselves are zero. */
static void test_partial_zeros_are_not_masking(void) {
  th_sysroot_write("/proc/iomem", "00000000-00000000 : Reserved\n"
                                  "80000000-bfffffff : System RAM\n"
                                  "  1bc00000-1d336cef : Kernel code\n");
  int rc;
  TH_RUN_COMPONENT(rc, proc_iomem_kernel_main());
  assert(rc == 0);
  assert(strstr(th_cap, "lo=0x1bc00000") != NULL);
}

/* An arch that publishes no kernel extents: the labels never match, so the
 * component emits nothing and says so rather than guessing from System RAM. */
static void test_no_kernel_labels_emits_nothing(void) {
  th_sysroot_write("/proc/iomem", "80000000-bfffffff : System RAM\n"
                                  "c0000000-c0003fff : PCI Bus 0000:00\n");
  int rc;
  TH_RUN_COMPONENT(rc, proc_iomem_kernel_main());
  assert(rc == 0);
  assert(th_cap[0] == '\0');
}

/* Only the three exact labels name a region. A prefix or a longer label is a
 * different resource, and matching it loosely would put an unrelated range on
 * the wire as the kernel image. */
static void test_label_match_is_exact(void) {
  th_sysroot_write("/proc/iomem", "80000000-bfffffff : System RAM\n"
                                  "  1bc00000-1d336cef : Kernel code extra\n"
                                  "  1e600000-1ead557f : Kernel\n"
                                  "  1f047000-1f5fffff : kernel code\n");
  int rc;
  TH_RUN_COMPONENT(rc, proc_iomem_kernel_main());
  assert(rc == 0);
  assert(th_cap[0] == '\0');
}

/* Lines that must not reach the wire: a reversed range, a missing separator,
 * and a missing label. Each is followed by a good line, so the test also proves
 * the parser keeps going rather than stopping at the first bad one.
 *
 * The reversed range is gated twice — the parser skips it, and
 * kasld_result_range refuses lo > hi regardless. This asserts the contract
 * rather than which layer enforces it, so it stays true if either moves. */
static void test_malformed_lines_are_skipped(void) {
  th_sysroot_write("/proc/iomem",
                   "80000000-bfffffff : System RAM\n"
                   "  1d336cef-1bc00000 : Kernel code\n" /* hi < lo */
                   "  1e600000 1ead557f : Kernel data\n" /* no '-'   */
                   "  1f047000-1f5fffff\n"               /* no label */
                   "  2a000000-2b000000 : Kernel bss\n");
  int rc;
  TH_RUN_COMPONENT(rc, proc_iomem_kernel_main());
  assert(rc == 0);
  assert(strstr(th_cap, "kernel_image:") == NULL);
  assert(strstr(th_cap, "kernel_data:") == NULL);
  assert(strstr(th_cap, "kernel_bss:kernel_bss") != NULL);
  assert(strstr(th_cap, "lo=0x2a000000") != NULL);
}

/* No file at all is a missing source, distinct from a masked one. */
static void test_absent_file_is_unavailable(void) {
  char full[TH_SYSROOT_MAX];
  th_sysroot_path("/proc/iomem", full, sizeof(full));
  unlink(full);
  int rc;
  TH_RUN_COMPONENT(rc, proc_iomem_kernel_main());
  assert(rc == KASLD_EXIT_UNAVAILABLE);
  assert(th_cap[0] == '\0');
}

int main(void) {
  th_sysroot_init("proc_iomem_kernel");
  TEST_SUITE("proc_iomem_kernel");

  BEGIN_CATEGORY("Kernel extents");
  RUN(test_emits_each_kernel_extent);
  RUN(test_no_kernel_labels_emits_nothing);
  RUN(test_label_match_is_exact);
  RUN(test_malformed_lines_are_skipped);

  BEGIN_CATEGORY("Capability masking");
  RUN(test_masked_file_emits_nothing);
  RUN(test_partial_zeros_are_not_masking);
  RUN(test_absent_file_is_unavailable);

  return TEST_DONE();
}
