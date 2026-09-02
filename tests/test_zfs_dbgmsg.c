// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for zfs_dbgmsg. The component is #included with its main renamed, then
// driven over a staged KASLD_SYSROOT /proc/spl/kstat/zfs/dbgmsg.
//
// The log prints whatever pointer a message carried, so the component has to
// decide for itself which hex runs on a line are kernel addresses. Two rules do
// that: a run must be pointer-width (8..16 hex digits), and the value must land
// in a kernel window — kasld_addr_classify() reports the region, and anything
// it cannot place is dropped. Both directions matter. Emitting a timestamp or a
// byte count as an address puts a fabricated observation on the wire; dropping
// a real pointer loses the leak.
//
// Addresses are built from the running architecture's own windows so the file
// means the same thing on every target test-cross runs it on. Where a window is
// empty on this architecture the case is skipped rather than asserted, matching
// the component, which finds nothing to classify there either.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int zfs_dbgmsg_main(int argc, char **argv);
#define main zfs_dbgmsg_main
#include "../src/components/zfs_dbgmsg.c"
#undef main

#include "test_component.h"
#include "test_harness.h"
#include "test_sysroot.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* A direct-map pointer, in the shape the formatter emits: timestamp, then the
 * curthread pointer, then the message. The task_struct is slab-allocated, so
 * the direct map is where the common case lands. */
static void test_emits_a_directmap_pointer(void) {
  unsigned long dm = (unsigned long)PAGE_OFFSET + 0x21000;
  if (kasld_addr_classify(dm) != REGION_DIRECTMAP_BAND)
    return; /* no direct-map window on this architecture */
  char fx[512];
  snprintf(fx, sizeof(fx),
           "1700000000   %016lx spa.c:123:spa_open(): opening pool\n", dm);
  th_sysroot_write("/proc/spl/kstat/zfs/dbgmsg", fx);
  int rc;
  {
    char a0[] = "zfs_dbgmsg";
    char *av[] = {a0, NULL};
    TH_RUN_COMPONENT(rc, zfs_dbgmsg_main(1, av));
  }
  assert(rc == 0);
  char want[64];
  snprintf(want, sizeof(want), "sample=0x%lx", dm);
  assert(strstr(th_cap, want) != NULL);
  assert(strstr(th_cap, "directmap_band") != NULL);
  /* Virtual, at parsed confidence: the log prints %px, so the value is raw. */
  assert(strstr(th_cap, "V ") != NULL);
  assert(strstr(th_cap, "conf=parsed") != NULL);
}

/* A value outside every kernel window is not an address the component may
 * report. Gated twice: emit_addr drops REGION_UNKNOWN, and kasld__emit_check
 * refuses the region again in the emitter, so this asserts that the value stays
 * off the wire rather than which of the two kept it off. */
static void test_drops_a_non_kernel_value(void) {
  th_sysroot_write("/proc/spl/kstat/zfs/dbgmsg",
                   "1700000000   0000000000badbee zfs.c:1:f(): user pointer\n");
  int rc;
  {
    char a0[] = "zfs_dbgmsg";
    char *av[] = {a0, NULL};
    TH_RUN_COMPONENT(rc, zfs_dbgmsg_main(1, av));
  }
  assert(rc == 0);
  assert(th_cap[0] == '\0');
}

/* The upper width bound, isolated. A run longer than 16 digits is not a
 * pointer however it parses, and padding a real kernel address to 17 digits is
 * the only way to say so on the wire: the value is in a kernel window, so the
 * window check would admit it and only the width rule refuses.
 *
 * The lower bound cannot be isolated the same way. No kernel address on any
 * supported target is expressible in fewer than eight hex digits, so a short
 * run is always rejected by the window check too — the bound is a filter ahead
 * of the classifier, not an independent gate, and the test below asserts the
 * contract without claiming to separate them. */
static void test_over_width_run_is_not_a_pointer(void) {
  unsigned long dm = (unsigned long)PAGE_OFFSET + 0x26000;
  if (kasld_addr_classify(dm) != REGION_DIRECTMAP_BAND)
    return;
  char fx[512];
  /* Same value, one leading zero too many. */
  snprintf(fx, sizeof(fx), "1700000000   0%016lx zil.c:4:z(): padded\n", dm);
  th_sysroot_write("/proc/spl/kstat/zfs/dbgmsg", fx);
  int rc;
  {
    char a0[] = "zfs_dbgmsg";
    char *av[] = {a0, NULL};
    TH_RUN_COMPONENT(rc, zfs_dbgmsg_main(1, av));
  }
  assert(rc == 0);
  assert(th_cap[0] == '\0');
}

/* Hex that is not pointer-width is not a pointer: the leading timestamp and a
 * short byte count are both hex runs on a real line. Neither is a kernel
 * address either, so the window check backs the width rule up here — this
 * asserts that they stay off the wire, not which rule kept them off. */
static void test_ignores_hex_that_is_not_pointer_width(void) {
  unsigned long dm = (unsigned long)PAGE_OFFSET + 0x22000;
  if (kasld_addr_classify(dm) != REGION_DIRECTMAP_BAND)
    return;
  char fx[512];
  /* 17 hex digits is too long to be a pointer, 7 too short; the real pointer
   * sits between them and must still be found. */
  snprintf(
      fx, sizeof(fx),
      "1700000000   %016lx vdev.c:9:v(): len=abcdef1 huge=123456789abcdef01\n",
      dm);
  th_sysroot_write("/proc/spl/kstat/zfs/dbgmsg", fx);
  int rc;
  {
    char a0[] = "zfs_dbgmsg";
    char *av[] = {a0, NULL};
    TH_RUN_COMPONENT(rc, zfs_dbgmsg_main(1, av));
  }
  assert(rc == 0);
  char want[64];
  snprintf(want, sizeof(want), "sample=0x%lx", dm);
  assert(strstr(th_cap, want) != NULL);
  assert(strstr(th_cap, "sample=0xabcdef1") == NULL);
  assert(strstr(th_cap, "123456789abcdef01") == NULL);
}

/* Every hex run on a line is scanned, not just the first: message bodies carry
 * their own pointers after the curthread one. */
static void test_scans_every_pointer_on_a_line(void) {
  unsigned long a = (unsigned long)PAGE_OFFSET + 0x23000;
  unsigned long b = (unsigned long)PAGE_OFFSET + 0x24000;
  if (kasld_addr_classify(a) != REGION_DIRECTMAP_BAND ||
      kasld_addr_classify(b) != REGION_DIRECTMAP_BAND)
    return;
  char fx[512];
  snprintf(fx, sizeof(fx),
           "1700000000   %016lx raidz.c:7:r(): reconstruct rm=%016lx\n", a, b);
  th_sysroot_write("/proc/spl/kstat/zfs/dbgmsg", fx);
  int rc;
  {
    char a0[] = "zfs_dbgmsg";
    char *av[] = {a0, NULL};
    TH_RUN_COMPONENT(rc, zfs_dbgmsg_main(1, av));
  }
  assert(rc == 0);
  char wa[64], wb[64];
  snprintf(wa, sizeof(wa), "sample=0x%lx", a);
  snprintf(wb, sizeof(wb), "sample=0x%lx", b);
  assert(strstr(th_cap, wa) != NULL);
  assert(strstr(th_cap, wb) != NULL);
}

/* The same pointer repeats on nearly every line — it is the current task. One
 * observation is the honest count; repeating it would weight the evidence by
 * how chatty the log is. */
static void test_repeated_pointer_is_emitted_once(void) {
  unsigned long dm = (unsigned long)PAGE_OFFSET + 0x25000;
  if (kasld_addr_classify(dm) != REGION_DIRECTMAP_BAND)
    return;
  char fx[768];
  snprintf(fx, sizeof(fx),
           "1700000000   %016lx a.c:1:a(): one\n"
           "1700000001   %016lx b.c:2:b(): two\n"
           "1700000002   %016lx c.c:3:c(): three\n",
           dm, dm, dm);
  th_sysroot_write("/proc/spl/kstat/zfs/dbgmsg", fx);
  int rc;
  {
    char a0[] = "zfs_dbgmsg";
    char *av[] = {a0, NULL};
    TH_RUN_COMPONENT(rc, zfs_dbgmsg_main(1, av));
  }
  assert(rc == 0);
  char want[64];
  snprintf(want, sizeof(want), "sample=0x%lx", dm);
  const char *first = strstr(th_cap, want);
  assert(first != NULL);
  assert(strstr(first + 1, want) == NULL);
}

/* An empty log is a live ZFS with nothing recorded: the source is present and
 * the technique applied, so this is exit 0 with no result rather than a claim
 * that ZFS is absent. */
static void test_empty_log_emits_nothing(void) {
  th_sysroot_write("/proc/spl/kstat/zfs/dbgmsg", "");
  int rc;
  {
    char a0[] = "zfs_dbgmsg";
    char *av[] = {a0, NULL};
    TH_RUN_COMPONENT(rc, zfs_dbgmsg_main(1, av));
  }
  assert(rc == 0);
  assert(th_cap[0] == '\0');
}

/* No file at all is ZFS not loaded — provably inapplicable, not a miss. */
static void test_absent_log_is_unavailable(void) {
  char full[TH_SYSROOT_MAX];
  th_sysroot_path("/proc/spl/kstat/zfs/dbgmsg", full, sizeof(full));
  unlink(full);
  int rc;
  {
    char a0[] = "zfs_dbgmsg";
    char *av[] = {a0, NULL};
    TH_RUN_COMPONENT(rc, zfs_dbgmsg_main(1, av));
  }
  assert(rc == KASLD_EXIT_UNAVAILABLE);
  assert(th_cap[0] == '\0');
}

int main(void) {
  th_sysroot_init("zfs_dbgmsg");
  TEST_SUITE("zfs_dbgmsg");

  BEGIN_CATEGORY("Pointer recovery");
  RUN(test_emits_a_directmap_pointer);
  RUN(test_scans_every_pointer_on_a_line);
  RUN(test_repeated_pointer_is_emitted_once);

  BEGIN_CATEGORY("Rejection");
  RUN(test_drops_a_non_kernel_value);
  RUN(test_ignores_hex_that_is_not_pointer_width);
  RUN(test_over_width_run_is_not_a_pointer);
  RUN(test_empty_log_emits_nothing);
  RUN(test_absent_log_is_unavailable);

  return TEST_DONE();
}
