// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for proc_timer_list's hashed-pointer rejection (the proc_net_sock_ptr
// class). The component is #included with its main renamed, so
// classify_timer_base is in scope, and it is driven end-to-end over a staged
// KASLD_SYSROOT /proc/timer_list.
//
// The '.base:' field is a per-CPU struct timer_base pointer printed with '%p',
// hashed to a random word on v4.15+. A real base is pointer-aligned; alignment
// is checked before the kernel-VAS floor, so an in-VAS hashed id is still
// caught, and a single misaligned '.base:' condemns the whole read.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int proc_timer_list_main(void);
#define main proc_timer_list_main
#include "../src/components/proc_timer_list.c"
#undef main

#include "test_harness.h"
#include "test_sysroot.h"

#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static char cap[8192];

static void stage_timer_list(const char *text) {
  th_sysroot_write("/proc/timer_list", text);
}

static void run_capture(void) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_tl_capXXXXXX";
  int fd = mkstemp(tmpl);
  assert(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);

  proc_timer_list_main();

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

/* classify_timer_base: alignment decided BEFORE the kernel-VAS floor. */
static void test_classify_alignment_beats_vas(void) {
  unsigned long base = (unsigned long)KERNEL_VIRT_VAS_START;
  assert(classify_timer_base(0) == TB_SKIP);
  assert(classify_timer_base(sizeof(void *)) ==
         TB_SKIP); /* aligned, below VAS */
  assert(classify_timer_base(base + 0x40) == TB_CANDIDATE);
  /* Misaligned -> hashed, even INSIDE the kernel VAS (the 32-bit failure mode).
   */
  assert(classify_timer_base(base + 0x45) == TB_HASHED);
}

/* End-to-end: an in-VAS MISALIGNED '.base:' condemns the read despite an
 * aligned sibling — no direct-map address emitted. */
static void test_hashed_batch_declines(void) {
  unsigned long base = (unsigned long)KERNEL_VIRT_VAS_START;
  char fx[512];
  snprintf(fx, sizeof(fx),
           "cpu: 0\n clock 0:\n  .base:       %016lx\n"
           " clock 1:\n  .base:       %016lx\n",
           base + 0x45,  /* misaligned -> hashed */
           base + 0x40); /* aligned sibling, but the read is condemned */
  stage_timer_list(fx);
  run_capture();
  assert(strstr(cap, "directmap") == NULL);
}

/* End-to-end: real (aligned, in-VAS) '.base:' values emit the first as an
 * interior sample, with a region that does NOT over-claim.
 *
 * The candidate test accepts any kernel VA, because the direct-map window is
 * empty wherever the linear map and the text window collide, so the region is a
 * range verdict and must come out as a band tag. Asserted as "some _band tag,
 * and no bare confident one" rather than by naming a region: which band it is
 * depends on the host's windows, and a substring test for "directmap" is
 * satisfied by "directmap_band" — which is how this assertion kept passing
 * after the region it was written to pin had changed underneath it. */
static void test_real_emits(void) {
  unsigned long base = (unsigned long)KERNEL_VIRT_VAS_START;
  unsigned long v = base + 0x40;
  char fx[512];
  snprintf(fx, sizeof(fx), "cpu: 0\n clock 0:\n  .base:       %016lx\n", v);
  stage_timer_list(fx);
  run_capture();
  char want[64];
  snprintf(want, sizeof(want), "sample=0x%lx", v);
  assert(strstr(cap, want) != NULL);
  assert(strstr(cap, "_band") != NULL);
  /* The wire field is "V <region> pos=..."; a confident tag would appear with a
   * trailing space, a band tag never does. */
  assert(strstr(cap, "V directmap ") == NULL);
  assert(strstr(cap, "V kernel_text ") == NULL);
}

int main(void) {
  th_sysroot_init("proc_timer_list");

  TEST_SUITE("test_proc_timer_list");
  BEGIN_CATEGORY("hashed-pointer rejection");
  RUN(test_classify_alignment_beats_vas);
  RUN(test_hashed_batch_declines);
  RUN(test_real_emits);
  return TEST_DONE();
}
