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

#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[256];
static char cap[8192];

static void stage_timer_list(const char *text) {
  char path[320];
  snprintf(path, sizeof(path), "%s/proc/timer_list", g_root);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(fd >= 0);
  size_t n = strlen(text);
  assert(write(fd, text, n) == (ssize_t)n);
  close(fd);
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

/* End-to-end: real (aligned, in-VAS) '.base:' values emit the first as a
 * direct-map interior sample. */
static void test_real_emits(void) {
  unsigned long base = (unsigned long)KERNEL_VIRT_VAS_START;
  unsigned long v = base + 0x40;
  char fx[512];
  snprintf(fx, sizeof(fx), "cpu: 0\n clock 0:\n  .base:       %016lx\n", v);
  stage_timer_list(fx);
  run_capture();
  char want[64];
  snprintf(want, sizeof(want), "sample=0x%lx", v);
  assert(strstr(cap, "directmap") != NULL);
  assert(strstr(cap, want) != NULL);
}

int main(void) {
  char tmpl[] = "/tmp/kasld_tl_rootXXXXXX";
  char *r = mkdtemp(tmpl);
  assert(r != NULL);
  snprintf(g_root, sizeof(g_root), "%s", r);
  char dir[320];
  snprintf(dir, sizeof(dir), "%s/proc", g_root);
  mkdir(dir, 0755);
  setenv("KASLD_SYSROOT", g_root, 1);

  TEST_SUITE("test_proc_timer_list");
  BEGIN_CATEGORY("hashed-pointer rejection");
  RUN(test_classify_alignment_beats_vas);
  RUN(test_hashed_batch_declines);
  RUN(test_real_emits);
  return TEST_DONE();
}
