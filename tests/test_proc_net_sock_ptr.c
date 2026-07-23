// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for proc_net_sock_ptr's hashed-pointer rejection. The component is
// #included with its main renamed, so its static classify_sock_ptr() is in
// scope, and it is also driven end-to-end over a staged KASLD_SYSROOT
// /proc/net/unix.
//
// The behaviour under test: a real struct sock pointer is slab-aligned, a
// hashed %pK id is a random word. Alignment is checked before the kernel-VAS
// floor, so a hashed id that lands inside the (wide, on 32-bit) VAS is still
// recognised as hashed; and because hashing is all-or-nothing per boot, a
// single misaligned token condemns the whole read — no forged direct-map
// address is emitted.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int proc_net_sock_ptr_main(int argc, char **argv);
#define main proc_net_sock_ptr_main
#include "../src/components/proc_net_sock_ptr.c"
#undef main

#include "test_harness.h"

#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[256];
static char cap[8192];

/* Write `text` as the sysroot's /proc/net/unix (the source the component reads
 * under KASLD_SYSROOT). /proc/net/netlink is left absent — the component scans
 * whichever source is present. */
static void stage_unix(const char *text) {
  char path[320];
  snprintf(path, sizeof(path), "%s/proc/net/unix", g_root);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(fd >= 0);
  size_t n = strlen(text);
  assert(write(fd, text, n) == (ssize_t)n);
  close(fd);
}

/* Run the component, capturing its stdout (the wire channel) into `cap`; stderr
 * diagnostics are silenced. */
static void run_capture(void) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_sock_capXXXXXX";
  int fd = mkstemp(tmpl);
  assert(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);

  char arg0[] = "proc_net_sock_ptr";
  char *argv[] = {arg0, NULL};
  proc_net_sock_ptr_main(1, argv);

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

/* classify_sock_ptr: alignment is decided BEFORE the kernel-VAS floor. */
static void test_classify_alignment_beats_vas(void) {
  unsigned long base = (unsigned long)KERNEL_VIRT_VAS_START;
  /* Zero and aligned-but-non-kernel are skipped. */
  assert(classify_sock_ptr(0) == SOCK_PTR_SKIP);
  assert(classify_sock_ptr(8) == SOCK_PTR_SKIP); /* aligned, below the VAS */
  /* Aligned + in the kernel VAS -> a plausible sock pointer. */
  assert(classify_sock_ptr(base + 0x40) == SOCK_PTR_CANDIDATE);
  /* Misaligned -> hashed, even when the value sits INSIDE the kernel VAS (the
   * 32-bit failure mode, where a hashed id passes the wide VAS floor). */
  assert(classify_sock_ptr(base + 0x45) == SOCK_PTR_HASHED);
  assert(classify_sock_ptr(0x7a5476c5UL) == SOCK_PTR_HASHED); /* misaligned */
}

/* End-to-end: an in-VAS MISALIGNED (hashed) token condemns the whole read, even
 * though an aligned in-VAS sibling is present — no direct-map address emitted.
 */
static void test_hashed_batch_declines(void) {
  unsigned long base = (unsigned long)KERNEL_VIRT_VAS_START;
  char fx[512];
  snprintf(fx, sizeof(fx),
           "Num       RefCount Protocol Flags    Type St Inode Path\n"
           "%016lx: 00000002 00000000 00010000 0001 01  1234 /run/a\n"
           "%016lx: 00000002 00000000 00010000 0001 01  1235 /run/b\n",
           base + 0x45,  /* misaligned -> hashed */
           base + 0x40); /* aligned sibling, but the read is condemned */
  stage_unix(fx);
  run_capture();
  assert(strstr(cap, "directmap") == NULL); /* nothing forged */
}

/* End-to-end: real (aligned, in-VAS) pointers emit the lowest as a direct-map
 * interior sample. */
static void test_real_pointers_emit_lowest(void) {
  unsigned long base = (unsigned long)KERNEL_VIRT_VAS_START;
  unsigned long lo = base + 0x40, hi = base + 0x2000;
  char fx[512];
  snprintf(fx, sizeof(fx),
           "Num       RefCount Protocol Flags    Type St Inode Path\n"
           "%016lx: 00000002 00000000 00010000 0001 01  1234 /run/a\n"
           "%016lx: 00000002 00000000 00010000 0001 01  1235 /run/b\n",
           hi, lo);
  stage_unix(fx);
  run_capture();
  char want[64];
  snprintf(want, sizeof(want), "sample=0x%lx", lo);
  assert(strstr(cap, "directmap") != NULL);
  assert(strstr(cap, want) != NULL);
}

int main(void) {
  char tmpl[] = "/tmp/kasld_sock_rootXXXXXX";
  char *r = mkdtemp(tmpl);
  assert(r != NULL);
  snprintf(g_root, sizeof(g_root), "%s", r);
  char dir[320];
  snprintf(dir, sizeof(dir), "%s/proc", g_root);
  mkdir(dir, 0755);
  snprintf(dir, sizeof(dir), "%s/proc/net", g_root);
  mkdir(dir, 0755);
  setenv("KASLD_SYSROOT", g_root, 1);

  TEST_SUITE("test_proc_net_sock_ptr");
  BEGIN_CATEGORY("hashed-pointer rejection");
  RUN(test_classify_alignment_beats_vas);
  RUN(test_hashed_batch_declines);
  RUN(test_real_pointers_emit_lowest);
  return TEST_DONE();
}
