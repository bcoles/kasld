// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for riscv64_no_seed: the non-EFI riscv64 KASLR-off detector. The kernel
// zeroes /chosen/kaslr-seed the moment it consumes it, so at userspace a cell
// still holding a NON-ZERO value proves the seed was never used and the kernel
// is at the compile-time default -- the detector must report KASLR off there,
// not leave the base to a slot derivation that the wipe makes impossible. The
// component is #included with its main renamed, then driven against a staged
// sysroot. riscv64 only; the source #errors on other arches, so the include and
// the cases are gated and the file is inert elsewhere.
#define _GNU_SOURCE /* mkdtemp / setenv / lstat used by test_sysroot.h */

#if defined(__riscv) && __riscv_xlen == 64
#define main riscv64_no_seed_main
#include "../src/components/riscv64_no_seed.c"
#undef main
#endif

#include "test_harness.h"
#include "test_sysroot.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if defined(__riscv) && __riscv_xlen == 64

static char cap[8192];

/* Run the component, capturing its stdout (the wire channel) into `cap`; stderr
 * diagnostics are silenced. */
static void run_capture(void) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_rv64noseed_capXXXXXX";
  int fd = mkstemp(tmpl);
  TH_CHECK(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);

  riscv64_no_seed_main();

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

/* An 8-byte big-endian /chosen/kaslr-seed with the given low word. */
static void stage_seed(unsigned long lo) {
  unsigned char be[8] = {0,
                         0,
                         0,
                         0,
                         (unsigned char)(lo >> 24),
                         (unsigned char)(lo >> 16),
                         (unsigned char)(lo >> 8),
                         (unsigned char)lo};
  th_sysroot_write_n("/proc/device-tree/chosen/kaslr-seed", be, sizeof(be));
}

static void stage_cpuinfo(int with_zkr) {
  th_sysroot_write("/proc/cpuinfo",
                   with_zkr ? "processor\t: 0\nisa\t\t: rv64imafdc_zkr\n"
                            : "processor\t: 0\nisa\t\t: rv64imafdc\n");
}

/* A cell still holding a non-zero value was never consumed -> KASLR off ->
 * report it. This is the case that previously drove a wrong slot pin. */
static void test_visible_nonzero_seed_pins_disabled(void) {
  th_sysroot_clear();
  stage_seed(0xdeadbeeful);
  stage_cpuinfo(0);
  run_capture();
  TH_CHECK(strstr(cap, "virt_kaslr_disabled") != NULL);
}

/* The soundness edge: a present-but-zero cell is ambiguous (consumed then
 * wiped, or a zero seed supplied). Reporting KASLR off here would exclude the
 * true base on a kernel that DID randomize, so the detector must stay silent.
 */
static void test_present_zero_seed_stays_silent(void) {
  th_sysroot_clear();
  stage_seed(0);
  stage_cpuinfo(0);
  run_capture();
  TH_CHECK(strstr(cap, "virt_kaslr_disabled") == NULL);
}

/* Zkr seeds KASLR ahead of the FDT and leaves the cell untouched, so a visible
 * seed on a Zkr-capable CPU may sit beside a randomized base: do not report
 * KASLR off. */
static void test_zkr_with_visible_seed_stays_silent(void) {
  th_sysroot_clear();
  stage_seed(0xdeadbeeful);
  stage_cpuinfo(1);
  run_capture();
  TH_CHECK(strstr(cap, "virt_kaslr_disabled") == NULL);
}

/* An absent cell on a non-Zkr CPU is the original no-seed signal and still
 * reports KASLR off. The device tree must be present for the branch to arm. */
static void test_absent_seed_pins_disabled(void) {
  th_sysroot_clear();
  th_sysroot_write("/proc/device-tree/chosen/bootargs", "console=ttyS0");
  stage_cpuinfo(0);
  run_capture();
  TH_CHECK(strstr(cap, "virt_kaslr_disabled") != NULL);
}

#else /* off-riscv64: the component is architecture-gated out of the build. */

static void test_inert_off_riscv64(void) { TH_CHECK(1); }

#endif

int main(void) {
  th_sysroot_init("riscv64_no_seed");

  TEST_SUITE("test_riscv64_no_seed");
#if defined(__riscv) && __riscv_xlen == 64
  BEGIN_CATEGORY("fdt seed -> kaslr-disabled");
  RUN(test_visible_nonzero_seed_pins_disabled);
  RUN(test_present_zero_seed_stays_silent);
  RUN(test_zkr_with_visible_seed_stays_silent);
  RUN(test_absent_seed_pins_disabled);
#else
  BEGIN_CATEGORY("inert off riscv64");
  RUN(test_inert_off_riscv64);
#endif
  return TEST_DONE();
}
