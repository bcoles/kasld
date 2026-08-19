// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Classification test for dmesg_kaslr_disabled. The component is #included with
// its main renamed and driven over a staged KASLD_SYSROOT /var/log/dmesg.
//
// The behaviour under test: a "KASLR disabled" dmesg line is turned into a
// pin-to-default opt-out ONLY for the specific phrases the boot stubs print for
// a definitive opt-out (nokaslr / hibernation-selected / arm64 command-line /
// loongarch "is disabled"). A known randomization-FAILURE reason emits the
// distinct RANDOMIZATION_FAILED facts (never the pin-to-default), and an
// UNRECOGNIZED "KASLR disabled" line emits nothing — so a future/unknown reason
// can never forge the pin-to-default C_EQUALS and exclude the true base.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int dmesg_kaslr_disabled_main(void);
#define main dmesg_kaslr_disabled_main
#include "../src/components/dmesg_kaslr_disabled.c"
#undef main

#include "test_harness.h"
#include "test_sysroot.h"

#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char cap[8192];

static void stage_dmesg(const char *text) {
  th_sysroot_write("/var/log/dmesg", text);
}

static void run_capture(void) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_kd_capXXXXXX";
  int fd = mkstemp(tmpl);
  assert(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);

  dmesg_kaslr_disabled_main();

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

/* nokaslr opt-out → pin-to-default facts. */
static void test_nokaslr_is_opt_out(void) {
  stage_dmesg("kernel: KASLR disabled: 'nokaslr' on cmdline.\n");
  run_capture();
  assert(strstr(cap, "virt_kaslr_disabled conf=") != NULL);
  assert(strstr(cap, "phys_kaslr_disabled conf=") != NULL);
  assert(strstr(cap, "randomization_failed") == NULL);
}

/* loongarch "KASLR is disabled." opt-out. */
static void test_loongarch_is_disabled_is_opt_out(void) {
  stage_dmesg("kernel: KASLR is disabled.\n");
  run_capture();
  assert(strstr(cap, "virt_kaslr_disabled conf=") != NULL);
}

/* A known randomization-failure reason is NOT a pin-to-default: it emits the
 * distinct RANDOMIZATION_FAILED facts and never virt/phys_kaslr_disabled. */
static void test_known_rand_failure_is_not_opt_out(void) {
  stage_dmesg("kernel: KASLR disabled: CPU has no PRNG\n");
  run_capture();
  assert(strstr(cap, "virt_kaslr_randomization_failed conf=") != NULL);
  assert(strstr(cap, "phys_kaslr_randomization_failed conf=") != NULL);
  assert(strstr(cap, "virt_kaslr_disabled conf=") == NULL);
  assert(strstr(cap, "phys_kaslr_disabled conf=") == NULL);
}

/* The fix: an unrecognized "KASLR disabled" line (e.g. a future reason not yet
 * classified) must emit NOTHING — neither the pin-to-default nor a
 * randomization-failed guess. */
static void test_unknown_disabled_line_emits_nothing(void) {
  stage_dmesg("kernel: KASLR disabled due to some brand-new future reason\n");
  run_capture();
  assert(strstr(cap, "kaslr_disabled conf=") == NULL);
  assert(strstr(cap, "randomization_failed conf=") == NULL);
}

int main(void) {
  th_sysroot_init("dmesg_kaslr_disabled");

  TEST_SUITE("test_dmesg_kaslr_disabled");
  BEGIN_CATEGORY("KASLR-disabled line classification");
  RUN(test_nokaslr_is_opt_out);
  RUN(test_loongarch_is_disabled_is_opt_out);
  RUN(test_known_rand_failure_is_not_opt_out);
  RUN(test_unknown_disabled_line_emits_nothing);
  return TEST_DONE();
}
