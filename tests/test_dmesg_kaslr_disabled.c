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

#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[256];
static char cap[8192];

static void stage_dmesg(const char *text) {
  char path[320];
  snprintf(path, sizeof(path), "%s/var/log/dmesg", g_root);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(fd >= 0);
  size_t n = strlen(text);
  assert(write(fd, text, n) == (ssize_t)n);
  close(fd);
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
  char tmpl[] = "/tmp/kasld_kd_rootXXXXXX";
  char *r = mkdtemp(tmpl);
  assert(r != NULL);
  snprintf(g_root, sizeof(g_root), "%s", r);
  char dir[300];
  snprintf(dir, sizeof(dir), "%s/var", g_root);
  mkdir(dir, 0755);
  snprintf(dir, sizeof(dir), "%s/var/log", g_root);
  mkdir(dir, 0755);
  setenv("KASLD_SYSROOT", g_root, 1);

  TEST_SUITE("test_dmesg_kaslr_disabled");
  BEGIN_CATEGORY("KASLR-disabled line classification");
  RUN(test_nokaslr_is_opt_out);
  RUN(test_loongarch_is_disabled_is_opt_out);
  RUN(test_known_rand_failure_is_not_opt_out);
  RUN(test_unknown_disabled_line_emits_nothing);
  return TEST_DONE();
}
