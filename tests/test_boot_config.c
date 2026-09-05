// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Provenance test for boot_config. The component is #included with its main
// renamed and driven over a staged KASLD_SYSROOT, so the whole config search +
// scalar-fact emission runs against hand-built /boot config files.
//
// The behaviour under test: a release-keyed config (/boot/config-$(uname -r))
// is bound to the running kernel and its facts are emitted at CONF_PARSED,
// reaching the guaranteed window; the unkeyed /boot/config carries no release
// binding and its facts are demoted to CONF_HEURISTIC so a stale/foreign file
// can never forge a guaranteed pin. The keyed paths are also tried first, so an
// unkeyed file never shadows the correct one.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int boot_config_main(void);
#define main boot_config_main
#include "../src/components/boot_config.c"
#undef main

#include "test_harness.h"
#include "test_sysroot.h"

#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

static char cap[8192];

/* KASLR compiled out so the disabled facts fire; CONFIG_PHYSICAL_START gives a
 * second scalar. text_order is emitted unconditionally, so it is the reliable
 * line to check the confidence on. The "# ... is not set" form is the real
 * .config representation of a compiled-out option and is required: the disabled
 * signal keys on that positive token, not on the mere absence of "=y" (which a
 * truncated or unreadable config would also show). */
static const char *CFG =
    "# CONFIG_RANDOMIZE_BASE is not set\nCONFIG_PHYSICAL_START=0x1000000\n";

static void write_file(const char *rel, const char *content) {
  th_sysroot_write(rel, content);
}

static void rm_file(const char *rel) { th_sysroot_rm(rel); }

/* The release the staged tree claims. Deliberately not this host's: the keyed
 * path is built from the release kasld resolves, so keying the file to
 * uname(2) would pass whenever the tool read the analysing host instead of the
 * tree -- the one substitution these tests must be able to catch. */
#define STAGED_RELEASE "5.15.207-0-staged"

/* A capture states its own release through /proc/version, the way collect
 * records it; without one the tree identifies no kernel and no keyed path can
 * be built. */
static void stage_identity(void) {
  th_sysroot_write("/proc/version",
                   "Linux version " STAGED_RELEASE " (b@h) (gcc) "
                   "#1-staged SMP Mon Jan 2 09:28:30 UTC 2023\n");
}

/* Run the component, capturing its stdout (the wire channel) into `cap`;
 * the stderr diagnostics are silenced. */
static void run_capture(void) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_bc_capXXXXXX";
  int fd = mkstemp(tmpl);
  assert(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);

  boot_config_main();

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

/* Only the unkeyed /boot/config is present: every fact must be demoted to
 * CONF_HEURISTIC so a config with no running-kernel binding cannot forge a
 * guaranteed pin. */
static void test_unkeyed_config_is_heuristic(void) {
  write_file("/boot/config", CFG);
  run_capture();
  rm_file("/boot/config");

  assert(strstr(cap, "text_order conf=heuristic") != NULL);
  assert(strstr(cap, "virt_kaslr_disabled conf=heuristic") != NULL);
  assert(strstr(cap, "phys_kaslr_disabled conf=heuristic") != NULL);
  /* No fact from an unkeyed source may reach the guaranteed floor. */
  assert(strstr(cap, "conf=parsed") == NULL);
}

/* The release-keyed /boot/config-$(uname -r) is authoritative for the running
 * kernel: its facts stay at CONF_PARSED. */
static void test_keyed_config_is_parsed(void) {
  char keyed[300];
  stage_identity();
  snprintf(keyed, sizeof(keyed), "/boot/config-%s", STAGED_RELEASE);
  write_file(keyed, CFG);
  run_capture();
  rm_file(keyed);

  assert(strstr(cap, "text_order conf=parsed") != NULL);
  assert(strstr(cap, "virt_kaslr_disabled conf=parsed") != NULL);
  assert(strstr(cap, "conf=heuristic") == NULL);
}

/* With BOTH present, the keyed path wins (tried first) — the unkeyed file must
 * not shadow the authoritative one. */
static void test_keyed_beats_unkeyed(void) {
  char keyed[300];
  stage_identity();
  snprintf(keyed, sizeof(keyed), "/boot/config-%s", STAGED_RELEASE);
  write_file(keyed, CFG);
  write_file("/boot/config", CFG);
  run_capture();
  rm_file(keyed);
  rm_file("/boot/config");

  assert(strstr(cap, "text_order conf=parsed") != NULL);
  assert(strstr(cap, "conf=heuristic") == NULL);
}

int main(void) {
  th_sysroot_init("boot_config");

  TEST_SUITE("test_boot_config");
  BEGIN_CATEGORY("kernel-config provenance -> confidence");
  RUN(test_unkeyed_config_is_heuristic);
  RUN(test_keyed_config_is_parsed);
  RUN(test_keyed_beats_unkeyed);
  return TEST_DONE();
}
