// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for the kernel identity reported under KASLD_SYSROOT
// (kasld_uname, kasld_uname_from_proc_version, kasld_uname_fingerprint).
//
// Replay has to describe the captured kernel, not the machine reading the
// capture. Two things ride on it: the report names a kernel, and the
// offset-table components key on "<release> <version>" -- a fingerprint mixing
// the two builds matches no table entry, and a missed lookup is indistinguish-
// able from a build with no entry, so replay silently under-reports.
//
// Every staged value here differs from any plausible host uname, so a test can
// only pass by reading the staged tree.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

#include "include/kasld/sysroot.h"
#include "test_harness.h"
#include "test_sysroot.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

/* An Alpine line, whose release and version match no host running this test. */
#define STAGED_RELEASE "5.15.207-0-lts"
#define STAGED_VERSION "#1-Alpine SMP Sat, 16 May 2026 10:46:17 +0000"
#define STAGED_LINE                                                            \
  "Linux version " STAGED_RELEASE " (buildozer@build-3-15-x86_64) (gcc "       \
                                  "(Alpine 12.2.1) 12.2.1) " STAGED_VERSION    \
  "\n"

static void stage_version(const char *line) {
  if (line == NULL) {
    th_sysroot_rm("/proc/version");
    return;
  }
  th_sysroot_write("/proc/version", line);
}

static void test_both_fields_come_from_the_capture(void) {
  struct utsname u, host;
  stage_version(STAGED_LINE);
  assert(uname(&host) == 0);
  assert(kasld_uname(&u) == 0);
  assert(strcmp(u.release, STAGED_RELEASE) == 0);
  assert(strcmp(u.version, STAGED_VERSION) == 0);
  /* The staged tree won: neither field is the analysing host's. */
  assert(strcmp(u.release, host.release) != 0);
  assert(strcmp(u.version, host.version) != 0);
}

/* .machine is the emulated arch under qemu-user and compile-time on native;
 * /proc/version does not carry it and must not disturb it. */
static void test_machine_is_left_alone(void) {
  struct utsname u, host;
  stage_version(STAGED_LINE);
  assert(uname(&host) == 0);
  assert(kasld_uname(&u) == 0);
  assert(strcmp(u.machine, host.machine) == 0);
}

/* A compiler string can carry its own " version ": the first match is the
 * kernel's, and a later one must not be mistaken for the release. */
static void test_compiler_version_is_not_the_release(void) {
  struct utsname u;
  stage_version("Linux version 4.14.141-169 (root@1604_builder_armhf) "
                "(gcc version 7.4.0 (Ubuntu/Linaro 7.4.0-1ubuntu1~18.04.1)) "
                "#1 SMP PREEMPT Sat Aug 31 23:19:59 -03 2019\n");
  assert(kasld_uname(&u) == 0);
  assert(strcmp(u.release, "4.14.141-169") == 0);
  assert(strcmp(u.version, "#1 SMP PREEMPT Sat Aug 31 23:19:59 -03 2019") == 0);
}

/* The environment override exists for a run with no captured /proc/version and
 * for qemu-user, which drops QEMU_UNAME across its self-re-exec. Where both are
 * present the explicit one wins. */
static void test_env_release_overrides_the_capture(void) {
  struct utsname u;
  stage_version(STAGED_LINE);
  assert(setenv("KASLD_UNAME_RELEASE", "9.9.9-explicit", 1) == 0);
  assert(kasld_uname(&u) == 0);
  assert(unsetenv("KASLD_UNAME_RELEASE") == 0);
  assert(strcmp(u.release, "9.9.9-explicit") == 0);
  assert(strcmp(u.version, STAGED_VERSION) == 0);
}

/* Unparseable input leaves both fields as uname(2) returned them. Blanking a
 * field would label the report with an empty kernel, which reads as a fact. */
static void test_unparseable_leaves_the_uname_fields(void) {
  struct utsname u, host;
  const char *bad[] = {
      "not a version line at all\n",
      "Linux version\n",                    /* no release token */
      "Linux version 5.15.0-0-lts\n",       /* release, no version tail */
      "Linux version  (gcc) #1 SMP\n",      /* empty release */
      "Linux version 5.15.0 (gcc) SMP x\n", /* no build number */
      "",                                   /* empty file */
  };
  size_t i;
  assert(uname(&host) == 0);
  for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    stage_version(bad[i]);
    assert(kasld_uname(&u) == 0);
    assert(strcmp(u.release, host.release) == 0);
    assert(strcmp(u.version, host.version) == 0);
  }
}

static void test_absent_version_leaves_the_uname_fields(void) {
  struct utsname u, host;
  stage_version(NULL);
  assert(uname(&host) == 0);
  assert(kasld_uname(&u) == 0);
  assert(strcmp(u.release, host.release) == 0);
  assert(strcmp(u.version, host.version) == 0);
}

static void test_fingerprint_names_the_captured_build(void) {
  struct utsname u;
  char fp[192];
  stage_version(STAGED_LINE);
  assert(kasld_uname(&u) == 0);
  kasld_uname_fingerprint(fp, sizeof(fp), &u);
  assert(strcmp(fp, STAGED_RELEASE " " STAGED_VERSION) == 0);
}

/* utsname.version is a 64-char field, so the kernel clips a long version
 * string. Reading the full line from a capture must clip identically, or the
 * replayed fingerprint differs from the one the target itself would compose. */
static void test_long_version_clips_to_the_uname_field(void) {
  struct utsname u;
  char fp[192];
  /* 64 chars through "...UTC", then a space and more: the clip lands on the
   * space and the fingerprint trim removes it. */
  const char *v =
      "#136-Ubuntu SMP PREEMPT_DYNAMIC Wed Jul  1 21:53:05 UTC 2026 xyz"
      " and more text beyond the field";
  char line[512];
  snprintf(line, sizeof(line), "Linux version %s (b@h) (gcc) %s\n",
           STAGED_RELEASE, v);
  stage_version(line);
  assert(kasld_uname(&u) == 0);
  assert(strlen(u.version) == sizeof(u.version) - 1);
  assert(strncmp(u.version, v, sizeof(u.version) - 1) == 0);
  kasld_uname_fingerprint(fp, sizeof(fp), &u);
  assert(fp[strlen(fp) - 1] != ' ');
}

int main(void) {
  TEST_SUITE("Kernel identity under KASLD_SYSROOT (sysroot.h)");
  th_sysroot_init("uname");

  BEGIN_CATEGORY("captured build");
  RUN(test_both_fields_come_from_the_capture);
  RUN(test_machine_is_left_alone);
  RUN(test_compiler_version_is_not_the_release);
  RUN(test_long_version_clips_to_the_uname_field);

  BEGIN_CATEGORY("fallbacks");
  RUN(test_env_release_overrides_the_capture);
  RUN(test_unparseable_leaves_the_uname_fields);
  RUN(test_absent_version_leaves_the_uname_fields);

  BEGIN_CATEGORY("offset-table fingerprint");
  RUN(test_fingerprint_names_the_captured_build);

  return TEST_DONE();
}
