// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for KASLD_UNAME_IS_OURS (api.h).
//
// The check that uses it warns when uname's machine field names a kernel this
// build does not model, which covers both a foreign architecture and a foreign
// address width, since a 64-bit kernel of a family reports a different string
// than its 32-bit one.
//
// The dangerous failure is not a missed mismatch -- that prints a window for
// the wrong machine, and only for someone who ran the wrong build on purpose --
// but a FALSE one, warning about a run that is entirely correct with nothing on
// the command line to get past it. So the first assertion is that the predicate
// accepts the machine this binary is running on.
//
// That assertion is per-architecture, and each architecture has its own
// predicate: `make test-cross` runs this under qemu for every cross target,
// where uname reports the emulated machine, so each predicate is put to its own
// kernel's spelling rather than only x86_64's.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

#include "include/kasld/api.h"
#include "test_harness.h"

#include <string.h>
#include <sys/utsname.h>

/* The machine this binary is running on is one this build models, or the check
 * built on this predicate warns about a correct run. */
static void test_accepts_its_own_machine(void) {
  struct utsname u;
  TH_CHECK(uname(&u) == 0);
  TH_CHECK(u.machine[0] != '\0');
  TH_CHECK(KASLD_UNAME_IS_OURS(u.machine));
}

/* A machine no architecture reports is not ours, whichever build this is. */
static void test_rejects_a_foreign_machine(void) {
  TH_CHECK(!KASLD_UNAME_IS_OURS("vax"));
  TH_CHECK(!KASLD_UNAME_IS_OURS(""));
}

/* The two families whose 32- and 64-bit kernels share a prefix, where a
 * predicate written as a plain prefix test would accept the wrong width. Both
 * are asserted from every build, because the mistake is in the narrow
 * predicate and only the narrow build would otherwise exercise it. */
static void test_shared_prefixes_do_not_collide(void) {
  int narrow =
      !strcmp(KASLD_ARCH_NAME, "mips32") || !strcmp(KASLD_ARCH_NAME, "ppc32");
  if (!narrow)
    return;
  if (!strcmp(KASLD_ARCH_NAME, "mips32")) {
    TH_CHECK(KASLD_UNAME_IS_OURS("mips"));
    TH_CHECK(!KASLD_UNAME_IS_OURS("mips64"));
  } else {
    TH_CHECK(KASLD_UNAME_IS_OURS("ppc"));
    TH_CHECK(!KASLD_UNAME_IS_OURS("ppc64"));
    TH_CHECK(!KASLD_UNAME_IS_OURS("ppc64le"));
  }
}

int main(void) {
  TEST_SUITE("Build/target identity (KASLD_UNAME_IS_OURS)");

  BEGIN_CATEGORY("predicate");
  RUN(test_accepts_its_own_machine);
  RUN(test_rejects_a_foreign_machine);
  RUN(test_shared_prefixes_do_not_collide);

  return TEST_DONE();
}
