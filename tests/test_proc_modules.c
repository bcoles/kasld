// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for proc_modules. The component is #included with its main renamed,
// then driven over a staged KASLD_SYSROOT /proc/modules.
//
// Two decisions are worth guarding. The addresses go out as REGION_MODULE, not
// REGION_MODULE_BAND: each is a loaded module's own base read from a per-module
// record, so the region is known structurally rather than inferred from the
// value landing in a band. That is what lets a consumer bracket module text on
// architectures whose band is a wide multi-layout union — a band-tagged
// observation says only "somewhere in this window", which those arches already
// knew. And every address is filtered through kasld_addr_is_module_band()
// before it counts, so a line whose hex is not a module address contributes
// nothing.
//
// The masking case is the one that matters in the field: /proc/modules prints
// module addresses through restricted_pointer(), so at any kptr_restrict above
// zero every line reads as 0x0000000000000000. The file is present, parses
// cleanly, and carries nothing — emitting from it would put address zero on the
// wire as a module base.
//
// Addresses are built from the architecture's own module band and the case is
// skipped where that band is empty, so the file means the same thing on every
// target test-cross runs it on.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int proc_modules_main(void);
#define main proc_modules_main
#include "../src/components/proc_modules.c"
#undef main

#include "test_component.h"
#include "test_harness.h"
#include "test_sysroot.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* A module address inside the band, and one below it that must not count. */
static int band_addrs(unsigned long *lo, unsigned long *hi) {
  *lo = (unsigned long)MODULES_START + 0x1000;
  *hi = (unsigned long)MODULES_START + 0x81000;
  return kasld_addr_is_module_band(*lo) && kasld_addr_is_module_band(*hi);
}

/* The /proc/modules line shape: name, size, refcount, deps, state, address. */
static void stage_modules(const char *body) {
  th_sysroot_write("/proc/modules", body);
}

/* Both edges reach the wire as REGION_MODULE samples — never module_band, and
 * never a base, since a module load address bounds nothing on its own. */
static void test_emits_module_addresses_as_samples(void) {
  unsigned long lo, hi;
  if (!band_addrs(&lo, &hi))
    return; /* no module band on this architecture */
  char fx[512];
  snprintf(fx, sizeof(fx),
           "nf_tables ryzen 0 - Live 0x%016lx\n"
           "overlay 151552 1 - Live 0x%016lx\n",
           hi, lo);
  stage_modules(fx);
  int rc;
  TH_RUN_COMPONENT(rc, proc_modules_main());
  assert(rc == 0);
  assert(th_cap_field_is("sample", lo));
  assert(th_cap_field_is("sample", hi));
  /* Structural region, not the band. */
  assert(strstr(th_cap, "V module ") != NULL ||
         strstr(th_cap, "V module:") != NULL);
  assert(strstr(th_cap, "module_band") == NULL);
  assert(!th_cap_field_is("lo", lo));
  assert(strstr(th_cap, "conf=parsed") != NULL);
}

/* kptr_restrict masks every address to zero. The file is present and parses
 * cleanly, so nothing about its shape says the addresses are gone.
 *
 * Gated twice, and the second gate cannot be taken away: the parser drops a
 * zero, and kasld_addr_is_module_band(0) is false on every architecture, so a
 * masked address fails the band test as well. No address is both zero and in
 * the band, which means the zero test has no case of its own to be caught on.
 * This asserts that a masked file yields nothing, not which check achieves
 * it. */
static void test_masked_addresses_emit_nothing(void) {
  stage_modules("nf_tables 315392 0 - Live 0x0000000000000000\n"
                "overlay 151552 1 - Live 0x0000000000000000\n");
  int rc;
  TH_RUN_COMPONENT(rc, proc_modules_main());
  assert(rc == 0);
  assert(th_cap[0] == '\0');
}

/* An address outside the module band is not a module base however it got onto
 * the line. Without the band test any hex on the line would be reported. */
static void test_out_of_band_address_is_ignored(void) {
  unsigned long lo, hi;
  if (!band_addrs(&lo, &hi))
    return;
  unsigned long stray = (unsigned long)PAGE_OFFSET + 0x1000;
  if (kasld_addr_is_module_band(stray))
    return; /* the two windows overlap here; nothing to distinguish */
  char fx[512];
  snprintf(fx, sizeof(fx),
           "overlay 151552 1 - Live 0x%016lx\n"
           "stray 4096 0 - Live 0x%016lx\n",
           lo, stray);
  stage_modules(fx);
  int rc;
  TH_RUN_COMPONENT(rc, proc_modules_main());
  assert(rc == 0);
  assert(th_cap_field_is("sample", lo));
  assert(!th_cap_field_is("sample", stray));
}

/* One module gives one observation, not the same address twice as a
 * degenerate low/high pair. */
static void test_single_module_emits_one_sample(void) {
  unsigned long lo, hi;
  if (!band_addrs(&lo, &hi))
    return;
  char fx[256];
  snprintf(fx, sizeof(fx), "overlay 151552 1 - Live 0x%016lx\n", lo);
  stage_modules(fx);
  int rc;
  TH_RUN_COMPONENT(rc, proc_modules_main());
  assert(rc == 0);
  char want[64];
  snprintf(want, sizeof(want), "sample=0x%lx", lo);
  const char *first = strstr(th_cap, want);
  assert(first != NULL);
  assert(strstr(first + 1, want) == NULL);
}

/* No modules loaded: the file exists and is empty of addresses, so the
 * technique applied and found nothing. */
static void test_no_modules_emits_nothing(void) {
  stage_modules("");
  int rc;
  TH_RUN_COMPONENT(rc, proc_modules_main());
  assert(rc == 0);
  assert(th_cap[0] == '\0');
}

/* A line with no address at all must not stop the scan reaching the ones that
 * follow it. */
static void test_addressless_line_does_not_end_the_scan(void) {
  unsigned long lo, hi;
  if (!band_addrs(&lo, &hi))
    return;
  char fx[512];
  snprintf(fx, sizeof(fx),
           "weird 4096 0 - Live\n"
           "overlay 151552 1 - Live 0x%016lx\n",
           lo);
  stage_modules(fx);
  int rc;
  TH_RUN_COMPONENT(rc, proc_modules_main());
  assert(rc == 0);
  assert(th_cap_field_is("sample", lo));
}

int main(void) {
  th_sysroot_init("proc_modules");
  TEST_SUITE("proc_modules");

  BEGIN_CATEGORY("Module addresses");
  RUN(test_emits_module_addresses_as_samples);
  RUN(test_single_module_emits_one_sample);
  RUN(test_addressless_line_does_not_end_the_scan);

  BEGIN_CATEGORY("Filtering");
  RUN(test_masked_addresses_emit_nothing);
  RUN(test_out_of_band_address_is_ignored);
  RUN(test_no_modules_emits_nothing);

  return TEST_DONE();
}
