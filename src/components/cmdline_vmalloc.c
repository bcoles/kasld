// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parse the `vmalloc=N` cmdline token and emit it as SF_CMDLINE_VMALLOC.
//
// On s390 the vmalloc size is one term of the vmem estimate the boot code
// compares against _REGION2_SIZE when it picks the kernel's ASCE limit
// (arch/s390/boot/startup.c get_vmem_size / setup_kernel_memory_layout). A
// consumer bounding that estimate from ABOVE therefore needs the size bounded
// from above too, and `vmalloc=` has no ceiling of its own: the boot parser
// takes whatever memparse() returns and rounds it up to _SEGMENT_SIZE
// (arch/s390/boot/ipl_parm.c). Absent the token the kernel uses
// VMALLOC_DEFAULT_SIZE, which a consumer knows.
//
// So the emission is three-state, and the third state is the important one:
//   value > 0  — the token is present, carrying its size in bytes.
//   value == 0 — /proc/cmdline was read and carries no `vmalloc=`, so the
//                kernel took its compile-time default.
//   no emission — /proc/cmdline could not be read. The size is then unbounded
//                and a consumer must decline rather than assume the default.
//
// /proc/cmdline is world-readable (0444). No privileges, no sysctl gate.
// s390 only: the token exists elsewhere but constrains no layout KASLD solves.
// ---
// <bcoles@gmail.com>

#if !defined(__s390x__) && !defined(__zarch__)
#error "Architecture is not supported"
#endif

#include "include/cmdline.h"
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <stdio.h>

KASLD_EXPLAIN(
    "Reads /proc/cmdline for the `vmalloc=` token and emits its size as "
    "SF_CMDLINE_VMALLOC, or zero when the command line carries no such token. "
    "On s390 the vmalloc size is one term of the vmem estimate the boot code "
    "weighs when choosing between 3-level and 4-level paging, so bounding that "
    "estimate needs this bounded. Emitting nothing at all means the command "
    "line was unreadable and the size is unknown. s390 only; unprivileged.");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "discloses:facts\n"
           "source:files\n");

int main(void) {
  unsigned long vmalloc = 0;
  char buf[2048];
  FILE *f;

  /* Distinguish "no token" from "no command line": only the former is a fact.
   * cmdline_get_memparse reports both as a failed lookup, so establish the
   * line is readable first and let an unreadable one emit nothing. The same
   * open cmdline_has_word and friends do, through the sysroot wrapper. */

  f = kasld_fopen("/proc/cmdline", "r");
  if (!f) {
    /* A denied read and an absent file are different vantages, and only errno
     * tells them apart: report the one that happened rather than assuming. */
    kasld_err("could not open /proc/cmdline");
    return kasld_exit_for_errno();
  }
  if (!fgets(buf, sizeof(buf), f)) {
    fclose(f);
    kasld_err("/proc/cmdline is empty");
    return KASLD_EXIT_UNAVAILABLE;
  }
  fclose(f);

  if (!cmdline_get_memparse("vmalloc=", &vmalloc))
    vmalloc = 0; /* read, and the token is not there */

  if (vmalloc)
    kasld_info("cmdline vmalloc=: %#lx (%lu bytes)", vmalloc, vmalloc);
  else
    kasld_info("no `vmalloc=` on the command line; the kernel default applies");
  kasld_emit_scalar(SF_CMDLINE_VMALLOC, vmalloc, CONF_PARSED);
  return 0;
}
