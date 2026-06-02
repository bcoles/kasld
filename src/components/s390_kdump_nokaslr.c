// This file is part of KASLD - https://github.com/bcoles/kasld
//
// s390: detect the `elfcorehdr=` cmdline parameter that disables KASLR on a
// kdump crash kernel.
//
// Detection component — does not leak an address.
//   Purpose: arch/s390/boot/startup.c setup_ident_map_size() forces
//   __kaslr_enabled = 0 when oldmem_data.start is non-zero (i.e. running as
//   the kdump crash kernel handed off by the predecessor). The canonical
//   handoff token is `elfcorehdr=<addr>`, set by kexec_file_load(2) with
//   KEXEC_FILE_ON_CRASH. The kernel then loads at the deterministic
//   __NO_KASLR_START_KERNEL address (= CONFIG_KERNEL_IMAGE_BASE + TEXT_OFFSET
//   = our KERNEL_TEXT_DEFAULT).
//
// s390 only. x86-64 and arm64 do NOT unconditionally disable KASLR for the
// kdump kernel — they re-run the KASLR path within the reserved crashkernel
// range. This signal is specific to s390's __kaslr_enabled = 0 short-circuit
// in setup_ident_map_size().
//
// References:
// arch/s390/boot/startup.c setup_ident_map_size() (v6.x):
//   if (oldmem_data.start) { __kaslr_enabled = 0; ... }
// elfcorehdr= is set by kexec_file_load(KEXEC_FILE_ON_CRASH) on every arch.
//
// s390 only — gated at compile time so non-s390 builds skip via the
// Makefile's `cc-component` wrapper instead of shipping an empty main().
// ---
// <bcoles@gmail.com>

#if !defined(__s390__) && !defined(__s390x__)
#error "Architecture is not supported"
#endif

#include "include/cmdline.h"
#include "include/kasld/api.h"
#include <stdio.h>

KASLD_EXPLAIN(
    "s390 only: when running as a kdump crash kernel (elfcorehdr= present "
    "on /proc/cmdline, set by kexec_file_load with KEXEC_FILE_ON_CRASH), "
    "arch/s390/boot/startup.c forces __kaslr_enabled = 0 and the kernel "
    "loads at CONFIG_KERNEL_IMAGE_BASE + TEXT_OFFSET. Emits SF_KASLR_DISABLED "
    "for the engine's kaslr_disabled_pin rule. /proc/cmdline is "
    "world-readable.");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "addr:none\n");

int main(void) {
  if (!cmdline_has_prefix("elfcorehdr=")) {
    fprintf(stderr, "[-] no 'elfcorehdr=' on /proc/cmdline\n");
    return 1;
  }

  printf("[.] s390 'elfcorehdr=' on /proc/cmdline — running as kdump "
         "crash kernel; __kaslr_enabled forced to 0.\n");
  kasld_emit_scalar(SF_KASLR_DISABLED, 1, CONF_PARSED);
  return 0;
}
