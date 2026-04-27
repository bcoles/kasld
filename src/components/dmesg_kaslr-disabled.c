// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for messages stating KASLR is disabled.
//
// x86/x86_64:
// KASLR disabled: 'kaslr' not on cmdline (hibernation selected).
// KASLR disabled: 'nokaslr' on cmdline.
//
// ARM64:
// KASLR disabled on command line
// KASLR disabled due to lack of seed
// KASLR disabled due to FDT remapping failure
//
// LoongArch:
// KASLR is disabled.
//
// S390:
// KASLR disabled: CPU has no PRNG
// KASLR disabled: not enough memory
//
// Introduced for ARM64 in kernel v5.5-rc1~22^2~11^9~1 on 2019-11-09:
// https://github.com/torvalds/linux/commit/294a9ddde6cdbf931a28b8c8c928d3f799b61cb5
//
// Detection component — does not leak an address.
//   Purpose: searches dmesg for messages indicating KASLR was disabled
//   (nokaslr boot param, missing entropy seed, etc.). If found, the
//   default text base is the actual kernel base.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v5.19.17/source/arch/arm64/kernel/kaslr.c#L197
// https://elixir.bootlin.com/linux/v5.19.17/source/arch/arm64/kernel/kaslr.c#L200
// https://elixir.bootlin.com/linux/v6.1.6/source/arch/arm64/kernel/kaslr.c#L45
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/s390/boot/kaslr.c#L35
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/s390/boot/kaslr.c#L201
// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/kernel/relocate.c#L107
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/dmesg.h"
#include "include/kasld.h"
#include "include/kasld_internal.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN("Searches dmesg for messages indicating KASLR was disabled or "
              "could not be enabled (nokaslr boot flag, missing entropy seed, "
              "insufficient randomness). If KASLR is off, the compile-time "
              "default kernel text base is the actual load address. Access is "
              "gated by dmesg_restrict.");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "addr:none\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

static int on_match(const char *line, void *ctx) {
  bool *found = ctx;

  if (strstr(line, "KASLR disabled") || strstr(line, "KASLR is disabled")) {
    *found = true;
    return 0;
  }
  return 1;
}

int main(void) {
  bool nokaslr = false;

  printf(
      "[.] searching dmesg for 'KASLR disabled' or 'KASLR is disabled' ...\n");
  int ds = dmesg_search("KASLR ", on_match, &nokaslr);

  if (!nokaslr) {
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    printf("[-] KASLR disabled indicator not found in dmesg\n");
    return 0;
  }

  printf("[.] Kernel was booted with KASLR disabled\n");

  unsigned long addr = (unsigned long)KERNEL_TEXT_DEFAULT;
  printf("common default kernel text for arch: %lx\n", addr);
  kasld_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, addr,
               KASLD_REGION_KERNEL_TEXT, "nokaslr");

  return 0;
}
