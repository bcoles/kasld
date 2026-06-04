// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parse the `mem=N` cmdline token (x86) and emit it as SF_PHYS_CMDLINE_MEM.
//
// Detection component — does not leak an address.
//   Purpose: when the cmdline carries `mem=<size>`, x86's KASLR placer caps
//   the physical base at this value (arch/x86/boot/compressed/kaslr.c
//   handle_mem_options() + find_random_phys_addr()): the kernel image must
//   satisfy `phys_base + image_size <= mem`. The cmdline_mem_phys_ceiling /
//   cmdline_mem_virt_ceiling rules consume the emitted scalar (plus
//   SF_IMAGE_SIZE) to bound Q_PHYS_TEXT_BASE or Q_VIRT_TEXT_BASE.
//
// /proc/cmdline is world-readable (0444), so the token is observable without
// privileges. The kernel-side parser is `memparse` (lib/cmdline.c): optional
// 0x/0 prefix, decimal/hex digits, optional K/M/G/T/P/E suffix — we mirror it
// in kasld_memparse() (cmdline.h) to accept exactly the same input.
//
// Scope: x86_32 + x86_64. On other arches `mem=` is parsed only after early
// boot and does not affect KASLR placement, so emitting the scalar would be
// misleading; the component returns 0 elsewhere.
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/boot/compressed/kaslr.c#L260
// https://elixir.bootlin.com/linux/v6.12/source/lib/cmdline.c
// ---
// <bcoles@gmail.com>

#include "include/cmdline.h"
#include "include/kasld/api.h"
#include <stdio.h>

KASLD_EXPLAIN(
    "x86 only: parses the `mem=<size>` cmdline token and emits its bytes as "
    "SF_PHYS_CMDLINE_MEM. x86's KASLR placer caps the physical base at this "
    "value, "
    "so the kernel image satisfies `phys_base + image_size <= mem`. The rule "
    "cmdline_mem_{phys,virt}_ceiling consumes the scalar (with SF_IMAGE_SIZE) "
    "to bound the text base. /proc/cmdline is world-readable (0444).");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "addr:none\n");

int main(void) {
#if defined(__x86_64__) || defined(__i386__)
  unsigned long mem = 0;
  if (!cmdline_get_memparse("mem=", &mem) || mem == 0) {
    fprintf(stderr, "[-] no `mem=` token on /proc/cmdline\n");
    return 1;
  }
  printf("[.] cmdline mem= cap: %#lx (%lu bytes)\n", mem, mem);
  kasld_emit_scalar(SF_PHYS_CMDLINE_MEM, mem, CONF_PARSED);
#endif
  /* Other arches: emit nothing (mem= does not constrain KASLR placement). */
  return 0;
}
