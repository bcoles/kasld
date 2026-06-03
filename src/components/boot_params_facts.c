// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit x86 boot_params scalar facts: SF_INIT_SIZE (exact in-memory kernel
// size) and SF_KERNEL_ALIGN (CONFIG_PHYSICAL_ALIGN slot granularity). x86 only;
// the readers return 0 elsewhere.
// ---
// <bcoles@gmail.com>
#define _POSIX_C_SOURCE 200809L /* pread() in boot_params.h */
#include "include/kasld/api.h"
#include "include/kasld/boot_params.h"

KASLD_EXPLAIN("Reads /sys/kernel/boot_params/data for the exact kernel "
              "init_size and CONFIG_PHYSICAL_ALIGN, emitted as scalar facts "
              "tightening the KASLR ceiling and slot granularity. x86 only.");
KASLD_META("method:parsed\n"
           "phase:inference\n");

int main(void) {
  unsigned long v;
  if ((v = kasld_read_boot_init_size()))
    kasld_emit_scalar(SF_INIT_SIZE, v, CONF_PARSED);
  if ((v = kasld_read_boot_kernel_align()))
    kasld_emit_scalar(SF_KERNEL_ALIGN, v, CONF_PARSED);
  return 0;
}
