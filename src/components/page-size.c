// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit SF_PAGE_SIZE: the kernel page size in bytes. The arm64 EFI_KIMG_ALIGN
// rule derives the physical slot granularity from it (4K/16K vs 64K pages).
// ---
// <bcoles@gmail.com>
#include "include/kasld/api.h"
#include <unistd.h>

KASLD_EXPLAIN("Emits the kernel page size (sysconf _SC_PAGESIZE) as a scalar "
              "fact; the arm64 physical-alignment rule consumes it.");
KASLD_META("method:parsed\n"
           "phase:inference\n");

int main(void) {
  long p = sysconf(_SC_PAGESIZE);
  if (p > 0)
    kasld_emit_scalar(SF_PAGE_SIZE, (unsigned long)p, CONF_PARSED);
  return 0;
}
