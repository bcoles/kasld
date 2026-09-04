// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit SF_PAGE_SIZE: the kernel page size in bytes. The arm64 EFI_KIMG_ALIGN
// rule derives the physical slot granularity from it (4K/16K vs 64K pages).
// ---
// <bcoles@gmail.com>
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <unistd.h>

KASLD_EXPLAIN("Emits the kernel page size (sysconf _SC_PAGESIZE) as a scalar "
              "fact; the arm64 physical-alignment rule consumes it.");
/* source:live — sysconf answers for the kernel executing this process. A
 * captured tree carries no page size, and the analysing host's is not the
 * captured target's: replaying an arm64 bundle on an x86_64 host would report
 * 4 KiB as though it were the target's page size, and the rules that multiply a
 * page-frame number by it would silently compute the wrong physical address.
 * Skipped under KASLD_SYSROOT, leaving those rules to decline instead. */
KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:facts\n"
           "source:live\n");

int main(int argc, char *argv[]) {
  kasld_cli(argc, argv);
  if (kasld_skip_live_probe("page size"))
    return 0;
  long p = sysconf(_SC_PAGESIZE);
  if (p > 0)
    kasld_emit_scalar(SF_PAGE_SIZE, (unsigned long)p, CONF_PARSED);
  return 0;
}
