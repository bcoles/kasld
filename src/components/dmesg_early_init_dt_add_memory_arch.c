// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Flattened Device Tree (FDT) driver prints "Ignoring memory range" error if
// the requested memblock range is higher than max physical memory or smaller
// than __virt_to_phys(PAGE_OFFSET).
//
// For example, early_init_dt_add_memory_arch(0x80000000, 0x80000) on a system
// with DRAM start of 0x80200000 will print:
//
// [    0.000000] OF: fdt: Ignoring memory range 0x80000000 - 0x80200000
//
// On RISCV64 this may occur as the first 2MB are reserved for OpenSBI.
//
// On systems with a known phys->virt offset mapping, this may be used to
// identify the kernel virtual address region used for direct mapping.
//
// Leak primitive:
//   Data leaked:      physical DRAM base address (memblock range boundary)
//   Kernel subsystem: drivers/of/fdt — early_init_dt_add_memory_arch()
//   Data structure:   memblock range (physical base address)
//   Address type:     physical (DRAM)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (printed unconditionally when range is truncated)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.1.1/source/drivers/of/fdt.c#L1251
//
// Mitigations:
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details). Only printed when FDT memory range extends below usable
//   DRAM start. On decoupled architectures, physical addresses cannot
//   derive the virtual text base.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/drivers/of/fdt.c#L1251
// https://patchwork.kernel.org/project/linux-riscv/patch/20211123015717.542631-2-guoren@kernel.org/#24615539
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/dmesg.h"
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Searches dmesg for 'Ignoring memory range' messages from the FDT "
    "(flattened device tree) memory setup. These print the boundary of a "
    "memory range that falls below the kernel's usable DRAM start, "
    "revealing the physical DRAM base (PAGE_OFFSET). Common on "
    "ARM/ARM64/RISC-V systems where firmware reserves memory below the "
    "DRAM start. Access is gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

static int on_match(const char *line, void *ctx) {
  unsigned long *result = ctx;

  /* OF: fdt: Ignoring memory range 0x80000000 - 0x80200000 */
  const char *p = strstr(line, " - ");
  if (!p)
    return 1;

  char *endptr;
  unsigned long addr = strtoul(p + 2, &endptr, 16);

  if (addr >= KERNEL_VIRT_VAS_END)
    return 1;

  if (addr) {
    kasld_found("leaked DRAM physical address: 0x%016lx", addr);
    *result = addr;
    return 0;
  }
  return 1;
}

int main(void) {
  unsigned long addr = 0;

  kasld_info(
      "[.] searching dmesg for early_init_dt_add_memory_arch() ignored memory "
      "ranges ...");
  int ds = dmesg_search("OF: fdt: Ignoring memory range 0x", on_match, &addr);

  if (!addr) {
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    kasld_err("early_init_dt_add_memory_arch info not found in dmesg");
    return 0;
  }

  kasld_info("possible PAGE_OFFSET physical address: 0x%016lx", addr);
  /* early_init_dt_add_memory_arch() prints "Ignoring memory range LO - HI" for
   * TWO distinct clips, and this parser reads only HI:
   *   low-clip  (base, phys_offset):        HI is the DRAM base — a sound floor
   *   high-clip (MAX_MEMBLOCK_ADDR+1, base+size): HI is the top of a bank that
   *             overran the arch/limit-imposed physical ceiling — ABOVE all
   *             usable RAM, not a floor.
   * The two are indistinguishable from the value alone (the high-clip fires
   * whenever RAM exceeds MAX_MEMBLOCK_ADDR, e.g. a mem= / memblock-limited
   * boot). Emitting HI as a guaranteed REGION_RAM floor would, on a high-clip,
   * place a C_LOWER_BOUND above the true base and exclude it. Emit at
   * CONF_HEURISTIC so it only shapes the likely window; the guaranteed DRAM
   * floor is supplied by the unambiguous maps (sysfs device-tree memory,
   * /proc/iomem System RAM). */
  kasld_result_base(KASLD_TYPE_PHYS, REGION_RAM, addr, NULL, CONF_HEURISTIC);

#ifdef phys_to_directmap_virt
  unsigned long virt = phys_to_directmap_virt(addr);
  kasld_info("possible direct-map virtual address: 0x%016lx", virt);
  /* Derived from the same ambiguous HI value — likely window only. */
  kasld_result_base(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL,
                    CONF_HEURISTIC);
#else
  kasld_info("note: phys and virt KASLR are decoupled on this arch; "
             "cannot derive kernel text virtual address from physical leak");
#endif

  return 0;
}
