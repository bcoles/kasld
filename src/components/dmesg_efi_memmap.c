// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parses EFI memory map entries from dmesg. Requires the `efi=debug`
// boot parameter (gates `efi_enabled(EFI_DBG)` in the kernel); not set
// by default on most distributions. Format differs by architecture:
//
// ARM / ARM64 / RISC-V (drivers/firmware/efi/efi-init.c):
//   efi:   0x000000000000-0x00000009ffff [Conventional Memory|  ...]
//
// x86 (arch/x86/platform/efi/efi.c):
//   efi: mem00: [Conventional Memory|  ...]
//   range=[0x0000000000000000-0x000000000009ffff] (0MB)
//
// Leak primitive:
//   Data leaked:      physical memory map (EFI memory map entries)
//   Kernel subsystem: drivers/firmware/efi — efi_print_memmap()
//   Data structure:   EFI memory descriptor entries (physical ranges)
//   Address type:     physical (DRAM + MMIO)
//   Method:           parsed (dmesg string)
//   Status:           unfixed; gated by efi=debug
//   Access check:     do_syslog() → check_syslog_permissions(),
//                     gated by dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/drivers/firmware/efi/efi-init.c#L164
//
// Mitigations:
//   efi=debug is off by default. Access is gated by dmesg_restrict (see
//   dmesg.h for the shared access path). On decoupled architectures the
//   physical addresses do not derive the virtual text base.
//
// Requires:
// - efi=debug kernel boot parameter.
// - kernel.dmesg_restrict = 0, or CAP_SYSLOG, or readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/firmware/efi/efi-init.c#L164
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/platform/efi/efi.c#L353
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

#define range_ctx addr_range

KASLD_EXPLAIN(
    "Parses EFI memory map entries from dmesg (requires efi=debug boot "
    "parameter). Each entry lists a physical address range and its type "
    "(conventional memory, MMIO, runtime services, loader code, etc.). "
    "Extracts physical DRAM, MMIO and EFI_LOADER_CODE ranges. Each "
    "EFI_LOADER_CODE entry is emitted as a separate REGION_EFI_LOADER_IMAGE "
    "observation with its full [start, end] extent — the running kernel is "
    "one of these entries on an EFI stub boot, with bootloader/driver "
    "images claiming the others. efi_loader_kernel_pick filters by EFI stub "
    "alignment + SF_IMAGE_SIZE match to identify the running-kernel entry. "
    "Access is gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

/* Per-entry storage for EFI_LOADER_CODE ranges. The kernel + bootloader +
 * driver images each get one entry on an EFI stub boot; efi_loader_kernel_pick
 * narrows to the running kernel via alignment / size filters. A small cap
 * keeps the worst case bounded — EFI memmaps in the wild rarely exceed a
 * handful of Loader Code entries; beyond the cap the rule produces no pin
 * (matches its conservative behaviour when multiple entries pass the filters
 * without a disambiguator). */
#define EFI_LOADER_MAX 16

struct efi_ctx {
  struct range_ctx dram;
  struct range_ctx mmio;
  struct {
    unsigned long lo, hi;
  } loader[EFI_LOADER_MAX];
  int loader_n; /* count of Loader Code entries seen (may exceed EFI_LOADER_MAX)
                 */
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

/* Detect EFI_LOADER_CODE (type 1) entries: "[Loader Code..."
 * These are physical ranges where EFI loaded PE/COFF images (the kernel
 * stub, the bootloader, or other EFI applications). On a direct EFI stub
 * boot the running kernel's PE image is one of these entries; additional
 * entries belong to the bootloader or firmware drivers. All are DRAM. */
static int is_efi_loader_code(const char *line) {
  const char *p = strchr(line, '[');
  if (!p)
    return 0;
  p++;
  return (strncmp(p, "Loader Code", 11) == 0);
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

  if (is_efi_mmio(line))
    update_range(&e->mmio, start, end);
  else {
    update_range(&e->dram, start, end);
    if (is_efi_loader_code(line)) {
      if (e->loader_n < EFI_LOADER_MAX) {
        e->loader[e->loader_n].lo = start;
        e->loader[e->loader_n].hi = end;
      }
      e->loader_n++;
    }
  }
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

  if (is_efi_mmio(line))
    update_range(&e->mmio, start, end);
  else {
    update_range(&e->dram, start, end);
    if (is_efi_loader_code(line)) {
      if (e->loader_n < EFI_LOADER_MAX) {
        e->loader[e->loader_n].lo = start;
        e->loader[e->loader_n].hi = end;
      }
      e->loader_n++;
    }
  }
  return 1; /* continue — multiple entries */
}

int main(void) {
  struct efi_ctx e;
  memset(&e, 0, sizeof(e));

  kasld_info("searching dmesg for EFI memory map (requires efi=debug) ...");

  /* ARM/ARM64/RISC-V format: lines start with "efi:   0x" */
  int ds = dmesg_search("efi:   0x", on_efi_init, &e);
  if (ds < 0)
    return KASLD_EXIT_NOPERM;

  /* x86 format: "efi: mem00: ... range=[0x...-0x...]" */
  if (!e.dram.lo && !e.mmio.lo)
    dmesg_search("efi: mem", on_efi_x86, &e);

  if (!e.dram.lo && !e.mmio.lo) {
    kasld_err("EFI memory map not found in dmesg");
    kasld_info("    (requires efi=debug kernel boot parameter)");
    return 0;
  }

  if (e.dram.lo) {
    kasld_info("lowest EFI RAM address:  0x%016lx", e.dram.lo);
    kasld_info("highest EFI RAM address: 0x%016lx", e.dram.hi);

    /* Soundness: EFI memmap entries are typed — Conventional Memory
     * (user-allocatable RAM), Loader Code (the running kernel image),
     * Boot Services Code/Data, Reserved, etc. on_efi_init aggregates
     * only the non-MMIO entries into e.dram, which in practice
     * skews toward Conventional Memory ranges. The kernel image
     * itself lives in Loader Code (a separate type), and on every EFI
     * system the Loader Code phys range sits BELOW the lowest
     * Conventional Memory entry — same shape as the ppc32 PowerMac
     * "kernel reserved below the lowest zone" case
     * (see dmesg_free_area_init_node / proc_zoneinfo /
     * sysfs_memory_blocks). Treating e.dram.lo as POS_BASE would feed
     * dram_floor_bound a bogus high floor and exclude the actual
     * phys text base. Emit as an interior SAMPLE — a sound RAM
     * witness, but not a floor pin. Authoritative phys floors come
     * from sysfs_devicetree_memory, sysfs_firmware_memmap and
     * boot_params_e820 (E820 Type 1 RAM ranges DO include the kernel
     * image area). e.dram.hi IS sound as a TOP bound. */
    kasld_result_sample(KASLD_TYPE_PHYS, REGION_RAM, e.dram.lo, NULL,
                        CONF_PARSED);

    if (e.dram.hi && e.dram.hi != e.dram.lo)
      kasld_result_top(KASLD_TYPE_PHYS, REGION_RAM, e.dram.hi, NULL,
                       CONF_PARSED);
  }

  if (e.mmio.lo) {
    kasld_info("lowest EFI MMIO address:  0x%016lx", e.mmio.lo);
    kasld_info("highest EFI MMIO address: 0x%016lx", e.mmio.hi);

    kasld_result_sample(KASLD_TYPE_PHYS, REGION_MMIO, e.mmio.lo, NULL,
                        CONF_PARSED);

    if (e.mmio.hi && e.mmio.hi != e.mmio.lo)
      kasld_result_sample(KASLD_TYPE_PHYS, REGION_MMIO, e.mmio.hi, NULL,
                          CONF_PARSED);
  }

  if (e.loader_n > 0) {
    /* Emit each EFI_LOADER_CODE entry as a separate REGION_EFI_LOADER_IMAGE
     * observation with its full [lo, hi] extent. On an EFI stub boot the
     * running kernel's PE image is one of these entries; bootloader and
     * driver images claim the others. The component cannot tell which
     * entry is the kernel from address/size alone — that's the
     * efi_loader_kernel_pick rule's job, which applies the per-arch
     * EFI_KIMG_ALIGN start-alignment filter and the SF_IMAGE_SIZE size-
     * tolerance filter. Separation of concerns: this component surfaces
     * raw EFI memmap entries; the rule performs the alignment/size
     * arithmetic that depends on arch constants and SF_IMAGE_SIZE.
     *
     * Cap at EFI_LOADER_MAX — beyond that the rule's per-entry scan would
     * not find more candidates anyway; the extra entries are noted but
     * not emitted. */
    int emit_n = e.loader_n < EFI_LOADER_MAX ? e.loader_n : EFI_LOADER_MAX;
    if (e.loader_n > EFI_LOADER_MAX)
      kasld_info("note: %d EFI Loader Code entries (cap %d); emitting first %d",
                 e.loader_n, EFI_LOADER_MAX, emit_n);
    for (int i = 0; i < emit_n; i++) {
      unsigned long lo = e.loader[i].lo;
      unsigned long hi = e.loader[i].hi;
      kasld_info("EFI Loader Code image #%d: 0x%016lx-0x%016lx", i, lo, hi);
      /* The EFI memmap end is an inclusive last-byte address (matches
       * dmesg's `[lo-hi]` rendering), so size = hi - lo + 1. */
      if (hi >= lo)
        kasld_result_sized(KASLD_TYPE_PHYS, REGION_EFI_LOADER_IMAGE, lo,
                           hi - lo + 1, NULL, CONF_PARSED);
    }
  }

#ifdef phys_to_directmap_virt
  if (e.dram.lo) {
    /* Same caveat: phys_to_directmap_virt(e.dram.lo) lands at the
     * directmap base ONLY when e.dram.lo is the actual phys floor.
     * When firmware reserves low phys for the kernel's Loader Code
     * range, e.dram.lo is interior to the directmap, not its base.
     * Emit as a directmap sample. */
    unsigned long virt = phys_to_directmap_virt(e.dram.lo);
    kasld_info("possible direct-map virtual address: 0x%016lx", virt);
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL,
                        CONF_PARSED);
  }
#else
  kasld_info("note: phys and virt KASLR are decoupled on this arch; "
             "cannot derive kernel text virtual address from physical leak");
#endif

  return 0;
}
