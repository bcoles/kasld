// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for virtual kernel memory layout.
//
// The `mem_init()` function prints the layout of the kernel segments
// to the kernel debug log, including kernel vas start, .text, .data,
// lowmem, modules, and memory sections.
//
// Sections extracted:
//   .text    -> V text      (kernel text virtual address)
//   .data    -> V data      (kernel data virtual address)
//   .bss     -> V bss       (kernel BSS virtual address; ARM and x86_32 only)
//   lowmem   -> V directmap (lowmem / direct-mapped region, x86_32/arm)
//   modules  -> V module    (kernel module region, arm/arm64)
//   memory   -> V directmap (linear memory map, arm64)
//   vmalloc  -> V vmalloc   (vmalloc region, range: riscv64 with
//                            CONFIG_DEBUG_VM; xtensa/sh/parisc; s390 KERN_DEBUG
//                            "vmalloc area:" boot-time line)
//   vmemmap  -> V vmemmap   (vmemmap region, range: riscv64 with
//                            CONFIG_DEBUG_VM)
//
// On riscv64 the vmalloc/vmemmap range lines feed the engine's
// riscv64_page_offset_from_vmalloc_vmemmap rule (tightens Q_PAGE_OFFSET).
// On s390 the "vmalloc area:" range line feeds s390_text_from_belows
// (tightens Q_VIRT_TEXT_BASE lower bound). On other arches with these prints
// the observations are still recorded — they cost nothing if no rule consumes
// them, and unlock future rules.
//
// x86:
// https://elixir.bootlin.com/linux/v5.6.19/source/arch/x86/mm/init_32.c
// Removed in kernel 5.7-rc1 on 2020-03-06:
// https://github.com/torvalds/linux/commit/681ff0181bbfb183e32bc6beb6ec076304470479#diff-3bfd62fd3cf596dbff9091b59a7168cdf8fb93ed342a633bd37fac9633e96025
//
// arm:
// https://elixir.bootlin.com/linux/v5.0.21/source/arch/arm/mm/init.c
// Removed in kernel 5.1-rc1 on 2019-03-16:
// https://github.com/torvalds/linux/commit/0be288630752e6358d02eba7b283c1783a5c7c38#diff-0ac47f754483fd3333a760d4285c7197ba5820b1ad1899f192270cd6a3a1e309
//
// arm64:
// https://elixir.bootlin.com/linux/v4.15.18/source/arch/arm64/mm/init.c
// Removed in kernel v4.16-rc1 on 2018-01-16:
// https://github.com/torvalds/linux/commit/071929dbdd865f779a89ba3f1e06ba8d17dd3743
//
// x86_64:
// This code was never present on x86_64.
//
// m68k:
// Due to a bug, this code always printed "ptrval", instead of segment
// addresses, and was later removed in kernel 4.17-rc1 on 2018-03-19:
// https://github.com/torvalds/linux/commit/31833332f79876366809ccb0614fee7df8afe9fe
//
// PA-RISC:
// https://elixir.bootlin.com/linux/v4.16-rc3/source/arch/parisc/mm/init.c
// Code was commented out in kernel 4.16-rc4 on 2018-03-02:
// https://github.com/torvalds/linux/commit/fd8d0ca2563151204f3fe555dc8ca4bcfe8677a3
//
// RISC-V:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/riscv/mm/init.c#L127
// Kernel virtual memory layout is printed (excluding .text section),
// but requires kernel to be configured with CONFIG_DEBUG_VM.
//
// Xtensa:
// Code is still present as of 2023:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/xtensa/mm/init.c#L134
//
// SuperH:
// Code is still present as of 2023:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/sh/mm/init.c#L371
//
// Leak primitive:
//   Data leaked:      kernel virtual memory layout (.text, .data, lowmem,
//   modules) Kernel subsystem: arch/*/mm/init — mem_init() layout printout Data
//   structure:   kernel segment boundaries (virtual addresses) Address type:
//   virtual (kernel text, data, direct-map) Method:           parsed (dmesg
//   string) Status:           removed from most architectures (x86_32: v5.7,
//   ARM: v5.1,
//                     ARM64: v4.16). Still present on RISC-V (CONFIG_DEBUG_VM),
//                     Xtensa, and SuperH.
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v5.6.19/source/arch/x86/mm/init_32.c
//
// Mitigations:
//   Removed from most architectures. On RISC-V, requires CONFIG_DEBUG_VM.
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details).
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
// - CONFIG_DEBUG_VM on RISC-V systems
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
    "Parses the kernel virtual memory layout block printed by mem_init() "
    "during boot. This block shows virtual address ranges for .text, "
    ".data, .bss (ARM and x86_32), lowmem, modules, and other sections. "
    "Removed from most architectures: ARM64 v4.16, ARM v5.1, x86_32 v5.7. "
    "Access is gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

/* Layout sections to extract from the kernel memory layout block.
 *
 * Needles match across architectures:
 *   x86_32: "      .text : 0x%08lx", "    lowmem  : 0x%08lx", etc.
 *   arm:    "      .text : 0x%p",    "    lowmem  : 0x%08lx",
 *           "    modules : 0x%08lx"
 *   arm64:  "      .text : 0x%p",    "    modules : 0x%16lx",
 *           "    memory  : 0x%16lx"
 *   riscv:  "       vmalloc : 0x... - 0x... (   N MB)" (range; CONFIG_DEBUG_VM)
 *   xtensa: "    vmalloc : 0x... - 0x... (    N MB)"   (range; current)
 *   sh:     "    vmalloc : 0x... - 0x... (   N MB)"    (range; current)
 *   s390:   "vmalloc area:        0x...-0x..."         (range; boot KERN_DEBUG)
 */
enum layout_kind {
  LK_BASE = 0, /* needle ... 0x<lo> ...      (single address) */
  LK_RANGE,    /* needle ... 0x<lo>[ ]-[ ]0x<hi> ... (two addresses) */
};

struct layout_entry {
  const char *needle;
  enum kasld_addr_type type;
  const char *display;
  enum kasld_region region;
  unsigned long gate_min;
  unsigned long gate_max;
  enum layout_kind kind;
};

static const struct layout_entry entries[] = {
    {".text : 0x", KASLD_TYPE_VIRT, "kernel .text start", REGION_KERNEL_TEXT,
     KERNEL_VIRT_TEXT_MIN, KERNEL_VIRT_TEXT_MAX, LK_BASE},
    {".data : 0x", KASLD_TYPE_VIRT, "kernel .data start", REGION_KERNEL_DATA,
     KERNEL_VIRT_VAS_START, KERNEL_VIRT_VAS_END, LK_BASE},
    {".bss  : 0x", KASLD_TYPE_VIRT, "kernel .bss start", REGION_KERNEL_BSS,
     KERNEL_VIRT_TEXT_MIN, KERNEL_VIRT_TEXT_MAX, LK_BASE},
    /* riscv print_vm_layout() prints the kernel image span as
     * "kernel : 0x<virt_addr> - 0x<end>"; the low edge is kernel_map.virt_addr
     * (where _start/_stext land) — a direct text pin. LK_BASE takes that first
     * address; the high edge (ADDRESS_SPACE_END) is a fixed VAS bound. */
    {"kernel : 0x", KASLD_TYPE_VIRT, "kernel image start", REGION_KERNEL_TEXT,
     KERNEL_VIRT_TEXT_MIN, KERNEL_VIRT_TEXT_MAX, LK_BASE},
    {"lowmem  : 0x", KASLD_TYPE_VIRT, "kernel lowmem start", REGION_DIRECTMAP,
     KERNEL_VIRT_VAS_START, KERNEL_VIRT_VAS_END, LK_BASE},
    {"modules : 0x", KASLD_TYPE_VIRT, "kernel modules start",
     REGION_MODULE_REGION, MODULES_START, MODULES_END, LK_BASE},
    {"memory  : 0x", KASLD_TYPE_VIRT, "kernel memory start", REGION_DIRECTMAP,
     KERNEL_VIRT_VAS_START, KERNEL_VIRT_VAS_END, LK_BASE},
    /* Range extractions (lo,hi). One needle per print-format dialect:
     *   "vmalloc : 0x"  — riscv/xtensa/sh/parisc print_ml() style
     *   "vmalloc area:" — s390 boot KERN_DEBUG (boot_debug)
     * The riscv/xtensa needle also matches "    fixmap : 0x", "    lowmem : 0x"
     * etc. — guard with a prefix-anchor on the region NAME (the substring
     * "vmalloc"/"vmemmap" appears only in matching layout lines on these
     * kernels; the needle includes it explicitly). */
    {"vmalloc : 0x", KASLD_TYPE_VIRT, "vmalloc region", REGION_VMALLOC,
     KERNEL_VIRT_VAS_START, KERNEL_VIRT_VAS_END, LK_RANGE},
    {"vmalloc area:", KASLD_TYPE_VIRT, "vmalloc region", REGION_VMALLOC,
     KERNEL_VIRT_VAS_START, KERNEL_VIRT_VAS_END, LK_RANGE},
    {"vmemmap : 0x", KASLD_TYPE_VIRT, "vmemmap region", REGION_VMEMMAP,
     KERNEL_VIRT_VAS_START, KERNEL_VIRT_VAS_END, LK_RANGE},
    {NULL, 0, NULL, REGION_UNKNOWN, 0, 0, LK_BASE},
};

#define NUM_ENTRIES (sizeof(entries) / sizeof(entries[0]) - 1)

/* Extract the first 0x-prefixed hex address from a string.
 * Returns 0 if no valid address found (handles ptrval gracefully). */
static unsigned long extract_addr(const char *s) {
  const char *p = strstr(s, "0x");
  if (!p)
    return 0;

  char *endptr;
  unsigned long addr = strtoul(p + 2, &endptr, 16);
  if (endptr == p + 2)
    return 0;

  return addr;
}

/* Extract a range from a line bearing "0x<lo>...0x<hi>" — both addresses must
 * parse. Tolerates the separator variants seen in the wild:
 *   "0x... - 0x..."   (riscv/xtensa/sh/parisc — spaces around the dash)
 *   "0x...-0x..."     (s390 boot_debug — no spaces around the dash)
 * Returns 1 on success (both addresses extracted, *lo and *hi set); 0 on
 * single-address line or parse failure. */
static int extract_range(const char *s, unsigned long *lo, unsigned long *hi) {
  const char *p1 = strstr(s, "0x");
  if (!p1)
    return 0;
  char *endptr;
  unsigned long v1 = strtoul(p1 + 2, &endptr, 16);
  if (endptr == p1 + 2)
    return 0;
  const char *p2 = strstr(endptr, "0x");
  if (!p2)
    return 0;
  unsigned long v2 = strtoul(p2 + 2, &endptr, 16);
  if (endptr == p2 + 2)
    return 0;
  /* Order-invariant: emit (min, max). */
  *lo = v1 < v2 ? v1 : v2;
  *hi = v1 < v2 ? v2 : v1;
  return 1;
}

static void emit_base(int idx, unsigned long addr) {
  enum kasld_region region = entries[idx].region;
  printf("%s: %lx\n", entries[idx].display, addr);

  if (region == REGION_KERNEL_TEXT)
    printf("possible kernel base: %lx\n", addr & -KASLR_VIRT_ALIGN);

  if ((region == REGION_DIRECTMAP || region == REGION_MODULE_REGION) &&
      addr < (unsigned long)KERNEL_VIRT_VAS_START)
    kasld_err("warning: %s %lx below configured KERNEL_VIRT_VAS_START %lx",
              entries[idx].display, addr, (unsigned long)KERNEL_VIRT_VAS_START);

  /* Each "kernel .text start" / ".data start" / "modules start" message
   * reports the BASE of the named region. */
  kasld_result_base(entries[idx].type, region, addr, NULL, CONF_PARSED);
#ifdef directmap_virt_to_phys
  if (region == REGION_DIRECTMAP) {
    unsigned long phys = directmap_virt_to_phys(addr);
    printf("  possible physical address: 0x%016lx\n", phys);
    kasld_result_base(KASLD_TYPE_PHYS, region, phys, NULL, CONF_PARSED);
  }
#endif
#if defined(directmap_virt_to_phys) && TEXT_TRACKS_DIRECTMAP
  /* The BSS virt is also the BSS directmap virt only when the kernel image
   * sits at the linear-map offset (TEXT_TRACKS_DIRECTMAP). Both gates are
   * required: without the second, a future (DIRECTMAP_STATIC=1,
   * TEXT_TRACKS_DIRECTMAP=0) arch would silently misproject the BSS virt
   * through the linear-map formula. Emitting the PHYS/KERNEL_BSS result
   * enables the BSS-resident gap refinement in kernel_image_phys_bound.c on
   * ARM32 and x86_32 (the only arches that print a ".bss  :" line). */
  if (region == REGION_KERNEL_BSS) {
    unsigned long phys = directmap_virt_to_phys(addr);
    printf("  possible physical address: 0x%016lx\n", phys);
    kasld_result_base(KASLD_TYPE_PHYS, REGION_KERNEL_BSS, phys, NULL,
                      CONF_PARSED);
  }
#endif
}

static void emit_range(int idx, unsigned long lo, unsigned long hi) {
  printf("%s: 0x%lx - 0x%lx\n", entries[idx].display, lo, hi);
  kasld_result_range(entries[idx].type, entries[idx].region, lo, hi, NULL,
                     CONF_PARSED);
}

struct search_ctx {
  int found_mask; /* bitmask of which entries have been found */
};

static int on_match(const char *line, void *ctx) {
  struct search_ctx *sc = ctx;

  for (int i = 0; entries[i].needle; i++) {
    if (sc->found_mask & (1 << i))
      continue;

    if (strstr(line, entries[i].needle) == NULL)
      continue;

    if (entries[i].kind == LK_RANGE) {
      unsigned long lo, hi;
      if (!extract_range(line, &lo, &hi))
        continue;
      /* Both edges must lie inside the gate, and the line must actually
       * describe a non-degenerate range (lo < hi). */
      if (lo < entries[i].gate_min || hi > entries[i].gate_max || lo >= hi)
        continue;
      emit_range(i, lo, hi);
    } else {
      unsigned long addr = extract_addr(line);
      if (!addr)
        continue;
      if (addr < entries[i].gate_min || addr > entries[i].gate_max)
        continue;
      emit_base(i, addr);
    }
    sc->found_mask |= (1 << i);
  }

  return 1; /* keep scanning */
}

int main(void) {
  struct search_ctx ctx = {0};

  /* Broad prefilter — any line carrying a hex address. The per-entry needles
   * in on_match() do the real selection; this just narrows the dmesg sweep to
   * lines that could plausibly be layout prints. Broadened from ": 0x" to
   * "0x" to catch the s390 boot_debug format "vmalloc area:        0x..."
   * (multiple spaces between colon and address) alongside the
   * single-space riscv/xtensa/sh/parisc form "vmalloc : 0x...". */
  kasld_info("searching dmesg for kernel memory layout sections ...");
  int ds = dmesg_search("0x", on_match, &ctx);

  if (!ctx.found_mask) {
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    kasld_err("kernel memory layout sections not found in dmesg");
  }

  return 0;
}
