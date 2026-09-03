// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parse /proc/cpuinfo for architecture-specific information useful
// for inferring the kernel memory layout.
//
// Currently extracts:
// - x86_64:  virtual address width -> 4-level vs 5-level paging
// - riscv64: MMU mode (sv39/sv48/sv57) -> deterministic PAGE_OFFSET
//
// Detection component — leaks no randomized (KASLR) address.
//   Purpose: reads /proc/cpuinfo to extract architecture-specific
//   information (address width, MMU mode) that constrains the kernel
//   virtual address layout. /proc/cpuinfo is world-readable (0444).
//
// Requires:
// - CONFIG_PROC_FS=y (universally enabled)
//
// References:
// https://www.kernel.org/doc/html/next/riscv/vm-layout.html
// https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/constraint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CPUINFO_PATH "/proc/cpuinfo"

KASLD_EXPLAIN(
    "Reads /proc/cpuinfo (world-readable 0444) for architecture info: "
    "on x86_64, the virtual address width determines 4-level vs 5-level "
    "paging; on RISC-V, the MMU mode (sv39/sv48/sv57) constrains "
    "PAGE_OFFSET (a single value for sv48/sv57, a two-candidate range for "
    "sv39). This constrains the kernel virtual address layout.");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "discloses:virtual\n");

/* Read the first value for a given key from /proc/cpuinfo.
 * Returns a pointer into buf on success, NULL on failure.
 * `unused`-marked so non-{riscv64,x86_64} arches (which fall through both
 * #if blocks below) don't warn. The attribute must precede `static` for
 * gcc to apply it to the definition. */
__attribute__((unused)) static char *cpuinfo_get(const char *key, char *buf,
                                                 size_t bufsz) {
  FILE *f = kasld_fopen(CPUINFO_PATH, "r");
  if (!f)
    return NULL;

  size_t keylen = strlen(key);
  while (fgets(buf, (int)bufsz, f)) {
    if (strncmp(buf, key, keylen) != 0)
      continue;

    /* Skip past key and separator (": " or "\t: ") */
    char *p = buf + keylen;
    while (*p == ' ' || *p == '\t' || *p == ':')
      p++;

    /* Trim trailing newline */
    char *nl = strchr(p, '\n');
    if (nl)
      *nl = '\0';

    fclose(f);
    return p;
  }

  fclose(f);
  return NULL;
}

#if defined(__riscv) && __riscv_xlen == 64
/* riscv64: /proc/cpuinfo contains "mmu : sv39" (or sv48, sv57). The MMU
 * mode determines PAGE_OFFSET and the VA width:
 *   sv39 -> PAGE_OFFSET ∈ { 0xffffffd600000000,    // 168 GiB linear (v6.12+)
 *                           0xffffffd800000000 },  // 160 GiB linear
 * (v5.10–v6.10) va_bits = 39 sv48 -> PAGE_OFFSET = 0xffffaf8000000000, va_bits
 * = 48 sv57 -> PAGE_OFFSET = 0xff60000000000000, va_bits = 57
 *
 * The SV39 linear-mapping region was expanded from 160 GiB to 168 GiB
 * between v6.10 and v6.12, shifting PAGE_OFFSET. The two candidates
 * differ by 8 GiB and the project does not gate on kernel version, so
 * SV39 is emitted as a range spanning both candidates instead of a
 * single pin (which would be wrong on the older window). SV48 and SV57
 * each have a single value. */
static int detect_riscv_mmu(void) {
  char buf[256];
  char *mmu = cpuinfo_get("mmu", buf, sizeof(buf));

  if (!mmu) {
    kasld_err("Could not read mmu field from %s", CPUINFO_PATH);
    return 0;
  }

  kasld_info("MMU mode: %s", mmu);

  unsigned long va_bits = 0;
  unsigned long po_lo = 0, po_hi = 0;

  if (strcmp(mmu, "sv39") == 0) {
    va_bits = 39;
    po_lo = 0xffffffd600000000ul; /* v6.12+ */
    po_hi = 0xffffffd800000000ul; /* v5.10–v6.10 */
  } else if (strcmp(mmu, "sv48") == 0) {
    va_bits = 48;
    po_lo = po_hi = 0xffffaf8000000000ul;
  } else if (strcmp(mmu, "sv57") == 0) {
    va_bits = 57;
    po_lo = po_hi = 0xff60000000000000ul;
  } else {
    kasld_err("Unknown MMU mode: %s", mmu);
    return 0;
  }

  kasld_emit_scalar(SF_VIRT_ADDR_BITS, va_bits, CONF_PARSED);
  kasld_info("va_bits = %lu", va_bits);

  /* PAGE_OFFSET here is DERIVED — the standard linear-map base assumed for the
   * detected SATP mode — not read from any PAGE_OFFSET field. Confidence tracks
   * provenance, so this is CONF_INFERRED, not CONF_PARSED, on ANY kernel:
   * a value assumed from the paging layout is lower-confidence than a direct
   * read, independent of whether the assumption happens to be correct this run.
   * Reserve CONF_PARSED for a direct read (proc_config's CONFIG_PAGE_OFFSET) or
   * for a sound architectural *bound* rather than an assumed point (e.g. the
   * x86_64 canonical floor below, emitted as a lower bound). */
  if (po_lo == po_hi) {
    kasld_info("PAGE_OFFSET for %s: 0x%016lx", mmu, po_lo);
    if (po_lo == PAGE_OFFSET) {
      kasld_info("Matches compile-time default; no adjustment needed.");
      return 1;
    }
    kasld_result_base(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, po_lo, NULL,
                      CONF_INFERRED);
  } else {
    kasld_info("PAGE_OFFSET for %s: [0x%016lx, 0x%016lx]", mmu, po_lo, po_hi);
    kasld_result_range(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, po_lo, po_hi, NULL,
                       CONF_INFERRED);
  }
  return 1;
}
#endif /* riscv64 */

#if defined(__powerpc64__) || defined(__ppc64__)
/* ppc64: "MMU : Radix" or "MMU : Hash".
 *
 * 64-bit PowerPC has no MODULES_VADDR — modules come from vmalloc, whose base
 * differs by translation mode and page size across a 32 TiB spread. This field
 * supplies the mode half; SF_PAGE_SIZE supplies the other, and a rule combines
 * them.
 *
 * Trustworthy for the purpose: the platform code prints it from
 * radix_enabled(), and that same runtime feature bit selects __vmalloc_start
 * (radix_pgtable.c sets RADIX_VMALLOC_START, hash_utils.c sets
 * H_VMALLOC_START). One bit drives both the report and the layout, so this is
 * the live mode, not a capability — unlike x86_64's "57 bits virtual", which
 * is what the CPU can do rather than what the kernel enabled.
 *
 * Emitted only on a POSITIVE match. The line comes from platform code
 * (pSeries, PowerNV), so Book3E parts do not print it at all — but a
 * restricted or absent /proc/cpuinfo looks identical, so absence is not
 * evidence of Book3E and nothing is inferred from it. */
static int detect_ppc64_mmu(void) {
  char buf[256];
  char *val = cpuinfo_get("MMU", buf, sizeof(buf));

  if (!val) {
    kasld_info("no MMU field in %s (Book3E, or a restricted /proc)",
               CPUINFO_PATH);
    return 0;
  }

  unsigned long mode;
  if (strncmp(val, "Radix", 5) == 0) {
    mode = KASLD_PPC64_MMU_RADIX;
  } else if (strncmp(val, "Hash", 4) == 0) {
    mode = KASLD_PPC64_MMU_HASH;
  } else {
    kasld_err("unrecognised MMU mode '%s'; not emitting", val);
    return 0;
  }

  kasld_info("MMU: %s", val);
  kasld_emit_scalar(SF_PPC64_MMU_MODE, mode, CONF_PARSED);
  return 1;
}
#endif /* ppc64 */

#if defined(__loongarch__) && __loongarch_grlen == 64
/* loongarch64: "Address Sizes  : N bits physical, M bits virtual" (note the
 * capitalisation, which differs from x86_64's "address sizes").
 *
 * M is cpu_vabits + 1, read from CPUCFG1.VALEN by cpu_probe_addrbits(). This
 * is the value that determines the whole upper VA layout:
 *
 *   vm_map_base   = 0 - (1 << cpu_vabits)
 *   MODULES_VADDR = vm_map_base + PCI_IOSIZE + 2 * PAGE_SIZE
 *
 * Published UNCONDITIONALLY, unlike the x86_64 case below which publishes only
 * a width of 48. That asymmetry is deliberate and must not be "fixed": on
 * x86_64 a reported 57 is the CPU *capability* and the kernel may still run
 * 4-level, so the width there does not state the active layout. LoongArch has
 * no such split — one CPUCFG field feeds both vm_map_base and this line, so the
 * width published here does describe the layout the kernel is running.
 *
 * What it is NOT is the shift. The field and the printed line differ by one:
 * cpu_vabits is VALEN and M is VALEN + 1, so a consumer placing a region at
 * `0 - (1 << M)` lands a full bit low. SF_VIRT_ADDR_BITS carries the width, and
 * a consumer that needs the shift subtracts one -- loongarch64_module_base is
 * the one that does.
 *
 * Note also that an mmap boundary probe CANNOT substitute for this read.
 * TASK_SIZE64 is `1 << min(cpu_vabits, VA_BITS)`, clamped to the kernel's
 * page-table width, while vm_map_base uses cpu_vabits unclamped. A 16K/3-level
 * kernel on VALEN=47 hardware has VA_BITS=47, so a probe would under-read and
 * place the module region 128 TiB too high. */
static int detect_loongarch_address_sizes(void) {
  char buf[256];
  char *val = cpuinfo_get("Address Sizes", buf, sizeof(buf));

  if (!val) {
    kasld_err("Could not read Address Sizes from %s", CPUINFO_PATH);
    return 0;
  }

  unsigned int phys_bits = 0, virt_bits = 0;
  if (sscanf(val, "%u bits physical, %u bits virtual", &phys_bits,
             &virt_bits) != 2) {
    kasld_err("Could not parse Address Sizes: %s", val);
    return 0;
  }

  kasld_info("Address sizes: %u bits physical, %u bits virtual", phys_bits,
             virt_bits);

  /* Sanity-bound before publishing: a width outside what the architecture can
   * express is a parse artefact, not a measurement. */
  if (virt_bits < 32 || virt_bits > 64) {
    kasld_err("implausible virtual width %u; not emitting", virt_bits);
    return 0;
  }
  kasld_emit_scalar(SF_VIRT_ADDR_BITS, virt_bits, CONF_PARSED);
  return 1;
}
#endif /* loongarch64 */

#if defined(__x86_64__) || defined(__amd64__)
/* x86_64: "address sizes : N bits physical, M bits virtual"
 * Virtual address width determines paging level:
 *   48 bits -> 4-level paging (common)
 *   57 bits -> 5-level paging (la57, newer CPUs)
 *
 * CONFIG_RANDOMIZE_MEMORY randomizes virt_page_offset_base by adding a
 * non-negative PUD-aligned random offset to __PAGE_OFFSET_BASE_L{4,5},
 * so the directmap base is always >= the compile-time base constant.
 * Emitting the base constant as the PAGEOFFSET floor is therefore sound.
 *
 * The floor is PAGE_OFFSET_BASE_MIN_L4/L5: the lowest address the direct map
 * has been based at on that level, which is one PGD entry below this layout's
 * base and is where the PTI LDT remap now sits. Below it is a guard hole that
 * holds nothing, so nothing is excluded by starting there rather than at the
 * canonical half boundary. */
static int detect_x86_address_sizes(void) {
  char buf[256];
  char *val = cpuinfo_get("address sizes", buf, sizeof(buf));

  if (!val) {
    kasld_err("Could not read address sizes from %s", CPUINFO_PATH);
    return 0;
  }

  unsigned int phys_bits = 0, virt_bits = 0;
  if (sscanf(val, "%u bits physical, %u bits virtual", &phys_bits,
             &virt_bits) != 2) {
    kasld_err("Could not parse address sizes: %s", val);
    return 0;
  }

  kasld_info("Address sizes: %u bits physical, %u bits virtual", phys_bits,
             virt_bits);

  /* Publish the active paging level as a scalar fact ONLY when the width is 48:
   * a 48-bit-virtual CPU cannot run 5-level paging, so L4 is certain. A width
   * of 57 is the CPU capability (5-level may not be enabled), so it is not
   * published here — the active level then comes from a runtime directmap
   * observation. Consumers (e.g. the RANDOMIZE_MEMORY budget bounds) rely on
   * this being a sound statement of the active level, not the CPU maximum. */
  if (virt_bits == 48)
    kasld_emit_scalar(SF_VIRT_ADDR_BITS, virt_bits, CONF_PARSED);

  unsigned long virt_page_offset = 0;

  if (virt_bits <= 48)
    virt_page_offset = PAGE_OFFSET_BASE_MIN_L4;
  else if (virt_bits <= 57)
    virt_page_offset = PAGE_OFFSET_BASE_MIN_L5;
  else {
    kasld_err("Unexpected virtual address width: %u", virt_bits);
    return 0;
  }

  if (virt_page_offset == PAGE_OFFSET) {
    kasld_info("Matches compile-time default; no adjustment needed.");
    return 0;
  }

  kasld_info("Paging level %s: PAGE_OFFSET floor -> 0x%016lx",
             virt_bits <= 48 ? "4" : "5", virt_page_offset);

  /* A LOWER BOUND, and stated as one. The direct-map base randomizes upward
   * from the compile-time base, so the canonical floor for the paging level is
   * the most that can be said here -- on this machine the true base can sit
   * terabytes above it. The constraint channel carries that claim; the
   * positional emitters would state it as the base itself, which is a
   * different and false assertion, and one the anchor rules would read as an
   * exact landmark. */
  kasld_emit_constraint(Q_PAGE_OFFSET, C_LOWER_BOUND, virt_page_offset,
                        CONF_PARSED);
  return 1;
}
#endif /* x86_64 */

int main(void) {
  int found = 0;

  kasld_info("checking %s ...", CPUINFO_PATH);

#if defined(__riscv) && __riscv_xlen == 64
  found |= detect_riscv_mmu();
#endif

#if defined(__x86_64__) || defined(__amd64__)
  found |= detect_x86_address_sizes();
#endif

#if defined(__loongarch__) && __loongarch_grlen == 64
  found |= detect_loongarch_address_sizes();
#endif

#if defined(__powerpc64__) || defined(__ppc64__)
  found |= detect_ppc64_mmu();
#endif

  if (!found) {
    kasld_err("No actionable cpuinfo data found for this architecture.");
    return 0;
  }

  return 0;
}
