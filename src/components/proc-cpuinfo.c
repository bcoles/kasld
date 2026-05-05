// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parse /proc/cpuinfo for architecture-specific information useful
// for inferring the kernel memory layout.
//
// Currently extracts:
// - x86_64:  virtual address width -> 4-level vs 5-level paging
// - riscv64: MMU mode (sv39/sv48/sv57) -> deterministic PAGE_OFFSET
//
// Detection component — does not leak an address.
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

#include "include/kasld.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CPUINFO_PATH "/proc/cpuinfo"

KASLD_EXPLAIN(
    "Reads /proc/cpuinfo (world-readable 0444) for architecture info: "
    "on x86_64, the virtual address width determines 4-level vs 5-level "
    "paging; on RISC-V, the MMU mode (sv39/sv48/sv57) determines "
    "PAGE_OFFSET. This constrains the kernel virtual address layout.");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "addr:none\n");

/* Read the first value for a given key from /proc/cpuinfo.
 * Returns a pointer into buf on success, NULL on failure. */
static char *cpuinfo_get(const char *key, char *buf, size_t bufsz) {
  FILE *f = fopen(CPUINFO_PATH, "r");
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
/* riscv64: /proc/cpuinfo contains "mmu : sv39" (or sv48, sv57).
 * The MMU mode determines PAGE_OFFSET on v5.10+ kernels:
 *   sv39 -> 0xffffffd600000000  (PAGE_OFFSET_L3, v6.12+)
 *           0xffffffd800000000  (PAGE_OFFSET_L3, v5.10 - v6.10)
 *   sv48 -> 0xffffaf8000000000  (PAGE_OFFSET_L4)
 *   sv57 -> 0xff60000000000000  (PAGE_OFFSET_L5)
 *
 * PAGE_OFFSET_L3 for sv39 changed between v6.10 and v6.12 when the
 * SV39 linear mapping region was expanded from 160 GiB to 168 GiB.
 * We use the newer value; this may be slightly off on older kernels but
 * remains within the broader PAGE_OFFSET range so results are conservative. */
static int detect_riscv_mmu(void) {
  char buf[256];
  char *mmu = cpuinfo_get("mmu", buf, sizeof(buf));

  if (!mmu) {
    fprintf(stderr, "[-] Could not read mmu field from %s\n", CPUINFO_PATH);
    return 0;
  }

  printf("[.] MMU mode: %s\n", mmu);

  unsigned long page_offset = 0;

  if (strcmp(mmu, "sv39") == 0)
    page_offset = 0xffffffd600000000ul;
  else if (strcmp(mmu, "sv48") == 0)
    page_offset = 0xffffaf8000000000ul;
  else if (strcmp(mmu, "sv57") == 0)
    page_offset = 0xff60000000000000ul;
  else {
    fprintf(stderr, "[-] Unknown MMU mode: %s\n", mmu);
    return 0;
  }

  printf("[.] PAGE_OFFSET for %s: 0x%016lx\n", mmu, page_offset);

  /* PAGE_OFFSET is already the compile-time default for sv57 */
  if (page_offset == PAGE_OFFSET) {
    printf("[.] Matches compile-time default; no adjustment needed.\n");
    return 0;
  }

  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_PAGEOFFSET, page_offset,
               KASLD_REGION_PAGE_OFFSET, NULL);
  return 1;
}
#endif /* riscv64 */

#if defined(__x86_64__) || defined(__amd64__)
/* x86_64: "address sizes : N bits physical, M bits virtual"
 * Virtual address width determines paging level:
 *   48 bits -> 4-level paging (common)
 *   57 bits -> 5-level paging (la57, newer CPUs)
 *
 * CONFIG_RANDOMIZE_MEMORY randomizes page_offset_base by adding a
 * non-negative PUD-aligned random offset to __PAGE_OFFSET_BASE_L{4,5},
 * so the directmap base is always >= the compile-time base constant.
 * Emitting the base constant as the PAGEOFFSET floor is therefore sound.
 *
 * 4-level: VAS floor = 0xffff800000000000 (47-bit sign extension).
 *          We use the canonical half floor rather than __PAGE_OFFSET_BASE_L4
 *          (0xffff888000000000) because the static (non-RANDOMIZE_MEMORY)
 *          layout places the vmemmap at 0xffff800000000000 and LDT remap at
 *          0xffff880000000000; raising the VAS floor higher would silently
 *          reject those legitimate virtual addresses.
 *
 * 5-level: Directmap floor = 0xff11000000000000 (__PAGE_OFFSET_BASE_L5).
 *          The range [0xff00000000000000, 0xff10000000000000) is a guard hole
 *          (never mapped), [0xff10000000000000, 0xff11000000000000) is the LDT
 *          remap for PTI (kernel-internal, not emitted by any KASLD component),
 *          so 0xff11000000000000 is a safe and tight directmap floor. */
static int detect_x86_address_sizes(void) {
  char buf[256];
  char *val = cpuinfo_get("address sizes", buf, sizeof(buf));

  if (!val) {
    fprintf(stderr, "[-] Could not read address sizes from %s\n", CPUINFO_PATH);
    return 0;
  }

  unsigned int phys_bits = 0, virt_bits = 0;
  if (sscanf(val, "%u bits physical, %u bits virtual", &phys_bits,
             &virt_bits) != 2) {
    fprintf(stderr, "[-] Could not parse address sizes: %s\n", val);
    return 0;
  }

  printf("[.] Address sizes: %u bits physical, %u bits virtual\n", phys_bits,
         virt_bits);

  unsigned long page_offset = 0;

  if (virt_bits <= 48)
    page_offset = 0xffff800000000000ul; /* L4 canonical half floor */
  else if (virt_bits <= 57)
    page_offset = 0xff11000000000000ul; /* __PAGE_OFFSET_BASE_L5 */
  else {
    fprintf(stderr, "[-] Unexpected virtual address width: %u\n", virt_bits);
    return 0;
  }

  if (page_offset == PAGE_OFFSET) {
    printf("[.] Matches compile-time default; no adjustment needed.\n");
    return 0;
  }

  printf("[.] Paging level %s: PAGE_OFFSET floor -> 0x%016lx\n",
         virt_bits <= 48 ? "4" : "5", page_offset);

  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_PAGEOFFSET, page_offset,
               KASLD_REGION_PAGE_OFFSET, NULL);
  return 1;
}
#endif /* x86_64 */

int main(void) {
  int found = 0;

  printf("[.] checking %s ...\n", CPUINFO_PATH);

#if defined(__riscv) && __riscv_xlen == 64
  found |= detect_riscv_mmu();
#endif

#if defined(__x86_64__) || defined(__amd64__)
  found |= detect_x86_address_sizes();
#endif

  if (!found) {
    printf("[-] No actionable cpuinfo data found for this architecture.\n");
    return 0;
  }

  return 0;
}
