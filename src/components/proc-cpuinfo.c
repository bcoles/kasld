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
 *   sv39 -> 0xffffffd800000000  (PAGE_OFFSET_L3)
 *   sv48 -> 0xffffaf8000000000  (PAGE_OFFSET_L4)
 *   sv57 -> 0xff60000000000000  (PAGE_OFFSET_L5)
 *
 * These are computed from the kernel source as:
 *   PAGE_OFFSET = -(1UL << (VA_BITS - 1))
 * where VA_BITS = 39, 48, or 57. */
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
    page_offset = 0xffffffd800000000ul;
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
 * On x86_64, CONFIG_RANDOMIZE_MEMORY randomizes page_offset_base
 * independently, so knowing the paging level only constrains the VAS
 * range — it does not reveal the actual directmap base. Still useful
 * for tightening validation bounds.
 *
 * 4-level: PAGE_OFFSET = 0xffff800000000000 (47-bit sign extension)
 * 5-level: PAGE_OFFSET = 0xff00000000000000 (56-bit sign extension) */
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
    page_offset = 0xffff800000000000ul;
  else if (virt_bits <= 57)
    page_offset = 0xff00000000000000ul;
  else {
    fprintf(stderr, "[-] Unexpected virtual address width: %u\n", virt_bits);
    return 0;
  }

  if (page_offset == PAGE_OFFSET) {
    printf("[.] Matches compile-time default; no adjustment needed.\n");
    return 0;
  }

  printf("[.] VAS narrowed: %u-bit virtual -> PAGE_OFFSET 0x%016lx\n",
         virt_bits, page_offset);

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
