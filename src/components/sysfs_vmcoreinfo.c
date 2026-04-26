// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read physical address of the vmcoreinfo_note page from
// /sys/kernel/vmcoreinfo. This sysfs attribute is world-readable (0444)
// and prints the physical address and size of the vmcoreinfo note,
// which is allocated via alloc_pages_exact() from the buddy allocator.
//
// The physical address falls within usable DRAM, so it can be used
// to derive a direct-map virtual address on coupled architectures.
//
// Format: "<hex_phys_addr> <hex_size>"
// Example: "0x00000001015f0000 1024"
//
// Leak primitive:
//   Data leaked:      physical memory layout (PHYS_OFFSET from vmcoreinfo)
//   Kernel subsystem: kernel/ksysfs — /sys/kernel/vmcoreinfo
//   Data structure:   vmcoreinfo note (NUMBER(phys_base), SYMBOL(_stext), etc.)
//   Address type:     physical (+ virtual symbols if present)
//   Method:           parsed
//   Status:           unfixed (information exposure by design)
//   Access check:     none (world-readable sysfs attribute); blocked by kernel
//                     lockdown (integrity)
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/kernel/ksysfs.c#L168
//
// Mitigations:
//   CONFIG_VMCORE_INFO=n (or CONFIG_CRASH_DUMP=n) removes the file.
//   The file is world-readable (0444); no runtime sysctl can restrict
//   access. Kernel lockdown (integrity mode) blocks access.
//
// Requires:
// - CONFIG_VMCORE_INFO (selected by crash dump support; enabled on
//   most distros)
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/kernel/ksysfs.c#L168
// https://elixir.bootlin.com/linux/v6.12/source/kernel/vmcore_info.c#L115
// ---
// <bcoles@gmail.com>

#include "include/kasld.h"
#include "include/kasld_internal.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Reads /sys/kernel/vmcoreinfo, a world-readable (0444) file that "
    "exposes the physical address of the vmcoreinfo_note page and, on "
    "some kernels, virtual symbol addresses. The file exists when "
    "CONFIG_VMCORE_INFO or CONFIG_CRASH_DUMP is enabled. The physical "
    "address reveals DRAM layout; symbols may reveal kernel text base.");

KASLD_META("method:parsed\n"
           "addr:physical\n"
           "lockdown:integrity\n"
           "config:CONFIG_VMCORE_INFO\n");

unsigned long get_phys_addr_vmcoreinfo(void) {
  FILE *f;
  const char *path = "/sys/kernel/vmcoreinfo";
  char buf[256];
  char *endptr;
  unsigned long addr;

  printf("[.] trying %s ...\n", path);

  f = fopen(path, "r");
  if (f == NULL) {
    perror("[-] fopen");
    return 0;
  }

  if (fgets(buf, sizeof(buf), f) == NULL) {
    perror("[-] fgets");
    fclose(f);
    return 0;
  }
  fclose(f);

  addr = strtoul(buf, &endptr, 16);
  if (endptr == buf || !addr) {
    fprintf(stderr, "[-] failed to parse physical address\n");
    return 0;
  }

  return addr;
}

int main(void) {
  /* Pre-check: can we access /sys/kernel/vmcoreinfo? */
  if (access("/sys/kernel/vmcoreinfo", R_OK) != 0)
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;

  unsigned long addr = get_phys_addr_vmcoreinfo();
  if (!addr)
    return 0;

  printf("vmcoreinfo_note physical address: 0x%016lx\n", addr);
  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, addr,
               KASLD_REGION_VMCOREINFO, NULL);

#if !PHYS_VIRT_DECOUPLED
  unsigned long virt = phys_to_virt(addr);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
               KASLD_REGION_VMCOREINFO, NULL);
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive directmap virtual address from physical leak\n");
#endif

  return 0;
}
