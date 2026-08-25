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
//   Data leaked:      physical address of the vmcoreinfo note page (DRAM)
//   Kernel subsystem: kernel/ksysfs — /sys/kernel/vmcoreinfo
//   Data structure:   vmcoreinfo note page (the attribute prints only its
//                     physical address and size, not the note contents)
//   Address type:     physical (DRAM)
//   Method:           parsed
//   Status:           unfixed (information exposure by design)
//   Access check:     none (world-readable sysfs attribute)
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/kernel/ksysfs.c#L168
//
// Mitigations:
//   CONFIG_VMCORE_INFO=n (or CONFIG_CRASH_DUMP=n) removes the file. The file
//   is world-readable (0444); no runtime sysctl restricts it, and kernel
//   lockdown does not gate it.
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

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Reads /sys/kernel/vmcoreinfo, a world-readable (0444) file that "
    "prints the physical address and size of the vmcoreinfo note page. "
    "The file exists when CONFIG_VMCORE_INFO or CONFIG_CRASH_DUMP is "
    "enabled. The note page sits in usable DRAM, so its physical address "
    "is a DRAM landmark (and a direct-map virtual address on coupled "
    "architectures).");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:physical\n"
           "config:CONFIG_VMCORE_INFO\n");

static unsigned long get_phys_addr_vmcoreinfo(void) {
  FILE *f;
  const char *path = "/sys/kernel/vmcoreinfo";
  char buf[256];
  unsigned long addr;

  kasld_info("trying %s ...", path);

  f = kasld_fopen(path, "r");
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

  if (!kasld_addr_parse(buf, 16, &addr, NULL) || !addr) {
    kasld_err("failed to parse physical address");
    return 0;
  }

  return addr;
}

int main(void) {
  /* Pre-check: is /sys/kernel/vmcoreinfo readable? */
  if (kasld_access("/sys/kernel/vmcoreinfo", R_OK) != 0)
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;

  unsigned long addr = get_phys_addr_vmcoreinfo();
  if (!addr)
    return 0;

  kasld_info("vmcoreinfo_note physical address: 0x%016lx", addr);
  kasld_result_sample(KASLD_TYPE_PHYS, REGION_VMCOREINFO, addr, NULL,
                      CONF_PARSED);

  return 0;
}
