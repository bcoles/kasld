// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read EFI runtime service virtual and physical addresses from
// /sys/firmware/efi/runtime-map/. Each numbered entry exposes five sysfs
// files: phys_addr, virt_addr, num_pages, attribute, and type. On current
// kernels these are created with __ATTR_RO_MODE(.., 0400) — root-only; an
// unprivileged user cannot read them (older kernels exposed them 0444).
//
// CONFIG_EFI_RUNTIME_MAP, which creates this directory, is an x86 option
// (arch/x86/Kconfig, selected when KEXEC_CORE is enabled); the sysfs
// interface is x86-only.
//
// On kernels without a dedicated EFI virtual address space (pre-~v5.14),
// the virtual addresses passed to SetVirtualAddressMap() are placed in the
// main kernel direct-map region. Subtracting the physical address from the
// virtual address yields virt_page_offset_base directly, bounding the
// direct-map base to KASLR granularity.
//
// On v5.14+ kernels with a dedicated EFI page table (CONFIG_EFI_MIXED),
// the EFI VA space is separate from the kernel direct-map; virt_addr no
// longer falls in the expected direct-map range and this technique is
// ineffective.
//
// Leak primitive:
//   Data leaked:      EFI runtime service virtual and physical addresses
//   Kernel subsystem: arch/x86/platform/efi/runtime-map.c (x86-only)
//   Data structure:   EFI memory map descriptors (efi_memory_desc_t)
//   Address type:     virtual (direct-map, pre-v5.14)
//   Method:           parsed (sysfs text files)
//   Status:           unfixed (information exposure by design)
//   Access check:     root-only (__ATTR_RO_MODE(.., 0400)) on current kernels
//   Source:
//   https://elixir.bootlin.com/linux/latest/source/arch/x86/platform/efi/runtime-map.c
//
// Mitigations:
//   On current kernels the sysfs files are mode 0400 (root-only), so an
//   unprivileged user cannot read them; the technique requires root or an
//   older kernel that exposed them world-readable.
//   Utility reduced on v5.14+ kernels with dedicated EFI VA space.
//   CONFIG_EFI_RUNTIME_MAP=n removes the sysfs entries entirely.
//
// Requires:
// - CONFIG_EFI
// - CONFIG_KEXEC_CORE (enables CONFIG_EFI_RUNTIME_MAP which creates the sysfs
//   directory; absent on stripped/virt kernels that omit kexec support)
// - UEFI-booted system (/sys/firmware/efi/runtime-map/ must exist)
//
// References:
// https://elixir.bootlin.com/linux/latest/source/arch/x86/platform/efi/runtime-map.c
// https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-firmware-efi-runtime-map
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads EFI runtime service virtual and physical addresses from "
    "/sys/firmware/efi/runtime-map/N/virt_addr and /phys_addr. On "
    "kernels without a dedicated EFI virtual address space (pre-~v5.14), "
    "runtime service virtual addresses are placed in the kernel "
    "direct-map. Subtracting phys_addr from virt_addr yields "
    "virt_page_offset_base directly. On current kernels these files are mode "
    "0400 (root-only via __ATTR_RO_MODE), so an unprivileged user cannot read "
    "them; older kernels exposed them world-readable (0444). The interface is "
    "x86-only (CONFIG_EFI_RUNTIME_MAP) and requires a UEFI-booted system.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "config:CONFIG_EFI\n"
           "config:CONFIG_KEXEC_CORE\n");

static int read_file_line(const char *path, char *buf, size_t len) {
  FILE *f = kasld_fopen(path, "r");
  if (!f)
    return -1;
  if (fgets(buf, (int)len, f) == NULL) {
    fclose(f);
    return -1;
  }
  fclose(f);
  buf[strcspn(buf, "\n")] = '\0';
  return 0;
}

int main(void) {
  const char *base = "/sys/firmware/efi/runtime-map";
  DIR *d;
  struct dirent *ent;
  char path[512];
  char buf[64];
  int count = 0;

  kasld_info("searching %s for EFI runtime service virtual addresses ...",
             base);

  d = kasld_opendir(base);
  if (!d) {
    int e = errno;
    perror("[-] opendir");
    return (e == EACCES || e == EPERM) ? KASLD_EXIT_NOPERM
                                       : KASLD_EXIT_UNAVAILABLE;
  }

  while ((ent = readdir(d)) != NULL) {
    if (ent->d_name[0] == '.')
      continue;

    snprintf(path, sizeof(path), "%s/%s/virt_addr", base, ent->d_name);
    if (read_file_line(path, buf, sizeof(buf)) < 0)
      continue;

    char *endptr;
    unsigned long virt = strtoul(buf, &endptr, 16);
    if (!virt || endptr == buf)
      continue;

    /* Must be in the direct-map region: at or above PAGE_OFFSET, below
     * kernel text. Rejects physical-range values on systems where
     * SetVirtualAddressMap was never called or used identity mapping. */
    if (!kasld_addr_is_directmap(virt))
      continue;

    snprintf(path, sizeof(path), "%s/%s/phys_addr", base, ent->d_name);
    if (read_file_line(path, buf, sizeof(buf)) < 0) {
      kasld_info("EFI runtime entry %s: virt=0x%016lx", ent->d_name, virt);
      kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL,
                          CONF_PARSED);
      count++;
      continue;
    }

    unsigned long phys = strtoul(buf, &endptr, 16);
    if (endptr == buf || phys > virt) {
      kasld_info("EFI runtime entry %s: virt=0x%016lx", ent->d_name, virt);
      kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL,
                          CONF_PARSED);
      count++;
      continue;
    }

    /* virt_page_offset_base = virt - phys for any direct-map entry */
    unsigned long virt_page_offset = virt - phys;
    if (!kasld_addr_in_window(virt_page_offset,
                              (unsigned long)KERNEL_VIRT_VAS_START,
                              (unsigned long)KERNEL_VIRT_TEXT_MIN))
      continue;

    kasld_info("EFI runtime entry %s: virt=0x%016lx phys=0x%016lx"
               " => virt_page_offset=0x%016lx",
               ent->d_name, virt, phys, virt_page_offset);
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, virt_page_offset,
                        NULL, CONF_PARSED);
    count++;
  }
  closedir(d);

  if (!count) {
    kasld_err("no EFI runtime map entries with direct-map virtual addresses"
              " found");
    return 0;
  }

  return 0;
}
