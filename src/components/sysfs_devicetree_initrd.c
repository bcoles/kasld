// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read physical initrd/initramfs address from device tree sysfs.
// On device tree platforms, the bootloader passes the initrd location
// via the "chosen" node properties:
//
//   /sys/firmware/devicetree/base/chosen/linux,initrd-start
//   /sys/firmware/devicetree/base/chosen/linux,initrd-end
//
// These properties contain raw big-endian physical addresses. Unlike
// kaslr-seed and rng-seed (which are zeroed after boot), the initrd
// properties are NOT sanitized and persist in the live device tree.
//
// The initrd is loaded by the bootloader into physical DRAM, so the
// address falls within the usable DRAM range.
//
// Not available on x86/x86_64 (no device tree). Only present when
// the bootloader passes a separate initrd via device tree (common on
// U-Boot, QEMU -initrd, GRUB-EFI on ARM/RISC-V).
//
// Analogous to dmesg_check_for_initrd but works without dmesg access.
//
// Requires:
// - CONFIG_OF (device tree support)
// - CONFIG_BLK_DEV_INITRD
// - Bootloader must pass initrd via device tree
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/of/fdt.c#L785
// https://elixir.bootlin.com/linux/v6.12/source/drivers/of/kobj.c#L65
// ---
// <bcoles@gmail.com>

#include "include/kasld.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* Read a big-endian value of 4 or 8 bytes into unsigned long. */
static unsigned long read_addr(const unsigned char *buf, int len) {
  if (len == 8) {
    uint64_t hi = read_be32(buf);
    uint64_t lo = read_be32(buf + 4);
    return (unsigned long)((hi << 32) | lo);
  }
  if (len == 4) {
    return (unsigned long)read_be32(buf);
  }
  return 0;
}

int main(void) {
  const char *bases[] = {"/sys/firmware/devicetree/base/chosen",
                         "/proc/device-tree/chosen", NULL};
  const char *chosen = NULL;
  char path[512];
  unsigned char buf[8];
  int n;

  for (int i = 0; bases[i]; i++) {
    snprintf(path, sizeof(path), "%s/linux,initrd-start", bases[i]);
    FILE *f = fopen(path, "rb");
    if (f) {
      fclose(f);
      chosen = bases[i];
      break;
    }
  }

  if (!chosen) {
    printf("[-] device tree chosen node not found or no initrd properties\n");
    return 1;
  }

  printf("[.] trying %s/linux,initrd-{start,end} ...\n", chosen);

  /* Read linux,initrd-start */
  snprintf(path, sizeof(path), "%s/linux,initrd-start", chosen);
  n = read_binary(path, buf, sizeof(buf));
  if (n != 4 && n != 8) {
    fprintf(stderr, "[-] failed to read %s (got %d bytes)\n", path, n);
    return 1;
  }

  unsigned long start = read_addr(buf, n);

  /* Read linux,initrd-end */
  snprintf(path, sizeof(path), "%s/linux,initrd-end", chosen);
  n = read_binary(path, buf, sizeof(buf));
  unsigned long end = 0;
  if (n == 4 || n == 8) {
    end = read_addr(buf, n);
  }

  if (!start) {
    fprintf(stderr, "[-] initrd-start is zero\n");
    return 1;
  }

  printf("initrd physical start: 0x%016lx\n", start);
  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, start,
               "sysfs_devicetree_initrd:start");

  if (end && end != start) {
    printf("initrd physical end:   0x%016lx\n", end);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, end,
                 "sysfs_devicetree_initrd:end");
  }

#if !PHYS_VIRT_DECOUPLED
  unsigned long virt = phys_to_virt(start);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
               "sysfs_devicetree_initrd:directmap");
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive directmap virtual address from physical leak\n");
#endif

  return 0;
}
