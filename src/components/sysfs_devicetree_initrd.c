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
// Leak primitive:
//   Data leaked:      physical initrd load address (start and end)
//   Kernel subsystem: drivers/of —
//   /sys/firmware/devicetree/base/chosen/linux,initrd-* Data structure: device
//   tree chosen node (linux,initrd-start / linux,initrd-end) Address type:
//   physical (DRAM) Method:           parsed (binary sysfs property) Status:
//   unfixed (information exposure by design)
//   Access check:     none (world-readable sysfs attribute, 0444)
//   Source: https://elixir.bootlin.com/linux/v6.12/source/drivers/of/fdt.c#L785
//
// Mitigations:
//   CONFIG_OF=n removes device tree sysfs. CONFIG_BLK_DEV_INITRD=n prevents
//   the property from existing. The property is world-readable (0444);
//   no runtime sysctl can restrict access. On decoupled architectures,
//   physical addresses cannot derive the virtual text base.
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

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads the physical initrd/initramfs address from the device tree "
    "sysfs chosen node (/sys/firmware/devicetree/base/chosen/"
    "linux,initrd-start). This world-readable binary property contains "
    "the physical address where the bootloader placed the initrd in "
    "RAM. Only present on device tree platforms with an initrd.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "config:CONFIG_OF\n"
           "config:CONFIG_BLK_DEV_INITRD\n");

/* Read raw binary content from a sysfs file. Returns bytes read, or -1. */
static int read_binary(const char *path, unsigned char *buf, size_t len) {
  FILE *f = kasld_fopen(path, "rb");
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
    FILE *f = kasld_fopen(path, "rb");
    if (f) {
      fclose(f);
      chosen = bases[i];
      break;
    }
  }

  if (!chosen) {
    kasld_err("device tree chosen node not found or no initrd properties");
    return KASLD_EXIT_UNAVAILABLE;
  }

  kasld_info("trying %s/linux,initrd-{start,end} ...", chosen);

  /* Read linux,initrd-start */
  snprintf(path, sizeof(path), "%s/linux,initrd-start", chosen);
  n = read_binary(path, buf, sizeof(buf));
  if (n != 4 && n != 8) {
    kasld_err("failed to read %s (got %d bytes)", path, n);
    return 0;
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
    kasld_err("initrd-start is zero");
    return 0;
  }

  printf("initrd physical start: 0x%016lx\n", start);

  if (end && end > start) {
    printf("initrd physical end:   0x%016lx\n", end);
    kasld_result_range(KASLD_TYPE_PHYS, REGION_INITRD, start, end, NULL,
                       CONF_PARSED);
  } else {
    kasld_result_base(KASLD_TYPE_PHYS, REGION_INITRD, start, NULL, CONF_PARSED);
  }

#ifdef phys_to_directmap_virt
  unsigned long virt = phys_to_directmap_virt(start);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL,
                      CONF_PARSED);
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive directmap virtual address from physical leak\n");
#endif

  return 0;
}
