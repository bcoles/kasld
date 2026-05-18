// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read physical addresses from the device tree "chosen" node properties
// that are set by the main kernel when loading a kdump crash kernel:
//
//   linux,elfcorehdr        — physical address and size of the ELF core header
//   linux,usable-memory-range — physical memory ranges usable by crash kernel
//
// When a kdump-capable kernel loads a crash kernel via kexec -p, it records
// these physical addresses in the device tree passed to the crash kernel.
// The crash kernel (secondary kernel) then finds them at boot via the DT
// chosen node, which is exposed as:
//
//   /sys/firmware/devicetree/base/chosen/linux,elfcorehdr      (0444)
//   /sys/firmware/devicetree/base/chosen/linux,usable-memory-range (0444)
//
// linux,elfcorehdr contains two big-endian u64 values: (address, size).
//   The address is the physical location of the ELF core header that
//   describes the crashed system's memory layout for makedumpfile/crash.
//
// linux,usable-memory-range contains one or more (base, size) u64 pairs
//   describing the physical memory ranges the crash kernel may use.
//   These are DRAM ranges within the crash kernel's memory reservation.
//
// All device tree sysfs properties are world-readable (0444); no capability
// check is performed. These properties are NOT sanitized after boot (unlike
// kaslr-seed and rng-seed, which are zeroed after reading).
//
// This component is only useful when:
//   1. Running on a device-tree platform (ARM64, RISC-V, MIPS, PowerPC)
//   2. Running as the kdump crash kernel (not the primary kernel)
//   3. kdump is configured and a crash occurred
//
// Leak primitive:
//   Data leaked:      physical DRAM addresses (ELF core header, crash kernel
//                     usable memory ranges)
//   Kernel subsystem: drivers/of — /sys/firmware/devicetree/base/chosen/
//   Data structure:   device tree chosen node
//                     (linux,elfcorehdr / linux,usable-memory-range)
//   Address type:     physical (DRAM)
//   Method:           parsed (binary sysfs property)
//   Status:           unfixed (information exposure by design; crash kernel
//                     context only)
//   Access check:     none (world-readable sysfs attribute, 0444)
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/arch/arm64/mm/init.c#L84
//
// Mitigations:
//   CONFIG_OF=n removes device tree sysfs entirely. These properties only
//   exist in the crash kernel's device tree; they are absent from the
//   primary kernel's DT. On architectures with decoupled KASLR, physical
//   addresses cannot derive the virtual text base.
//
// Requires:
// - CONFIG_OF (device tree support — ARM64, RISC-V, MIPS, PowerPC)
// - CONFIG_KEXEC_CORE / CONFIG_CRASH_DUMP
// - Running as the kdump crash kernel after a system crash
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/arch/arm64/mm/init.c#L84
// https://elixir.bootlin.com/linux/v6.12/source/arch/riscv/mm/init.c
// https://www.kernel.org/doc/Documentation/kdump/kdump.txt
// https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-firmware-ofw
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/internal.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads physical DRAM addresses from device tree chosen node properties "
    "set by the primary kernel when loading a kdump crash kernel: "
    "linux,elfcorehdr (physical address + size of ELF core header) and "
    "linux,usable-memory-range (usable DRAM ranges for the crash kernel). "
    "All DT sysfs properties are world-readable (0444). These properties "
    "only exist in the crash kernel's device tree on DT platforms (ARM64, "
    "RISC-V) after a system crash with kdump configured.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "config:CONFIG_OF\n"
           "config:CONFIG_CRASH_DUMP\n"
           "status:experimental\n");

/* Read raw binary content from a sysfs file. Returns bytes read, or -1. */
static int read_binary(const char *path, unsigned char *buf, size_t len) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return -1;
  int n = (int)fread(buf, 1, len, f);
  fclose(f);
  return n;
}

/* Read a big-endian 64-bit value from raw bytes. */
static uint64_t read_be64(const unsigned char *p) {
  return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
         ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
         ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
         ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

int main(void) {
  const char *bases[] = {"/sys/firmware/devicetree/base/chosen",
                         "/proc/device-tree/chosen", NULL};
  const char *chosen = NULL;
  char path[512];
  unsigned char buf[256];
  int n;
  int count = 0;

  /* Find the chosen node */
  for (int i = 0; bases[i]; i++) {
    snprintf(path, sizeof(path), "%s/linux,elfcorehdr", bases[i]);
    FILE *f = fopen(path, "rb");
    if (f) {
      fclose(f);
      chosen = bases[i];
      break;
    }
    /* Also check for linux,usable-memory-range as fallback probe */
    snprintf(path, sizeof(path), "%s/linux,usable-memory-range", bases[i]);
    f = fopen(path, "rb");
    if (f) {
      fclose(f);
      chosen = bases[i];
      break;
    }
  }

  if (!chosen) {
    printf(
        "[-] device tree chosen node not found or no kdump crash kernel "
        "properties (linux,elfcorehdr / linux,usable-memory-range) present\n"
        "    (this component only works in the kdump crash kernel context)\n");
    return KASLD_EXIT_UNAVAILABLE;
  }

  /* --- linux,elfcorehdr: <u64 address> <u64 size> --- */
  snprintf(path, sizeof(path), "%s/linux,elfcorehdr", chosen);
  n = read_binary(path, buf, sizeof(buf));
  if (n >= 16) {
    uint64_t ehdr_addr = read_be64(buf);
    uint64_t ehdr_size = read_be64(buf + 8);
    if (ehdr_addr) {
      printf("linux,elfcorehdr address: 0x%016llx  size: 0x%llx\n",
             (unsigned long long)ehdr_addr, (unsigned long long)ehdr_size);
      if (ehdr_size) {
        kasld_result_sized(KASLD_TYPE_PHYS, REGION_CRASHKERNEL,
                           (unsigned long)ehdr_addr, (unsigned long)ehdr_size,
                           "elfcorehdr", CONF_PARSED);
      } else {
        kasld_result_sample(KASLD_TYPE_PHYS, REGION_CRASHKERNEL,
                            (unsigned long)ehdr_addr, "elfcorehdr",
                            CONF_PARSED);
      }
#if !PHYS_VIRT_DECOUPLED
      unsigned long virt = phys_to_virt((unsigned long)ehdr_addr);
      printf("possible direct-map virtual address: 0x%016lx\n", virt);
      kasld_result_sample(KASLD_TYPE_VIRT, REGION_CRASHKERNEL, virt,
                          "elfcorehdr", CONF_PARSED);
#endif
      count++;
    }
  } else if (n > 0) {
    fprintf(stderr, "[-] linux,elfcorehdr: expected >= 16 bytes, got %d\n", n);
  }

  /* --- linux,usable-memory-range: array of <u64 base> <u64 size> pairs --- */
  snprintf(path, sizeof(path), "%s/linux,usable-memory-range", chosen);
  n = read_binary(path, buf, sizeof(buf));
  if (n >= 16) {
    int npairs = n / 16;
    for (int i = 0; i < npairs && i * 16 + 15 < n; i++) {
      uint64_t base = read_be64(buf + i * 16);
      uint64_t size = read_be64(buf + i * 16 + 8);
      if (!base)
        continue;
      printf("linux,usable-memory-range[%d]: base=0x%016llx  size=0x%llx\n", i,
             (unsigned long long)base, (unsigned long long)size);
      if (size) {
        kasld_result_sized(KASLD_TYPE_PHYS, REGION_CRASHKERNEL,
                           (unsigned long)base, (unsigned long)size,
                           "usable-memory", CONF_PARSED);
      } else {
        kasld_result_sample(KASLD_TYPE_PHYS, REGION_CRASHKERNEL,
                            (unsigned long)base, "usable-memory", CONF_PARSED);
      }
#if !PHYS_VIRT_DECOUPLED
      unsigned long virt = phys_to_virt((unsigned long)base);
      printf("possible direct-map virtual address: 0x%016lx\n", virt);
      kasld_result_sample(KASLD_TYPE_VIRT, REGION_CRASHKERNEL, virt,
                          "usable-memory", CONF_PARSED);
#endif
      count++;
    }
  } else if (n > 0) {
    fprintf(stderr,
            "[-] linux,usable-memory-range: expected >= 16 bytes, got %d\n", n);
  }

  if (!count) {
    printf("[-] no physical addresses found in crash kernel DT chosen node\n");
    return KASLD_EXIT_UNAVAILABLE;
  }

  return 0;
}
