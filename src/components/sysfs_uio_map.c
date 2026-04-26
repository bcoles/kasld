// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read physical memory map addresses from UIO (Userspace I/O) sysfs.
// The UIO subsystem exposes world-readable memory map attributes for
// every registered UIO device:
//
//   /sys/class/uio/uioN/maps/mapN/addr  (physical address, %pa format)
//   /sys/class/uio/uioN/maps/mapN/size  (region size)
//   /sys/class/uio/uioN/maps/mapN/name  (optional region name)
//
// The %pa format specifier is NOT gated by kptr_restrict: it prints
// phys_addr_t values unconditionally. All map attributes are created
// with S_IRUGO (0444, world-readable) via __ATTR().
//
// UIO maps of type UIO_MEM_PHYS contain physical addresses of device
// memory (MMIO regions or DMA buffers). On architectures where the
// physical-to-virtual mapping is trivial and fixed, this directly
// yields a linear-map kernel virtual address:
//
//   arm32 / MIPS:  va = phys + PAGE_OFFSET - PHYS_OFFSET
//   arm64 (no CONFIG_RANDOMIZE_MEMORY):  va = phys + linear_offset
//   x86_64 (no CONFIG_RANDOMIZE_MEMORY): va = phys + 0xffff888000000000
//
// On x86_64 with CONFIG_RANDOMIZE_MEMORY enabled, the physical and
// virtual offsets are independently randomized, so physical addresses
// alone cannot derive the virtual text base.
//
// UIO is commonly deployed on embedded/industrial systems using
// arm32 and MIPS, where KASLR is absent and physical-to-virtual
// translation is fixed — making this a reliable direct-map leak.
//
// Leak primitive:
//   Data leaked:      UIO device physical map addresses
//   Kernel subsystem: drivers/uio — /sys/class/uio/*/maps/*/addr
//   Data structure:   struct uio_mem → addr (phys_addr_t)
//   Address type:     physical (device MMIO or DMA)
//   Method:           parsed (sysfs text attribute)
//   Status:           unfixed (information exposure by design)
//   Access check:     none (world-readable via S_IRUGO / __ATTR)
//   Source:
//   https://elixir.bootlin.com/linux/latest/source/drivers/uio/uio.c#L57
//
// Mitigations:
//   CONFIG_UIO=n removes the subsystem entirely. Individual device
//   permissions could be tightened, but the kernel default is 0444.
//   On x86_64 with CONFIG_RANDOMIZE_MEMORY, physical addresses do not
//   directly reveal the virtual text base.
//
// Requires:
// - CONFIG_UIO
// - At least one UIO device registered with a non-zero map address
//
// References:
// https://elixir.bootlin.com/linux/latest/source/drivers/uio/uio.c#L57
// https://www.kernel.org/doc/html/latest/driver-api/uio-howto.html
// ---
// <bcoles@gmail.com>

#include "include/kasld.h"
#include "include/kasld_internal.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

KASLD_EXPLAIN(
    "Reads physical memory map addresses from UIO (Userspace I/O) sysfs. "
    "Each UIO device exposes world-readable (0444) map attributes at "
    "/sys/class/uio/uioN/maps/mapN/addr using the %pa format specifier, "
    "which is NOT gated by kptr_restrict. On architectures with a fixed "
    "physical-to-virtual mapping (arm32, MIPS, arm64 without "
    "CONFIG_RANDOMIZE_MEMORY), the physical address directly yields a "
    "linear-map kernel virtual address. Requires CONFIG_UIO.");

KASLD_META("method:parsed\n"
           "addr:physical\n"
           "config:CONFIG_UIO\n");

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
  const char *base = "/sys/class/uio";
  DIR *d_uio, *d_maps;
  struct dirent *ent_uio, *ent_map;
  char path[1024];
  char buf[256];
  char name[128];
  char label[512];
  int device_count = 0;
  int map_count = 0;

  fprintf(stderr, "[.] searching %s for UIO device map addresses ...\n", base);

  d_uio = opendir(base);
  if (!d_uio) {
    if (errno == EACCES || errno == EPERM)
      return KASLD_EXIT_NOPERM;
    /* /sys/class/uio doesn't exist if CONFIG_UIO is not enabled */
    return KASLD_EXIT_UNAVAILABLE;
  }

  while ((ent_uio = readdir(d_uio)) != NULL) {
    if (ent_uio->d_name[0] == '.')
      continue;

    /* Each UIO device has a maps/ subdirectory */
    snprintf(path, sizeof(path), "%s/%s/maps", base, ent_uio->d_name);

    d_maps = opendir(path);
    if (!d_maps)
      continue;

    device_count++;

    while ((ent_map = readdir(d_maps)) != NULL) {
      if (ent_map->d_name[0] == '.')
        continue;

      /* Read the physical address */
      snprintf(path, sizeof(path), "%s/%s/maps/%s/addr", base, ent_uio->d_name,
               ent_map->d_name);

      if (read_file_line(path, buf, sizeof(buf)) < 0)
        continue;

      unsigned long long addr = 0;
      if (sscanf(buf, "0x%llx", &addr) != 1 && sscanf(buf, "%llu", &addr) != 1)
        continue;

      if (!addr)
        continue;

      /* Read optional region name for the label */
      snprintf(path, sizeof(path), "%s/%s/maps/%s/name", base, ent_uio->d_name,
               ent_map->d_name);
      if (read_file_line(path, name, sizeof(name)) < 0 || name[0] == '\0') {
        memcpy(name, ent_map->d_name, sizeof(name) - 1);
        name[sizeof(name) - 1] = '\0';
      }

      /* Encode the device + map identity in the result name so the
       * compact column reads "mmio:uio0/map0" or similar — distinguishes
       * multiple UIO mappings on the same machine. The optional human
       * region name (if present in maps/<n>/name) goes in the stderr log
       * for context. */
      snprintf(label, sizeof(label), "%.32s/%.32s", ent_uio->d_name,
               ent_map->d_name);

      fprintf(stderr, "[+] sysfs_uio_map %s [%.64s]: phys = 0x%016llx\n", label,
              name, addr);
      kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_MMIO, (unsigned long)addr,
                   KASLD_REGION_MMIO, label);

      map_count++;

#if !PHYS_VIRT_DECOUPLED
      unsigned long virt = phys_to_virt((unsigned long)addr);
      fprintf(stderr, "[+] sysfs_uio_map %s: directmap va = 0x%016lx\n", label,
              virt);
      kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
                   KASLD_REGION_MMIO, label);
#endif
    }
    closedir(d_maps);
  }
  closedir(d_uio);

  if (!map_count) {
    if (!device_count)
      fprintf(stderr, "[-] no UIO devices found in %s\n", base);
    else
      fprintf(stderr,
              "[-] %d UIO device(s) found but no non-zero map "
              "addresses\n",
              device_count);
    return KASLD_EXIT_UNAVAILABLE;
  }

  return 0;
}
