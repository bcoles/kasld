// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read physical memory map and initrd address from
// /sys/kernel/boot_params/data.
//
// Since Linux 3.10 (commit a6b2a69a0f77), the full struct boot_params passed
// from the bootloader is exposed as a 4096-byte binary sysfs file:
//
//   /sys/kernel/boot_params/data  (0444 — world-readable, no config gate)
//
// The interface is implemented in arch/x86/kernel/ksysfs.c and compiled
// unconditionally for x86/x86_64. Two regions of the struct yield physical
// addresses invisible to plain-text interfaces:
//
//   1. E820 physical memory map (BIOS-provided firmware memory table):
//        e820_entries  u8     @ boot_params+0x1e8 — number of entries
//        e820_table[]         @ boot_params+0x2d0 — array of boot_e820_entry
//        Each 20-byte entry: { u64 addr; u64 size; u32 type; } __packed
//        type 1 (E820_TYPE_RAM) entries are usable DRAM.
//
//   2. initrd (ramdisk) physical address set by the bootloader:
//        hdr.ramdisk_image u32 LE @ boot_params+0x218 — low 32 bits of phys
//        ext_ramdisk_image u32 LE @ boot_params+0x0c0 — high 32 bits of phys
//        hdr.ramdisk_size  u32 LE @ boot_params+0x21c — low 32 bits of size
//        ext_ramdisk_size  u32 LE @ boot_params+0x0c4 — high 32 bits of size
//
// This component provides the same E820 data as dmesg_e820_memory_map.c but
// without requiring dmesg access (works when dmesg_restrict=1). The initrd
// physical address is the x86 counterpart to sysfs_devicetree_initrd.c
// (which serves ARM/RISC-V device tree platforms).
//
// Leak primitive:
//   Data leaked:      physical memory map (E820 BIOS table) + initrd address
//   Kernel subsystem: arch/x86/kernel — ksysfs.c (boot_params_data_attr)
//   Data structure:   struct boot_params / struct boot_e820_entry
//   Address type:     physical (DRAM)
//   Method:           parsed (binary sysfs attribute, struct boot_params)
//   Status:           unfixed (information exposure by design)
//   Access check:     none (S_IRUGO — world-readable, no sysctl gate)
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/arch/x86/kernel/ksysfs.c#L30
//
// Mitigations:
//   No kernel runtime sysctl restricts access to this file. The file is
//   unconditionally present on x86/x86_64 (ksysfs.c is always compiled).
//   On x86-64 (TEXT_TRACKS_DIRECTMAP=0), physical addresses cannot be used
//   to derive the virtual kernel text base directly.
//
// Requires:
//   x86 or x86_64 architecture (boot_params is x86-specific)
//
// References:
//   https://elixir.bootlin.com/linux/v6.12/source/arch/x86/kernel/ksysfs.c
//   https://elixir.bootlin.com/linux/v6.12/source/arch/x86/include/uapi/asm/bootparam.h
//   https://elixir.bootlin.com/linux/v6.12/source/arch/x86/include/uapi/asm/setup_data.h
//   https://www.kernel.org/doc/html/latest/arch/x86/boot.html
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if !defined(__i386__) && !defined(__x86_64__) && !defined(__amd64__)
#error "Architecture is not supported"
#endif

KASLD_EXPLAIN(
    "Reads the x86 E820 physical memory map and initrd physical address "
    "directly from /sys/kernel/boot_params/data — a world-readable "
    "(0444) 4096-byte binary sysfs file exposing the full struct "
    "boot_params passed from the bootloader. No dmesg access is "
    "required. The E820 table yields physical DRAM bounds; the "
    "ramdisk_image field yields the initrd load address in DRAM. "
    "x86/x86_64 only; always present (no CONFIG gate).");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n");

/* Path and size of the boot_params sysfs binary attribute. */
#define BOOT_PARAMS_PATH "/sys/kernel/boot_params/data"
#define BOOT_PARAMS_SIZE 4096u

/* boot_params field offsets (absolute byte positions, x86 boot protocol).
 * setup_header starts at boot_params+0x1f1; e820_table is after the header. */
#define OFF_EXT_RAMDISK_IMAGE                                                  \
  0x0c0ul /* u32 LE: high 32 bits of initrd phys addr */
#define OFF_EXT_RAMDISK_SIZE                                                   \
  0x0c4ul                        /* u32 LE: high 32 bits of initrd byte count */
#define OFF_E820_ENTRIES 0x1e8ul /* u8: number of populated E820 entries */
#define OFF_RAMDISK_IMAGE                                                      \
  0x218ul /* u32 LE: low  32 bits of initrd phys addr                          \
           */
#define OFF_RAMDISK_SIZE                                                       \
  0x21cul                      /* u32 LE: low  32 bits of initrd byte count    \
                                */
#define OFF_E820_TABLE 0x2d0ul /* boot_e820_entry[128]: E820 memory map */

/* E820 region type for usable RAM (E820_TYPE_RAM). */
#define E820_TYPE_RAM 1u

/* struct boot_e820_entry { u64 addr; u64 size; u32 type; } __packed;
 * Byte offsets within each 20-byte table entry: */
#define E820_BYTES_PER_ENTRY 20u
#define E820_OFF_ADDR 0u  /* u64 LE: physical start address */
#define E820_OFF_SIZE 8u  /* u64 LE: region byte count */
#define E820_OFF_TYPE 16u /* u32 LE: E820 memory type */

/* Maximum entries in the zero-page E820 table (E820_MAX_ENTRIES_ZEROPAGE). */
#define E820_MAX_ENTRIES 128u

static inline uint32_t read_le32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static inline uint64_t read_le64(const uint8_t *p) {
  return (uint64_t)read_le32(p) | ((uint64_t)read_le32(p + 4) << 32);
}

int main(void) {
  static uint8_t buf[BOOT_PARAMS_SIZE];

  kasld_info("reading E820 memory map and initrd address from " BOOT_PARAMS_PATH
             " ...");

  int fd = kasld_open(BOOT_PARAMS_PATH, O_RDONLY);
  if (fd < 0) {
    int saved_errno = errno;
    perror("[-] open " BOOT_PARAMS_PATH);
    return (saved_errno == EACCES || saved_errno == EPERM)
               ? KASLD_EXIT_NOPERM
               : KASLD_EXIT_UNAVAILABLE;
  }

  ssize_t n = pread(fd, buf, sizeof(buf), 0);
  close(fd);

  if (n != (ssize_t)sizeof(buf)) {
    kasld_err("short read from " BOOT_PARAMS_PATH " (%zd of %u bytes)", n,
              BOOT_PARAMS_SIZE);
    return KASLD_EXIT_UNAVAILABLE;
  }

  /* ------------------------------------------------------------------ */
  /* E820 physical memory map                                            */
  /* ------------------------------------------------------------------ */

  uint8_t e820_entries = buf[OFF_E820_ENTRIES];

  if (e820_entries > E820_MAX_ENTRIES)
    e820_entries = E820_MAX_ENTRIES;

  if (e820_entries == 0) {
    kasld_err("E820 table is empty");
  } else {
    unsigned long lo = ~0ul;
    unsigned long hi = 0;
    unsigned int ram_count = 0;
    int covering_ok = 1; /* clears if any RAM entry exceeds unsigned long */

    for (unsigned int i = 0; i < (unsigned int)e820_entries; i++) {
      const uint8_t *entry = buf + OFF_E820_TABLE + i * E820_BYTES_PER_ENTRY;
      uint32_t type = read_le32(entry + E820_OFF_TYPE);

      if (type != E820_TYPE_RAM)
        continue;

      uint64_t start = read_le64(entry + E820_OFF_ADDR);
      uint64_t size = read_le64(entry + E820_OFF_SIZE);

      if (size == 0)
        continue;

      uint64_t end = start + size - 1; /* inclusive last byte */

      /* A covering extent silently truncated to unsigned long (32-bit / PAE)
       * would fabricate a false gap; if any RAM entry would truncate, suppress
       * the covering entirely (an incomplete map is worse than none). */
      if ((unsigned long)start != start || (unsigned long)end != end)
        covering_ok = 0;

      kasld_info("E820 RAM: 0x%016llx - 0x%016llx", (unsigned long long)start,
                 (unsigned long long)end);

      /* Skip physical address 0: trivially known, no KASLR information. */
      if (start != 0 && (unsigned long)start < lo)
        lo = (unsigned long)start;
      if ((unsigned long)end > hi)
        hi = (unsigned long)end;

      ram_count++;
    }

    if (ram_count == 0) {
      kasld_err("no E820 RAM entries found");
    } else {
      if (lo != ~0ul) {
        kasld_found("leaked E820 DRAM low:  0x%016lx", lo);
        kasld_result_base(KASLD_TYPE_PHYS, REGION_RAM, lo, NULL, CONF_PARSED);
      }
      if (hi) {
        kasld_found("leaked E820 DRAM high: 0x%016lx", hi);
        kasld_result_top(KASLD_TYPE_PHYS, REGION_RAM, hi, NULL, CONF_PARSED);
      }

      /* Emit the whole RAM map as a covering: each E820 type-RAM entry is one
       * RAM extent, and the gaps between a source's extents are non-RAM the
       * kernel image cannot occupy (ram_map_phys_exclude /
       * firmware_memmap_holes carve them). boot_params holds the complete,
       * authoritative E820 table — the zero-page is hard-capped at
       * E820_MAX_ENTRIES, so it is never a partial leak — making this a sound
       * covering, and the only one available when CONFIG_FIRMWARE_MEMMAP=n
       * hides /sys/firmware/memmap. Every RAM entry must be emitted (including
       * any at address 0): a skipped extent would synthesize a false gap. The
       * covering goes out-of-band into coverings[] (pos=extent), complementing
       * the base/top envelope above. */
      if (covering_ok) {
        for (unsigned int i = 0; i < (unsigned int)e820_entries; i++) {
          const uint8_t *e = buf + OFF_E820_TABLE + i * E820_BYTES_PER_ENTRY;
          if (read_le32(e + E820_OFF_TYPE) != E820_TYPE_RAM)
            continue;
          uint64_t start = read_le64(e + E820_OFF_ADDR);
          uint64_t size = read_le64(e + E820_OFF_SIZE);
          if (size == 0)
            continue;
          kasld_result_extent(KASLD_TYPE_PHYS, REGION_RAM, (unsigned long)start,
                              (unsigned long)(start + size - 1), NULL,
                              CONF_PARSED);
        }
      }

#ifdef phys_to_directmap_virt
      if (lo != ~0ul) {
        unsigned long virt = phys_to_directmap_virt(lo);
        kasld_info("possible direct-map virtual address (low):  0x%016lx",
                   virt);
        kasld_result_base(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL,
                          CONF_PARSED);
      }
      if (hi) {
        unsigned long virt = phys_to_directmap_virt(hi);
        kasld_info("possible direct-map virtual address (high): 0x%016lx",
                   virt);
        kasld_result_top(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL,
                         CONF_PARSED);
      }
#else
      kasld_info(
          "note: phys and virt KASLR are decoupled on this arch; "
          "cannot derive kernel text virtual address from physical leak");
#endif
    }
  }

  /* ------------------------------------------------------------------ */
  /* initrd (ramdisk) physical address                                   */
  /* ------------------------------------------------------------------ */

  /* Combine low and high 32-bit halves into a 64-bit physical address.
   * ext_ramdisk_image (high bits) is non-zero only when the initrd is
   * placed above 4 GiB — uncommon but possible on large-RAM systems. */
  uint32_t lo_img = read_le32(buf + OFF_RAMDISK_IMAGE);
  uint32_t hi_img = read_le32(buf + OFF_EXT_RAMDISK_IMAGE);
  uint32_t lo_sz = read_le32(buf + OFF_RAMDISK_SIZE);
  uint32_t hi_sz = read_le32(buf + OFF_EXT_RAMDISK_SIZE);

  /* Combine 32-bit halves into 64-bit values using uint64_t arithmetic.
   * Casting hi_img to unsigned long before shifting would be UB on i386
   * (shift count equals the type width). */
  uint64_t initrd_start = ((uint64_t)hi_img << 32) | lo_img;
  uint64_t initrd_size = ((uint64_t)hi_sz << 32) | lo_sz;

  if (!initrd_start || !initrd_size) {
    kasld_err("no initrd found in boot_params");
    return 0;
  }

  uint64_t initrd_end = initrd_start + initrd_size - 1;

  kasld_found("leaked initrd physical start: 0x%016llx",
              (unsigned long long)initrd_start);
  kasld_found("leaked initrd physical end:   0x%016llx",
              (unsigned long long)initrd_end);
  kasld_result_range(KASLD_TYPE_PHYS, REGION_INITRD,
                     (unsigned long)initrd_start, (unsigned long)initrd_end,
                     NULL, CONF_PARSED);

#ifdef phys_to_directmap_virt
  unsigned long virt = phys_to_directmap_virt((unsigned long)initrd_start);
  kasld_info("possible direct-map virtual address: 0x%016lx", virt);
  kasld_result_base(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL, CONF_PARSED);
#endif

  return 0;
}
