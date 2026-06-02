// This file is part of KASLD - https://github.com/bcoles/kasld
//
// x86 boot_params reader (/sys/kernel/boot_params/data), without privileges.
//
// The x86 setup_header carries the exact in-memory kernel init_size, a tighter
// (exact) kernel-size than the /boot image-size estimate. Read by the engine
// bridge.
// x86-only (the file is x86-specific); returns 0 elsewhere or on failure.
// Reads route through the kasld_* wrappers, so it is KASLD_SYSROOT-aware.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_BOOT_PARAMS_H
#define KASLD_BOOT_PARAMS_H

#include "sysroot.h"

#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

/* setup_header starts at boot_params+0x1f1 (__packed). init_size is hdr+0x6f
 * => boot_params+0x260. */
#define KASLD_BOOT_PARAMS_PATH "/sys/kernel/boot_params/data"
#define KASLD_BOOT_PARAMS_INIT_SIZE 0x260ul
/* kernel_alignment (CONFIG_PHYSICAL_ALIGN) is hdr+0x3f => boot_params+0x230. */
#define KASLD_BOOT_PARAMS_KERNEL_ALIGN 0x230ul
/* cmd_line_ptr (physical address of the cmdline buffer) is hdr+0x37
 * => boot_params+0x228, __u32. cmdline_size is hdr+0x47 => boot_params+0x238.
 */
#define KASLD_BOOT_PARAMS_CMD_LINE_PTR 0x228ul
#define KASLD_BOOT_PARAMS_CMDLINE_SIZE 0x238ul

/* Exact kernel init_size from x86 boot_params, or 0 if unavailable. */
__attribute__((unused)) static unsigned long kasld_read_boot_init_size(void) {
#if defined(__x86_64__) || defined(__i386__)
  int fd = kasld_open(KASLD_BOOT_PARAMS_PATH, O_RDONLY);
  if (fd < 0)
    return 0;
  uint32_t init_size = 0;
  ssize_t n = pread(fd, &init_size, 4, KASLD_BOOT_PARAMS_INIT_SIZE);
  close(fd);
  return (n == 4) ? (unsigned long)init_size : 0;
#else
  return 0;
#endif
}

/* CONFIG_PHYSICAL_ALIGN (KASLR slot granularity) from x86 boot_params, or 0 if
 * unavailable. The caller sanity-checks the value (power of two, sane range).
 */
__attribute__((unused)) static unsigned long
kasld_read_boot_kernel_align(void) {
#if defined(__x86_64__) || defined(__i386__)
  int fd = kasld_open(KASLD_BOOT_PARAMS_PATH, O_RDONLY);
  if (fd < 0)
    return 0;
  uint32_t align = 0;
  ssize_t n = pread(fd, &align, 4, KASLD_BOOT_PARAMS_KERNEL_ALIGN);
  close(fd);
  return (n == 4) ? (unsigned long)align : 0;
#else
  return 0;
#endif
}

/* Physical address of the kernel cmdline buffer (boot_params.hdr.cmd_line_ptr),
 * or 0 if unavailable. The kernel placement code refuses to overlap this
 * region; the cmdline_phys_exclude rule turns it into a C_EXCLUDE on the
 * physical text base. __u32 — for cmdlines above 4 GiB ext_cmd_line_ptr would
 * extend it (not handled here). */
__attribute__((unused)) static unsigned long
kasld_read_boot_cmd_line_ptr(void) {
#if defined(__x86_64__) || defined(__i386__)
  int fd = kasld_open(KASLD_BOOT_PARAMS_PATH, O_RDONLY);
  if (fd < 0)
    return 0;
  uint32_t ptr = 0;
  ssize_t n = pread(fd, &ptr, 4, KASLD_BOOT_PARAMS_CMD_LINE_PTR);
  close(fd);
  return (n == 4) ? (unsigned long)ptr : 0;
#else
  return 0;
#endif
}

/* Bootloader-reported size of the kernel cmdline buffer, or 0 if unavailable.
 * Together with kasld_read_boot_cmd_line_ptr() it describes the forbidden
 * region [cmd_line_ptr, cmd_line_ptr + cmdline_size). */
__attribute__((unused)) static unsigned long
kasld_read_boot_cmdline_size(void) {
#if defined(__x86_64__) || defined(__i386__)
  int fd = kasld_open(KASLD_BOOT_PARAMS_PATH, O_RDONLY);
  if (fd < 0)
    return 0;
  uint32_t size = 0;
  ssize_t n = pread(fd, &size, 4, KASLD_BOOT_PARAMS_CMDLINE_SIZE);
  close(fd);
  return (n == 4) ? (unsigned long)size : 0;
#else
  return 0;
#endif
}

#endif /* KASLD_BOOT_PARAMS_H */
