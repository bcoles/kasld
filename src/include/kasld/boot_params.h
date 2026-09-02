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

/* The setup header this file reads from the kernel's copy is the same header
 * kernel_image.h reads from the image, so the protocol-version thresholds that
 * say when a field came into existence are shared rather than restated. */
#include "kernel_image.h"

#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

/* setup_header starts at boot_params+0x1f1 (__packed). init_size is hdr+0x6f
 * => boot_params+0x260. */
#define KASLD_BOOT_PARAMS_PATH "/sys/kernel/boot_params/data"
#define KASLD_BOOT_PARAMS_INIT_SIZE 0x260ul
/* kernel_alignment (CONFIG_PHYSICAL_ALIGN) is hdr+0x3f => boot_params+0x230. */
#define KASLD_BOOT_PARAMS_KERNEL_ALIGN 0x230ul
#define KASLD_BOOT_PARAMS_RELOCATABLE 0x234ul
#define KASLD_BOOT_PARAMS_LOADFLAGS 0x211ul
#define KASLD_BOOT_PARAMS_KASLR_FLAG (1u << 1) /* bootparam.h KASLR_FLAG */
/* The header's own "HdrS" magic is hdr+0x11 => boot_params+0x202, and the boot
 * protocol version hdr+0x15 => boot_params+0x206. */
#define KASLD_BOOT_PARAMS_HDR_MAGIC 0x202ul
#define KASLD_BOOT_PARAMS_HDR_VERSION 0x206ul
/* cmd_line_ptr (physical address of the cmdline buffer) is hdr+0x37
 * => boot_params+0x228, __u32. cmdline_size is hdr+0x47 => boot_params+0x238.
 */
#define KASLD_BOOT_PARAMS_CMD_LINE_PTR 0x228ul
#define KASLD_BOOT_PARAMS_CMDLINE_SIZE 0x238ul

/* Boot protocol version of the setup header in boot_params, or 0 where what is
 * there is not a setup header at all.
 *
 * A boot_params that reached the kernel through the EFI stub does not hold the
 * image's header. The stub allocates a page, zeroes it, and assigns only the
 * few fields the boot path needs -- loader type, video mode, cmdline pointer --
 * so every BUILD-TIME field, and the "HdrS" magic itself, stays zero. Those
 * zeroes are indistinguishable from answers to a reader that just takes the
 * byte: relocatable_kernel reads 0, which states that the kernel cannot be
 * relocated, on a machine where the stub relocated it and set the KASLR flag
 * two fields away.
 *
 * The magic separates the two. A header a boot loader copied from the image
 * carries it; a header the stub synthesized never does. Readers of a
 * build-time field gate on this and report "could not ask" without it, which
 * sends the caller to the image, where the field really lives.
 *
 * Readers of a field the stub DOES populate -- the KASLR flag, the cmdline
 * pointer and size -- must not gate on it. Those are valid whichever path
 * booted, and the KASLR flag is valid ONLY here. */
__attribute__((unused)) static unsigned kasld_boot_params_hdr_version(void) {
#if defined(__x86_64__) || defined(__i386__)
  int fd = kasld_open(KASLD_BOOT_PARAMS_PATH, O_RDONLY);
  if (fd < 0)
    return 0;
  unsigned char magic[4] = {0};
  uint16_t version = 0;
  ssize_t nm = pread(fd, magic, 4, KASLD_BOOT_PARAMS_HDR_MAGIC);
  ssize_t nv = pread(fd, &version, 2, KASLD_BOOT_PARAMS_HDR_VERSION);
  close(fd);
  if (nm != 4 || nv != 2)
    return 0;
  if (magic[0] != 'H' || magic[1] != 'd' || magic[2] != 'r' || magic[3] != 'S')
    return 0;
  return (unsigned)version;
#else
  return 0;
#endif
}

/* Exact kernel init_size from x86 boot_params, or 0 if unavailable. */
__attribute__((unused)) static unsigned long kasld_read_boot_init_size(void) {
#if defined(__x86_64__) || defined(__i386__)
  if (kasld_boot_params_hdr_version() < KASLD_BZ_VER_INIT_SIZE)
    return 0;
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
  if (kasld_boot_params_hdr_version() < KASLD_BZ_VER_KERNEL_ALIGN)
    return 0;
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

/* boot_params.hdr.relocatable_kernel: 1 where the kernel was built with
 * CONFIG_RELOCATABLE, 0 where it was not, and -1 where the field could not be
 * read. A kernel built without it decompresses to the address it was compiled
 * for whatever the boot loader chose (arch/x86/Kconfig, PHYSICAL_ALIGN help),
 * so it is not relocated and cannot be randomized -- CONFIG_RANDOMIZE_BASE
 * depends on CONFIG_RELOCATABLE. The caller turns a 0 into the KASLR-off
 * scalars; the tri-state keeps "said no" apart from "could not ask", which a
 * plain int cannot carry. */
__attribute__((unused)) static int kasld_read_boot_relocatable(void) {
#if defined(__x86_64__) || defined(__i386__)
  if (kasld_boot_params_hdr_version() < KASLD_BZ_VER_RELOCATABLE)
    return -1;
  int fd = kasld_open(KASLD_BOOT_PARAMS_PATH, O_RDONLY);
  if (fd < 0)
    return -1;
  uint8_t v = 0;
  ssize_t n = pread(fd, &v, 1, KASLD_BOOT_PARAMS_RELOCATABLE);
  close(fd);
  return (n == 1) ? (v ? 1 : 0) : -1;
#else
  return -1;
#endif
}

/* Did the boot stub randomize the kernel THIS BOOT? 1 yes, 0 no, -1 unreadable.
 *
 * boot_params.hdr.loadflags carries KASLR_FLAG, which the decompressor clears
 * on entry (misc.c) and sets in choose_random_location() -- after that
 * function's early return on a `nokaslr` command line, and from a translation
 * unit the build includes only under CONFIG_RANDOMIZE_BASE. So the bit answers
 * three questions at once: whether randomization happened, whether the option
 * was even compiled in, and hence which KERNEL_IMAGE_SIZE (and therefore which
 * MODULES_VADDR) the kernel is using.
 *
 * READ ONLY FROM /sys/kernel/boot_params/data. The bit is written at RUNTIME
 * into the copy the kernel kept; the same header in /boot/vmlinuz-<release>
 * carries the build-time value, where it is clear on every kernel ever built.
 * Falling back to the image -- as the alignment and relocatable readers above
 * deliberately do, both of those being build-time constants -- would report
 * "KASLR did not run" universally. There is no fallback here, and there must
 * not be one. */
__attribute__((unused)) static int kasld_read_boot_kaslr_randomized(void) {
#if defined(__x86_64__) || defined(__i386__)
  int fd = kasld_open(KASLD_BOOT_PARAMS_PATH, O_RDONLY);
  if (fd < 0)
    return -1;
  uint8_t v = 0;
  ssize_t n = pread(fd, &v, 1, KASLD_BOOT_PARAMS_LOADFLAGS);
  close(fd);
  return (n == 1) ? ((v & KASLD_BOOT_PARAMS_KASLR_FLAG) ? 1 : 0) : -1;
#else
  return -1;
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
