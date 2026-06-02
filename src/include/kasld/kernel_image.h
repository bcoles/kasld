// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Kernel image size estimation, without privileges.
//
// Estimates the in-memory kernel image size (init_size) from the on-disk
// /boot artefacts of the running kernel:
//   - EFI/PE Image header (arm64, riscv64): exact image_size at byte 16.
//   - vmlinuz size (stat): compressed size x a low-end ratio.
//   - System.map size (stat): line count -> text symbols -> init_size.
// Each fallback deliberately *under*estimates, so a ceiling derived from it
// only eliminates positions certainly in the forbidden band.
//
// Read by the ceiling rule. Reads route through the kasld_* wrappers, so it is
// KASLD_SYSROOT-aware (replayable).
// ---
// <bcoles@gmail.com>

#ifndef KASLD_KERNEL_IMAGE_H
#define KASLD_KERNEL_IMAGE_H

#include "sysroot.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/utsname.h>

/* Low-end compression ratio: underestimates kernel_size so that only slots
 * certainly in the forbidden band are eliminated. Typical xz/gzip/lzma
 * ratio for init_size on x86 is 4-5x; using 3.5 stays below that floor. */
#define KASLR_CEILING_RATIO 3.5

/* Parameters for estimating kernel text size from System.map file size.
 * Format: ~43 bytes per line; ~87% of symbols are in the text section;
 * symbol density ~7 symbols/KiB. The multiplier converts text size to
 * init_size (data + bss + decompressor slack). */
#define SMAP_BYTES_PER_LINE 43UL
#define SMAP_TEXT_FRACTION 0.87
#define SMAP_SYMS_PER_KIB 7.0
#define SMAP_INIT_MULTIPLIER 2.0 /* low end of 2.0-2.5 range; underestimate */

/* Minimum plausible file sizes. A real compressed vmlinuz is always several
 * MiB; a real System.map always contains thousands of symbol lines. Reject
 * tiny stub files, placeholder symlinks, and partial downloads that would
 * produce wildly wrong kernel-size estimates. */
#define MIN_VMLINUZ_BYTES (512UL * 1024)
#define MIN_SYSMAP_BYTES (256UL * 1024)

/* Read exact image_size from an EFI/PE-style Image header (riscv64, arm64).
 * The header layout (arch/riscv/include/asm/image.h,
 * arch/arm64/include/asm/image.h) places image_size as a u64 LE field at
 * byte offset 16, preceded by MZ magic at offset 0. Returns 0 on failure. */
__attribute__((unused)) static unsigned long
kasld_image_size_from_header(const char *release) {
  const char *const paths[] = {
      "/boot/Image-%s",
      "/boot/vmlinuz-%s",
      NULL,
  };
  char path[256];
  uint8_t hdr[24];

  for (int i = 0; paths[i] != NULL; i++) {
    snprintf(path, sizeof(path), paths[i], release);
    FILE *fp = kasld_fopen(path, "rb");
    if (!fp)
      continue;
    size_t n = fread(hdr, 1, sizeof(hdr), fp);
    fclose(fp);

    if (n < sizeof(hdr))
      continue;
    if (hdr[0] != 0x4d || hdr[1] != 0x5a)
      continue;

    uint64_t image_size =
        ((uint64_t)hdr[16]) | ((uint64_t)hdr[17] << 8) |
        ((uint64_t)hdr[18] << 16) | ((uint64_t)hdr[19] << 24) |
        ((uint64_t)hdr[20] << 32) | ((uint64_t)hdr[21] << 40) |
        ((uint64_t)hdr[22] << 48) | ((uint64_t)hdr[23] << 56);

    if (image_size < MIN_VMLINUZ_BYTES)
      continue;

    return (unsigned long)image_size;
  }
  return 0;
}

__attribute__((unused)) static unsigned long
kasld_image_size_from_vmlinuz(const char *release) {
  char path[256];
  struct stat st;
  snprintf(path, sizeof(path), "/boot/vmlinuz-%s", release);
  if (kasld_stat(path, &st) != 0)
    return 0;
  if ((unsigned long)st.st_size < MIN_VMLINUZ_BYTES)
    return 0;
  return (unsigned long)((double)st.st_size * KASLR_CEILING_RATIO);
}

__attribute__((unused)) static unsigned long
kasld_image_size_from_sysmap(const char *release) {
  char path[256];
  struct stat st;
  snprintf(path, sizeof(path), "/boot/System.map-%s", release);
  if (kasld_stat(path, &st) != 0)
    return 0;
  if ((unsigned long)st.st_size < MIN_SYSMAP_BYTES)
    return 0;
  unsigned long lines = (unsigned long)st.st_size / SMAP_BYTES_PER_LINE;
  double text_syms = (double)lines * SMAP_TEXT_FRACTION;
  double text_kib = text_syms / SMAP_SYMS_PER_KIB;
  return (unsigned long)(text_kib * 1024.0 * SMAP_INIT_MULTIPLIER);
}

/* Use the most accurate available estimate. Image header gives the exact
 * decompressed size (no ratio needed); vmlinuz and System.map are fallbacks
 * with underestimating ratios to avoid excluding valid positions. The
 * header value is discarded if it falls below either lower bound (a sign of
 * a misidentified file or a non-standard PE layout). Returns 0 on failure. */
__attribute__((unused)) static unsigned long kasld_estimate_kernel_size(void) {
  struct utsname uts;
  if (kasld_uname(&uts) != 0)
    return 0;

  unsigned long from_hdr = kasld_image_size_from_header(uts.release);
  unsigned long vmlinuz = kasld_image_size_from_vmlinuz(uts.release);
  unsigned long sysmap = kasld_image_size_from_sysmap(uts.release);

  /* Discard the header value if it falls below a known lower bound. */
  if (from_hdr > 0 && ((vmlinuz > 0 && from_hdr < vmlinuz) ||
                       (sysmap > 0 && from_hdr < sysmap)))
    from_hdr = 0;

  if (from_hdr)
    return from_hdr;

  if (vmlinuz == 0 && sysmap == 0)
    return 0;
  if (vmlinuz == 0)
    return sysmap;
  if (sysmap == 0)
    return vmlinuz;
  return vmlinuz < sysmap ? vmlinuz : sysmap;
}

#endif /* KASLD_KERNEL_IMAGE_H */
