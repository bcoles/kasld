// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Kernel image size, read from the on-disk /boot artefacts, without privileges.
//
// The size rules need two things about the kernel's in-memory footprint: a
// guaranteed LOWER bound (the ceiling/exclusion rules subtract it from a window
// top, so an over-estimate would wrongly exclude a valid high base) and, for
// the image-base floor rule, a value that is at least the footprint. These
// readers return REAL values parsed from the running kernel's image, never a
// guess:
//
//   - EFI/PE Image header (arm64, riscv64): exact image_size (_end - _text).
//   - x86 bzImage setup header: exact init_size (no privilege; not
//   boot_params).
//   - ELF vmlinux (ppc, mips, ...): exact PT_LOAD span (_end - _text).
//   - System.map (any arch): exact _end - _text from the symbol addresses.
//   - gzip stream, whole-file or EFI-zboot inner (arm64, loongarch64): the
//     ISIZE trailer = decompressed size (_edata - _text). This EXCLUDES BSS, so
//     it is a sound lower bound only, not a footprint upper bound.
//   - vmlinuz file size (any compressed, non-ELF image): the image never
//     decompresses to fewer bytes than its on-disk size, so the file size is a
//     sound (loose) lower bound. A last-resort fallback, e.g. for arm32/s390
//     whose vmlinuz exposes no size field; vmlinuz is world-readable where
//     System.map usually is not.
//
// The first four are exact and serve both directions; the component emits them
// as both SF_IMAGE_SIZE_MIN and SF_IMAGE_SIZE_MAX. The gzip and file-size
// readers are lower-bound-only, emitted as SF_IMAGE_SIZE_MIN. The file size is
// used at ratio 1.0 only (a sound
// lower bound) -- there is deliberately no ratio ABOVE 1.0, which would
// over-estimate the footprint and be unsound for the ceiling. ELF vmlinux is
// excluded from the file-size bound: its on-disk symbol/section data is not
// loaded, so the file can be larger than the footprint (ppc/mips are read
// exactly by from_elf first). Where no artefact is readable, no size fact is
// emitted and the rules fall back to their own conservative MIN_IMAGE_SIZE.
//
// Reads route through the kasld_* wrappers, so this is KASLD_SYSROOT-aware.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_KERNEL_IMAGE_H
#define KASLD_KERNEL_IMAGE_H

#include "sysroot.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>

/* Minimum plausible kernel image size. A real kernel is always several MiB; a
 * read below this from any source signals a truncated file, a stub symlink, or
 * a misparse, so it is discarded rather than fed to the size rules. */
#define KIMG_MIN_BYTES (512UL * 1024)

/* Read exact image_size from a Linux EFI/PE Image header (arm64, riscv64).
 * The header (arch/arm64/include/asm/image.h, arch/riscv/include/asm/image.h)
 * places image_size as a u64 LE field at byte offset 16, with "MZ" at offset 0
 * and an arch magic at offset 56 ("ARM\x64" / "RSC\x05"). An x86 bzImage also
 * starts with "MZ" but has a different layout, so the offset-56 magic is
 * required before trusting offset 16. image_size is _end - _text (includes
 * BSS): the exact footprint. Returns 0 on failure. */
__attribute__((unused)) static unsigned long
kasld_image_size_from_header(const char *release) {
  const char *const paths[] = {
      "/boot/Image-%s",
      "/boot/vmlinuz-%s",
      NULL,
  };
  char path[256];
  uint8_t hdr[60];

  for (int i = 0; paths[i] != NULL; i++) {
    snprintf(path, sizeof(path), paths[i], release);
    FILE *fp = kasld_fopen(path, "rb");
    if (!fp)
      continue;
    size_t n = fread(hdr, 1, sizeof(hdr), fp);
    fclose(fp);

    if (n < sizeof(hdr))
      continue;
    if (hdr[0] != 0x4d || hdr[1] != 0x5a) /* "MZ" */
      continue;

    /* Require a Linux Image magic at offset 56 (arm64 "ARM\x64" = 0x644d5241,
     * riscv "RSC\x05" = 0x05435352). An x86 bzImage carries "MZ" too, but its
     * offset-16 bytes are not image_size; the magic gate rejects it so the
     * caller falls back to the other readers. */
    uint32_t magic = (uint32_t)hdr[56] | ((uint32_t)hdr[57] << 8) |
                     ((uint32_t)hdr[58] << 16) | ((uint32_t)hdr[59] << 24);
    if (magic != 0x644d5241u && magic != 0x05435352u)
      continue;

    uint64_t image_size =
        ((uint64_t)hdr[16]) | ((uint64_t)hdr[17] << 8) |
        ((uint64_t)hdr[18] << 16) | ((uint64_t)hdr[19] << 24) |
        ((uint64_t)hdr[20] << 32) | ((uint64_t)hdr[21] << 40) |
        ((uint64_t)hdr[22] << 48) | ((uint64_t)hdr[23] << 56);

    if (image_size < KIMG_MIN_BYTES)
      continue;

    return (unsigned long)image_size;
  }
  return 0;
}

/* Exact x86 image size from the bzImage setup header in
 * /boot/vmlinuz-<release>. The setup header carries "HdrS" at offset 0x202 and,
 * since boot protocol 2.10, a u32 LE init_size at offset 0x260 — the exact
 * footprint the boot loader reserves (the same value boot_params exposes),
 * readable from the public vmlinuz with no privilege. The "HdrS" gate rejects
 * other arches' MZ images. Returns 0 if not a bzImage or the field predates
 * protocol 2.10. */
__attribute__((unused)) static unsigned long
kasld_image_size_from_bzimage(const char *release) {
  char path[256];
  uint8_t b[0x264];
  snprintf(path, sizeof(path), "/boot/vmlinuz-%s", release);
  FILE *fp = kasld_fopen(path, "rb");
  if (!fp)
    return 0;
  size_t n = fread(b, 1, sizeof(b), fp);
  fclose(fp);

  if (n < sizeof(b))
    return 0;
  if (b[0x202] != 'H' || b[0x203] != 'd' || b[0x204] != 'r' || b[0x205] != 'S')
    return 0;
  unsigned version = (unsigned)b[0x206] | ((unsigned)b[0x207] << 8);
  if (version < 0x020a) /* init_size was added in boot protocol 2.10 */
    return 0;
  unsigned long init_size =
      (unsigned long)b[0x260] | ((unsigned long)b[0x261] << 8) |
      ((unsigned long)b[0x262] << 16) | ((unsigned long)b[0x263] << 24);
  return init_size >= KIMG_MIN_BYTES ? init_size : 0;
}

/* Read an n-byte (n <= 8) unsigned integer from b, little- or big-endian.
 * Accumulates in 64 bits so an ELF64 field is read correctly even by a 32-bit
 * build; callers that keep only a difference stay exact after truncation. */
__attribute__((unused)) static uint64_t kasld_rd_uint(const uint8_t *b, int n,
                                                      int be) {
  uint64_t v = 0;
  for (int i = 0; i < n; i++)
    v |= (uint64_t)b[be ? (n - 1 - i) : i] << (8 * i);
  return v;
}

/* Exact in-memory image size from an ELF vmlinux at /boot/vmlinuz-<release>
 * (ppc, mips, and any arch whose vmlinuz is an uncompressed ELF): the span
 * max(p_vaddr + p_memsz) - min(p_vaddr) over PT_LOAD segments. p_memsz includes
 * BSS, so the span is _end - _text — the exact footprint, sound in both
 * directions. Handles ELFCLASS32/64 and either byte order (the vmlinux matches
 * the running kernel's arch). Returns 0 if not an ELF or it has no PT_LOAD. */
__attribute__((unused)) static unsigned long
kasld_image_size_from_elf(const char *release) {
  char path[256];
  uint8_t e[64];
  snprintf(path, sizeof(path), "/boot/vmlinuz-%s", release);
  FILE *fp = kasld_fopen(path, "rb");
  if (!fp)
    return 0;
  size_t n = fread(e, 1, sizeof(e), fp);
  if (n < 52 || e[0] != 0x7f || e[1] != 'E' || e[2] != 'L' || e[3] != 'F') {
    fclose(fp);
    return 0;
  }
  int is64 = (e[4] == 2); /* EI_CLASS: 1=32-bit, 2=64-bit */
  int be = (e[5] == 2);   /* EI_DATA:  1=LE,     2=BE     */

  uint64_t phoff;
  unsigned phentsize, phnum;
  int vaddr_off, memsz_off, fldw, phmin;
  if (is64) {
    phoff = kasld_rd_uint(e + 32, 8, be);
    phentsize = (unsigned)kasld_rd_uint(e + 54, 2, be);
    phnum = (unsigned)kasld_rd_uint(e + 56, 2, be);
    vaddr_off = 16;
    memsz_off = 40;
    fldw = 8;
    phmin = 56;
  } else {
    phoff = kasld_rd_uint(e + 28, 4, be);
    phentsize = (unsigned)kasld_rd_uint(e + 42, 2, be);
    phnum = (unsigned)kasld_rd_uint(e + 44, 2, be);
    vaddr_off = 8;
    memsz_off = 20;
    fldw = 4;
    phmin = 32;
  }
  /* Bound the table so a corrupt header cannot drive a huge loop. */
  if (phoff == 0 || phentsize < (unsigned)phmin || phnum == 0 || phnum > 256) {
    fclose(fp);
    return 0;
  }

  uint64_t lo = UINT64_MAX, hi = 0;
  uint8_t ph[64];
  for (unsigned i = 0; i < phnum; i++) {
    if (fseek(fp, (long)(phoff + (uint64_t)i * phentsize), SEEK_SET) != 0)
      break;
    size_t want = phentsize < sizeof(ph) ? phentsize : sizeof(ph);
    if (fread(ph, 1, want, fp) < (size_t)(memsz_off + fldw))
      break;
    if (kasld_rd_uint(ph, 4, be) != 1) /* PT_LOAD */
      continue;
    uint64_t vaddr = kasld_rd_uint(ph + vaddr_off, fldw, be);
    uint64_t memsz = kasld_rd_uint(ph + memsz_off, fldw, be);
    if (memsz == 0)
      continue;
    if (vaddr < lo)
      lo = vaddr;
    if (vaddr + memsz > hi)
      hi = vaddr + memsz;
  }
  fclose(fp);
  if (lo == UINT64_MAX || hi <= lo)
    return 0;
  uint64_t span = hi - lo;
  return span >= KIMG_MIN_BYTES ? (unsigned long)span : 0;
}

/* Exact image size from /boot/System.map-<release>: address(_end) -
 * address(_text), or _stext if _text is absent. System.map lists every symbol
 * at its link-time virtual address; _end - _text spans the whole image
 * including BSS — the exact footprint, invariant under KASLR (it is a size).
 * Returns 0 if unreadable or the bracketing symbols are not found. */
__attribute__((unused)) static unsigned long
kasld_image_size_from_sysmap(const char *release) {
  char path[256];
  snprintf(path, sizeof(path), "/boot/System.map-%s", release);
  FILE *fp = kasld_fopen(path, "rb");
  if (!fp)
    return 0;

  /* 64-bit accumulators: a 32-bit build reading a 64-bit kernel's map must not
   * truncate the addresses; only the final span (always < 4 GiB) is narrowed.
   */
  unsigned long long text = 0, stext = 0, end = 0;
  char line[256];
  while (fgets(line, sizeof(line), fp)) {
    /* Each line is "<hex-addr> <type> <name>". */
    char *type = strchr(line, ' ');
    if (!type || type == line)
      continue;
    char *name = strchr(type + 1, ' ');
    if (!name)
      continue;
    name++;
    char *nl = strpbrk(name, " \t\r\n");
    if (nl)
      *nl = '\0';
    unsigned long long addr = strtoull(line, NULL, 16);
    if (addr == 0)
      continue;
    if (strcmp(name, "_text") == 0)
      text = addr;
    else if (strcmp(name, "_stext") == 0)
      stext = addr;
    else if (strcmp(name, "_end") == 0)
      end = addr;
  }
  fclose(fp);

  unsigned long long base = text ? text : stext;
  if (base == 0 || end <= base)
    return 0;
  unsigned long long span = end - base;
  if (span < KIMG_MIN_BYTES || span > (unsigned long long)ULONG_MAX)
    return 0;
  return (unsigned long)span;
}

/* Read the 32-bit little-endian gzip ISIZE trailer (uncompressed length mod
 * 2^32) of the gzip stream whose last byte is at file offset stream_end. A
 * kernel is far below 4 GiB, so the modulo is exact. Returns 0 on a bad read.
 */
__attribute__((unused)) static unsigned long kasld_gzip_isize(FILE *fp,
                                                              long stream_end) {
  uint8_t t[4];
  if (stream_end < 4 || fseek(fp, stream_end - 4, SEEK_SET) != 0)
    return 0;
  if (fread(t, 1, 4, fp) != 4)
    return 0;
  return (unsigned long)t[0] | ((unsigned long)t[1] << 8) |
         ((unsigned long)t[2] << 16) | ((unsigned long)t[3] << 24);
}

/* Decompressed kernel image size from a gzip stream on disk, via its ISIZE
 * trailer (no actual decompression). Two layouts are handled:
 *   - a whole-file gzip vmlinuz (magic 1f 8b 08 at offset 0): ISIZE is the
 *     last 4 bytes of the file.
 *   - an EFI zboot image ("MZ" at 0, "zimg" at 4) whose inner payload is gzip
 *     ("gzip" at offset 24): payload_offset is a u32 LE at 8, payload_size a
 *     u32 LE at 12, and ISIZE the last 4 bytes of that inner stream.
 * The result is _edata - _text: it EXCLUDES BSS, so it is a sound LOWER bound
 * on the footprint but not an upper bound. Returns 0 if no gzip stream is
 * found. */
__attribute__((unused)) static unsigned long
kasld_image_size_from_gzip(const char *release) {
  const char *const paths[] = {"/boot/vmlinuz-%s", "/boot/Image-%s", NULL};
  char path[256];
  uint8_t hdr[28];

  for (int i = 0; paths[i] != NULL; i++) {
    snprintf(path, sizeof(path), paths[i], release);
    FILE *fp = kasld_fopen(path, "rb");
    if (!fp)
      continue;
    size_t n = fread(hdr, 1, sizeof(hdr), fp);
    unsigned long isize = 0;

    if (n >= 3 && hdr[0] == 0x1f && hdr[1] == 0x8b && hdr[2] == 0x08) {
      /* Whole-file gzip: ISIZE is the final 4 bytes. */
      if (fseek(fp, 0, SEEK_END) == 0)
        isize = kasld_gzip_isize(fp, ftell(fp));
    } else if (n >= sizeof(hdr) && hdr[0] == 0x4d &&
               hdr[1] == 0x5a && /* "MZ" */
               hdr[4] == 'z' && hdr[5] == 'i' && hdr[6] == 'm' &&
               hdr[7] == 'g' && /* "zimg" */
               hdr[24] == 'g' && hdr[25] == 'z' && hdr[26] == 'i' &&
               hdr[27] == 'p') { /* "gzip" */
      unsigned long poff =
          (unsigned long)hdr[8] | ((unsigned long)hdr[9] << 8) |
          ((unsigned long)hdr[10] << 16) | ((unsigned long)hdr[11] << 24);
      unsigned long psz =
          (unsigned long)hdr[12] | ((unsigned long)hdr[13] << 8) |
          ((unsigned long)hdr[14] << 16) | ((unsigned long)hdr[15] << 24);
      if (poff > 0 && psz > 4)
        isize = kasld_gzip_isize(fp, (long)(poff + psz));
    }
    fclose(fp);
    if (isize >= KIMG_MIN_BYTES)
      return isize;
  }
  return 0;
}

/* A sound (loose) LOWER bound on the footprint from the vmlinuz file size: a
 * compressed image never decompresses to fewer bytes than its on-disk size, and
 * the loader reserves at least the decompressed image, so file_size <=
 * decompressed <= footprint. Emitted as SF_IMAGE_SIZE_MIN (lower bound only). A
 * last resort, used after the exact readers and the tighter gzip ISIZE.
 *
 * ELF vmlinux is rejected: an ELF file carries symbol/section data that is NOT
 * loaded, so its on-disk size can EXCEED the footprint and is not a lower bound
 * (ppc/mips are read exactly by kasld_image_size_from_elf first). Returns 0 on
 * an unreadable file, an ELF, or a size below the plausibility floor. */
__attribute__((unused)) static unsigned long
kasld_image_size_from_vmlinuz(const char *release) {
  char path[256];
  uint8_t magic[4];
  snprintf(path, sizeof(path), "/boot/vmlinuz-%s", release);
  FILE *fp = kasld_fopen(path, "rb");
  if (!fp)
    return 0;
  size_t n = fread(magic, 1, sizeof(magic), fp);
  long sz = (fseek(fp, 0, SEEK_END) == 0) ? ftell(fp) : -1;
  fclose(fp);

  if (n == sizeof(magic) && magic[0] == 0x7f && magic[1] == 'E' &&
      magic[2] == 'L' && magic[3] == 'F')
    return 0; /* ELF on-disk size is not a footprint lower bound */
  if (sz < (long)KIMG_MIN_BYTES)
    return 0;
  return (unsigned long)sz;
}

#endif /* KASLD_KERNEL_IMAGE_H */
