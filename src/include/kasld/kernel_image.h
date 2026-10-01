// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Kernel image size, read from whatever the vantage exposes, without
// privileges.
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
//   - ELF vmlinux (ppc, mips, ...): _end - _text from its own symbol table.
//     Exact where both of those symbols are present, a lower bound otherwise.
//   - System.map (any arch): the same pair, read from the map instead.
//   - whole-file gzip vmlinuz: the ISIZE trailer = decompressed size
//     (_edata - _text). This EXCLUDES BSS, so it is a sound lower bound only,
//     not a footprint upper bound.
//   - EFI zboot container (arm64, riscv64, loongarch64): the exact footprint
//     its payload declares, read by the component, which corroborates it
//     against the container's own length word before using either.
//   - .BTF section length (/sys/kernel/btf/vmlinux): a section inside the
//     image, so its length is a sound lower bound. The weakest of the readers
//     and the only one needing neither /boot nor dmesg nor a relaxed sysctl.
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

/* api.h for the arch axes read below (BOOT_IMAGE_SIZE_FLOORS_FOOTPRINT), so
 * this header stands on its own: tests/test_kernel_image.c includes it directly
 * and would otherwise see the axis undefined and silently take the wrong
 * branch. */
#include "api.h"
#include "sysroot.h"

#include <errno.h>
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

/* Maximum plausible kernel image size. x86_64 caps the kernel image's highest
 * virtual address at 1 GiB above its mapping when KASLR is configured and at
 * 512 MiB when it is not, and x86_32 at 512 MiB (KERNEL_IMAGE_SIZE, which
 * bounds the image's end rather than its size, and which
 * arch/x86/kernel/vmlinux.lds.S asserts at link time), so no x86 image reaches
 * this. The band exists to reject a misread field, and a value outside it is
 * dropped rather than clamped: a kernel larger than this would lose its size
 * fact, never gain a wrong one. Read values are bounded by it before reaching
 * the size rules, since the floor rule subtracts the upper bound from an
 * observed address and an unbounded value read from a file would wrap that
 * subtraction on a 32-bit target. */
#define KIMG_MAX_BYTES (1024UL * 1024 * 1024)

/* Ceiling on an ELF string table read into memory while resolving the boundary
 * symbols. A kernel's runs to a few MiB; this caps what a corrupt sh_size can
 * ask for. */
#define KIMG_STRTAB_MAX (32UL * 1024 * 1024)

/* `v` if it is a plausible kernel footprint, else 0. Every reader here returns
 * through this, so the band is stated once and no source can put a figure
 * outside it in front of the size rules. Both ends matter and for opposite
 * reasons: the ceiling rules subtract the lower bound from a window top, so a
 * figure too LARGE wrongly excludes a valid high base, while the image-base
 * floor rule subtracts the upper bound from an observed address, so one too
 * SMALL puts the floor above the true base. A field read from a corrupted or
 * unfamiliar artefact lands outside the band long before it lands inside it. */
__attribute__((unused)) static unsigned long
kasld_image_size_plausible(unsigned long long v) {
  if (v < KIMG_MIN_BYTES || v > KIMG_MAX_BYTES)
    return 0;
  return (unsigned long)v;
}

/* Which end of the footprint a reader's answer proves.
 *
 * The evidence layer takes the MAX over lower bounds and the MIN over upper
 * bounds, so a figure offered as the end it does not prove displaces the exact
 * facts rather than merely widening the window -- in whichever direction it is
 * wrong. Each reader therefore states the end it bounds, because what a field
 * means is the reader's knowledge and not the caller's.
 *
 * Three values and not a flag because all three occur. x86's bzImage init_size
 * is at or above the footprint and never below it (arch/x86/boot/header.S takes
 * the greater of the image and the decompressor's workspace), so it bounds the
 * image-base floor alone; a span resting on a partial symbol pair is at or
 * below, so it bounds the ceiling alone; only a declared _end - _text is both.
 */
enum kasld_image_bound {
  KIMG_BOUND_NONE = 0, /* no answer */
  KIMG_BOUND_EXACT,    /* the footprint itself: bounds both ends */
  KIMG_BOUND_LOWER,    /* at or below it: the ceiling side only (MIN) */
  KIMG_BOUND_UPPER, /* at or above it: the image-base floor side only (MAX) */
};

/* Record `kind` for `v` and return it, so a reader classifies its own answer at
 * the point of return. A zero value records no bound whatever `kind` says. */
__attribute__((unused)) static unsigned long
kasld_image_bounded(unsigned long v, enum kasld_image_bound kind,
                    enum kasld_image_bound *out) {
  if (out)
    *out = v ? kind : KIMG_BOUND_NONE;
  return v;
}

/* Little-endian field reads over a caller-bounded buffer. Every image header
 * read here is little-endian regardless of the target's own byte order, so the
 * assembly is explicit rather than a cast through a struct. The caller checks
 * the buffer length; these do not. */
__attribute__((unused)) static uint32_t kasld_rd_le32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

__attribute__((unused)) static uint32_t kasld_rd_be32(const uint8_t *p) {
  return (uint32_t)p[3] | ((uint32_t)p[2] << 8) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[0] << 24);
}

__attribute__((unused)) static uint64_t kasld_rd_le64(const uint8_t *p) {
  return (uint64_t)kasld_rd_le32(p) | ((uint64_t)kasld_rd_le32(p + 4) << 32);
}

/* Linux image magics at byte offset 56. The first two name one architecture
 * each; LINUX_PE_MAGIC (include/linux/pe.h) marks any EFI-bootable Linux image,
 * including an x86 bzImage and an EFI zboot container, so it does NOT identify
 * the layout and is accepted only where the caller has already established one
 * (see kasld_image_extent_from_prefix). */
#define KIMG_MAGIC_ARM64 0x644d5241u /* "ARM\x64" */
#define KIMG_MAGIC_RISCV 0x05435352u /* "RSC\x05" */
#define KIMG_MAGIC_LINUX_PE 0x818223cdu

/* The exact in-memory extent (_end - _text, BSS included) declared in the first
 * 64 bytes of a decompressed kernel image, or 0 when the prefix declares none.
 *
 * arm64 and riscv64 place image_size as a u64 LE at offset 16 behind their own
 * magic at offset 56 (arch/arm64/include/asm/image.h,
 * arch/riscv/include/asm/image.h). loongarch64 places _kernel_asize in the same
 * slot (arch/loongarch/kernel/head.S), defined as _end - _text in
 * arch/loongarch/kernel/vmlinux.lds.S, but carries only LINUX_PE_MAGIC at
 * offset 56 -- which an x86 bzImage carries too, over unrelated bytes at offset
 * 16. `established` therefore gates that magic: it is set only for a payload
 * taken out of an EFI zboot container, which exists for arm64, riscv and
 * loongarch alone, so no x86 image can reach the offset-16 read through it. */
__attribute__((unused)) static unsigned long
kasld_image_extent_from_prefix(const uint8_t *p, size_t n, int established) {
  /* 60 bytes: the magic is the last field read, at offsets 56-59. */
  if (n < 60)
    return 0;

  uint32_t magic = kasld_rd_le32(p + 56);
  if (magic != KIMG_MAGIC_ARM64 && magic != KIMG_MAGIC_RISCV &&
      !(established && magic == KIMG_MAGIC_LINUX_PE))
    return 0;

  uint64_t extent = kasld_rd_le64(p + 16);
  return kasld_image_size_plausible(extent);
}

/* Read exact image_size from a Linux EFI/PE Image header (arm64, riscv64).
 * The header (arch/arm64/include/asm/image.h, arch/riscv/include/asm/image.h)
 * places image_size as a u64 LE field at byte offset 16, with "MZ" at offset 0
 * and an arch magic at offset 56 ("ARM\x64" / "RSC\x05"). An x86 bzImage also
 * starts with "MZ" but has a different layout, so the offset-56 magic is
 * required before trusting offset 16. image_size is _end - _text (includes
 * BSS): the exact footprint. Returns 0 on failure. */
__attribute__((unused)) static unsigned long
kasld_image_size_from_header(const char *release,
                             enum kasld_image_bound *bound) {
  if (bound)
    *bound = KIMG_BOUND_NONE;

  /* Prefixes rather than formats: a format reaching snprintf through an array
   * cannot be checked against its argument, while one literal with the varying
   * part passed as an argument is checked in full. */
  static const char *const prefix[] = {"/boot/Image-", "/boot/vmlinuz-"};
  char path[256];
  uint8_t hdr[64];

  for (unsigned i = 0; i < sizeof(prefix) / sizeof(prefix[0]); i++) {
    snprintf(path, sizeof(path), "%s%s", prefix[i], release);
    FILE *fp = kasld_fopen(path, "rb");
    if (!fp)
      continue;
    size_t n = fread(hdr, 1, sizeof(hdr), fp);
    fclose(fp);

    if (n < 2 || hdr[0] != 0x4d || hdr[1] != 0x5a) /* "MZ" */
      continue;

    /* A bare file, so the layout is not established from anything else: only
     * the two arch magics are accepted. An x86 bzImage carries "MZ" and
     * LINUX_PE_MAGIC but not these, so it falls through to the other readers
     * rather than having its offset-16 bytes read as a size. */
    unsigned long image_size = kasld_image_extent_from_prefix(hdr, n, 0);
    if (image_size)
      return kasld_image_bounded(image_size, KIMG_BOUND_EXACT, bound);
  }
  return 0;
}

/* The x86 bzImage setup header, read from /boot/vmlinuz-<release>.
 *
 * boot_params IS this header: the kernel copies it into the structure sysfs
 * publishes at /sys/kernel/boot_params/data, field for field at the same
 * offsets. So the image on disk answers the same questions as that file, and
 * answers them where it is unreadable or absent -- which is not the same
 * vantage in either direction, since the two carry different permissions and
 * distros disagree about both.
 *
 * Fields taken, all gated on "HdrS" at 0x202 (which rejects other arches' MZ
 * images):
 *   init_size (0x260, u32 LE, boot protocol 2.10) -- the exact in-memory
 *     footprint the boot loader reserves.
 *   kernel_alignment (0x230, u32 LE) -- CONFIG_PHYSICAL_ALIGN, the KASLR slot
 *     granularity itself.
 *   relocatable_kernel (0x234, u8) -- 0 for a kernel built without
 *     CONFIG_RELOCATABLE, which decompresses to the address it was compiled
 *     for whatever the boot loader chose, and therefore cannot be randomized.
 *
 * Each field is populated only from the boot protocol version that introduced
 * it. Below that version the offset is not the field: it holds real-mode setup
 * code, and reading it yields whatever instruction byte happens to sit there.
 * The versions are per field and are named individually below, so a field added
 * here later cannot silently inherit a neighbour's gate -- which is how
 * relocatable_kernel came to be read unconditionally beside a gated init_size.
 *
 * Each output pointer may be NULL. Returns 1 if the header was read and passed
 * its gates, 0 otherwise. A field the protocol does not carry is reported as
 * unknown, which for the tri-state relocatable is -1 and NOT 0 -- a zero there
 * means "this kernel cannot be relocated", which the caller turns into a
 * KASLR-off pin. */
/* Documentation/arch/x86/boot.rst, "The Real-Mode Kernel Header": the version
 * column beside each offset. */
#define KASLD_BZ_VER_KERNEL_ALIGN 0x0205u /* 0230/4 */
#define KASLD_BZ_VER_RELOCATABLE 0x0205u  /* 0234/1 */
#define KASLD_BZ_VER_INIT_SIZE 0x020au    /* 0260/4 */
__attribute__((unused)) static int
kasld_read_bzimage_hdr(const char *release, unsigned long *init_size,
                       unsigned long *kernel_align, int *relocatable) {
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

  if (init_size)
    *init_size =
        version < KASLD_BZ_VER_INIT_SIZE
            ? 0
            : ((unsigned long)b[0x260] | ((unsigned long)b[0x261] << 8) |
               ((unsigned long)b[0x262] << 16) |
               ((unsigned long)b[0x263] << 24));
  if (kernel_align)
    *kernel_align =
        version < KASLD_BZ_VER_KERNEL_ALIGN
            ? 0
            : ((unsigned long)b[0x230] | ((unsigned long)b[0x231] << 8) |
               ((unsigned long)b[0x232] << 16) |
               ((unsigned long)b[0x233] << 24));
  if (relocatable)
    *relocatable = version < KASLD_BZ_VER_RELOCATABLE ? -1 : (b[0x234] ? 1 : 0);
  return 1;
}

/* The x86 bzImage setup header's init_size, an UPPER bound on the footprint.
 *
 * arch/x86/boot/header.S defines INIT_SIZE as the greater of VO_INIT_SIZE
 * (VO__end - VO__text, the footprint itself) and ZO_INIT_SIZE (the compressed
 * image plus the space its decompressor needs to run), so it is at or above the
 * footprint and never below it. Documentation/arch/x86/boot.rst says the same
 * in words: the field is "not the same thing as the total amount of memory the
 * kernel needs to boot". On 64-bit builds the decompressor's figure wins, and
 * the field then exceeds _end - _text by several per cent; on 32-bit the two
 * are commonly equal, which is why reading it as the footprint looks right
 * there. It therefore bounds the image-base floor and must not be offered as
 * the ceiling's lower bound.
 *
 * Read from /boot/vmlinuz-<release> rather than boot_params, so no privilege is
 * needed. Returns 0 on failure. */
__attribute__((unused)) static unsigned long
kasld_image_size_from_bzimage(const char *release,
                              enum kasld_image_bound *bound) {
  if (bound)
    *bound = KIMG_BOUND_NONE;

  unsigned long init_size = 0;
  if (!kasld_read_bzimage_hdr(release, &init_size, NULL, NULL))
    return 0;
  return kasld_image_bounded(kasld_image_size_plausible(init_size),
                             KIMG_BOUND_UPPER, bound);
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

/* The image footprint spanned by the outermost boundary symbols in hand, and
 * through *bound which end of it that span proves.
 *
 * Any pair with _text <= lo and hi <= _end satisfies hi - lo <= _end - _text,
 * so a partial pair bounds the footprint from BELOW: _stext sits above _text by
 * a head gap (0x400 on mips, 0xf8000 on arm32) and _etext below _end by the
 * whole of data and BSS. Only _text with _end gives the footprint ITSELF, which
 * is what an upper bound requires -- it must be a value no in-image address can
 * exceed, and every arch linker script places _end after BSS, so nothing in
 * text, data or BSS lies above it. A span built from a partial pair understates
 * and is a lower bound alone.
 *
 * Returns 0 when no usable pair is present. *bound may be NULL. */
__attribute__((unused)) static unsigned long
kasld_image_span_from_edges(unsigned long long text, unsigned long long stext,
                            unsigned long long etext, unsigned long long end,
                            enum kasld_image_bound *bound) {
  unsigned long long lo = text ? text : stext;
  unsigned long long hi = end ? end : etext;

  if (bound)
    *bound = KIMG_BOUND_NONE;
  if (!lo || !hi || hi <= lo)
    return 0;

  return kasld_image_bounded(
      kasld_image_size_plausible(hi - lo),
      (text != 0 && end != 0) ? KIMG_BOUND_EXACT : KIMG_BOUND_LOWER, bound);
}

/* The in-memory image size from an ELF vmlinux at /boot/vmlinuz-<release> (ppc,
 * mips, and any arch whose vmlinuz is an uncompressed ELF), read from the
 * boundary symbols in its own symbol table, with *bound as
 * kasld_image_span_from_edges describes it.
 *
 * NOT the PT_LOAD span: segment geometry does not give this footprint in either
 * direction. A segment's p_memsz stops at the last section it carries, while
 * _end is aligned above that -- short by 0x164 to 0xee28 across the ppc images
 * measured -- and a segment can also reach PAST _end, as a relocatable ppc32
 * kernel's does by 0x2d950, because p_filesz there spans the appended
 * relocation data. The span happens to equal _end - _text on mips and on
 * neither ppc32 nor ppc64.
 *
 * Handles ELFCLASS32/64 and either byte order (the vmlinux matches the running
 * kernel's arch). Returns 0 when the file is not an ELF or carries no symbol
 * table: a stripped vmlinux yields no size fact rather than one derived from
 * the segments. */
__attribute__((unused)) static unsigned long
kasld_image_size_from_elf(const char *release, enum kasld_image_bound *bound) {
  static const char *const want[] = {"_text", "_stext", "_etext", "_end"};
  enum { WANTN = 4 };
  unsigned long long addr[WANTN] = {0, 0, 0, 0};

  char path[256];
  uint8_t e[64];

  if (bound)
    *bound = KIMG_BOUND_NONE;

  snprintf(path, sizeof(path), "/boot/vmlinuz-%s", release);
  FILE *fp = kasld_fopen(path, "rb");
  if (!fp)
    return 0;
  size_t n = fread(e, 1, sizeof(e), fp);
  if (n < 6 || e[0] != 0x7f || e[1] != 'E' || e[2] != 'L' || e[3] != 'F') {
    fclose(fp);
    return 0;
  }
  int is64 = (e[4] == 2); /* EI_CLASS: 1=32-bit, 2=64-bit */
  int be = (e[5] == 2);   /* EI_DATA:  1=LE,     2=BE     */

  /* The whole header, per class: 64 bytes for ELF64 and 52 for ELF32. Every
   * field below is read from within it, so a file too short to hold one is
   * refused before any of them -- a shorter read leaves the tail of this buffer
   * holding whatever the stack held, and the section-table bounds would then be
   * decided by it. */
  if (n < (size_t)(is64 ? 64 : 52)) {
    fclose(fp);
    return 0;
  }

  /* Section header table, and the per-class field offsets within an entry. */
  uint64_t shoff;
  unsigned shentsize, shnum;
  int sh_type_off = 4, sh_size_off, sh_link_off, sh_offset_off, shmin;
  int sym_name_off = 0, sym_value_off, symsz;
  if (is64) {
    shoff = kasld_rd_uint(e + 40, 8, be);
    shentsize = (unsigned)kasld_rd_uint(e + 58, 2, be);
    shnum = (unsigned)kasld_rd_uint(e + 60, 2, be);
    sh_offset_off = 24;
    sh_size_off = 32;
    sh_link_off = 40;
    shmin = 64;
    sym_value_off = 8;
    symsz = 24;
  } else {
    shoff = kasld_rd_uint(e + 32, 4, be);
    shentsize = (unsigned)kasld_rd_uint(e + 46, 2, be);
    shnum = (unsigned)kasld_rd_uint(e + 48, 2, be);
    sh_offset_off = 16;
    sh_size_off = 20;
    sh_link_off = 24;
    shmin = 40;
    sym_value_off = 4;
    symsz = 16;
  }
  /* Bound the table so a corrupt header cannot drive a huge loop. SHN_LORESERVE
   * is the ceiling on a real section count. */
  if (shoff == 0 || shentsize < (unsigned)shmin || shnum == 0 ||
      shnum >= 0xff00u) {
    fclose(fp);
    return 0;
  }

  /* SHT_SYMTAB (2) and the string table it names through sh_link. */
  uint64_t symoff = 0, symsize = 0, stroff = 0, strsize = 0;
  uint8_t sh[64];
  unsigned strndx = 0;
  for (unsigned i = 0; i < shnum; i++) {
    if (fseek(fp, (long)(shoff + (uint64_t)i * shentsize), SEEK_SET) != 0)
      break;
    size_t wsz = shentsize < sizeof(sh) ? shentsize : sizeof(sh);
    if (fread(sh, 1, wsz, fp) < (size_t)shmin)
      break;
    if (kasld_rd_uint(sh + sh_type_off, 4, be) != 2) /* SHT_SYMTAB */
      continue;
    symoff = kasld_rd_uint(sh + sh_offset_off, is64 ? 8 : 4, be);
    symsize = kasld_rd_uint(sh + sh_size_off, is64 ? 8 : 4, be);
    strndx = (unsigned)kasld_rd_uint(sh + sh_link_off, 4, be);
    break;
  }
  if (symoff == 0 || symsize < (uint64_t)symsz || strndx == 0 ||
      strndx >= shnum) {
    fclose(fp);
    return 0;
  }
  if (fseek(fp, (long)(shoff + (uint64_t)strndx * shentsize), SEEK_SET) != 0 ||
      fread(sh, 1, (size_t)shmin, fp) < (size_t)shmin) {
    fclose(fp);
    return 0;
  }
  stroff = kasld_rd_uint(sh + sh_offset_off, is64 ? 8 : 4, be);
  strsize = kasld_rd_uint(sh + sh_size_off, is64 ? 8 : 4, be);
  if (stroff == 0 || strsize < 2) {
    fclose(fp);
    return 0;
  }

  /* The string table, read once. st_name is an offset into it, and the
   * boundary symbols are TAIL-MERGED by the linker: _text and _end are stored
   * as the suffix of a longer symbol's name, so neither is preceded by a NUL
   * and neither can be found by scanning for NUL-delimited strings -- that
   * finds only _stext and _etext, the pair that gives a lower bound alone.
   * Resolving each symbol's own name is the only correct reading. Bounded so a
   * corrupt sh_size cannot ask for an unreasonable allocation; a kernel's
   * string table is a few MiB. */
  if (strsize > KIMG_STRTAB_MAX) {
    fclose(fp);
    return 0;
  }
  char *str = (char *)malloc((size_t)strsize);
  if (!str) {
    fclose(fp);
    return 0;
  }
  if (fseek(fp, (long)stroff, SEEK_SET) != 0 ||
      fread(str, 1, (size_t)strsize, fp) != (size_t)strsize) {
    free(str);
    fclose(fp);
    return 0;
  }
  /* A table whose final string is unterminated would otherwise let a compare
   * run past the buffer. */
  str[strsize - 1] = '\0';

  uint64_t count = symsize / (uint64_t)symsz;
  uint8_t sym[24];
  for (uint64_t i = 0; i < count; i++) {
    if (fseek(fp, (long)(symoff + i * (uint64_t)symsz), SEEK_SET) != 0)
      break;
    if (fread(sym, 1, (size_t)symsz, fp) < (size_t)symsz)
      break;
    uint64_t nm = kasld_rd_uint(sym + sym_name_off, 4, be);
    if (nm == 0 || nm >= strsize)
      continue;
    for (unsigned k = 0; k < WANTN; k++) {
      if (addr[k] || strcmp(str + nm, want[k]) != 0)
        continue;
      addr[k] = kasld_rd_uint(sym + sym_value_off, is64 ? 8 : 4, be);
    }
    if (addr[0] && addr[1] && addr[2] && addr[3])
      break;
  }
  free(str);
  fclose(fp);

  /* want[] order: _text, _stext, _etext, _end. */
  return kasld_image_span_from_edges(addr[0], addr[1], addr[2], addr[3], bound);
}

/* The image size from /boot/System.map-<release>, with *bound as
 * kasld_image_span_from_edges describes it: _end - _text is the exact
 * footprint, and a span resting on _stext or _etext instead is a lower bound.
 * System.map lists every symbol at its link-time virtual address, so the span
 * is invariant under KASLR (it is a size). Returns 0 if unreadable or no
 * bracketing pair is found. */
__attribute__((unused)) static unsigned long
kasld_image_size_from_sysmap(const char *release,
                             enum kasld_image_bound *bound) {
  char path[256];

  /* Cleared before anything can fail: a reader that declines must not leave a
   * caller's word describing a bound it did not supply. */
  if (bound)
    *bound = KIMG_BOUND_NONE;

  snprintf(path, sizeof(path), "/boot/System.map-%s", release);
  FILE *fp = kasld_fopen(path, "rb");
  if (!fp)
    return 0;

  /* 64-bit accumulators: a 32-bit build reading a 64-bit kernel's map must not
   * truncate the addresses; only the final span (always < 4 GiB) is narrowed.
   */
  unsigned long long text = 0, stext = 0, etext = 0, end = 0;
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
    else if (strcmp(name, "_etext") == 0)
      etext = addr;
    else if (strcmp(name, "_end") == 0)
      end = addr;
  }
  fclose(fp);

  return kasld_image_span_from_edges(text, stext, etext, end, bound);
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

/* An EFI zboot container: a small PE executable whose payload is the compressed
 * kernel, as built by drivers/firmware/efi/libstub/Makefile.zboot for arm64,
 * riscv and loongarch. It is not itself a kernel image.
 *
 * Header layout (drivers/firmware/efi/libstub/zboot-header.S): "MZ\0\0" at 0,
 * "zimg" at 4, payload offset as a u32 LE at 8, payload size as a u32 LE at 12,
 * and a NUL-terminated compressor name at 24.
 *
 * `size_trailer` is the offset of the u32 LE holding the payload's decompressed
 * length. zboot.lds places that word at the end of the payload region
 * (__efistub_payload_size = . - 4) and the header's payload-size field excludes
 * a ZBOOT_SIZE_LEN trailer, which Makefile.zboot sets to 0 for gzip -- whose
 * own ISIZE serves -- and 4 for anything else, where the length is appended. */
struct kasld_zboot {
  unsigned long payload_off;
  unsigned long payload_size;
  unsigned long size_trailer;
  int gzip; /* payload is gzip, so it can be decompressed in-process */
};

/* Parse and bounds-check a zboot container header. `file_size` is the whole
 * file's length: every offset returned is checked against it here, so callers
 * read at them without re-deriving the bounds. Returns 0 when the buffer is not
 * a zboot container or any field is inconsistent with the file. */
__attribute__((unused)) static int kasld_zboot_header(const uint8_t *h,
                                                      size_t n,
                                                      unsigned long file_size,
                                                      struct kasld_zboot *z) {
  if (n < 56 || file_size < 56)
    return 0;
  if (h[0] != 0x4d || h[1] != 0x5a || h[2] || h[3]) /* "MZ\0\0" */
    return 0;
  if (memcmp(h + 4, "zimg", 4) != 0)
    return 0;

  /* The compressor name decides where the length word sits, so an unrecognised
   * one is refused rather than guessed at: reading the wrong offset would
   * return an unrelated u32 from inside the compressed stream. */
  unsigned long size_len;
  if (memcmp(h + 24, "gzip", 5) == 0) /* with its NUL */
    size_len = 0;
  else if (memcmp(h + 24, "zstd", 5) == 0)
    size_len = 4;
  else
    return 0;

  unsigned long off = kasld_rd_le32(h + 8);
  unsigned long sz = kasld_rd_le32(h + 12);

  /* The payload starts after the header and lies wholly inside the file. The
   * subtraction is the safe direction of the same test: off < file_size is
   * already established, so file_size - off cannot wrap. */
  if (off <= 56 || off >= file_size)
    return 0;
  if (sz < 64 || sz > file_size - off)
    return 0;

  /* off + sz is bounded by file_size above, so this cannot wrap; the length
   * word must also lie inside the file when zstd appends it past payload_size.
   */
  unsigned long trailer = off + sz + size_len;
  if (trailer < 4 || trailer > file_size)
    return 0;

  z->payload_off = off;
  z->payload_size = sz;
  z->size_trailer = trailer - 4;
  z->gzip = (size_len == 0);
  return 1;
}

/* Decompressed kernel image size from a WHOLE-FILE gzip vmlinuz on disk (magic
 * 1f 8b 08 at offset 0), via its ISIZE trailer -- the last four bytes of the
 * file -- with no actual decompression. The result is _edata - _text: it
 * EXCLUDES BSS, so it is a sound LOWER bound on the footprint but not an upper
 * bound. Returns 0 if the file does not begin a gzip stream. */
__attribute__((unused)) static unsigned long
kasld_image_size_from_gzip(const char *release, enum kasld_image_bound *bound) {
  if (bound)
    *bound = KIMG_BOUND_NONE;

  /* Prefixes rather than formats: a format reaching snprintf through an array
   * cannot be checked against its argument, while one literal with the varying
   * part passed as an argument is checked in full. */
  static const char *const prefix[] = {"/boot/vmlinuz-", "/boot/Image-"};
  char path[256];
  uint8_t hdr[56];

  for (unsigned i = 0; i < sizeof(prefix) / sizeof(prefix[0]); i++) {
    snprintf(path, sizeof(path), "%s%s", prefix[i], release);
    FILE *fp = kasld_fopen(path, "rb");
    if (!fp)
      continue;
    size_t n = fread(hdr, 1, sizeof(hdr), fp);
    unsigned long isize = 0;
    long fsize = -1;

    if (fseek(fp, 0, SEEK_END) == 0)
      fsize = ftell(fp);

    /* Whole-file gzip only. ISIZE is the final four bytes of the file, a
     * FIXED position, so no field read out of the file can move this read.
     *
     * An EFI zboot container is deliberately not read here. Its length word
     * sits at an offset derived from the header's payload-size field, and
     * nothing at that offset corroborates it: a payload size agreeing with
     * neither the stream it names nor the file would place the read inside the
     * compressed data and return an unrelated u32. As a lower bound that is
     * the unsound direction -- the ceiling rules subtract it from a window top,
     * so a figure too large excludes a valid high base. The word is read only
     * where it can be checked against the size the payload declares of itself,
     * which is what the component's corroborated zboot reader does; a container
     * whose payload cannot be decompressed falls through to the file size,
     * which bounds the footprint from below without being read at an offset the
     * file chose. */
    if (n >= 3 && hdr[0] == 0x1f && hdr[1] == 0x8b && hdr[2] == 0x08 &&
        fsize >= 0)
      isize = kasld_gzip_isize(fp, fsize);

    fclose(fp);
    if (kasld_image_size_plausible(isize))
      return kasld_image_bounded(isize, KIMG_BOUND_LOWER, bound);
  }
  return 0;
}

/* The exact in-memory extent (_end - _text) from an arm32 zImage's loader
 * table. No decompression: both figures are stored uncompressed in the file.
 *
 * arch/arm/boot/compressed/head.S writes a loader header at offset 0x24 --
 * signature 0x016f2818, then the load/run addresses, an endianness flag, a
 * second marker, and at 0x38 the offset of an additional data table.
 * arch/arm/boot/compressed/vmlinux.lds.S lays that table out as:
 *   [0] entry count            [1] 0x5a534c4b
 *   [2] offset of the inflated-image-size word
 *   [3] _kernel_bss_size       [4] TEXT_OFFSET        [5] MALLOC_SIZE
 * The word [2] points at holds the decompressed kernel's length (_edata -
 * _text); head.S documents it as appended "in little-endian form" whatever the
 * target's byte order, so it is read LE unconditionally. Adding the BSS size
 * gives _end - _text: the exact footprint, and the only in-file source of it on
 * arm32, whose vmlinuz is a zImage that no other reader here parses.
 *
 * ZIMAGE_MAGIC byte-swaps the table's own words only under
 * CONFIG_CPU_ENDIAN_BE8, so the table's byte order is established from its
 * magic rather than inherited from the signature's. Returns 0 on failure. */
__attribute__((unused)) static unsigned long
kasld_image_size_from_zimage(const char *release,
                             enum kasld_image_bound *bound) {
  if (bound)
    *bound = KIMG_BOUND_NONE;

  char path[256];
  uint8_t hdr[0x3c], tab[24], word[4];

  snprintf(path, sizeof(path), "/boot/vmlinuz-%s", release);
  FILE *fp = kasld_fopen(path, "rb");
  if (!fp)
    return 0;

  unsigned long extent = 0;
  long fsize = -1;
  size_t n = fread(hdr, 1, sizeof(hdr), fp);
  if (fseek(fp, 0, SEEK_END) == 0)
    fsize = ftell(fp);

  if (n == sizeof(hdr) && fsize > 0) {
    /* The signature settles how this header's words are read; a BE8 build
     * stores them big-endian. */
    uint32_t (*rd)(const uint8_t *) = NULL;
    if (kasld_rd_le32(hdr + 0x24) == 0x016f2818u)
      rd = kasld_rd_le32;
    else if (kasld_rd_be32(hdr + 0x24) == 0x016f2818u)
      rd = kasld_rd_be32;

    unsigned long tbl = rd ? rd(hdr + 0x38) : 0;
    /* The table must lie wholly inside the file. Compared as the file size
     * minus the table's length so neither side of the test can wrap. */
    if (rd && tbl > 0 && tbl <= (unsigned long)fsize - sizeof(tab) &&
        fseek(fp, (long)tbl, SEEK_SET) == 0 &&
        fread(tab, 1, sizeof(tab), fp) == sizeof(tab)) {
      uint32_t (*trd)(const uint8_t *) = NULL;
      if (kasld_rd_le32(tab + 4) == 0x5a534c4bu)
        trd = kasld_rd_le32;
      else if (kasld_rd_be32(tab + 4) == 0x5a534c4bu)
        trd = kasld_rd_be32;

      /* Entries [2] and [3] are read, so a table declaring fewer than four is
       * refused rather than read past its own count. */
      if (trd && trd(tab) >= 4) {
        unsigned long piggy = trd(tab + 8);
        unsigned long bss = trd(tab + 12);
        if (piggy > 0 && piggy <= (unsigned long)fsize - sizeof(word) &&
            fseek(fp, (long)piggy, SEEK_SET) == 0 &&
            fread(word, 1, sizeof(word), fp) == sizeof(word)) {
          unsigned long inflated = kasld_rd_le32(word);
          /* The image size is banded before the BSS size is added to it, and
           * the sum is formed at 64 bits, so neither can wrap where unsigned
           * long is 32 bits. BSS is a fraction of any real image; a figure
           * exceeding the image it belongs to means the table was misread. */
          if (kasld_image_size_plausible(inflated) && bss <= inflated)
            extent =
                kasld_image_size_plausible((unsigned long long)inflated + bss);
        }
      }
    }
  }

  fclose(fp);
  return kasld_image_bounded(extent, KIMG_BOUND_LOWER, bound);
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
kasld_image_size_from_vmlinuz(const char *release,
                              enum kasld_image_bound *bound) {
  if (bound)
    *bound = KIMG_BOUND_NONE;

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
  return kasld_image_bounded(
      sz < 0 ? 0 : kasld_image_size_plausible((unsigned long long)sz),
      KIMG_BOUND_LOWER, bound);
}

/* The blob's size where its CONTENT cannot be read at all.
 *
 * Distributions commonly ship /boot/vmlinuz-* mode 0600 inside a world-listable
 * /boot, so an unprivileged run can stat the file but not open it. Every reader
 * above needs the content and returns 0 there, which costs more than precision:
 * dram_ceiling declines outright without a size, leaving the physical ceiling
 * at the architectural top rather than a DRAM-relative one.
 *
 * The size alone still bounds the footprint from below, but only for a blob --
 * an ELF carries unloaded symbol and section data and can exceed its footprint.
 * Which one this architecture ships is BOOT_IMAGE_SIZE_FLOORS_FOOTPRINT, and it
 * is consulted only here, where nothing better is available: an open that
 * SUCCEEDS is left to the readers above, whose magic check rejects a stray ELF
 * on its own evidence rather than on the axis.
 *
 * Emitted as a lower bound and never as an exact size. Returns 0 where the
 * architecture ships an ELF, where the file opens, or where the size is
 * implausible. */
__attribute__((unused)) static unsigned long
kasld_image_size_from_stat(const char *release, enum kasld_image_bound *bound) {
  if (bound)
    *bound = KIMG_BOUND_NONE;

#if BOOT_IMAGE_SIZE_FLOORS_FOOTPRINT
  char path[256];
  struct stat st;

  snprintf(path, sizeof(path), "/boot/vmlinuz-%s", release);
  FILE *fp = kasld_fopen(path, "rb");
  if (fp) {
    fclose(fp);
    return 0; /* readable: the content readers own this file */
  }
  if (errno != EACCES && errno != EPERM)
    return 0; /* absent, not withheld -- nothing to bound */
  if (kasld_stat(path, &st) != 0 || st.st_size < 0)
    return 0;
  return kasld_image_bounded(
      kasld_image_size_plausible((unsigned long long)st.st_size),
      KIMG_BOUND_LOWER, bound);
#else
  (void)release;
  return 0;
#endif
}

/* The .BTF section's length, from /sys/kernel/btf/vmlinux.
 *
 * BTF is linked into the kernel image -- the section is emitted inside
 * RO_DATA(), which every architecture's linker script places between _text and
 * _end -- so its length can never exceed the footprint. A lower bound, and the
 * weakest of these readers: BTF runs to a few MiB against an image of tens.
 *
 * It earns its place on reach rather than tightness. Every other reader needs
 * /boot, and this one needs nothing: the file is mode 0444 with no sysctl gate,
 * so it answers in a container with no /boot and a masked /proc, where the size
 * would otherwise fall back to the rules' own conservative floor.
 *
 * The SIZE is authoritative here, which is worth saying because the BTF reader
 * elsewhere in the tree treats a sysfs size as unreliable -- true of an
 * ordinary text attribute, and not of this one. /sys/kernel/btf/vmlinux is a
 * bin_attribute carrying an explicit size (__stop_BTF - __start_BTF), and sysfs
 * hands that through to the inode, so stat() reports the section length
 * exactly. Nothing is read from the file itself.
 *
 * Live only: no capture stages this file, so a replay falls through to the
 * readers above. Returns 0 where BTF is not built in, the file is denied, or
 * the length is implausible. */
__attribute__((unused)) static unsigned long
kasld_image_size_from_btf(enum kasld_image_bound *bound) {
  if (bound)
    *bound = KIMG_BOUND_NONE;

  struct stat st;

  if (kasld_stat("/sys/kernel/btf/vmlinux", &st) != 0)
    return 0;
  if (st.st_size < 0)
    return 0;
  return kasld_image_bounded(
      kasld_image_size_plausible((unsigned long long)st.st_size),
      KIMG_BOUND_LOWER, bound);
}

#endif /* KASLD_KERNEL_IMAGE_H */
