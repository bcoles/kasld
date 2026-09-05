// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Shared kernel config parsing helpers.
//
// Provides is_kconfig_set(), get_kconfig_page_offset(), and
// kconfig_has_kaslr() for use by boot_config.c and proc_config.c.
//
// All functions operate on an already-opened seekable FILE* — the caller
// is responsible for opening the config source (boot file, /proc/config.gz,
// etc.) and closing it afterwards.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_KCONFIG_H
#define KASLD_KCONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Check if a kernel config option is set (CONFIG_FOO=y).
 * Rewinds fp before searching. Returns 1 if set, 0 otherwise. */
static int is_kconfig_set(FILE *fp, const char *config) {
  char pattern[BUFSIZ], buf[BUFSIZ];

  snprintf(pattern, sizeof(pattern), "%s=y", config);
  rewind(fp);

  printf("[.] checking for %s... \n", config);

  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (strncmp(buf, pattern, strlen(pattern)) == 0)
      return 1;
  }

  return 0;
}

/* Search for CONFIG_PAGE_OFFSET=0x... in the kernel config.
 * Falls back to CONFIG_VMSPLIT_* choices (x86_32, arm32).
 * Returns the value, or 0 if not found.
 * __attribute__((unused)): callers gate use on PAGE_OFFSET_FROM_CONFIG, so this
 * is unreferenced on arches where CONFIG_PAGE_OFFSET != runtime page_offset. */
__attribute__((unused)) static unsigned long get_kconfig_page_offset(FILE *fp) {
  const char *key = "CONFIG_PAGE_OFFSET=";
  size_t keylen = strlen(key);
  char buf[BUFSIZ];

  rewind(fp);

  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (strncmp(buf, key, keylen) == 0) {
      unsigned long val = strtoul(buf + keylen, NULL, 0);
      if (val)
        return val;
    }
  }

  /* Fallback: check CONFIG_VMSPLIT_* choices (x86_32, arm32) */
  const struct {
    const char *config;
    unsigned long virt_page_offset;
  } vmsplit_map[] = {
      {"CONFIG_VMSPLIT_1G", 0x40000000ul},
      {"CONFIG_VMSPLIT_2G", 0x80000000ul},
      {"CONFIG_VMSPLIT_2G_OPT", 0x78000000ul},
      {"CONFIG_VMSPLIT_3G", 0xc0000000ul},
      {"CONFIG_VMSPLIT_3G_OPT", 0xb0000000ul},
      {NULL, 0},
  };

  for (int i = 0; vmsplit_map[i].config; i++) {
    if (is_kconfig_set(fp, vmsplit_map[i].config))
      return vmsplit_map[i].virt_page_offset;
  }

  return 0;
}

/* Search for CONFIG_PHYSICAL_START=0x... in the kernel config.
 * Returns the value, or 0 if not found. x86 only — other arches don't
 * have this knob (riscv64 has CONFIG_RISCV_BASE_ADDRESS, arm64 doesn't
 * have one at all; defer arch-specific siblings until needed). */
static unsigned long __attribute__((unused))
get_kconfig_physical_start(FILE *fp) {
  const char *key = "CONFIG_PHYSICAL_START=";
  size_t keylen = strlen(key);
  char buf[BUFSIZ];

  rewind(fp);

  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (strncmp(buf, key, keylen) == 0)
      return strtoul(buf + keylen, NULL, 0);
  }
  return 0;
}

/* Search for CONFIG_PHYSICAL_ALIGN=0x... in the kernel config — the x86
 * KASLR slot granularity (= boot_params.hdr.kernel_alignment). x86 only;
 * Kconfig minimum is 0x2000 on X86_32 and 0x200000 on X86_64, up to
 * 0x1000000. Returns the value, or 0 if not
 * found. Fallback for systems where /sys/kernel/boot_params/data is
 * unreadable; boot_params_kaslr_align consumes the value identically via
 * SF_PHYS_KERNEL_ALIGN regardless of source. */
static unsigned long __attribute__((unused))
get_kconfig_physical_align(FILE *fp) {
  const char *key = "CONFIG_PHYSICAL_ALIGN=";
  size_t keylen = strlen(key);
  char buf[BUFSIZ];

  rewind(fp);

  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (strncmp(buf, key, keylen) == 0)
      return strtoul(buf + keylen, NULL, 0);
  }
  return 0;
}

/* Search for CONFIG_KERNEL_IMAGE_BASE=0x... in the kernel config — the s390
 * image-base relocation floor (introduced ~v6.10 with the high separate kernel
 * mapping). Its PRESENCE distinguishes the modern high-kernel layout from the
 * pre-v6.10 identity-mapped layout (where kernel text sits in low RAM). s390
 * only. Returns the value, or 0 if not found. */
static unsigned long __attribute__((unused))
get_kconfig_kernel_image_base(FILE *fp) {
  const char *key = "CONFIG_KERNEL_IMAGE_BASE=";
  size_t keylen = strlen(key);
  char buf[BUFSIZ];

  rewind(fp);

  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (strncmp(buf, key, keylen) == 0)
      return strtoul(buf + keylen, NULL, 0);
  }
  return 0;
}

/* Check if the kernel was compiled with KASLR support
 * (CONFIG_RANDOMIZE_BASE=y).
 *
 * CONFIG_RANDOMIZE_BASE alone is the signal on every architecture, though not
 * for one reason: x86 makes CONFIG_RELOCATABLE a hard Kconfig dependency of it,
 * arm64 has RANDOMIZE_BASE `select RELOCATABLE`, and on s390 the two are
 * unrelated. Either way a set RANDOMIZE_BASE settles it, and no arch needs
 * RELOCATABLE read alongside. Several arches that do define RELOCATABLE use it
 * for purposes of their own (powerpc for kdump, for one), so its state answers
 * a different question.
 *
 * Returns 1 when CONFIG_RANDOMIZE_BASE=y is present (KASLR compiled in), 0 when
 * "# CONFIG_RANDOMIZE_BASE is not set" is present (compiled out), and -1 when
 * neither line is seen. Those are the only two forms a generated .config can
 * carry for this bool -- Kconfig writes an unset bool as the "is not set"
 * comment, never "=n", and the build re-normalizes .config before compiling, so
 * /proc/config.gz and /boot/config never show "=n". The -1 case is
 * load-bearing for soundness: a truncated
 * decompression (a zcat killed mid-stream leaves a non-empty but partial
 * prefix), a mid-scan read error, or a config from an arch without the option
 * all leave neither token — and the KASLR-disabled pin must NOT be asserted
 * from the mere absence of "=y", which would pin the base to the compile-time
 * default on an incompletely read config. Keying on the positive "is not set"
 * token instead means absence-of-evidence never narrows the window. Both
 * callers treat a non-zero return (1 or -1) as "not off" and assert disabled
 * only on 0. */
static int kconfig_has_kaslr(FILE *fp) {
  static const char yes[] = "CONFIG_RANDOMIZE_BASE=y";
  static const char no[] = "# CONFIG_RANDOMIZE_BASE is not set";
  char buf[BUFSIZ];
  printf("[.] checking for CONFIG_RANDOMIZE_BASE... \n");
  rewind(fp);
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (strncmp(buf, yes, sizeof(yes) - 1) == 0)
      return 1;
    if (strncmp(buf, no, sizeof(no) - 1) == 0)
      return 0;
  }
  return -1;
}

#endif /* KASLD_KCONFIG_H */
