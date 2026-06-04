// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parse /proc/config.gz for kernel configuration.
//
// Checks for CONFIG_RELOCATABLE, CONFIG_RANDOMIZE_BASE,
// and CONFIG_PAGE_OFFSET (32-bit vmsplit).
//
// Uses zlib for native gzip decompression when available (HAVE_ZLIB),
// otherwise falls back to popen("zcat").
//
// Detection component — does not leak an address.
//   Purpose: reads /proc/config.gz to determine whether
//   CONFIG_RANDOMIZE_BASE is set (KASLR compiled in) and what the
//   32-bit vmsplit (CONFIG_PAGE_OFFSET) is.
//
// Requires:
// - CONFIG_PROC_FS=y
// - CONFIG_IKCONFIG=y
// - CONFIG_IKCONFIG_PROC=y
// - zlib or zcat utility
//
// References:
// https://lwn.net/Articles/444556/
// https://cateee.net/lkddb/web-lkddb/RANDOMIZE_BASE.html
// https://cateee.net/lkddb/web-lkddb/RELOCATABLE.html
// https://cateee.net/lkddb/web-lkddb/PAGE_OFFSET.html
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kconfig.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#define PROC_CONFIG_GZ "/proc/config.gz"

KASLD_EXPLAIN(
    "Reads /proc/config.gz (requires CONFIG_IKCONFIG_PROC) to check "
    "CONFIG_RANDOMIZE_BASE and CONFIG_PAGE_OFFSET. Determines whether "
    "KASLR is compiled in and the 32-bit user/kernel address split.");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "addr:none\n"
           "config:CONFIG_IKCONFIG_PROC\n");

/* Decompress /proc/config.gz into a seekable FILE*.
 * Uses zlib if available, otherwise falls back to popen("zcat"). */
static FILE *open_proc_config(void) {
  FILE *fp;
  char buf[4096];
  /* gzopen()/popen() don't go through the kasld_* wrappers, so resolve the
   * KASLD_SYSROOT path explicitly and use it for both decompression paths. */
  char pathbuf[KASLD_PATH_MAX];
  const char *cfg = kasld_resolve(PROC_CONFIG_GZ, pathbuf, sizeof(pathbuf));

  printf("[.] checking %s ...\n", PROC_CONFIG_GZ);

  if (kasld_access(PROC_CONFIG_GZ, R_OK) != 0) {
    fprintf(stderr, "[-] Could not read %s\n", PROC_CONFIG_GZ);
    return NULL;
  }

#ifdef HAVE_ZLIB
  gzFile gz = gzopen(cfg, "rb");
  if (gz) {
    fp = tmpfile();
    if (fp) {
      int n;
      while ((n = gzread(gz, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, (size_t)n, fp);
      gzclose(gz);
      rewind(fp);
      return fp;
    }
    gzclose(gz);
  }
#endif

  /* Fallback: decompress via zcat and buffer into a seekable tmpfile. */
  char cmd[KASLD_PATH_MAX + 16];
  snprintf(cmd, sizeof(cmd), "zcat \"%s\"", cfg);
  FILE *proc = popen(cmd, "r");
  if (!proc) {
    perror("[-] popen");
    return NULL;
  }

  fp = tmpfile();
  if (!fp) {
    perror("[-] tmpfile");
    pclose(proc);
    return NULL;
  }

  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), proc)) > 0)
    fwrite(buf, 1, n, fp);
  pclose(proc);

  fseek(fp, 0, SEEK_END);
  if (ftell(fp) <= 0) {
    fprintf(stderr, "[-] Failed to decompress %s\n", PROC_CONFIG_GZ);
    fclose(fp);
    return NULL;
  }
  rewind(fp);

  return fp;
}

static int kaslr_disabled_from_config(FILE *fp) {
  if (kconfig_has_kaslr(fp))
    return 0;

  printf(
      "[.] Kernel appears to have been compiled without CONFIG_RANDOMIZE_BASE"
      " (KASLR not compiled in)\n");
  return 1;
}

int main(void) {
  FILE *fp = open_proc_config();
  if (!fp)
    return KASLD_EXIT_UNAVAILABLE;

  /* Detect PAGE_OFFSET (32-bit vmsplit) */
  unsigned long virt_page_offset = get_kconfig_page_offset(fp);
  if (virt_page_offset) {
    printf("[.] CONFIG_PAGE_OFFSET: %#lx\n", virt_page_offset);
    kasld_result_base(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, virt_page_offset,
                      NULL, CONF_PARSED);
  }

  /* CONFIG_PHYSICAL_START (x86 LOAD_PHYSICAL_ADDR) — see boot_config.c. */
  unsigned long phys_start = get_kconfig_physical_start(fp);
  if (phys_start) {
    printf("[.] CONFIG_PHYSICAL_START: %#lx\n", phys_start);
    kasld_emit_scalar(SF_PHYSICAL_START, phys_start, CONF_PARSED);
  }

  /* CONFIG_PHYSICAL_ALIGN — KASLR slot granularity (x86). See boot_config.c.
   * Fallback for systems where /sys/kernel/boot_params/data is unreadable.  */
  unsigned long phys_align = get_kconfig_physical_align(fp);
  if (phys_align) {
    printf("[.] CONFIG_PHYSICAL_ALIGN: %#lx\n", phys_align);
    kasld_emit_scalar(SF_PHYS_KERNEL_ALIGN, phys_align, CONF_PARSED);
  }

  /* KASLR-off detection. CONFIG_RANDOMIZE_BASE=n in /proc/config.gz means
   * the kernel binary was built without KASLR support — both virtual and
   * physical placement use compile-time defaults. virt_kaslr_disabled_pin
   * and phys_kaslr_disabled_pin each gate by its arch macro
   * (KASLR_DISABLED_PINS_VIRT_TEXT / KASLR_DISABLED_PINS_PHYS) + window-
   * containment. */
  if (kaslr_disabled_from_config(fp)) {
    kasld_emit_scalar(SF_VIRT_KASLR_DISABLED, 1, CONF_PARSED);
    kasld_emit_scalar(SF_PHYS_KASLR_DISABLED, 1, CONF_PARSED);
  }

  fclose(fp);

  return 0;
}
