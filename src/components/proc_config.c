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
#include "include/kasld/cli.h"
#include "include/kconfig.h"
#include "include/text_order.h"
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

  kasld_info("checking %s ...", PROC_CONFIG_GZ);

  if (kasld_access(PROC_CONFIG_GZ, R_OK) != 0) {
    kasld_err("Could not read %s", PROC_CONFIG_GZ);
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

  /* Fallback when zlib is not linked (e.g. the static cross builds): decompress
   * via zcat and buffer into a seekable tmpfile. Interpolating `cfg` into the
   * shell command is safe: it is the fixed literal "/proc/config.gz", or that
   * literal under the KASLD_SYSROOT prefix — an environment variable set by the
   * same user who runs kasld. kasld is never setuid, so no privilege boundary
   * is crossed and the double-quoting is sufficient (no untrusted input reaches
   * the shell). */
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
    kasld_err("Failed to decompress %s", PROC_CONFIG_GZ);
    fclose(fp);
    return NULL;
  }
  rewind(fp);

  return fp;
}

static int kaslr_disabled_from_config(FILE *fp) {
  if (kconfig_has_kaslr(fp))
    return 0;

  kasld_info(
      "[.] Kernel appears to have been compiled without CONFIG_RANDOMIZE_BASE"
      " (KASLR not compiled in)");
  return 1;
}

int main(void) {
  FILE *fp = open_proc_config();
  if (!fp)
    return KASLD_EXIT_UNAVAILABLE;

#if PAGE_OFFSET_FROM_CONFIG
  /* Detect PAGE_OFFSET (32-bit vmsplit). CONFIG_PAGE_OFFSET equals the runtime
   * page_offset only on PAGE_OFFSET_FROM_CONFIG arches (x86_32, arm32); pinning
   * Q_PAGE_OFFSET to it via page_offset_from_landmark's C_EQUALS would exclude
   * the truth on arches whose CONFIG_PAGE_OFFSET differs from the running base.
   * (The properly gated scalar path is bootconfig_facts ->
   * page_offset_from_config.) */
  unsigned long virt_page_offset = get_kconfig_page_offset(fp);
  if (virt_page_offset) {
    kasld_info("CONFIG_PAGE_OFFSET: %#lx", virt_page_offset);
    kasld_result_base(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, virt_page_offset,
                      NULL, CONF_PARSED);
  }
#endif

  /* CONFIG_PHYSICAL_START (x86 LOAD_PHYSICAL_ADDR) — see boot_config.c. */
  unsigned long phys_start = get_kconfig_physical_start(fp);
  if (phys_start) {
    kasld_info("CONFIG_PHYSICAL_START: %#lx", phys_start);
    kasld_emit_scalar(SF_PHYSICAL_START, phys_start, CONF_PARSED);
  }

  /* CONFIG_PHYSICAL_ALIGN — KASLR slot granularity (x86). See boot_config.c.
   * Fallback for systems where /sys/kernel/boot_params/data is unreadable.  */
  unsigned long phys_align = get_kconfig_physical_align(fp);
  if (phys_align) {
    kasld_info("CONFIG_PHYSICAL_ALIGN: %#lx", phys_align);
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

  /* CONFIG_KASAN=y forces the direct-map randomization off at runtime —
   * kaslr_memory_enabled() = kaslr_enabled() && !IS_ENABLED(CONFIG_KASAN) —
   * so page_offset / vmalloc / vmemmap stay at their compile-time defaults even
   * when CONFIG_RANDOMIZE_MEMORY=y. Consumed by directmap_kaslr_disabled_pin
   * (x86_64). The fact is arch-neutral; the rule gates on the arch. */
  if (is_kconfig_set(fp, "CONFIG_KASAN")) {
    kasld_info("CONFIG_KASAN=y");
    kasld_emit_scalar(SF_KASAN_ENABLED, 1, CONF_PARSED);
  }

  /* Kernel-text function ordering (canonical / static-reorder / FG-KASLR) —
   * gates whether a generic System.map can resolve symbols. See text_order.h.
   */
  emit_text_order_from_kconfig(fp);

  /* s390 image-base layout discriminator. On an s390 config (CONFIG_S390=y),
   * the presence/absence of CONFIG_KERNEL_IMAGE_BASE distinguishes the modern
   * high separate-kernel-mapping layout (value > 0 → relocation floor) from the
   * pre-v6.8 identity-mapped layout (knob absent → kernel text in low RAM,
   * emitted as value 0). s390_image_base_from_config consumes this to recover a
   * tight image-base window without trusting version numbers. */
  if (is_kconfig_set(fp, "CONFIG_S390")) {
    unsigned long s390_image_base = get_kconfig_kernel_image_base(fp);
    kasld_info("CONFIG_KERNEL_IMAGE_BASE: %#lx%s", s390_image_base,
               s390_image_base ? "" : " (absent: identity-mapped layout)");
    kasld_emit_scalar(SF_VIRT_KERNEL_IMAGE_BASE, s390_image_base, CONF_PARSED);
  }

  fclose(fp);

  return 0;
}
