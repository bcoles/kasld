// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Check kernel config for CONFIG_RELOCATABLE, CONFIG_RANDOMIZE_BASE,
// and CONFIG_PAGE_OFFSET (32-bit vmsplit).
//
// Detection component — does not leak an address.
//   Purpose: reads /boot/config-$(uname -r) to determine whether
//   CONFIG_RANDOMIZE_BASE is set (KASLR compiled in) and what the
//   32-bit vmsplit (CONFIG_PAGE_OFFSET) is. Readable when /boot is
//   accessible (common on most distros).
//
// References:
// https://lwn.net/Articles/444556/
// https://cateee.net/lkddb/web-lkddb/RANDOMIZE_BASE.html
// https://cateee.net/lkddb/web-lkddb/RELOCATABLE.html
// https://cateee.net/lkddb/web-lkddb/PAGE_OFFSET.html
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kconfig.h"
#include "include/text_order.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

KASLD_EXPLAIN(
    "Reads /boot/config-$(uname -r) to check whether CONFIG_RANDOMIZE_BASE "
    "is set (KASLR compiled in) and determines the 32-bit vmsplit "
    "(CONFIG_PAGE_OFFSET). Readable when /boot is accessible.");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "addr:none\n");

/* Open the kernel config file. Release-keyed paths (bound to the running
 * kernel's uname release) are tried FIRST; the unkeyed /boot/config is a
 * best-effort fallback tried LAST and reported via *is_unkeyed, since it has no
 * release binding and may describe a different kernel. Availability depends on
 * CONFIG_IKCONFIG, distro layout, and whether kernel headers are installed. */
static int open_boot_config(FILE **fpp, int *is_unkeyed) {
  struct utsname utsname;
  char path[256];

  *is_unkeyed = 0;

  if (kasld_uname(&utsname) == 0) {
    const char *release_fmts[] = {
        "/boot/config-%s",
        "/lib/modules/%s/build/.config",
        "/lib/modules/%s/config",
        NULL,
    };

    for (int i = 0; release_fmts[i]; i++) {
      snprintf(path, sizeof(path), release_fmts[i], utsname.release);
      *fpp = kasld_fopen(path, "r");
      if (*fpp)
        return 0;
    }
  }

  /* Last resort: the unkeyed /boot/config (no release binding). */
  *fpp = kasld_fopen("/boot/config", "r");
  if (*fpp) {
    *is_unkeyed = 1;
    return 0;
  }

  kasld_err("could not find kernel config");
  return -1;
}

static unsigned long get_kernel_addr_boot_config(FILE *fp) {
  if (kconfig_has_kaslr(fp))
    return 0;

  kasld_info(
      "[.] Kernel appears to have been compiled without CONFIG_RANDOMIZE_BASE"
      " (KASLR not compiled in)");

  return (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
}

int main(void) {
  FILE *fp;
  int is_unkeyed = 0;
  if (open_boot_config(&fp, &is_unkeyed) < 0)
    return KASLD_EXIT_UNAVAILABLE;

  /* An unkeyed /boot/config carries no binding to the running kernel: it may be
   * a leftover from another kernel or a rescue image. Its Kconfig answers drive
   * guaranteed pins (the KASLR-disabled C_EQUALS pin, the PHYSICAL_START floor,
   * the s390 layout discriminator, ...), so a stale file could exclude the true
   * base from the guaranteed window. Demote every fact from that source below
   * the guaranteed floor — it then shapes only the likely window. Release-keyed
   * paths are bound to the running kernel and stay at CONF_PARSED. */
  enum kasld_confidence cfg_conf = is_unkeyed ? CONF_HEURISTIC : CONF_PARSED;

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
                      NULL, cfg_conf);
  }
#endif

  /* CONFIG_PHYSICAL_START (x86 LOAD_PHYSICAL_ADDR). The honest-top floors
   * for Q_VIRT_IMAGE_BASE / Q_PHYS_IMAGE_BASE are *widened* to the smallest
   * practical value (2 MiB, the minimum CONFIG_PHYSICAL_START alignment);
   * when we can learn the real value, the physical_start_lower_bound rule
   * raises the floor to the precise position at CONF_PARSED. */
  unsigned long phys_start = get_kconfig_physical_start(fp);
  if (phys_start) {
    kasld_info("CONFIG_PHYSICAL_START: %#lx", phys_start);
    kasld_emit_scalar(SF_PHYSICAL_START, phys_start, cfg_conf);
  }

  /* CONFIG_PHYSICAL_ALIGN — KASLR slot granularity on x86. boot_params
   * exposes the same value at hdr.kernel_alignment; this is a fallback for
   * systems where /sys/kernel/boot_params/data is unreadable. Both sources
   * emit the same SF_PHYS_KERNEL_ALIGN scalar; boot_params_kaslr_align raises
   * Q_VIRT_KASLR_ALIGN / Q_PHYS_KASLR_ALIGN regardless of source. */
  unsigned long phys_align = get_kconfig_physical_align(fp);
  if (phys_align) {
    kasld_info("CONFIG_PHYSICAL_ALIGN: %#lx", phys_align);
    kasld_emit_scalar(SF_PHYS_KERNEL_ALIGN, phys_align, cfg_conf);
  }

  /* KASLR-off detection. CONFIG_RANDOMIZE_BASE=n means the kernel binary
   * was built without KASLR support entirely — both virtual and physical
   * placement use compile-time defaults. virt_kaslr_disabled_pin /
   * phys_kaslr_disabled_pin each gate by its arch macro
   * (KASLR_DISABLED_PINS_VIRT_TEXT / KASLR_DISABLED_PINS_PHYS) + window-
   * containment to decide whether to pin. */
  if (get_kernel_addr_boot_config(fp)) {
    kasld_emit_scalar(SF_VIRT_KASLR_DISABLED, 1, cfg_conf);
    kasld_emit_scalar(SF_PHYS_KASLR_DISABLED, 1, cfg_conf);
  }

  /* CONFIG_KASAN=y forces the direct-map randomization off at runtime
   * (kaslr_memory_enabled() = kaslr_enabled() && !IS_ENABLED(CONFIG_KASAN)), so
   * page_offset / vmalloc / vmemmap stay at their compile-time defaults even
   * with CONFIG_RANDOMIZE_MEMORY=y. Consumed by directmap_kaslr_disabled_pin.
   */
  if (is_kconfig_set(fp, "CONFIG_KASAN")) {
    kasld_info("CONFIG_KASAN=y");
    kasld_emit_scalar(SF_KASAN_ENABLED, 1, cfg_conf);
  }

  /* Kernel-text function ordering (canonical / static-reorder / FG-KASLR) —
   * gates whether a generic System.map can resolve symbols. See text_order.h.
   */
  emit_text_order_from_kconfig(fp, cfg_conf);

  /* s390 image-base layout discriminator — see proc_config.c. CONFIG_S390=y
   * with CONFIG_KERNEL_IMAGE_BASE present (value > 0) selects the modern high
   * separate-kernel-mapping layout; absent (value 0) selects the pre-v6.8
   * identity-mapped layout. Consumed by s390_image_base_from_config. */
  if (is_kconfig_set(fp, "CONFIG_S390")) {
    unsigned long s390_image_base = get_kconfig_kernel_image_base(fp);
    kasld_info("CONFIG_KERNEL_IMAGE_BASE: %#lx%s", s390_image_base,
               s390_image_base ? "" : " (absent: identity-mapped layout)");
    kasld_emit_scalar(SF_VIRT_KERNEL_IMAGE_BASE, s390_image_base, cfg_conf);
  }

  fclose(fp);

  return 0;
}
