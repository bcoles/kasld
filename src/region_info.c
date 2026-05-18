// This file is part of KASLD - https://github.com/bcoles/kasld
//
// region_info[] — per-region wire name, render section, default alignment,
// and VAS-bound resolver. Generated from the KASLD_REGION_LIST X-macro in
// kasld/api.h so the enum, wire table, and this descriptor table all stay
// in sync from a single source row.
//
// Adding a region: edit the X-list in kasld/api.h. Don't add entries here.
// Per-region VAS rules live in the VAS_*_STATIC / VAS_*_DERIVE pairs
// below; if a region needs a brand-new VAS shape, add a new pair and a
// matching `kind` token to its X-list row.
// ---
// <bcoles@gmail.com>

#include "include/kasld/internal.h"

/* =========================================================================
 * derive_vas implementations for layout-derived regions
 *
 * Contract: produce valid (lo <= hi) bounds for ANY layout state,
 * including the initial compile-time-defaults state. Never crash.
 * Conservative bounds are fine when layout fields haven't been set yet.
 * ========================================================================= */

static void derive_vas_page_offset(const struct kasld_layout *ly,
                                   unsigned long *lo, unsigned long *hi) {
  /* PAGE_OFFSET is itself a layout field. Validate page_offset records
   * against the ARCH-default kernel VAS window (compile-time constants),
   * NOT the runtime layout.kernel_vas_start — the latter gets tightened
   * by inference plugins (phys_virt_synth, directmap_page_offset_bounds)
   * which themselves derive their tightenings from page_offset records.
   * Using the runtime layout would create a circular dependency where
   * a page_offset record gets rejected because earlier inference (based
   * on different records) tightened the bound above it.
   *
   * The compile-time KERNEL_VAS_START/END from the arch header is the
   * widest plausible PAGE_OFFSET range; that's the right validation
   * window. */
  (void)ly;
  *lo = (unsigned long)KERNEL_VAS_START;
  *hi = (unsigned long)KERNEL_VAS_END;
}

#if !PHYS_VIRT_DECOUPLED
static void derive_vas_module_region_coupled(const struct kasld_layout *ly,
                                             unsigned long *lo,
                                             unsigned long *hi) {
  *lo = ly->modules_start;
  *hi = ly->modules_end;
}
#endif

/* =========================================================================
 * VAS-kind dispatch
 *
 * One pair per kind: VAS_<kind>_STATIC is the static_vas initializer,
 * VAS_<kind>_DERIVE is the derive_vas function pointer (NULL for regions
 * with no runtime derivation). The X-list row's `kind` token selects
 * which pair lands in the row's region_info entry via token-pasting.
 * ========================================================================= */

/* K_OPEN: any address admitted. Used for all DRAM-resident regions,
 * MMIO, and the kernel-image regions (which legitimately appear in both
 * phys and virt contexts). */
#define VAS_K_OPEN_STATIC {0, ULONG_MAX}
#define VAS_K_OPEN_DERIVE NULL

/* K_VIRT: virtual-only regions bounded by the architectural kernel VAS
 * window (DIRECTMAP / VMALLOC / VMEMMAP). Sub-VAS phys leaks are
 * rejected by result_in_bounds(). */
#define VAS_K_VIRT_STATIC {KERNEL_VAS_START, KERNEL_VAS_END}
#define VAS_K_VIRT_DERIVE NULL

/* K_PAGEOFFSET: PAGE_OFFSET itself, validated against the compile-time
 * KERNEL_VAS window to avoid the circular dependency with runtime
 * inference. (Bare `PAGE_OFFSET` as the kind token would collide with
 * the arch-header macro — see api.h note on the K_ prefix.) */
#define VAS_K_PAGEOFFSET_STATIC {0, 0}
#define VAS_K_PAGEOFFSET_DERIVE derive_vas_page_offset

/* K_MODULE: on coupled arches the range tracks ly->modules_start/end
 * (which shifts with PAGE_OFFSET); on decoupled arches the range is
 * fixed. */
#if !PHYS_VIRT_DECOUPLED
#define VAS_K_MODULE_STATIC {0, 0}
#define VAS_K_MODULE_DERIVE derive_vas_module_region_coupled
#else
#define VAS_K_MODULE_STATIC {MODULES_START, MODULES_END}
#define VAS_K_MODULE_DERIVE NULL
#endif

/* Helpers: paste `kind` onto VAS_ and the suffix, then expand. The
 * K_ prefix on every kind token keeps `kind` from being pre-expanded
 * as an arch macro before the paste. */
#define VAS_STATIC(kind) VAS_##kind##_STATIC
#define VAS_DERIVE(kind) VAS_##kind##_DERIVE

/* =========================================================================
 * The table — generated from KASLD_REGION_LIST.
 * ========================================================================= */

const struct region_info region_info[REGION__COUNT] = {
    /* REGION_UNKNOWN — sentinel; result_in_bounds() short-circuits before
     * reading. Not in the X-list because it has no wire name and no VAS. */
    [REGION_UNKNOWN] =
        {
            .wire_name = "unknown",
            .section_name = "",
            .default_align = 0,
            .static_vas = {0, 0},
            .derive_vas = NULL,
        },

#define X(name, wire, sec, kind)                                               \
  [name] = {                                                                   \
      .wire_name = wire,                                                       \
      .section_name = sec,                                                     \
      .default_align = 0,                                                      \
      .static_vas = VAS_STATIC(kind),                                          \
      .derive_vas = VAS_DERIVE(kind),                                          \
  },
    KASLD_REGION_LIST(X)
#undef X
};
