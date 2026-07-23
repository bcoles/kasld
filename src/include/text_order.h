// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Shared kernel-text function-ordering classification from the kernel config
// (+ the nofgkaslr cmdline override). Used by the config-reading components
// (proc_config.c, boot_config.c) so they emit SF_TEXT_ORDER without each
// duplicating the classification.
//
// The class gates symbol-offset propagation: a generic version-level
// System.map resolves symbols from the KASLR slide only when the text is in
// canonical (source/link) order. Reordered builds need the exact-build map;
// FG-KASLR (per-boot) needs no static map at all.
// ---
// <bcoles@gmail.com>
#ifndef KASLD_TEXT_ORDER_H
#define KASLD_TEXT_ORDER_H

#include "include/cmdline.h"
#include "include/kasld/api.h"

#include <stdio.h>
#include <string.h>

/* True if `buf` is exactly the config line "<name>=y" (prefix match, then the
 * '=' and 'y' — so "CONFIG_LTO_CLANG" does not match "CONFIG_LTO_CLANG_THIN").
 */
static int kconfig_line_is_y(const char *buf, const char *name) {
  size_t n = strlen(name);
  return strncmp(buf, name, n) == 0 && buf[n] == '=' && buf[n + 1] == 'y';
}

/* Pure classification of text ordering from an open kernel-config stream and a
 * pre-resolved nofgkaslr flag (kept a parameter so this stays I/O-free and
 * unit- testable). Precedence: FG-KASLR (per-boot, dynamic) > static reorder
 * (LTO / AutoFDO / Propeller) > canonical. nofgkaslr demotes an FG-KASLR build
 * to whatever its static configs imply (it can only turn the feature off, never
 * on). One pass; `fp` must be a seekable config stream. */
static enum kasld_text_order classify_text_order(FILE *fp, int nofgkaslr) {
  int fgkaslr = 0, lto = 0, autofdo = 0, propeller = 0;
  char buf[256];

  rewind(fp);
  while (fgets(buf, sizeof(buf), fp)) {
    if (kconfig_line_is_y(buf, "CONFIG_FG_KASLR"))
      fgkaslr = 1;
    /* CONFIG_LTO_CLANG is the umbrella the THIN/FULL variants select, so it is
     * present whenever LTO is on; the variants are checked too so a missed LTO
     * (which would wrongly read as canonical -> unsafe map) cannot slip by. */
    else if (kconfig_line_is_y(buf, "CONFIG_LTO_CLANG") ||
             kconfig_line_is_y(buf, "CONFIG_LTO_CLANG_THIN") ||
             kconfig_line_is_y(buf, "CONFIG_LTO_CLANG_FULL"))
      lto = 1;
    else if (kconfig_line_is_y(buf, "CONFIG_AUTOFDO_CLANG"))
      autofdo = 1;
    else if (kconfig_line_is_y(buf, "CONFIG_PROPELLER_CLANG"))
      propeller = 1;
  }

  if (fgkaslr && nofgkaslr)
    fgkaslr = 0; /* compiled in but disabled at boot */

  return fgkaslr                         ? TEXT_ORDER_DYNAMIC
         : (lto || autofdo || propeller) ? TEXT_ORDER_STATIC
                                         : TEXT_ORDER_CANONICAL;
}

/* Emit SF_TEXT_ORDER from a config stream at the caller-supplied confidence,
 * resolving the nofgkaslr cmdline override. The confidence is a parameter
 * because an authoritative source (/proc/config.gz, a release-keyed
 * /boot/config-*) warrants CONF_PARSED, whereas an unverifiable one (the
 * unkeyed /boot/config) must stay below the guaranteed floor. No diagnostics on
 * stdout (the wire stays clean). */
static void __attribute__((unused))
emit_text_order_from_kconfig(FILE *fp, enum kasld_confidence conf) {
  kasld_emit_scalar(SF_TEXT_ORDER,
                    classify_text_order(fp, cmdline_has_word("nofgkaslr")),
                    conf);
}

#endif /* KASLD_TEXT_ORDER_H */
