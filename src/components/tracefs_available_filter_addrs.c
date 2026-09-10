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
// The distance between the lowest and highest kernel row also bounds the image
// SIZE from below. A core record's ip is an mcount call site registered from
// __start_mcount_loc..__stop_mcount_loc, so it lies inside [_text, _end); the
// lowest and highest are therefore both interior, and their distance is
// strictly under the footprint. Module rows are excluded by ftrace's own tag,
// since a module address is outside the image and would inflate the span. The
// bound is loose — text ends well below _end — but it carries no kptr_restrict
// gate, so it answers on a host where every /boot and kallsyms source is
// masked, which is the vantage where the size still binds.
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
#include "include/kasld/kernel_image.h"
#include <dirent.h>
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
    "an interior point bounding the kernel text base, and the span between the "
    "lowest and highest is a lower bound on the kernel image size. Unlike "
    "printk_formats, the table is populated whenever CONFIG_DYNAMIC_FTRACE is "
    "set.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:virtual\n"
           "source:files\n"
           "note:bypasses_kptr_restrict\n");

/* Does this row's symbol field carry ftrace's module tag?
 *
 * print_rec() in the kernel emits the symbol and then, only when the address
 * resolved to a module, " [<name>]" -- so a bracketed trailing field is the
 * table's own statement that the call site is in a module. `sym` points at the
 * symbol; a symbol name never contains a space, so the tag is the bracketed
 * token after it. Anything else, including a truncated row, reads as kernel. */
static int row_names_a_module(const char *sym) {
  const char *p = strchr(sym, '[');

  if (!p || p == sym || p[-1] != ' ')
    return 0;
  p++;
  if (*p == ']')
    return 0; /* "[]" names nothing */
  while (*p && *p != ']' && *p != '\n')
    p++;
  return *p == ']';
}

/* Where the table may live, canonical first, each paired with the mount it sits
 * in. tracefs is a SINGLE-INSTANCE filesystem, so where both are mounted they
 * are one filesystem seen twice and the second can never hold a file the first
 * lacks.
 *
 * That is what decides how to read a failure, and it is easy to get backwards.
 * /sys/kernel/debug is root-only, so an unprivileged run that does not find the
 * table at the canonical path and then falls through collects an EACCES from
 * the debugfs mount point itself. That denial says nothing about whether the
 * table exists: it reports a blocked data source where the usual truth is a
 * kernel built without dynamic ftrace.
 *
 * What that costs is worth stating exactly, because it is easy to over- or
 * under-rate. Today it is the reported outcome and nothing further, because
 * the hardening report credits a denial -- to a sysctl knob, or to an enforcing
 * MAC policy -- only for a component that declares a sysctl gate, and this one
 * declares none. Declare a gate here and a spurious denial would begin
 * crediting a control that blocked nothing.
 *
 * So where the canonical mount is live its answer is the whole answer, and the
 * fallback is left alone; the fallback earns its place only when tracefs is not
 * mounted canonically, where a denial really is a denied data source. */
static const char *const MOUNTS[] = {
    "/sys/kernel/tracing",
    "/sys/kernel/debug/tracing",
};
static const char *const PATHS[] = {
    "/sys/kernel/tracing/available_filter_functions_addrs",
    "/sys/kernel/debug/tracing/available_filter_functions_addrs",
};
__extension__ _Static_assert(sizeof(PATHS) == sizeof(MOUNTS),
                             "every candidate path needs its mount");

/* Is a tracefs actually mounted here, or is this the bare directory the kernel
 * leaves behind as a mount point? A mounted one is populated; an unmounted one
 * is empty. Readability is part of the question rather than a precondition: a
 * directory that cannot be enumerated settles nothing, and answering 0 sends
 * the caller on to the fallback, which is the conservative direction. */
static int tracefs_live_at(const char *dir) {
  DIR *d = kasld_opendir(dir);
  struct dirent *ent;
  int populated = 0;

  if (!d)
    return 0;
  while ((ent = readdir(d)) != NULL)
    if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
      populated = 1;
      break;
    }
  closedir(d);
  return populated;
}

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
    if (errno == EACCES || errno == EPERM) {
      kasld_err("%s: permission denied", PATHS[i]);
      return KASLD_EXIT_NOPERM;
    }
    /* Not here -- and if this mount is live it answers for every other one, so
     * the table is not built into this kernel. Say that, rather than walking
     * into the next path's mount point and reporting whatever it says. */
    if (tracefs_live_at(MOUNTS[i])) {
      kasld_err("%s is mounted and carries no address table (kernel built "
                "without dynamic ftrace)",
                MOUNTS[i]);
      return KASLD_EXIT_UNAVAILABLE;
    }
  }
  if (!f) {
    kasld_err(
        "available_filter_functions_addrs not present (kernel without the "
        "ftrace addrs table, or tracefs unavailable)");
    return KASLD_EXIT_UNAVAILABLE;
  }

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
    /* Which region a row belongs to is STATED by the table, not inferred from
     * the address: ftrace appends " [<module>]" to the symbol for a module
     * function and nothing for a kernel one. Reading the address's band
     * instead misclassifies wherever the text validation window covers the
     * module region -- s390 carries a module band starting at 0, and arm64's
     * union spans most of the kernel VAS -- and a module call site accepted as
     * kernel text is an interior sample BELOW the real _text, which lowers the
     * image ceiling past the truth. The band check stays, demoted to what it
     * can soundly answer: whether the address is usable at all. */
    int is_mod = row_names_a_module(e);

    if (!is_mod && kasld_addr_is_kernel_text(a)) {
      if (!have_text || a < text_lo)
        text_lo = a;
      if (!have_text || a > text_hi)
        text_hi = a;
      have_text = 1;
    } else if (is_mod && kasld_addr_is_module_band(a)) {
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

    /* Both endpoints are interior to the image, so their distance is under the
     * footprint. A span below the plausibility floor says the table was too
     * sparse to bound anything, not that the kernel is tiny. */
    unsigned long span = text_hi - text_lo;
    if (span >= KIMG_MIN_BYTES) {
      kasld_info("ftrace call-site span: %lu bytes", span);
      kasld_emit_scalar(SF_IMAGE_SIZE_MIN, span, CONF_PARSED);
    }
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
