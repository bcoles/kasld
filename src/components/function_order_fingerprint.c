// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Kernel-text function-ordering fingerprint (kallsyms clustering heuristic).
//
// A traditional -O2 kernel places the functions of one source file
// contiguously, so a set of same-source-file symbols (the kernel/sys.c syscall
// wrappers) clusters within a tiny line-span of /proc/kallsyms. Heavy /
// per-boot text randomization (FG-KASLR and the like) scatters them across the
// whole symbol table. This measures that span as a ONE-SIDED "heavily
// reordered" flag.
//
// Calibrated against real kernels, one-sided by design:
//   span/total_T >= 30%  -> emit SF_TEXT_ORDER = TEXT_ORDER_DYNAMIC
//   (heuristic):
//                           non-canonical, consistent with per-boot
//                           randomization; a static System.map is unreliable.
//                           The cause cannot be determined from kallsyms alone.
//   span/total_T <  30%  -> ABSTAIN (emit nothing). A low span does NOT certify
//                           canonical order: deterministic link-time reordering
//                           (e.g. ThinLTO) reads well below 1% yet still needs
//                           a build-specific map. Map-safety is decided by the
//                           config detector, not here.
//
// Uses kallsyms NAME ORDER only, so it survives kptr_restrict<=1 (addresses
// zeroed, names/order intact) -- the config-locked-but-kallsyms-readable target
// where this is the only available signal.
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/cli.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* Per-arch same-source-file probe set: the kernel/sys.c syscall wrappers, which
 * exist in essentially every build. The arch syscall-wrapper prefix differs;
 * ppc/mips/loongarch have no wrapper macro, so the bare name is used. */
#if defined(__x86_64__)
#define SYS_PREFIX "__x64_sys_"
#elif defined(__i386__)
#define SYS_PREFIX "__ia32_sys_"
#elif defined(__aarch64__)
#define SYS_PREFIX "__arm64_sys_"
#elif defined(__riscv) && __riscv_xlen == 64
#define SYS_PREFIX "__riscv_sys_"
#elif defined(__s390x__) || defined(__s390__)
#define SYS_PREFIX "__s390_sys_"
#else
#define SYS_PREFIX "sys_"
#endif

static const char *const probe_tails[] = {
    "getpid",  "getppid", "getuid",      "geteuid",       "getgid",
    "getegid", "umask",   "sethostname", "setdomainname", "prctl",
};
#define NPROBE ((int)(sizeof(probe_tails) / sizeof(probe_tails[0])))

/* Minimums below which the span is statistically meaningless -> abstain. */
#define MIN_PROBES 6
#define MIN_T_SYMS 1000
#define REORDER_RATIO 0.30 /* span/total_T at/above which we flag reordered */

KASLD_EXPLAIN(
    "Measures how far the kernel/sys.c syscall wrappers are scattered across "
    "/proc/kallsyms. A traditional build clusters them within ~0.1% of the "
    "symbol table; heavy/per-boot text randomization (FG-KASLR-class) scatters "
    "them past 30%. One-sided: at >=30% emits SF_TEXT_ORDER=dynamic at "
    "heuristic "
    "confidence; below that it abstains (a low span does not certify canonical "
    "order -- link-time reordering like ThinLTO reads <1% yet still needs a "
    "build-specific System.map). Uses name order, so it survives "
    "kptr_restrict<=1 (addresses zeroed, names and order intact).");
/* method:detection — this detects a hardening *property* (text ordering); it
 * leaks no address, so it is excluded from the exposure/leak accounting. The
 * emitted fact's confidence is CONF_HEURISTIC (separate from the method). */
KASLD_META("method:detection\n"
           "phase:inference\n");

int main(void) {
  FILE *f = kasld_fopen("/proc/kallsyms", "r");
  if (!f) {
    kasld_err("kallsyms unreadable; cannot fingerprint function order");
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;
  }

  char full[NPROBE][64];
  long pos[NPROBE];
  for (int i = 0; i < NPROBE; i++) {
    snprintf(full[i], sizeof(full[i]), "%s%s", SYS_PREFIX, probe_tails[i]);
    pos[i] = -1;
  }

  char line[512], type, name[256];
  long t_index = 0;
  while (fgets(line, sizeof(line), f)) {
    /* Skip module symbols ("addr type name [module]"): the probes are all
     * core-kernel, and counting module symbols would make total_T (and thus the
     * ratio) depend on how many modules happen to be loaded. Core kernel only.
     */
    if (strchr(line, '['))
      continue;
    if (sscanf(line, "%*s %c %255s", &type, name) != 2)
      continue;
    if (type != 't' && type != 'T')
      continue;
    t_index++; /* 1-based position within the core-kernel T/t-symbol stream */
    for (int i = 0; i < NPROBE; i++)
      if (pos[i] < 0 && strcmp(name, full[i]) == 0) {
        pos[i] = t_index;
        break;
      }
  }
  fclose(f);

  /* Span over the probes that were found. */
  int found = 0;
  long lo = 0, hi = 0;
  for (int i = 0; i < NPROBE; i++) {
    if (pos[i] < 0)
      continue;
    if (!found || pos[i] < lo)
      lo = pos[i];
    if (!found || pos[i] > hi)
      hi = pos[i];
    found++;
  }

  if (found < MIN_PROBES || t_index < MIN_T_SYMS) {
    kasld_info("function order: insufficient data (%d/%d probes, %ld T-syms); "
               "abstaining",
               found, NPROBE, t_index);
    return 0;
  }

  double ratio = (double)(hi - lo) / (double)t_index;

  /* Span thresholds calibrated against real kernels (2026-06):
   *   -O2 (no reordering) ........ ~0.1%   clusters tightly
   *   ThinLTO .................... ~0.1%   still clusters (no false positive)
   *   ThinLTO + AutoFDO .......... ~11%    partial scatter (ambiguous)
   *   FG-KASLR (per-boot) ........ 60-78%  fully scattered
   * Only per-boot randomization crossed 30%; deterministic link-time reordering
   * (LTO/AutoFDO) stayed below it -- which is why <30% must ABSTAIN, never
   * assert "canonical": ThinLTO reads ~0.1% yet still needs a build-specific
   * map.
   *
   * NOT empirically verified: Propeller (CONFIG_PROPELLER_CLANG). It requires
   * an LLVM-19 toolchain that was unavailable at calibration time (the only
   * distro shipping it builds with LLVM 18 and disables the feature), so its
   * span was never measured. It orders function entries by hotness like
   * AutoFDO, so it is EXPECTED ~= AutoFDO (~11%, <30%) -- an assumption, not a
   * measurement. If a Propeller kernel ever reads >= 30%, revisit this
   * threshold. */
  if (ratio >= REORDER_RATIO) {
    kasld_info("function order: heavily reordered "
               "(kernel/sys.c span %.1f%% of %ld T-syms)",
               ratio * 100.0, t_index);
    kasld_emit_scalar(SF_TEXT_ORDER, TEXT_ORDER_DYNAMIC, CONF_HEURISTIC);
  } else {
    kasld_info(
        "function order: kernel/sys.c span %.1f%% below %.0f%% threshold; "
        "abstaining (not a canonical-order assertion)",
        ratio * 100.0, REORDER_RATIO * 100.0);
  }
  return 0;
}
