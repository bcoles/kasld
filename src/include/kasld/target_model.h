// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Does this build model the kernel being analysed?
//
// The arch header is selected by the ANALYSING binary's architecture, and it
// supplies the whole layout model: PAGE_OFFSET, the KASLR window, the module
// band, the address width. Where the binary and the kernel are the same
// machine those answers describe the kernel too. Where they are not, every
// window resolved from them describes an address space the kernel does not
// have — a GUARANTEED window that cannot contain the base, which is the one
// output this tool must never produce.
//
// Live, the two can only disagree about WIDTH, and only one way round: a
// 64-bit kernel running a 32-bit binary. Every 64-bit architecture keeps a
// 32-bit compat ABI (x86_64/IA32, arm64/AArch32, mips64/o32, ppc64, s390x,
// rv64), and a 64-bit kernel with a 32-bit userland is the normal Android
// arrangement, so a build chosen from the device's reported ABI lands here by
// default rather than by mistake. A foreign ARCHITECTURE cannot arise: the
// kernel would not have loaded the binary.
//
// Under KASLD_SYSROOT no kernel loads anything. The facts come from a captured
// tree that may have been taken from any machine, so both disagreements are
// reachable, in both directions — and the arch one is the likely one, since
// the point of a capture is to analyse it somewhere else.
//
// That is not fixable by parsing more carefully. It is fixable by noticing, so
// this header answers one question and the caller declines the run.
//
// THREE SIGNALS, NONE SUFFICIENT ALONE:
//
//   TASK_SIZE   mmap refuses at or above the user/kernel boundary, and no
//               policy can make it accept — this is the signal that survives a
//               mandatory access control policy denying every /proc source.
//               But it measures the kernel the process is RUNNING on, so it
//               says nothing about a captured tree and must not be consulted
//               under KASLD_SYSROOT.
//   kallsyms    /proc/kallsyms prints its address column at the KERNEL's width,
//               zero-padded, so the column is 16 characters on a 64-bit kernel
//               even when kptr_restrict has masked every value to zero. Being a
//               file read it describes whichever tree is being analysed, which
//               makes it the only width signal available offline — and it is
//               absent exactly where a policy hides the file.
//   kconfig     a kernel built for architecture X sets CONFIG_X=y, so a
//               captured config is the kernel NAMING ITS OWN architecture
//               rather than anything inferred from a file's shape. It is the
//               only signal that separates two architectures of equal width,
//               and it is present only where the config was captured.
//
// None is a fallback for another: each covers where the others cannot.
//
// UNKNOWN IS NOT A MISMATCH. Every path that cannot establish an answer returns
// "no mismatch proven", because declining a run the tool could have completed
// is a worse failure than the wide-but-honest window it would otherwise print.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_TARGET_MODEL_H
#define KASLD_TARGET_MODEL_H

#include "include/kasld/api.h"
#include "include/kasld/task_size.h"

#include <stdio.h>
#include <string.h>

enum kasld_model_verdict {
  KASLD_MODEL_OK = 0,       /* no mismatch proven */
  KASLD_MODEL_MISMATCH = 1, /* this build does not model the target */
};

/* Which signal decided it, for the operator-facing message. The width signals
 * and the architecture signal reach the same verdict for different reasons and
 * call for different corrective action, so the caller reports them apart. */
enum kasld_model_signal {
  KASLD_MODEL_SIGNAL_NONE = 0,
  KASLD_MODEL_SIGNAL_TASK_SIZE,
  KASLD_MODEL_SIGNAL_KALLSYMS,
  KASLD_MODEL_SIGNAL_KCONFIG,
};

struct kasld_model_check {
  enum kasld_model_verdict verdict;
  enum kasld_model_signal signal;
  unsigned long task_size; /* measured boundary, 0 when not measured */
  int kallsyms_hex_digits; /* width of the address column, 0 when unread */
  char
      declared_arch[24]; /* the arch the capture named, "" when it named none */
};

/* Whether a signal names the address width rather than the architecture. */
static inline int kasld_model_signal_is_width(enum kasld_model_signal s) {
  return s == KASLD_MODEL_SIGNAL_TASK_SIZE || s == KASLD_MODEL_SIGNAL_KALLSYMS;
}

/* The kernel prints kallsyms addresses zero-padded to its own pointer width, so
 * the leading run of hex digits is 2 * sizeof(kernel pointer). Returns that
 * count, or 0 when the file could not be read or the first line does not start
 * with a hex column.
 *
 * Deliberately reads the WIDTH and not the value: kptr_restrict masks the
 * digits to zeros but does not change how many there are. */
static inline int kasld__kallsyms_hex_digits(void) {
  FILE *f = kasld_fopen("/proc/kallsyms", "r");
  if (!f)
    return 0;
  char line[256];
  int n = 0;
  if (fgets(line, sizeof(line), f)) {
    while (line[n] && ((line[n] >= '0' && line[n] <= '9') ||
                       (line[n] >= 'a' && line[n] <= 'f') ||
                       (line[n] >= 'A' && line[n] <= 'F')))
      n++;
    /* A column, not a stray token: the digits must be followed by the space
     * that separates them from the symbol type. */
    if (line[n] != ' ')
      n = 0;
  }
  fclose(f);
  return n;
}

/* Whether a config line is exactly `CONFIG_<id>=y`, so CONFIG_ARM does not
 * match on a line reading CONFIG_ARM_SMMU=y. */
static inline int kasld__kconfig_declares(const char *line, const char *id) {
  size_t n = strlen(id);
  if (strncmp(line, "CONFIG_", 7) != 0 || strncmp(line + 7, id, n) != 0)
    return 0;
  return line[7 + n] == '=' && line[8 + n] == 'y';
}

/* The architecture a captured kernel declares for itself.
 *
 * Read from /boot/config-<release> and no other path. An unkeyed /boot/config
 * carries no binding to any particular kernel — it may be a leftover or a
 * rescue image — and refusing a run on a file that describes a different kernel
 * would be the same error in the opposite direction. /proc/config.gz answers
 * the same question but needs a decompressor this caller does not link.
 *
 * Sets `declared_arch` and returns 1 only on POSITIVE evidence: this build's
 * identifier absent AND a different one present. Absence alone decides nothing,
 * because a captured file is restored to its true length with whatever prefix
 * was collected, so the line naming the architecture may simply not be there.
 */
static inline int kasld__declared_arch_differs(const char *release, char *out,
                                               size_t out_len) {
#define KASLD__ID_ENTRY(s) s,
  static const char *const ids[] = {KASLD_KCONFIG_IDS(KASLD__ID_ENTRY)};
#undef KASLD__ID_ENTRY
  char path[320];
  char line[256];
  const char *other = NULL;
  int mine = 0;
  FILE *f;

  if (!release || !*release)
    return 0;
  if (snprintf(path, sizeof(path), "/boot/config-%s", release) >=
      (int)sizeof(path))
    return 0;
  f = kasld_fopen(path, "r");
  if (!f)
    return 0;

  while (fgets(line, sizeof(line), f)) {
    size_t i;
    for (i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
      if (!kasld__kconfig_declares(line, ids[i]))
        continue;
      if (strcmp(ids[i], KASLD_KCONFIG_ID) == 0)
        mine = 1;
      else if (!other)
        other = ids[i];
    }
  }
  fclose(f);

  if (mine || !other)
    return 0;
  snprintf(out, out_len, "%s", other);
  return 1;
}

/* Establish whether this build models the target.
 *
 * `facts` says where the run's facts come from. KASLD_FACTS_CAPTURE suppresses
 * the TASK_SIZE probe: mmap would measure the host running the analysis, not
 * the kernel the capture came from. It is also what enables the two signals
 * that only a capture can trip. `release` identifies the captured kernel, for
 * the config path; pass NULL when none is known. Both are passed rather than
 * read here so a test can exercise every answer without staging a tree. */
static inline struct kasld_model_check
kasld_check_target_model(enum kasld_fact_source facts, const char *release) {
  struct kasld_model_check r;
  const int build_digits = (int)(sizeof(kasld_addr_t) * 2);
  memset(&r, 0, sizeof(r));

#if !defined(__LP64__) && !defined(_LP64)
  /* Signal 1: the measured user/kernel boundary against the highest this
   * architecture's own 32-bit kernels can place it. TASK_SIZE never exceeds
   * PAGE_OFFSET (arm32 leaves a 16 MiB gap, riscv32 the whole fixmap stack), so
   * a boundary ABOVE the highest split is not a wide-split kernel — it is a
   * kernel whose user half is the compat window of a 64-bit address space. */
  if (facts == KASLD_FACTS_LIVE) {
    unsigned long split = 0;
    enum kasld_ts_status st = kasld_task_size_probe(&split);
    if ((st == KASLD_TS_EXACT || st == KASLD_TS_APPROX) && split != 0) {
      r.task_size = split;
      if (split > (unsigned long)PAGE_OFFSET_MAX) {
        r.verdict = KASLD_MODEL_MISMATCH;
        r.signal = KASLD_MODEL_SIGNAL_TASK_SIZE;
        return r;
      }
    }
  }

  /* Signal 1b: where the architecture fixes the boundary rather than offering a
   * choice of splits, the measurement has an exact expectation, and any other
   * value is a kernel this build does not model. mips is the case that needs
   * it: its o32 compat boundary (0x7fff8000) sits BELOW the native one, so the
   * highest-split comparison above cannot see it, and without this the arch
   * would rest entirely on a kallsyms file a policy may hide.
   *
   * An architecture may only declare TASK_SIZE_EXACT when its split is fixed
   * AND its linear map begins at the boundary. riscv32 meets the first and not
   * the second — the fixmap/PCI-IO/vmemmap stack sits between TASK_SIZE and
   * PAGE_OFFSET — so declaring it there would refuse every native kernel. */
#ifdef TASK_SIZE_EXACT
  if (facts == KASLD_FACTS_LIVE && r.task_size != 0 &&
      r.task_size != (unsigned long)TASK_SIZE_EXACT) {
    r.verdict = KASLD_MODEL_MISMATCH;
    r.signal = KASLD_MODEL_SIGNAL_TASK_SIZE;
    return r;
  }
#endif
#endif /* !LP64 */

  /* Signal 2: the width of the kallsyms address column.
   *
   * Live, only a WIDER target is reachable — a kernel narrower than this binary
   * could not have loaded it — so a 64-bit build has nothing to look for there
   * and does not open the file. Offline nothing was loaded by anything, so the
   * capture may sit on either side and ANY difference is a mismatch. An absent
   * or unparsable column stays silent: that is the Android shape, where a
   * policy hides the file. */
  if (facts == KASLD_FACTS_CAPTURE || build_digits < 16) {
    r.kallsyms_hex_digits = kasld__kallsyms_hex_digits();
    if (r.kallsyms_hex_digits != 0 &&
        (facts == KASLD_FACTS_CAPTURE ? r.kallsyms_hex_digits != build_digits
                                      : r.kallsyms_hex_digits > build_digits)) {
      r.verdict = KASLD_MODEL_MISMATCH;
      r.signal = KASLD_MODEL_SIGNAL_KALLSYMS;
      return r;
    }
  }

  /* Signal 3: the architecture the captured kernel declares. Two architectures
   * of equal width are invisible to everything above, and that pair is the
   * common case offline — a capture taken on one machine and read on another.
   */
  if (facts == KASLD_FACTS_CAPTURE &&
      kasld__declared_arch_differs(release, r.declared_arch,
                                   sizeof(r.declared_arch))) {
    r.verdict = KASLD_MODEL_MISMATCH;
    r.signal = KASLD_MODEL_SIGNAL_KCONFIG;
  }
  return r;
}

/* One line naming what was observed, for the decline message. */
static inline const char *kasld_model_signal_name(enum kasld_model_signal s) {
  switch (s) {
  case KASLD_MODEL_SIGNAL_TASK_SIZE:
    return "measured user/kernel boundary";
  case KASLD_MODEL_SIGNAL_KALLSYMS:
    return "/proc/kallsyms address column";
  case KASLD_MODEL_SIGNAL_KCONFIG:
    return "captured kernel config";
  default:
    return "none";
  }
}

#endif /* KASLD_TARGET_MODEL_H */
