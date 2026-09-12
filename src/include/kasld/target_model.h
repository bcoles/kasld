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
//   provenance  extra/collect records the machine it ran on, and
//               extra/prepare-bundle carries that record into the tree it
//               prepares. It is the capture STATING where it came from, which
//               is the only thing that separates two architectures of equal
//               width, and it is present only in a tree prepared from a
//               bundle. Nothing about the kernel itself answers this: no
//               procfs or sysfs file names the machine, which is why uname's
//               .machine describes the analysing binary even on a replay.
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
  KASLD_MODEL_SIGNAL_PROVENANCE,
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

/* The verdict a signal returns when it proves a mismatch.
 *
 * Every signal answers the same question and differs only in what it read, so
 * each leaves through here rather than assigning the verdict itself. The two
 * fields cannot then drift apart: there is no way to record a mismatch that
 * does not say which signal reached it, and that is what selects both the
 * operator-facing message and the reported error code. */
static inline struct kasld_model_check
kasld__mismatch(struct kasld_model_check r, enum kasld_model_signal s) {
  r.verdict = KASLD_MODEL_MISMATCH;
  r.signal = s;
  return r;
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

/* The capture file extra/prepare-bundle writes into a tree it prepares.
 *
 * A dotfile at the root of the sysroot, which is not a path any kernel has —
 * deliberately, because nothing the kernel exposes answers this question. It is
 * the bundle's own meta.txt, carried across unchanged so the two cannot drift
 * into disagreeing about the same capture. */
#define KASLD_CAPTURE_FILE "/.kasld-capture"

/* The architecture a prepared capture records for itself, or "" if it records
 * none. The record states the machine in KASLD's own vocabulary, which is
 * KASLD_ARCH_NAME's set, so the comparison is a string equality and needs no
 * translation table.
 *
 * "unknown" is that field's answer for a machine collect did not recognise, and
 * is read as no answer rather than as a name. Comparing it would refuse a
 * capture that is merely unlabelled, including to the build that models it.
 *
 * A trailing el or eb is dropped because the field carried the byte order in
 * the earliest bundle layout, which recorded mips64el where the header is
 * mips64. The two orders share an arch header and resolve identical windows, so
 * the suffix names nothing this check is about. No architecture name ends in
 * either, which is what makes dropping it unambiguous. */
static inline void kasld__captured_arch(char *out, size_t out_len) {
  char line[256];
  FILE *f;

  out[0] = '\0';
  f = kasld_fopen(KASLD_CAPTURE_FILE, "r");
  if (!f)
    return;
  while (fgets(line, sizeof(line), f)) {
    char *v;
    size_t n;
    if (strncmp(line, "arch_canonical:", 15) != 0)
      continue;
    v = line + 15;
    while (*v == ' ' || *v == '\t')
      v++;
    n = strcspn(v, " \t\r\n");
    if (n == 0 || n >= out_len)
      break;
    memcpy(out, v, n);
    out[n] = '\0';
    if (strcmp(out, "unknown") == 0) {
      out[0] = '\0';
      break;
    }
    if (n > 2 &&
        (strcmp(out + n - 2, "el") == 0 || strcmp(out + n - 2, "eb") == 0))
      out[n - 2] = '\0';
    break;
  }
  fclose(f);
}

/* Establish whether this build models the target.
 *
 * `facts` says where the run's facts come from. KASLD_FACTS_CAPTURE suppresses
 * the TASK_SIZE probe: mmap would measure the host running the analysis, not
 * the kernel the capture came from. It is also what enables the two signals
 * that only a capture can trip. Passed rather than read here so a test can
 * exercise both answers without staging a tree. */
static inline struct kasld_model_check
kasld_check_target_model(enum kasld_fact_source facts) {
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
      if (split > (unsigned long)PAGE_OFFSET_MAX)
        return kasld__mismatch(r, KASLD_MODEL_SIGNAL_TASK_SIZE);
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
      r.task_size != (unsigned long)TASK_SIZE_EXACT)
    return kasld__mismatch(r, KASLD_MODEL_SIGNAL_TASK_SIZE);
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
                                      : r.kallsyms_hex_digits > build_digits))
      return kasld__mismatch(r, KASLD_MODEL_SIGNAL_KALLSYMS);
  }

  /* Signal 3: the architecture the capture records for itself. Two
   * architectures of equal width are invisible to everything above, and that
   * pair is the common case offline — a capture taken on one machine and read
   * on another. A capture recording nothing is not a mismatch. */
  if (facts == KASLD_FACTS_CAPTURE) {
    kasld__captured_arch(r.declared_arch, sizeof(r.declared_arch));
    if (r.declared_arch[0] && strcmp(r.declared_arch, KASLD_ARCH_NAME) != 0)
      return kasld__mismatch(r, KASLD_MODEL_SIGNAL_PROVENANCE);
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
  case KASLD_MODEL_SIGNAL_PROVENANCE:
    return "capture record";
  default:
    return "none";
  }
}

#endif /* KASLD_TARGET_MODEL_H */
