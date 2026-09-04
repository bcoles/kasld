// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Does the target kernel address memory more widely than this build can
// represent?
//
// kasld_addr_t is the ANALYSING process's word standing in for the TARGET
// kernel's address width. They coincide in the ordinary case, and a 64-bit
// build cannot meet a 32-bit kernel — the kernel would not run the binary. The
// reverse does happen, and routinely: every 64-bit architecture keeps a 32-bit
// compat ABI (x86_64/IA32, arm64/AArch32, mips64/o32, ppc64, s390x, rv64), and
// a 64-bit kernel with a 32-bit userland is the normal Android arrangement, so
// a build chosen from the device's reported ABI lands here by default rather
// than by mistake.
//
// The parse layer already refuses an address wider than the word
// (kasld_addr_parse), so nothing wrong is emitted. What remains is the model:
// the arch header is selected by the BUILD's architecture, so a 32-bit build
// keeps reporting a 32-bit layout — its PAGE_OFFSET, its KASLR window, its
// module band — for a kernel that has none of them. On a coupled architecture
// the physical bounds, correctly read, are then projected through the wrong
// linear map into a virtual text window that cannot contain the truth.
//
// That is not fixable by parsing more carefully. It is fixable by noticing, so
// this header answers one question and the caller declines the run.
//
// TWO SIGNALS, NEITHER SUFFICIENT ALONE:
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
//               makes it the only signal available offline — and it is absent
//               exactly where a policy hides the file.
//
// Neither is a fallback for the other: each covers where the other cannot.
//
// UNKNOWN IS NOT A MISMATCH. Every path that cannot establish an answer returns
// "no mismatch proven", because declining a run the tool could have completed
// is a worse failure than the wide-but-honest window it would otherwise print.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_TARGET_WIDTH_H
#define KASLD_TARGET_WIDTH_H

#include "include/kasld/api.h"
#include "include/kasld/task_size.h"

#include <stdio.h>
#include <string.h>

enum kasld_width_verdict {
  KASLD_WIDTH_OK = 0,       /* no mismatch proven */
  KASLD_WIDTH_MISMATCH = 1, /* the target is wider than this build's word */
};

/* Which signal decided it, for the operator-facing message. */
enum kasld_width_signal {
  KASLD_WIDTH_SIGNAL_NONE = 0,
  KASLD_WIDTH_SIGNAL_TASK_SIZE,
  KASLD_WIDTH_SIGNAL_KALLSYMS,
};

struct kasld_width_check {
  enum kasld_width_verdict verdict;
  enum kasld_width_signal signal;
  unsigned long task_size; /* measured boundary, 0 when not measured */
  int kallsyms_hex_digits; /* width of the address column, 0 when unread */
};

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

/* Establish whether the target is wider than this build can represent.
 *
 * `facts` says where the run's facts come from. KASLD_FACTS_CAPTURE suppresses
 * the TASK_SIZE probe: mmap would measure the host running the analysis, not
 * the kernel the capture came from. Passed rather than read here so a test can
 * exercise both answers without staging a tree. */
static inline struct kasld_width_check
kasld_check_target_width(enum kasld_fact_source facts) {
  struct kasld_width_check r;
  memset(&r, 0, sizeof(r));

#if defined(__LP64__) || defined(_LP64)
  /* A 64-bit build cannot be narrower than its kernel: a 32-bit kernel would
   * not have loaded it. */
  (void)facts;
  return r;
#else
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
        r.verdict = KASLD_WIDTH_MISMATCH;
        r.signal = KASLD_WIDTH_SIGNAL_TASK_SIZE;
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
    r.verdict = KASLD_WIDTH_MISMATCH;
    r.signal = KASLD_WIDTH_SIGNAL_TASK_SIZE;
    return r;
  }
#endif

  /* Signal 2: the width of the kallsyms address column. Works against a
   * captured tree, and survives kptr_restrict; absent when a policy hides the
   * file, which is why it does not stand alone either. */
  r.kallsyms_hex_digits = kasld__kallsyms_hex_digits();
  if (r.kallsyms_hex_digits > (int)(sizeof(kasld_addr_t) * 2)) {
    r.verdict = KASLD_WIDTH_MISMATCH;
    r.signal = KASLD_WIDTH_SIGNAL_KALLSYMS;
  }
  return r;
#endif
}

/* One line naming what was observed, for the decline message. */
static inline const char *kasld_width_signal_name(enum kasld_width_signal s) {
  switch (s) {
  case KASLD_WIDTH_SIGNAL_TASK_SIZE:
    return "measured user/kernel boundary";
  case KASLD_WIDTH_SIGNAL_KALLSYMS:
    return "/proc/kallsyms address column";
  default:
    return "none";
  }
}

#endif /* KASLD_TARGET_WIDTH_H */
