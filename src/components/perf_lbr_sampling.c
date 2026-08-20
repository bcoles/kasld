// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Capture kernel branch addresses via perf Last Branch Record sampling.
//
// The CPU's LBR (Last Branch Record) hardware records the most recent N
// branches the CPU executed. Modern Intel CPUs (Nehalem+) provide 16 entries;
// Sandy Bridge+ provides 32; AMD Zen+ provides similar. Each entry holds the
// `from` and `to` virtual address of one branch.
//
// perf_event_open() exposes LBR via:
//   sample_type        |= PERF_SAMPLE_BRANCH_STACK
//   branch_sample_type  = PERF_SAMPLE_BRANCH_KERNEL | PERF_SAMPLE_BRANCH_ANY
//   exclude_user        = 1
// On every PERF_RECORD_SAMPLE the kernel emits the LBR snapshot at the moment
// the sample fired, yielding 16–32 kernel branch addresses per sample. With
// sample_period = 10000 cycles and a child doing a busy syscall loop, this
// densely samples the syscall fast path — entry_SYSCALL_64, do_syscall_64,
// the syscall handler, and any helpers it touches.
//
// Gating: PERF_SAMPLE_BRANCH_KERNEL sets PERF_SAMPLE_BRANCH_PERM_PLM, which
// trips perf_allow_kernel() in perf_event_open() — paranoid<=1 OR CAP_PERFMON.
// The attr.exclude_user=1 path also goes through perf_allow_kernel for the
// same reason (it's about who is allowed to sample kernel state).
//
// Requires:
// - kernel.perf_event_paranoid <= 1 OR CAP_PERFMON
// - x86_64 with LBR-capable CPU (Intel Nehalem+, AMD Zen+)
//
// Leak primitive:
//   Data leaked:      kernel branch addresses (from / to per LBR entry)
//   Kernel subsystem: kernel/events + arch/x86/events — Last Branch Record
//   Data structure:   perf_branch_entry { from, to, flags }
//   Address type:     virtual (kernel text)
//   Method:           parsed (CPU hardware branch trace)
//   Access check:     perf_allow_kernel() — paranoid<=1 or CAP_PERFMON
//   Source:
//     https://elixir.bootlin.com/linux/v6.12/source/kernel/events/core.c
//     https://elixir.bootlin.com/linux/v6.12/source/arch/x86/events/intel/lbr.c
//
// Mitigations:
//   kernel.perf_event_paranoid >= 2 (default on most distros) blocks
//   unprivileged LBR. Bypass requires CAP_PERFMON (v5.8+) or CAP_SYS_ADMIN.
//
// x86_64 only — LBR is x86-specific hardware. ARM has BRBE (Branch Record
// Buffer Extension, v8.9+) with a different perf interface; not covered here.
// ---
// <bcoles@gmail.com>

#if !defined(__x86_64__)
#error "Architecture is not supported"
#endif

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/constraint.h"
#include "include/kasld/perf_branch.h"
#include <errno.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Opens a perf event with PERF_SAMPLE_BRANCH_STACK and "
    "branch_sample_type=KERNEL|ANY against a child process doing a busy "
    "syscall loop. Each PERF_RECORD_SAMPLE delivers the CPU's Last Branch "
    "Record snapshot (16-32 kernel branch addresses per sample). Gated by "
    "kernel.perf_event_paranoid <= 1 or CAP_PERFMON.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "live:1\n"
           "discloses:virtual\n"
           "sysctl:perf_event_paranoid>=2\n"
           "bypass:CAP_PERFMON\n"
           "bypass:CAP_SYS_ADMIN\n");

int main(int argc, char *argv[]) {
  kasld_cli(argc, argv);
  if (kasld_skip_live_probe("perf LBR"))
    return 0;
  int verbose = kasld_is_verbose();

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0)
    return KASLD_EXIT_UNAVAILABLE;

  kasld_info("trying perf LBR sampling on a busy-syscall child ...");

  pid_t child = fork();
  if (child == -1) {
    perror("[-] fork");
    return KASLD_EXIT_UNAVAILABLE;
  }
  if (child == 0) {
    /* Busy syscall loop — same shape as perf_event_open.c, gives the kernel
     * something to branch through on every sample. */
    struct utsname self;
    while (1)
      kasld_uname(&self);
    _exit(0);
  }

  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_HARDWARE;
  attr.config = PERF_COUNT_HW_CPU_CYCLES;
  attr.size = sizeof(attr);
  attr.sample_period = 10000;
  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_BRANCH_STACK;
  attr.branch_sample_type = PERF_SAMPLE_BRANCH_KERNEL | PERF_SAMPLE_BRANCH_ANY;
  attr.exclude_user = 1;
  attr.exclude_hv = 1;
  attr.disabled = 1;
  attr.wakeup_events = 1;

  long fd = kasld_perf_event_open(&attr, child, -1, -1, 0);
  if (fd < 0) {
    int e = errno;
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    if (e == EACCES || e == EPERM) {
      fprintf(stderr,
              "[-] perf_event_open EACCES - needs perf_event_paranoid<=1 or "
              "CAP_PERFMON\n");
      return KASLD_EXIT_NOPERM;
    }
    if (e == ENOENT || e == EOPNOTSUPP) {
      kasld_err("LBR not available on this CPU");
      return KASLD_EXIT_UNAVAILABLE;
    }
    errno = e;
    perror("[-] perf_event_open");
    return KASLD_EXIT_UNAVAILABLE;
  }

  /* Drain the ring: consider every branch endpoint (from AND to are kernel
   * under a BRANCH_KERNEL request), tracking the lowest kernel-text address. */
  struct kasld_perf_min acc = {
      .min_addr = ~0UL, .n = 0, .from_only = 0, .verbose = verbose};
  int n_samples = kasld_perf_branch_collect(
      (int)fd, page_size, KASLD_PERF_TARGET_SAMPLES, kasld_perf_min_cb, &acc);

  close((int)fd);
  kill(child, SIGKILL);
  waitpid(child, NULL, 0);

  if (n_samples < 0) {
    kasld_err("perf ring mmap/enable failed");
    return KASLD_EXIT_UNAVAILABLE;
  }
  if (acc.n == 0) {
    kasld_err("no kernel branch addresses captured");
    return KASLD_EXIT_UNAVAILABLE;
  }

  /* The captured branch address sits at image_base + offset (offset >= 0), a
   * sound interior witness: image_base <= min_addr on every arch. Emit it RAW
   * as the interior sample; range_from_interior turns the raw sample into a
   * sound C_UPPER_BOUND on Q_VIRT_IMAGE_BASE. Do NOT floor the sample here:
   * flooring an interior witness can drop the ceiling below the truth on
   * sub-offset arches, and any sound alignment tightening belongs on the
   * aligned image base in the engine, not on a text-region witness (see
   * rules/range_from_interior.c). */
  kasld_found("%lu kernel address(es) considered across %d sample(s)", acc.n,
              n_samples);
  kasld_info(
      "    lowest leaked kernel-text address: 0x%lx (upper bound on base)",
      acc.min_addr);
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, acc.min_addr, NULL,
                      CONF_PARSED);

  /* On large-page arches the lowest sample also brackets the base from below:
   * flooring it to the base grid lands on the image base whenever the lowest
   * sampled branch sits in the base's own slot, and one slot high otherwise —
   * so the base is the floored slot or one below it. Emit the lower bound
   * (floor - one slot) on the constraint channel at CONF_HEURISTIC so it shapes
   * only the speculative LIKELY window, never the guaranteed one; the interior
   * sample keeps the sound upper bound. A below-_text bound is not an address,
   * so the anchor rules never read it.
   * LBR is x86-only today (KASLR_VIRT_ALIGN = 2 MiB, so the gate always holds);
   * the gate keeps this correct-by-construction should LBR ever gain a finer
   * target, where flooring the lowest sample is not a within-one-slot guess. */
#if KASLR_VIRT_ALIGN >= 2 * MB
  kasld_emit_constraint(Q_VIRT_IMAGE_BASE, C_LOWER_BOUND,
                        kasld_floor_text_base(acc.min_addr) - KASLR_VIRT_ALIGN,
                        CONF_HEURISTIC);
#endif
  return 0;
}
