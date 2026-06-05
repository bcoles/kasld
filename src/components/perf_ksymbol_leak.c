// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Capture BPF JIT / kprobe / ftrace trampoline kernel addresses from perf
// side-band ksymbol records.
//
// The kernel emits a PERF_RECORD_KSYMBOL event each time it registers or
// unregisters a non-image kernel code region:
//
//   ksym_type=BPF  (1): BPF program load/unload, BPF trampoline add/remove
//                       (kernel/events/core.c, kernel/bpf/trampoline.c)
//   ksym_type=OOL  (2): kprobe out-of-line instruction page, ftrace
//                       trampoline alloc/free
//                       (kernel/kprobes.c, kernel/trace/ftrace.c)
//
// Kernel module loads do NOT emit PERF_RECORD_KSYMBOL — those go through
// PERF_RECORD_MMAP2. Each ksymbol record carries the kernel virtual address,
// length, type, and a NUL-terminated symbol name. perf_event_ksymbol_output()
// writes the address unmasked (no kallsyms_show_value gate).
//
// Subscription requires opening a side-band perf event (pid=-1, cpu>=0) with
// attr.ksymbol=1. attr.exclude_kernel=1 bypasses the perf_allow_kernel() check,
// but the pid=-1 path still routes through perf_allow_cpu(), which requires
// perf_event_paranoid<=0 for unprivileged users (or CAP_PERFMON).
//
// The component subscribes, polls for a short window, and emits one
// REGION_MODULE_REGION observation per ksymbol register record. The kernel
// virtual addresses BPF JIT pages, kprobe OOL pages, and ftrace trampolines
// occupy all live in the module region on every supported arch.
// Notification-driven: yields nothing if no BPF / kprobe / ftrace registration
// activity occurs during the window.
//
// CPU dispatch caveat: perf_iterate_sb_cpu() in kernel/events/core.c uses
// this_cpu_ptr(&pmu_sb_events) — an event opened on cpu=N only receives
// notifications fired while cpu N is the running CPU. The component therefore
// subscribes once per online CPU and aggregates all ring buffers; any other
// side-band-event consumer needs the same pattern.
//
// Triggering (manual verification, root required):
//
//   1. Ftrace tracer first-enable (one-shot per ops struct):
//        echo function_graph > /sys/kernel/tracing/current_tracer
//
//   2. New BPF program load (every load is a unique allocation — reliably
//      repeatable):
//        bpftool prog load <some.o> /sys/fs/bpf/test_N
//
//   3. Unique-named kprobe (fires only when a fresh kprobe_insn_page is
//      allocated, i.e. every ~256 slot):
//        echo "p:kasld_$$ schedule" >> /sys/kernel/tracing/kprobe_events
//
// One-shot caveat: many ftrace ops cache their trampoline pointer for the
// lifetime of the ops struct. Toggling the SAME tracer off and on does NOT
// reallocate — the existing trampoline pointer is reused and no
// PERF_RECORD_KSYMBOL fires on re-enable. To force a fresh notification,
// switch to a DIFFERENT tracer (different ops, different trampoline) or
// load a new BPF program. The same applies to kprobes: once a slot in a
// kprobe_insn_page is freed it is reused without a new page allocation, so
// no notification fires.
//
// Requires:
// - kernel.perf_event_paranoid <= 0
//
// Leak primitive:
//   Data leaked:      kernel module / BPF JIT virtual addresses
//   Kernel subsystem: kernel/events — perf side-band PERF_RECORD_KSYMBOL
//   Data structure:   perf_ksymbol_event (addr, len, ksym_type, name)
//   Address type:     virtual (kernel module region)
//   Method:           exact (perf record stream)
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
#include <errno.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Subscribes to perf side-band PERF_RECORD_KSYMBOL events with pid=-1, "
    "cpu=0, ksymbol=1. Each notification carries the kernel virtual address "
    "and name of a registered ksymbol (BPF program, BPF trampoline, kernel "
    "module). Gated by kernel.perf_event_paranoid: the system-wide path "
    "needs paranoid<=0 (or CAP_PERFMON). Notification-driven: yields nothing "
    "if no module/BPF activity occurs during the polling window.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "sysctl:perf_event_paranoid>=1\n"
           "bypass:CAP_PERFMON\n"
           "bypass:CAP_SYS_ADMIN\n");

/* Multi-page data ring: must be power-of-2 pages, plus the metadata page. */
#define DATA_PAGES 16

/* Polling window for ksymbol notifications. Side-band events fire only when
 * the kernel registers or unregisters a ksymbol; on a quiet system no event
 * may arrive within the window. */
#define POLL_MS 3000

/* Maximum on-stack copy buffer for one record. KSYMBOL records carry a
 * NUL-padded name; KSYM_NAME_LEN is 512 upstream, plus header (8) + addr (8)
 * + len (4) + type (2) + flags (2) + sample_id padding. 1024 covers it. */
#define MAX_RECORD 1024

static int perf_event_open_(struct perf_event_attr *attr, pid_t pid, int cpu,
                            int group_fd, unsigned long flags) {
  return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* PERF_RECORD_KSYMBOL wire layout (after the 8-byte perf_event_header):
 *   u64 addr
 *   u32 len
 *   u16 ksym_type
 *   u16 flags
 *   char name[]  (NUL-padded to u64 alignment)
 * See kernel/events/core.c:perf_event_ksymbol_output. */
struct __attribute__((packed)) ksymbol_payload {
  uint64_t addr;
  uint32_t len;
  uint16_t ksym_type;
  uint16_t flags;
  char name[];
};

/* PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER bit in the flags field. */
#define KSYM_FLAG_UNREGISTER 0x1

/* PERF_RECORD_KSYMBOL constant — pinned in the ABI; redefine in case the
 * installed headers don't expose it. */
#ifndef PERF_RECORD_KSYMBOL
#define PERF_RECORD_KSYMBOL 17
#endif
#ifndef PERF_RECORD_BPF_EVENT
#define PERF_RECORD_BPF_EVENT 18
#endif

/* Sanitise a ksymbol name for the wire format: the tagged-line parser
 * rejects whitespace, so trim at the first space or non-printable. */
static void sanitise_name(char *s, size_t max) {
  for (size_t i = 0; i < max; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == 0)
      return;
    if (c <= 0x20 || c >= 0x7f || c == ':') {
      s[i] = 0;
      return;
    }
  }
  s[max - 1] = 0;
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

/* Drain one ring buffer; emit observations; return count of new emissions. */
static int drain_ring(struct perf_event_mmap_page *meta, const char *ring,
                      size_t ring_size) {
  uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
  uint64_t tail = meta->data_tail;
  int emitted = 0;

  while (tail < head) {
    struct perf_event_header header;
    if (head - tail < sizeof(header))
      break;
    ring_copy(ring, ring_size, tail, &header, sizeof(header));
    if (header.size < sizeof(header) || header.size > MAX_RECORD)
      break;
    if (head - tail < header.size)
      break;

    if (header.type == PERF_RECORD_KSYMBOL) {
      char buf[MAX_RECORD];
      ring_copy(ring, ring_size, tail, buf, header.size);

      const struct ksymbol_payload *k = (const void *)(buf + sizeof(header));
      size_t name_off = sizeof(header) + sizeof(*k);
      if (name_off >= header.size) {
        tail += header.size;
        continue;
      }
      size_t name_max = header.size - name_off;
      char name_copy[256];
      size_t copy_len =
          name_max < sizeof(name_copy) ? name_max : sizeof(name_copy) - 1;
      memcpy(name_copy, buf + name_off, copy_len);
      name_copy[copy_len] = 0;
      sanitise_name(name_copy, sizeof(name_copy));

      if (!(k->flags & KSYM_FLAG_UNREGISTER) && k->addr != 0) {
        printf("[+] ksymbol: addr=0x%lx len=%u type=%u name=%s\n",
               (unsigned long)k->addr, k->len, k->ksym_type,
               name_copy[0] ? name_copy : "(anon)");
        kasld_result_sample(KASLD_TYPE_VIRT, REGION_MODULE_REGION,
                            (unsigned long)k->addr,
                            name_copy[0] ? name_copy : NULL, CONF_PARSED);
        emitted++;
      }
    }

    tail += header.size;
  }

  __atomic_store_n(&meta->data_tail, tail, __ATOMIC_RELEASE);
  return emitted;
}

int main(int argc, char *argv[]) {
  int poll_ms = POLL_MS;
  if (argc > 1) {
    char *endptr;
    long v = strtol(argv[1], &endptr, 10);
    if (*endptr != 0 || v < 100 || v > 600000) {
      fprintf(stderr,
              "usage: %s [poll_ms]   (default %d, valid range 100..600000)\n",
              argv[0], POLL_MS);
      return KASLD_EXIT_UNAVAILABLE;
    }
    poll_ms = (int)v;
  }

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
  attr.ksymbol = 1;
  attr.bpf_event = 1;
  attr.wakeup_events = 1; /* wake poll() on every record */

  /* Side-band events are dispatched via this_cpu_ptr(&pmu_sb_events) in
   * perf_iterate_sb_cpu(), so an event opened on cpu=N only receives ksymbol
   * notifications fired while cpu N is the current CPU. Subscribe on every
   * online CPU so notifications from any core are captured. */
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
      fprintf(stderr, "[-] perf_event_open EACCES — perf_event_paranoid > 0\n");
    else
      fprintf(stderr, "[-] perf_event_open failed on every cpu: %s\n",
              strerror(first_err));
    free(fds);
    free(maps);
    free(pfds);
    return rc;
  }

  printf("[.] subscribed to PERF_RECORD_KSYMBOL on %d cpu(s); polling %d ms "
         "...\n",
         opened, poll_ms);

  poll(pfds, (nfds_t)opened, poll_ms);

  int emitted = 0;
  for (int cpu = 0; cpu < ncpus; cpu++) {
    if (fds[cpu] < 0)
      continue;
    struct perf_event_mmap_page *meta = maps[cpu];
    const char *ring = (const char *)maps[cpu] + page_size;
    emitted += drain_ring(meta, ring, ring_size);
    munmap(maps[cpu], map_size);
    close(fds[cpu]);
  }

  free(fds);
  free(maps);
  free(pfds);

  if (emitted == 0) {
    printf("[-] no ksymbol events arrived in the polling window\n");
    return KASLD_EXIT_UNAVAILABLE;
  }

  printf("[+] %d ksymbol observation(s) emitted\n", emitted);
  return 0;
}
