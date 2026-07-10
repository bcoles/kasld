// This file is part of KASLD - https://github.com/bcoles/kasld
//
// CPU detection and feature query primitives for x86_64.
//
// Shared by side-channel components that need CPU vendor identification,
// KPTI detection, CPU feature checks, and core pinning.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_CPU_H
#define KASLD_CPU_H

#if !defined(__x86_64__) && !defined(__amd64__)
#error "cpu.h: x86_64 only"
#endif

#include "include/kasld/sysroot.h"

#include <cpuid.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * CPU vendor detection
 * =========================================================================
 */

#define CPU_VENDOR_UNKNOWN 0
#define CPU_VENDOR_AMD 1
#define CPU_VENDOR_INTEL 2

__attribute__((unused)) static bool is_intel_cpu(void) {
  unsigned int eax, ebx, ecx, edx;
  __asm__ volatile("cpuid"
                   : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                   : "a"(0)
                   :);
  /* "GenuineIntel" = EBX:EDX:ECX */
  return ebx == 0x756e6547 && edx == 0x49656e69 && ecx == 0x6c65746e;
}

__attribute__((unused)) static bool is_amd_cpu(void) {
  unsigned int eax, ebx, ecx, edx;
  __asm__ volatile("cpuid"
                   : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                   : "a"(0)
                   :);
  /* "AuthenticAMD": ebx="Auth", edx="enti", ecx="cAMD" */
  return ebx == 0x68747541 && edx == 0x69746e65 && ecx == 0x444d4163;
}

__attribute__((unused)) static int detect_cpu_vendor(void) {
  FILE *f = kasld_fopen("/proc/cpuinfo", "r");
  if (!f)
    return CPU_VENDOR_UNKNOWN;

  char *line = NULL;
  size_t len = 0;
  int cpu = CPU_VENDOR_UNKNOWN;
  while (getline(&line, &len, f) != -1) {
    if (strstr(line, "vendor") == NULL)
      continue;
    if (strstr(line, "AuthenticAMD") != NULL) {
      cpu = CPU_VENDOR_AMD;
      break;
    }
    if (strstr(line, "GenuineIntel") != NULL) {
      cpu = CPU_VENDOR_INTEL;
      break;
    }
  }
  free(line);
  fclose(f);
  return cpu;
}

/* =========================================================================
 * KPTI detection
 * =========================================================================
 */

__attribute__((unused)) static bool detect_kpti(void) {
  FILE *f = kasld_fopen("/proc/cpuinfo", "r");
  if (!f)
    return false;

  char *line = NULL;
  size_t len = 0;
  bool pti = false;
  while (getline(&line, &len, f) != -1) {
    if (strstr(line, "flags") == NULL)
      continue;
    if (strstr(line, " pti") != NULL) {
      pti = true;
      break;
    }
  }
  free(line);
  fclose(f);
  return pti;
}

/* =========================================================================
 * Paging-level detection
 * =========================================================================
 */

/* 5-level paging (LA57) active. The kernel exports the "la57" flag in
 * /proc/cpuinfo only when it is actually using 5-level paging (it clears the
 * feature otherwise, even on capable CPUs), so this reflects the live VA layout
 * — which selects between the L4 and L5 kernel region bases. */
__attribute__((unused)) static bool detect_la57(void) {
  FILE *f = kasld_fopen("/proc/cpuinfo", "r");
  if (!f)
    return false;

  char *line = NULL;
  size_t len = 0;
  bool la57 = false;
  while (getline(&line, &len, f) != -1) {
    if (strstr(line, "flags") == NULL)
      continue;
    if (strstr(line, " la57") != NULL) {
      la57 = true;
      break;
    }
  }
  free(line);
  fclose(f);
  return la57;
}

/* =========================================================================
 * CPU feature checks (CPUID)
 * =========================================================================
 */

__attribute__((unused)) static int has_rdtscp(void) {
  unsigned int eax, ebx, ecx, edx;
  __asm__ volatile("cpuid"
                   : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                   : "a"(0x80000001)
                   :);
  return (edx >> 27) & 1;
}

__attribute__((unused)) static int has_rtm(void) {
  unsigned int eax, ebx, ecx, edx;
  if (__get_cpuid_max(0, NULL) >= 7) {
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (ebx >> 11) & 1;
  }
  return 0;
}

/* =========================================================================
 * CPU pinning
 * =========================================================================
 */

/* Pin the calling thread to a single CPU for stable timing. `pref` is the
 * caller's preferred CPU; if it is not in the process's allowed affinity mask
 * — e.g. a cgroup cpuset or `taskset` excludes it — fall back to the lowest
 * allowed CPU. The old code hardcoded `pref` and ignored the failure, so under
 * such a cpuset the affinity was left unchanged and the probe ran across
 * several CPUs (noisy). Best-effort: on any error the affinity is left as-is.
 * Returns the CPU pinned to, or -1 (callers may note a -1 as "unpinned"). */
__attribute__((unused)) static int pin_cpu(int pref) {
  cpu_set_t allowed;
  CPU_ZERO(&allowed);
  if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0)
    return -1;

  int target = -1;
  if (pref >= 0 && pref < CPU_SETSIZE && CPU_ISSET(pref, &allowed)) {
    target = pref; /* preference is allowed — keep it */
  } else {
    for (int c = 0; c < CPU_SETSIZE; c++) {
      if (CPU_ISSET(c, &allowed)) {
        target = c; /* lowest allowed CPU */
        break;
      }
    }
  }
  if (target < 0)
    return -1;

  cpu_set_t one;
  CPU_ZERO(&one);
  CPU_SET(target, &one);
  if (sched_setaffinity(0, sizeof(one), &one) != 0)
    return -1;
  return target;
}

#endif /* KASLD_CPU_H */
