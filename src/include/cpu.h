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
  FILE *f = fopen("/proc/cpuinfo", "r");
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
  FILE *f = fopen("/proc/cpuinfo", "r");
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

__attribute__((unused)) static void pin_cpu(int cpu) {
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  sched_setaffinity(0, sizeof(set), &set);
}

#endif /* KASLD_CPU_H */
