// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for pin_cpu() (cpu.h).
//
// pin_cpu() pins the side-channel probes to a single CPU for stable timing. It
// must pin to an ALLOWED CPU: under a cgroup cpuset (or `taskset`) that
// excludes the caller's preferred CPU, the old code hardcoded the preference,
// silently failed the sched_setaffinity, and left the probe running across
// several CPUs. These tests drive it against a restricted affinity mask and
// check it lands on an allowed CPU. Each test saves and restores the process
// affinity. cpu.h is x86_64-only, so the suite is inert elsewhere.
// ---
// <bcoles@gmail.com>

#if defined(__x86_64__) || defined(__amd64__)

#define _GNU_SOURCE /* cpu.h uses sched_getaffinity / CPU_ISSET / CPU_SETSIZE  \
                     */
#include "include/cpu.h"
#include "test_harness.h"

#include <assert.h>
#include <sched.h>

/* CPUs the process is currently allowed on, ascending. Returns the count. */
static int allowed_cpus(int *list, int max) {
  cpu_set_t m;
  CPU_ZERO(&m);
  if (sched_getaffinity(0, sizeof(m), &m) != 0)
    return 0;
  int n = 0;
  for (int c = 0; c < CPU_SETSIZE && n < max; c++)
    if (CPU_ISSET(c, &m))
      list[n++] = c;
  return n;
}

/* The single CPU the process is pinned to, or -1 if not pinned to exactly one.
 */
static int current_single_cpu(void) {
  cpu_set_t m;
  CPU_ZERO(&m);
  if (sched_getaffinity(0, sizeof(m), &m) != 0 || CPU_COUNT(&m) != 1)
    return -1;
  for (int c = 0; c < CPU_SETSIZE; c++)
    if (CPU_ISSET(c, &m))
      return c;
  return -1;
}

/* Preferred CPU is allowed -> keep it. */
static void test_pin_cpu_keeps_allowed_preference(void) {
  int cpus[64];
  int n = allowed_cpus(cpus, 64);
  if (n < 2)
    return; /* need a non-zero preferred CPU that exists */
  cpu_set_t orig;
  CPU_ZERO(&orig);
  sched_getaffinity(0, sizeof(orig), &orig);

  assert(pin_cpu(cpus[1]) == cpus[1]);
  assert(current_single_cpu() == cpus[1]);

  sched_setaffinity(0, sizeof(orig), &orig);
}

/* Preferred CPU excluded by the affinity mask -> fall back to the lowest
 * allowed CPU (the bug: the old code failed silently and stayed multi-CPU). */
static void test_pin_cpu_falls_back_when_pref_excluded(void) {
  int cpus[64];
  int n = allowed_cpus(cpus, 64);
  if (n < 2)
    return;
  cpu_set_t orig;
  CPU_ZERO(&orig);
  sched_getaffinity(0, sizeof(orig), &orig);

  /* Restrict to every allowed CPU except the first, then ask for the first. */
  cpu_set_t sub;
  CPU_ZERO(&sub);
  for (int i = 1; i < n; i++)
    CPU_SET(cpus[i], &sub);
  assert(sched_setaffinity(0, sizeof(sub), &sub) == 0);

  assert(pin_cpu(cpus[0]) == cpus[1]); /* excluded pref -> lowest allowed */
  assert(current_single_cpu() == cpus[1]);

  sched_setaffinity(0, sizeof(orig), &orig);
}

/* A single-CPU mask -> pin to that CPU regardless of the preference. */
static void test_pin_cpu_single_cpu_mask(void) {
  int cpus[64];
  int n = allowed_cpus(cpus, 64);
  if (n < 1)
    return;
  cpu_set_t orig;
  CPU_ZERO(&orig);
  sched_getaffinity(0, sizeof(orig), &orig);

  int only = cpus[n - 1];
  cpu_set_t one;
  CPU_ZERO(&one);
  CPU_SET(only, &one);
  assert(sched_setaffinity(0, sizeof(one), &one) == 0);

  assert(pin_cpu(0) == only); /* 0 may be excluded; only one choice anyway */
  assert(current_single_cpu() == only);

  sched_setaffinity(0, sizeof(orig), &orig);
}

int main(void) {
  TEST_SUITE("pin_cpu affinity");
  BEGIN_CATEGORY("cpuset-aware pinning");
  RUN(test_pin_cpu_keeps_allowed_preference);
  RUN(test_pin_cpu_falls_back_when_pref_excluded);
  RUN(test_pin_cpu_single_cpu_mask);
  return TEST_DONE();
}

#else /* cpu.h is x86_64-only */

#include "test_harness.h"

int main(void) {
  TEST_SUITE("pin_cpu affinity (x86_64 only - inert here)");
  return TEST_DONE();
}

#endif
