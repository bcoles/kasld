// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Side-channel timing and cache primitives for x86_64.
//
// Shared by components that use Flush+Reload, TSX transactions,
// or prefetch timing to leak kernel address information.
//
// Timing primitives based on cacheutils.h by Daniel Gruss and Michael
// Schwarz (IAIK, TU Graz / isec-tugraz):
//   https://github.com/isec-tugraz/prefetch (Gruss, 2015)
// Extended with TSX and signal-based fault suppression:
//   https://github.com/isec-tugraz/ZombieLoad (Schwarz)
// Used in the EchoLoad / Data Bounce reference implementation:
//   https://github.com/cc0x1f/store-to-leak-forwarding-there-and-back-again
// ---
// <bcoles@gmail.com>

#ifndef KASLD_SIDECHANNEL_H
#define KASLD_SIDECHANNEL_H

#if !defined(__x86_64__) && !defined(__amd64__)
#error "sidechannel.h: x86_64 only"
#endif

#include "cpu.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* =========================================================================
 * Timing (rdtscp)
 * =========================================================================
 */

static size_t cache_miss_threshold;

static inline __attribute__((always_inline)) uint64_t rdtscp_time(void) {
  uint64_t lo, hi;
  __asm__ volatile("mfence\n\t"
                   "rdtscp\n\t"
                   "mov %%rax, %0\n\t"
                   "mov %%rdx, %1\n\t"
                   "mfence"
                   : "=r"(lo), "=r"(hi)
                   :
                   : "rax", "rcx", "rdx");
  return (hi << 32) | lo;
}

/* =========================================================================
 * Cache primitives (Flush+Reload)
 * =========================================================================
 */

static inline __attribute__((always_inline)) void maccess(volatile void *p) {
  __asm__ volatile("movq (%0), %%rax" : : "c"(p) : "rax");
}

static inline __attribute__((always_inline)) void flush(volatile void *p) {
  __asm__ volatile("clflush 0(%0)" : : "c"(p) : "rax");
}

__attribute__((unused))
static int flush_reload(volatile void *ptr) {
  uint64_t start, end;
  start = rdtscp_time();
  maccess(ptr);
  end = rdtscp_time();
  flush(ptr);
  return (end - start) < cache_miss_threshold;
}

__attribute__((unused))
static size_t detect_flush_reload_threshold(void) {
  size_t reload_time = 0, flush_reload_time = 0;
  const size_t count = 1000000;
  size_t dummy[16];
  volatile size_t *ptr = dummy + 8;

  maccess((volatile void *)ptr);
  for (size_t i = 0; i < count; i++) {
    uint64_t s = rdtscp_time();
    maccess((volatile void *)ptr);
    uint64_t e = rdtscp_time();
    reload_time += (size_t)(e - s);
  }
  for (size_t i = 0; i < count; i++) {
    flush((volatile void *)ptr);
    uint64_t s = rdtscp_time();
    maccess((volatile void *)ptr);
    uint64_t e = rdtscp_time();
    flush_reload_time += (size_t)(e - s);
  }
  reload_time /= count;
  flush_reload_time /= count;

  return (flush_reload_time + reload_time * 2) / 3;
}

/* =========================================================================
 * Probe array (Flush+Reload target — 256 pages, one per byte value)
 *
 * 1 MiB, page-aligned. Each of the 256 entries occupies one 4 KiB page
 * so that a cache hit on any entry cannot alias another.
 * =========================================================================
 */

__attribute__((unused))
static char __attribute__((aligned(4096))) probe[4096 * 256];

/* =========================================================================
 * TSX (RTM) transactional wrappers
 * =========================================================================
 */

static inline __attribute__((always_inline)) unsigned int xbegin_wrapper(void) {
  unsigned int status;
  __asm__ volatile(".byte 0xc7,0xf8,0x00,0x00,0x00,0x00"
                   : "=a"(status)
                   : "a"(-1UL)
                   : "memory");
  return status;
}

static inline __attribute__((always_inline)) void xend_wrapper(void) {
  __asm__ volatile(".byte 0x0f,0x01,0xd5" ::: "memory");
}

/* =========================================================================
 * Prefetch timing
 *
 * Issues prefetchnta + prefetcht2 on the target address bracketed by
 * serialising instructions (mfence/lfence) and timed with rdtscp.
 * The double-prefetch (NTA then T2) amplifies the timing differential
 * as described in Gruss et al.
 *
 * Measurement sequence based on EntryBleed PoC by Will:
 *   https://www.willsroot.io/2022/12/entrybleed.html
 * =========================================================================
 */

__attribute__((unused))
static uint64_t time_prefetch(uint64_t addr) {
  uint64_t t0_lo, t0_hi, t1_lo, t1_hi;

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
                   : "=r"(t0_lo), "=r"(t0_hi), "=r"(t1_lo), "=r"(t1_hi)
                   : "r"(addr)
                   : "rax", "rbx", "rcx", "rdx");

  uint64_t t0 = (t0_hi << 32) | t0_lo;
  uint64_t t1 = (t1_hi << 32) | t1_lo;
  return t1 - t0;
}

#endif /* KASLD_SIDECHANNEL_H */
