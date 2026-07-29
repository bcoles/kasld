// This file is part of KASLD - https://github.com/bcoles/kasld
//
// kasld_fnv1a64 — FNV-1a-64 over a NUL-terminated string.
//
// Keys the per-build offset tables (qemu_tcg_iret and other uname-fingerprint
// components) on a compact 64-bit hash of the trimmed "<release> <version>"
// fingerprint instead of the full string, to keep the tables small. The
// generator that emits those tables must compute the identical hash, so the two
// stay a single algorithm split across languages; tests/check-hash-parity
// recomputes every shipped row's hash from its uname comment to catch any
// drift.
//
// Parity vector: kasld_fnv1a64("6.8.0-134-generic #134-Ubuntu SMP "
// "PREEMPT_DYNAMIC Fri Jun 26 18:43:11 UTC 2026") == 0x99d7d97f07f75fba.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_HASH_H
#define KASLD_HASH_H

#include <stdint.h>

/* FNV-1a-64. The (unsigned char) cast is load-bearing: a byte >= 0x80 must not
 * sign-extend, or the hash would diverge from the generator's over any
 * non-ASCII input. */
static inline uint64_t kasld_fnv1a64(const char *s) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (; *s; s++) {
    h ^= (unsigned char)*s;
    h *= 0x100000001b3ULL;
  }
  return h;
}

#endif /* KASLD_HASH_H */
