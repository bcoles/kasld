// This file is part of KASLD - https://github.com/bcoles/kasld
//
// The perf mmap ring, for any component that reads one.
//
// Five components open a perf event and drain its ring. What they do with the
// records differs completely -- branch stacks, ksymbol records, text-poke
// records, a sampled IP -- but two things do not: the syscall has no libc
// wrapper, and a record can straddle the end of the ring buffer and has to be
// read in two halves. Both live here, so a component reading a perf ring
// answers neither question for itself.
//
// What stays with the caller is everything the record type decides: the
// perf_event_attr, the ring's page count (a power of two, plus the metadata
// page -- the right number depends on how large that component's records are
// and how many it wants before wrap), the poll loop, the drain, and the bound
// on how much a single read asks for -- see kasld_ring_copy below.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_PERF_RING_H
#define KASLD_PERF_RING_H

#include <linux/perf_event.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* perf_event_open(2) ships no libc wrapper. */
static inline long kasld_perf_event_open(struct perf_event_attr *attr,
                                         pid_t pid, int cpu, int group_fd,
                                         unsigned long flags) {
  return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* Copy `n` bytes out of the ring at byte offset `off`, handling wrap.
 *
 * `n` must not exceed `ring_size`. A larger request wraps past the end of the
 * ring on the second copy and reads whatever follows it. The bound belongs to
 * the caller because only the caller knows it: the length comes from a record
 * header the kernel wrote, which is untrusted input to a reader, and every
 * caller already rejects a header claiming more than its own record cap before
 * asking for the bytes. Clamping here instead would turn a caller that lost
 * that check into a silently short read rather than a visible fault. */
static inline void kasld_ring_copy(const char *ring, size_t ring_size,
                                   uint64_t off, void *dst, size_t n) {
  size_t off_in = (size_t)(off % ring_size);
  size_t first = ring_size - off_in;
  if (first >= n) {
    memcpy(dst, ring + off_in, n);
  } else {
    memcpy(dst, ring + off_in, first);
    memcpy((char *)dst + first, ring, n - first);
  }
}

#endif /* KASLD_PERF_RING_H */
