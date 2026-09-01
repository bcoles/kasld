// This file is part of KASLD - https://github.com/bcoles/kasld
//
// The discard ledger: what left the pipeline, and why.
//
// A discarded record matters to the answer. The run resolved from a subset of
// the evidence that was available, so its residual-entropy figure overstates
// what KASLR retains, and a consumer that cannot see the discard reads a
// bounded answer as a complete one. One ledger records every such loss,
// whichever layer it happened in, so the fact has a single source rather than
// each layer reporting it on its own channel or not at all.
//
// A leaf: nothing here takes another lock or does I/O, which is what lets it be
// written from the component worker threads and read by the renderers without
// the callers coordinating.
// ---
// <bcoles@gmail.com>

#include "include/kasld/discard.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

/* -------------------------------------------------------------------------
 * The discard ledger's storage. Every path that drops evidence records here,
 * whichever layer it belongs to: the orchestrator's fixed-size buffers write
 * directly, and the engine's caps and rulings are projected in after the run by
 * discard_project_engine() so the engine stays pure.
 *
 * None of the orchestrator caps bind on realistic workloads; they are recorded
 * so growth is detected rather than absorbed.
 * -------------------------------------------------------------------------
 */
static struct kasld_discard discard_ledger[MAX_DISCARDS];
static int n_discards;
static int discards_truncated;
static unsigned int discards_total;

/* Defined after the lock below so it can take it: reset is a mutator like any
 * other, and a public one, so it does not rely on its callers happening to be
 * single-threaded. */

/* The ledger is written from the component worker threads (a rejected wire
 * line, an out-of-VAS address) as well as from single-threaded phases, so it
 * carries its own mutex.
 *
 * A LEAF: nothing here takes another lock or does I/O, so the only ordering in
 * play is result_mutex -> discard_mutex, taken by append_result() recording a
 * full results table. Nothing acquires result_mutex while holding this one, so
 * that edge cannot close into a cycle — the same one-way discipline the
 * result_mutex -> output_mutex pair already follows. */
#ifdef HAVE_PTHREAD
static pthread_mutex_t discard_mutex = PTHREAD_MUTEX_INITIALIZER;
#define DISCARD_LOCK() pthread_mutex_lock(&discard_mutex)
#define DISCARD_UNLOCK() pthread_mutex_unlock(&discard_mutex)
#else
#define DISCARD_LOCK() ((void)0)
#define DISCARD_UNLOCK() ((void)0)
#endif

void kasld_discard_reset(void) {
  DISCARD_LOCK();
  n_discards = 0;
  discards_truncated = 0;
  discards_total = 0;
  memset(discard_ledger, 0, sizeof(discard_ledger));
  DISCARD_UNLOCK();
}

void kasld_discard_record(enum kasld_discard_reason reason,
                          const char *source) {
  const char *src = (source && *source) ? source : "";
  if (reason < 0 || reason >= DISCARD__COUNT)
    return;
  DISCARD_LOCK();
  /* Counted before the aggregation cap, so the total stays truthful even once
   * the ledger stops taking new (reason, source) pairs. */
  discards_total++;
  for (int i = 0; i < n_discards; i++) {
    if (discard_ledger[i].reason == reason &&
        strncmp(discard_ledger[i].source, src, ORIGIN_LEN) == 0) {
      if (discard_ledger[i].count != UINT_MAX)
        discard_ledger[i].count++;
      DISCARD_UNLOCK();
      return;
    }
  }
  if (n_discards >= MAX_DISCARDS) {
    discards_truncated = 1;
    DISCARD_UNLOCK();
    return;
  }
  discard_ledger[n_discards].reason = reason;
  snprintf(discard_ledger[n_discards].source, ORIGIN_LEN, "%s", src);
  discard_ledger[n_discards].count = 1;
  n_discards++;
  DISCARD_UNLOCK();
}

int kasld_discard_count(void) { return n_discards; }

const struct kasld_discard *kasld_discard_at(int i) {
  if (i < 0 || i >= n_discards)
    return NULL;
  return &discard_ledger[i];
}

int kasld_discard_truncated(void) { return discards_truncated; }

unsigned int kasld_discard_total(void) { return discards_total; }

/* Wire names for the reason enum. Closed set; a new reason must be added here,
 * and the compiler's -Wswitch flags the omission. */
const char *kasld_discard_reason_name(enum kasld_discard_reason r) {
  switch (r) {
  case DISCARD_PARSE:
    return "parse";
  case DISCARD_BOUNDS:
    return "bounds";
  case DISCARD_CURATED:
    return "curated";
  case DISCARD_CONFLICT:
    return "conflict";
  case DISCARD_CAPACITY:
    return "capacity";
  case DISCARD__COUNT:
    break;
  }
  return "unknown";
}