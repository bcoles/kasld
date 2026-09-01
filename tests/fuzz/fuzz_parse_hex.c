// libFuzzer harness for orchestrator's parse_hex() — the 0x-prefixed
// hex-integer parser used by capture_result and capture_scalar.
//
// Contract: returns 1 + writes the parsed value to *out on success,
// returns 0 on any malformed input (wrong prefix, errno, trailing chars).
//
// Run with the seed corpus:
//   build/fuzz/fuzz_parse_hex tests/fuzz/corpus/parse_hex/ \
//     -timeout=10 -max_len=64

#include "../../src/capture.c"
#include "../../src/discard.c"
#include "../../src/region_info.c"

/* capture.c calls outward to five orchestrator-owned symbols: the discard
 * origin-name lookup and the store lock. Stubbing them keeps this harness
 * pointed at the parsers alone rather than compiling the orchestrator around
 * them. Neither affects a parse decision: the name is for display, and the lock
 * is uncontended in a single-threaded harness. The discard ledger is taken for
 * real -- it is a leaf, so a rejected record still lands where it would in a
 * live run. */
const char *kasld_origin_name(int idx) {
  (void)idx;
  return "";
}
void kasld_result_lock(void) {}
void kasld_result_unlock(void) {}

/* The two output flags capture reads before reporting a rejection, and the
 * reporter itself. A harness prints nothing, so these are inert -- but they are
 * the parser's only remaining reach outside its own translation unit, and
 * naming them here keeps that surface visible rather than implied. */
int verbose = 0;
int quiet = 1;
__attribute__((format(printf, 1, 2))) void progress_note(const char *fmt, ...) {
  (void)fmt;
}

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Hex tokens are short. Caller-side callers pass values that fit in an
   * unsigned long; this cap keeps fuzzing focused on the parser, not on
   * pathological string lengths. */
  if (size == 0 || size >= 64)
    return 0;

  char buf[64];
  memcpy(buf, data, size);
  buf[size] = '\0';

  unsigned long out;
  parse_hex(buf, &out);
  return 0;
}
