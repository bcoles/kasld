// libFuzzer harness for orchestrator's parse_hex() — the 0x-prefixed
// hex-integer parser used by capture_result and capture_scalar.
//
// Contract: returns 1 + writes the parsed value to *out on success,
// returns 0 on any malformed input (wrong prefix, errno, trailing chars).
//
// Run with the seed corpus:
//   build/fuzz/fuzz_parse_hex tests/fuzz/corpus/parse_hex/ \
//     -timeout=10 -max_len=64

#include "../../src/orchestrator.c"
#include "../../src/region_info.c"

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
