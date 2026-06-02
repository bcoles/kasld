// libFuzzer harness for orchestrator's capture_result() — the tagged-line
// parser that consumes attacker-influenced bytes from component stdout.
//
// Wire format reference (see src/include/kasld/api.h):
//   <P|V> <region>[:<name>] pos=<pos> conf=<conf> [lo=<hex>]
//   [hi=<hex>|sz=<hex>]
//     [sample=<hex>] [base_align=<hex>]
//
// Build with the make fuzz target:
//   make fuzz FUZZ_CC=clang
//
// Run with the seed corpus:
//   build/fuzz/fuzz_capture_result tests/fuzz/corpus/capture_result/ \
//     -timeout=10 -max_len=4096

#include "../../src/orchestrator.c"
#include "../../src/region_info.c"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Bound the input shape to what the orchestrator's read loop would emit:
   * LINE_LEN-sized line, single-line (capture_result expects pre-tokenised
   * input — the read loop splits on '\n' before calling). */
  if (size == 0 || size >= LINE_LEN)
    return 0;

  char *buf = malloc(size + 1);
  if (!buf)
    return 0;
  memcpy(buf, data, size);
  buf[size] = '\0';

  /* Drop embedded newlines: the parser sees a single line at a time. */
  for (size_t i = 0; i < size; i++)
    if (buf[i] == '\n')
      buf[i] = '\0';

  /* Reset orchestrator state so results[] and scalar_facts[] do not grow
   * unbounded across iterations. Cap saturation flags too — a single fuzz
   * input shouldn't carry state from the previous one. */
  num_results = 0;
  num_scalar_facts = 0;
  orchestrator_saturation = 0;

  capture_result(buf, "fuzz", "fuzz");

  free(buf);
  return 0;
}
