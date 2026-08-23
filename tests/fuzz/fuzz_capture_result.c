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
  if (size == 0 || size >= MAX_LINE_LEN)
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
   * unbounded across iterations, and clear the discard ledger with them: a
   * single fuzz input should not carry state from the previous one, and a
   * ledger left full would make every later iteration's caps look reached. */
  num_results = 0;
  num_scalar_facts = 0;
  kasld_discard_reset();

  capture_result(buf, "fuzz", 0);

  free(buf);
  return 0;
}
