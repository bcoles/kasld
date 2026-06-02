// libFuzzer harness for orchestrator's capture_scalar() — the scalar-fact
// wire parser. Sibling of fuzz_capture_result; same input-conditioning and
// reset discipline.
//
// Wire format reference (see src/include/kasld/api.h):
//   S <fact> conf=<c> value=0x<hex>
//
// Run with the seed corpus:
//   build/fuzz/fuzz_capture_scalar tests/fuzz/corpus/capture_scalar/ \
//     -timeout=10 -max_len=4096

#include "../../src/orchestrator.c"
#include "../../src/region_info.c"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size >= LINE_LEN)
    return 0;

  char *buf = malloc(size + 1);
  if (!buf)
    return 0;
  memcpy(buf, data, size);
  buf[size] = '\0';

  for (size_t i = 0; i < size; i++)
    if (buf[i] == '\n')
      buf[i] = '\0';

  num_results = 0;
  num_scalar_facts = 0;
  orchestrator_saturation = 0;

  capture_scalar(buf, "fuzz");

  free(buf);
  return 0;
}
