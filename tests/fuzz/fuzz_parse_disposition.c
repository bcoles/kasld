// libFuzzer harness for orchestrator's parse_disposition() — the disposition
// wire parser. Sibling of fuzz_capture_scalar; parse_disposition is pure (it
// writes only its out-param), so no global reset is needed.
//
// Wire format reference (see kasld_disposition in src/include/kasld/api.h):
//   cat=<category> [gate=<token>] [msg="<text>"]
// The input is the R-line body — the bytes AFTER the leading "R " that
// handle_component_line() strips before calling parse_disposition().
//
// Run with the seed corpus:
//   build/fuzz/fuzz_parse_disposition tests/fuzz/corpus/parse_disposition/ \
//     -timeout=10 -max_len=4096

#include "../../src/orchestrator.c"
#include "../../src/region_info.c"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size >= MAX_LINE_LEN)
    return 0;

  char *buf = malloc(size + 1);
  if (!buf)
    return 0;
  memcpy(buf, data, size);
  buf[size] = '\0';

  for (size_t i = 0; i < size; i++)
    if (buf[i] == '\n')
      buf[i] = '\0';

  struct component_disposition d;
  parse_disposition(buf, &d);

  free(buf);
  return 0;
}
