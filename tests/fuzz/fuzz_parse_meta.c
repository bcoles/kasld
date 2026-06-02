// libFuzzer harness for orchestrator's parse_meta() — reads
// newline-delimited key:value pairs from a component's .kasld_meta ELF
// section. The raw bytes are extracted from the component binary by
// extract_elf_section; this harness fuzzes the parse step that consumes
// those bytes after extraction.
//
// Run with the seed corpus:
//   build/fuzz/fuzz_parse_meta tests/fuzz/corpus/parse_meta/ \
//     -timeout=10 -max_len=4096

#include "../../src/orchestrator.c"
#include "../../src/region_info.c"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* ELF section payloads are bounded by extract_elf_section's 8 KiB sanity
   * cap; constrain fuzz inputs to the same scale. */
  if (size == 0 || size >= 8192)
    return 0;

  char *buf = malloc(size + 1);
  if (!buf)
    return 0;
  memcpy(buf, data, size);
  buf[size] = '\0';

  struct component_meta m = {0};
  parse_meta(buf, &m);

  free(buf);
  return 0;
}
