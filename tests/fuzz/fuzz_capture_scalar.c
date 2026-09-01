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

  num_results = 0;
  num_scalar_facts = 0;
  kasld_discard_reset();

  capture_scalar(buf, 0);

  free(buf);
  return 0;
}
