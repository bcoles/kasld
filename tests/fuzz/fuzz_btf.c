// libFuzzer harness for btf_struct_page_size's BTF reader — btf_struct_size()
// walks a binary blob (a fixed header carrying section offsets/lengths, then a
// type section whose records each carry kind-specific trailing data, then a
// string section) to find sizeof(struct page).
//
// Unlike the orchestrator string parsers this input is kernel-provided rather
// than attacker-supplied, but it is the most intricate binary walk in the tree,
// so fuzz the bounds checks (header + section bounds, per-record trailing skip,
// string-section name reads) against arbitrary / truncated bytes. ASan + UBSan
// flag any over-read, overflow, or unbounded loop.
//
// Run with the seed corpus:
//   build/fuzz/fuzz_btf tests/fuzz/corpus/btf/ -timeout=10 -max_len=65536

int btf_struct_page_main(int argc, char **argv);
#define main btf_struct_page_main
#include "../../src/components/btf_struct_page_size.c"
#undef main

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* btf_struct_size must never read past `size` for any input. Exercise the
   * production target ("page") and an absent name (which forces a full
   * type-section scan rather than an early match). */
  (void)btf_struct_size(data, size, "page");
  (void)btf_struct_size(data, size, "nonexistent_zzz");
  return 0;
}
