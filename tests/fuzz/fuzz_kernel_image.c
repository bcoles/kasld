// libFuzzer harness for the kernel image-size readers in kasld/kernel_image.h.
//
// These walk on-disk binary formats at offsets the file itself supplies: an EFI
// zboot container names where its payload starts and ends, and an arm32 zImage
// names a table which in turn names where the inflated-size word sits. Every
// one of those is a chance to read somewhere the file does not reach, or to
// return an unrelated word as a size. The size facts bound the KASLR window in
// both directions, and the evidence layer takes the MINIMUM over upper bounds,
// so a wrong small value displaces the correct ones rather than merely being
// loose -- which makes a misparse here worse than no answer at all.
//
// Two layers are driven:
//   - the buffer parsers directly, so arbitrary bytes reach the offset
//     arithmetic with no file structure in the way;
//   - the file readers and the component through a KASLD_SYSROOT, so the
//     fseek/fread bounds are exercised on a real descriptor, which is where an
//     offset derived from file contents is actually used.
// ASan + UBSan flag any over-read or overflow; FUZZ_REQUIRE flags a value
// outside the contract the size rules are entitled to assume.
//
// Run with the seed corpus:
//   build/fuzz/fuzz_kernel_image tests/fuzz/corpus/kernel_image/ -max_len=65536

#define _DEFAULT_SOURCE         /* mkdtemp */
#define _POSIX_C_SOURCE 200809L /* setenv */

int kernel_image_facts_main(void);
#define main kernel_image_facts_main
#include "../../src/components/kernel_image_facts.c"
#undef main

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FUZZ_RELEASE "0.0.0-fuzz"

/* A violated invariant must stop the run whatever the build flags. The C
 * library assertion macro expands to nothing under NDEBUG, and a fuzz run whose
 * checks can vanish reports clean on the very tree it was meant to catch. */
#define FUZZ_REQUIRE(cond)                                                     \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "fuzz_kernel_image: invariant failed: %s\n", #cond);     \
      abort();                                                                 \
    }                                                                          \
  } while (0)

static char sysroot[512];
static char vmlinuz[768];

/* One sysroot for the whole run: KASLD_SYSROOT is resolved once and cached, so
 * it has to be set before the first reader call, and the staged /proc/version
 * fixes the release the readers build their paths from. */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;

  const char *tmp = getenv("TMPDIR");
  snprintf(sysroot, sizeof(sysroot), "%s/kasld-fuzz-kimg-XXXXXX",
           tmp && *tmp ? tmp : "/tmp");
  if (!mkdtemp(sysroot))
    return 0;

  char path[768];
  snprintf(path, sizeof(path), "%s/boot", sysroot);
  mkdir(path, 0755);
  snprintf(path, sizeof(path), "%s/proc", sysroot);
  mkdir(path, 0755);

  snprintf(path, sizeof(path), "%s/proc/version", sysroot);
  FILE *f = fopen(path, "w");
  if (f) {
    fprintf(f, "Linux version " FUZZ_RELEASE " (f@f) (gcc) #1 SMP\n");
    fclose(f);
  }

  snprintf(vmlinuz, sizeof(vmlinuz), "%s/boot/vmlinuz-" FUZZ_RELEASE, sysroot);
  setenv("KASLD_SYSROOT", sysroot, 1);
  return 0;
}

/* A size that reached a caller must be inside the plausibility band the readers
 * promise, whatever the input was. Outside it, a rule would subtract a figure
 * no kernel could have. */
static void check_band(unsigned long v) {
  if (v)
    FUZZ_REQUIRE(v >= KIMG_MIN_BYTES && v <= KIMG_MAX_BYTES);
}

/* A reader's value and the end it claims to bound must agree: a declined read
 * records no bound, an answer records one, and the value stays in the band. */
static void check_bound(unsigned long (*rd)(const char *,
                                            enum kasld_image_bound *),
                        const char *name) {
  enum kasld_image_bound b = KIMG_BOUND_EXACT; /* poisoned, not a valid reset */
  unsigned long v = rd(FUZZ_RELEASE, &b);
  (void)name;
  check_band(v);
  if (v)
    FUZZ_REQUIRE(b == KIMG_BOUND_EXACT || b == KIMG_BOUND_LOWER ||
                 b == KIMG_BOUND_UPPER);
  else
    FUZZ_REQUIRE(b == KIMG_BOUND_NONE);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Buffer parsers: arbitrary bytes straight into the offset arithmetic. The
   * file size is taken from the input so the bounds checks are driven with a
   * length that matches the buffer, and separately with lengths that do not --
   * a header consistent with a larger file than it came from is exactly what a
   * truncated download looks like. */
  struct kasld_zboot z;
  unsigned long sizes[] = {
      (unsigned long)size,        0,   56, (unsigned long)size / 2,
      (unsigned long)size + 4096, ~0UL};
  for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
    memset(&z, 0, sizeof(z));
    if (kasld_zboot_header(data, size, sizes[i], &z)) {
      /* Everything the parser returns must be usable as a file offset without
       * further checking: that is the contract its callers rely on. */
      FUZZ_REQUIRE(z.payload_off > 56 && z.payload_off < sizes[i]);
      FUZZ_REQUIRE(z.payload_size >= 64 &&
                   z.payload_size <= sizes[i] - z.payload_off);
      FUZZ_REQUIRE(z.size_trailer + 4 <= sizes[i]);
    }
  }

  check_band(kasld_image_extent_from_prefix(data, size, 0));
  check_band(kasld_image_extent_from_prefix(data, size, 1));

  /* File readers and the component, over the same bytes on disk. Writing the
   * input to the staged vmlinuz drives the fseek/fread paths, where an offset
   * taken from the file's own contents is turned into a real read. */
  if (!vmlinuz[0])
    return 0;
  FILE *f = fopen(vmlinuz, "wb");
  if (!f)
    return 0;
  if (size)
    fwrite(data, 1, size, f);
  fclose(f);

  /* Every reader reports which end of the footprint its answer bounds, and the
   * component emits each fact on that word alone. A reader that declines must
   * record no bound, and one that answers must record a real one -- either way
   * the pair must agree, or a figure reaches the end it does not prove. */
  check_bound(kasld_image_size_from_elf, "elf");
  check_bound(kasld_image_size_from_sysmap, "sysmap");
  check_bound(kasld_image_size_from_header, "header");
  check_bound(kasld_image_size_from_bzimage, "bzimage");
  check_bound(kasld_image_size_from_gzip, "gzip");
  check_bound(kasld_image_size_from_zimage, "zimage");
  check_bound(kasld_image_size_from_vmlinuz, "vmlinuz");

  /* The corroborated zboot reader decompresses a prefix, so it walks a real
   * decompressor over fuzzer bytes as well as the header arithmetic. */
  enum kasld_image_bound zb = KIMG_BOUND_NONE;
  check_band(zboot_exact_size(FUZZ_RELEASE, &zb));

  return 0;
}
