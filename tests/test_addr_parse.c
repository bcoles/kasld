// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for the checked address parser (api.h): kasld_addr_parse().
//
// The property under test is refusal, not conversion. Kernel-supplied text can
// name an address this build has no room for — a 32-bit binary reading a PAE
// /proc/iomem, or any 64-bit kernel — and the C library's usual answers are
// both wrong for that: sscanf("%lx") reports success and hands back a
// truncated value, strtoul saturates to ULONG_MAX. Either becomes a plausible
// wrong address at CONF_PARSED, indistinguishable downstream from a correct
// one. The parser must reject instead.
//
// Runs under tests/test-cross on every width, which is what makes the
// too-wide cases meaningful: the same source is a genuine overflow on the
// 32-bit targets and a representable value on the 64-bit ones, so the tests
// derive their inputs from the build's own word size rather than hardcoding a
// width.
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "test_harness.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

/* A hex string one nibble wider than this build's address type: an address the
 * word provably cannot hold, whatever the word is. */
static const char *too_wide_hex(void) {
  static char buf[40];
  size_t nibbles = sizeof(kasld_addr_t) * 2 + 1;
  memset(buf, '1', 1);
  memset(buf + 1, '0', nibbles - 1);
  buf[nibbles] = '\0';
  return buf;
}

static void test_plain_hex(void) {
  kasld_addr_t v = 0;
  assert(kasld_addr_parse("ffff0000", 16, &v, NULL) == 1);
  assert(v == (kasld_addr_t)0xffff0000UL);
}

static void test_base_zero_honours_prefix(void) {
  kasld_addr_t v = 0;
  assert(kasld_addr_parse("0x1000", 0, &v, NULL) == 1);
  assert(v == (kasld_addr_t)0x1000);
  assert(kasld_addr_parse("4096", 0, &v, NULL) == 1);
  assert(v == (kasld_addr_t)4096);
}

static void test_decimal(void) {
  kasld_addr_t v = 0;
  /* /proc/<pid>/stat and the iscsi transport handle print decimal. */
  assert(kasld_addr_parse("18446744073709551615", 10, &v, NULL) ==
         (sizeof(kasld_addr_t) == 8));
  assert(kasld_addr_parse("4096", 10, &v, NULL) == 1);
  assert(v == (kasld_addr_t)4096);
}

/* The end pointer is what lets a caller walk "<addr>-<addr>" without sscanf. */
static void test_end_pointer_walks_a_range(void) {
  const char *line = "100000-1fffff : System RAM";
  kasld_addr_t lo = 0, hi = 0;
  const char *e = NULL;
  assert(kasld_addr_parse(line, 16, &lo, &e) == 1);
  assert(lo == (kasld_addr_t)0x100000);
  assert(*e == '-');
  assert(kasld_addr_parse(e + 1, 16, &hi, &e) == 1);
  assert(hi == (kasld_addr_t)0x1fffff);
  assert(*e == ' ');
}

/* No digits is a refusal, and the end pointer still marks where scanning
 * stopped so a caller can skip the field. */
static void test_no_digits_refused(void) {
  kasld_addr_t v = 0xa5;
  const char *e = NULL;
  assert(kasld_addr_parse(" : System RAM", 16, &v, &e) == 0);
  assert(v == (kasld_addr_t)0xa5); /* untouched on failure */
  assert(e != NULL);
  assert(kasld_addr_parse("", 16, &v, NULL) == 0);
}

/* The case this parser exists for: an address wider than the word. */
static void test_too_wide_is_refused(void) {
  kasld_addr_t v = 0xa5;
  assert(kasld_addr_parse(too_wide_hex(), 16, &v, NULL) == 0);
  assert(v == (kasld_addr_t)0xa5);
}

/* A PAE /proc/iomem line. On a 32-bit build both edges are unrepresentable and
 * must be refused — sscanf("%lx-%lx") reports success here and yields
 * 0x0-0x3fffffff, a believable region in the first gigabyte. On a 64-bit build
 * the same line parses exactly. */
static void test_pae_iomem_line(void) {
  const char *line = "100000000-13fffffff : System RAM";
  kasld_addr_t lo = 0, hi = 0;
  const char *e = NULL;
  int ok = kasld_addr_parse(line, 16, &lo, &e);
  if (sizeof(kasld_addr_t) >= 8) {
    assert(ok == 1);
    assert(lo == (kasld_addr_t)0x100000000ULL);
    assert(*e == '-');
    assert(kasld_addr_parse(e + 1, 16, &hi, NULL) == 1);
    assert(hi == (kasld_addr_t)0x13fffffffULL);
  } else {
    assert(ok == 0);
    /* The end pointer still advances past the digits, so a caller can find the
     * separator and report the whole line as unrepresentable rather than
     * mis-parsing its second half. */
    assert(*e == '-');
    assert(kasld_addr_parse(e + 1, 16, &hi, NULL) == 0);
  }
}

/* The word's own maximum is representable; one more is not. */
static void test_boundary_is_inclusive(void) {
  char buf[40];
  kasld_addr_t v = 0;
  snprintf(buf, sizeof(buf), "%llx", (unsigned long long)(kasld_addr_t)-1);
  assert(kasld_addr_parse(buf, 16, &v, NULL) == 1);
  assert(v == (kasld_addr_t)-1);
}

/* A stale errno from an earlier call must not be read as this call's overflow,
 * and a refusal must not leave errno set in a way a caller would misread. */
static void test_does_not_inherit_stale_errno(void) {
  kasld_addr_t v = 0;
  errno = ERANGE;
  assert(kasld_addr_parse("1000", 16, &v, NULL) == 1);
  assert(v == (kasld_addr_t)0x1000);
}

/* strtoull accepts a sign and NEGATES, so "-1" would convert to the word's
 * maximum with no ERANGE — a successful parse of a huge address from a field
 * that never legitimately carries one. Both signs are refused, and the end
 * pointer stays at the start so a caller cannot mistake it for progress. */
static void test_signed_input_refused(void) {
  kasld_addr_t v = 0xa5;
  const char *e = NULL;
  assert(kasld_addr_parse("-1", 16, &v, &e) == 0);
  assert(v == (kasld_addr_t)0xa5);
  assert(e != NULL && *e == '-');
  assert(kasld_addr_parse("-0009fbff", 16, &v, NULL) == 0);
  assert(kasld_addr_parse("+10", 16, &v, NULL) == 0);
  assert(kasld_addr_parse("  -1", 16, &v, NULL) == 0);
  assert(v == (kasld_addr_t)0xa5);
  /* Leading whitespace on an unsigned value is still accepted. */
  assert(kasld_addr_parse("  1000", 16, &v, NULL) == 1);
  assert(v == (kasld_addr_t)0x1000);
}

/* A refusal for width is distinguishable from a field that held no digits;
 * an accumulator uses that to know its aggregate is partial. */
static void test_refused_wide_is_distinguishable(void) {
  kasld_addr_t v = 0;
  const char *e = NULL;
  assert(kasld_addr_parse(too_wide_hex(), 16, &v, &e) == 0);
  assert(kasld_addr_refused_wide(too_wide_hex(), e) == 1);
  const char *none = " : System RAM";
  assert(kasld_addr_parse(none, 16, &v, &e) == 0);
  assert(kasld_addr_refused_wide(none, e) == 0);
}

int main(void) {
  TEST_SUITE("Checked address parser (kasld_addr_parse)");
  BEGIN_CATEGORY("conversion");
  RUN(test_plain_hex);
  RUN(test_base_zero_honours_prefix);
  RUN(test_decimal);
  RUN(test_end_pointer_walks_a_range);
  BEGIN_CATEGORY("refusal");
  RUN(test_no_digits_refused);
  RUN(test_too_wide_is_refused);
  RUN(test_pae_iomem_line);
  RUN(test_boundary_is_inclusive);
  RUN(test_does_not_inherit_stale_errno);
  RUN(test_signed_input_refused);
  RUN(test_refused_wide_is_distinguishable);
  return TEST_DONE();
}
