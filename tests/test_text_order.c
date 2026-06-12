// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for the kernel-text ordering classifier (text_order.h):
//   classify_text_order() maps a kernel-config stream (+ the resolved nofgkaslr
//   flag) to a kasld_text_order class.
//
// Precedence: FG-KASLR (per-boot, dynamic) > static reorder (LTO/AutoFDO/
// Propeller) > canonical. nofgkaslr can only turn FG-KASLR off, never on. The
// class gates whether a generic System.map can resolve symbols, so a missed LTO
// (false canonical) is the dangerous failure -- the variant-config and
// prefix-guard cases pin that shut.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE /* fmemopen */

#include "include/text_order.h"
#include "test_harness.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Classify an in-memory config string (copied to a writable buffer so fmemopen
 * takes no const-cast). */
static enum kasld_text_order cls(const char *config, int nofgkaslr) {
  char buf[1024];
  size_t n = strlen(config);
  assert(n < sizeof(buf));
  memcpy(buf, config, n);
  FILE *f = fmemopen(buf, n, "r");
  assert(f);
  enum kasld_text_order o = classify_text_order(f, nofgkaslr);
  fclose(f);
  return o;
}

static void test_canonical(void) {
  assert(cls("CONFIG_RANDOMIZE_BASE=y\nCONFIG_X=y\n", 0) ==
         TEXT_ORDER_CANONICAL);
}

static void test_lto_is_static(void) {
  assert(cls("CONFIG_LTO_CLANG=y\nCONFIG_LTO_CLANG_THIN=y\n", 0) ==
         TEXT_ORDER_STATIC);
}

/* Belt-and-suspenders: a variant line alone (umbrella missing) still counts, so
 * a missed LTO can't masquerade as canonical. */
static void test_lto_variant_only_is_static(void) {
  assert(cls("CONFIG_LTO_CLANG_FULL=y\n", 0) == TEXT_ORDER_STATIC);
}

static void test_autofdo_is_static(void) {
  assert(cls("CONFIG_AUTOFDO_CLANG=y\n", 0) == TEXT_ORDER_STATIC);
}

static void test_propeller_is_static(void) {
  assert(cls("CONFIG_PROPELLER_CLANG=y\n", 0) == TEXT_ORDER_STATIC);
}

static void test_fgkaslr_is_dynamic(void) {
  assert(cls("CONFIG_FG_KASLR=y\n", 0) == TEXT_ORDER_DYNAMIC);
}

/* FG-KASLR (dynamic) outranks a co-present static reorder when active. */
static void test_dynamic_outranks_static(void) {
  assert(cls("CONFIG_FG_KASLR=y\nCONFIG_LTO_CLANG=y\n", 0) ==
         TEXT_ORDER_DYNAMIC);
}

/* nofgkaslr disables FG-KASLR -> falls back to whatever the static configs
 * imply: canonical when nothing else, static when LTO/etc. are also present. */
static void test_nofgkaslr_demotes(void) {
  assert(cls("CONFIG_FG_KASLR=y\n", 1) == TEXT_ORDER_CANONICAL);
  assert(cls("CONFIG_FG_KASLR=y\nCONFIG_AUTOFDO_CLANG=y\n", 1) ==
         TEXT_ORDER_STATIC);
}

/* The prefix guard: a longer config name that merely shares a prefix, and the
 * "=n" / "is not set" forms, must not match. */
static void test_prefix_and_value_guard(void) {
  assert(cls("CONFIG_LTO_CLANGXYZ=y\nCONFIG_FG_KASLR_FOO=y\n", 0) ==
         TEXT_ORDER_CANONICAL);
  assert(cls("CONFIG_LTO_CLANG=n\n# CONFIG_FG_KASLR is not set\n", 0) ==
         TEXT_ORDER_CANONICAL);
}

int main(void) {
  TEST_SUITE("Text-order classification (text_order.h)");
  BEGIN_CATEGORY("config -> class");
  RUN(test_canonical);
  RUN(test_lto_is_static);
  RUN(test_lto_variant_only_is_static);
  RUN(test_autofdo_is_static);
  RUN(test_propeller_is_static);
  RUN(test_fgkaslr_is_dynamic);
  RUN(test_dynamic_outranks_static);
  RUN(test_nofgkaslr_demotes);
  RUN(test_prefix_and_value_guard);
  return TEST_DONE();
}
