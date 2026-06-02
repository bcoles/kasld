// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Shared test harness — one RUN() macro and one category mechanism across all
// test binaries. Replaces the ad-hoc per-file copies that drifted over time.
//
// Output modes:
//   default tty            — pretty, colorised: category headers + per-test
//                            ✓/✗ + per-category summary line + suite total
//   stderr not a tty       — same content but no ANSI codes (CI / piped logs)
//   TEST_QUIET=1 env       — per-category one-liner only (no per-test lines);
//                            failures still printed in full
//
// Categories are optional: tests that never call BEGIN_CATEGORY get the
// implicit "(uncategorised)" bucket.
//
// Failure model: tests use plain assert(); a failing assert aborts the process
// (SIGABRT) and the "· name ... " line printed before the test ran is the
// breadcrumb. No setjmp/longjmp isolation — keeps the harness ~80 lines.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_TEST_HARNESS_H
#define KASLD_TEST_HARNESS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Suite state. Each test_main_*() shares these via the `static` translation
 * unit; the harness binary is a single .c, so per-file `static` is fine. */
static int th_total, th_pass;
static int th_cat_total, th_cat_pass;
static const char *th_cat_name = NULL;
static const char *th_suite = NULL;

static int th_use_color(void) { return isatty(2); }
#define TH_RED (th_use_color() ? "\033[31m" : "")
#define TH_GREEN (th_use_color() ? "\033[32m" : "")
#define TH_BOLD (th_use_color() ? "\033[1m" : "")
#define TH_DIM (th_use_color() ? "\033[2m" : "")
#define TH_RESET (th_use_color() ? "\033[0m" : "")

static int th_quiet(void) {
  static int q = -1;
  if (q < 0) {
    const char *e = getenv("TEST_QUIET");
    q = (e && *e && *e != '0') ? 1 : 0;
  }
  return q;
}

/* Print the category footer (final tally for the most-recently-opened
 * category). Idempotent: a second call before BEGIN_CATEGORY is a no-op. */
static void th_close_category(void) {
  if (!th_cat_name)
    return;
  int ok = th_cat_pass == th_cat_total;
  if (th_quiet()) {
    fprintf(stderr, "  %-44s %s%d/%d%s\n", th_cat_name, ok ? TH_GREEN : TH_RED,
            th_cat_pass, th_cat_total, TH_RESET);
  } else {
    fprintf(stderr, "  %s└─ %d/%d%s\n", TH_DIM, th_cat_pass, th_cat_total,
            TH_RESET);
  }
  th_cat_total = th_cat_pass = 0;
  th_cat_name = NULL;
}

/* Open a category. Closes the previous one if any. */
#define BEGIN_CATEGORY(name)                                                   \
  do {                                                                         \
    th_close_category();                                                       \
    th_cat_name = (name);                                                      \
    if (!th_quiet())                                                           \
      fprintf(stderr, "%s%s%s\n", TH_BOLD, th_cat_name, TH_RESET);             \
  } while (0)

/* Run a single test. */
#define RUN(t)                                                                 \
  do {                                                                         \
    th_total++;                                                                \
    th_cat_total++;                                                            \
    if (!th_quiet())                                                           \
      fprintf(stderr, "  %s·%s %-60s ", TH_DIM, TH_RESET, #t);                 \
    t();                                                                       \
    th_pass++;                                                                 \
    th_cat_pass++;                                                             \
    if (!th_quiet())                                                           \
      fprintf(stderr, "%s✓%s\n", TH_GREEN, TH_RESET);                          \
  } while (0)

/* Optional: name the suite for the header + final tally. Call once at the
 * top of main(). If never called, the suite header is omitted. */
#define TEST_SUITE(name)                                                       \
  do {                                                                         \
    th_suite = (name);                                                         \
    fprintf(stderr, "%s── %s ──%s\n", TH_BOLD, th_suite, TH_RESET);            \
  } while (0)

/* Final tally for this binary. Returns the exit code (0 ok, 1 fail). Call as
 * `return TEST_DONE();` from main(). */
static int th_done(void) {
  th_close_category();
  int ok = th_pass == th_total;
  fprintf(stderr, "%s%s%d/%d tests passed%s\n", ok ? TH_GREEN : TH_RED, TH_BOLD,
          th_pass, th_total, TH_RESET);
  return ok ? 0 : 1;
}
#define TEST_DONE() th_done()

#endif /* KASLD_TEST_HARNESS_H */
