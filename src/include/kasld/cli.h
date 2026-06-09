// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Standard component command-line options + levelled diagnostics. Header-only:
// components are standalone single-TU binaries with no shared object to link,
// so this mirrors api.h's all-static-inline style. Include it explicitly in a
// component that takes options or wants the logger; it is NOT pulled in by
// api.h, so a component that ignores it pays nothing.
//
// Contract:
//   * stdout is the MACHINE channel — only wire lines (P/V/S via the
//     kasld_result_* / kasld_emit_scalar helpers). Never a human message.
//   * stderr is the HUMAN channel — every diagnostic, via the macros below.
//   * options are MANUAL (testing / debugging); the orchestrator passes none
//     and sets no env. A component's -t budget is its own; it is deliberately
//     NOT kasld's per-component kill timeout (different roles — see the
//     dev/proposals note).
// ---
// <bcoles@gmail.com>

#ifndef KASLD_CLI_H
#define KASLD_CLI_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int kasld_verbose; /* set by -v / --verbose (or $KASLD_VERBOSE)        */
static long kasld_time_s; /* -t SECS; 0 = unset -> component's own default    */

/* True under -v / --verbose, or $KASLD_VERBOSE set to a non-empty, non-"0"
 * value (the latter lets a no-arg `main(void)` component be debugged without an
 * argv conversion). Env is read once and cached. */
static inline int kasld_is_verbose(void) {
  if (kasld_verbose)
    return 1;
  static int env = -1;
  if (env < 0) {
    const char *e = getenv("KASLD_VERBOSE");
    env = (e && *e && *e != '0') ? 1 : 0;
  }
  return env;
}

/* Emit `[<level>] <msg>\n` to stderr. `gated` lines print only when verbose.
 * Prefer the wrappers below; the level alphabet is closed at '.', '-', '+'. */
static inline void kasld_logf(char level, int gated, const char *fmt, ...) {
  if (gated && !kasld_is_verbose())
    return;
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "[%c] ", level);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

#define kasld_info(...) kasld_logf('.', 0, __VA_ARGS__) /* normal progress */
#define kasld_debug(...)                                                       \
  kasld_logf('.', 1, __VA_ARGS__)                      /* firehose; only -v  */
#define kasld_err(...) kasld_logf('-', 0, __VA_ARGS__) /* failure / N-A */
#define kasld_found(...)                                                       \
  kasld_logf('+', 0, __VA_ARGS__) /* a leak was produced*/

static inline void kasld_cli_usage(const char *prog, FILE *out) {
  fprintf(out,
          "usage: %s [-v] [-t SECS] [-h]\n"
          "  -v, --verbose    extra (debug-level) diagnostics\n"
          "  -t, --time SECS  probe budget in seconds (0 = component default)\n"
          "  -h, --help       show this message\n",
          prog);
}

/* Parse the standard options. Call once at the top of main():
 *     int main(int argc, char **argv) { kasld_cli(argc, argv); ... }
 * Unknown option -> usage to stderr + exit 2;  -h/--help -> usage to stdout +
 * exit 0. The component then reads kasld_verbose / kasld_time_s as it cares; it
 * never touches argv itself. */
static inline void kasld_cli(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    const char *a = argv[i];
    if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) {
      kasld_verbose = 1;
    } else if (!strcmp(a, "-t") || !strcmp(a, "--time")) {
      if (++i >= argc) {
        fprintf(stderr, "[-] %s: %s requires a SECS value\n", argv[0], a);
        exit(2);
      }
      char *end;
      long v = strtol(argv[i], &end, 10);
      if (*end != '\0' || v < 0) {
        fprintf(stderr, "[-] %s: invalid -t value: %s\n", argv[0], argv[i]);
        exit(2);
      }
      kasld_time_s = v;
    } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
      kasld_cli_usage(argv[0], stdout);
      exit(0);
    } else {
      fprintf(stderr, "[-] %s: unknown option: %s\n", argv[0], a);
      kasld_cli_usage(argv[0], stderr);
      exit(2);
    }
  }
}

#endif /* KASLD_CLI_H */
