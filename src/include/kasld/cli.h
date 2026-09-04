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
//     NOT kasld's per-component kill timeout (different roles).
// ---
// <bcoles@gmail.com>

#ifndef KASLD_CLI_H
#define KASLD_CLI_H

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sysroot.h" /* kasld_sysroot() for the live-probe guard below */

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
 * Prefer the wrappers below; the level alphabet is closed at '.', '-', '+'.
 *
 * The format attribute is what makes every CALLER checkable: the format reaches
 * vfprintf through a va_list, where a compiler can no longer relate it to the
 * arguments, so without this the check is lost at the one place a mismatch
 * would print a plausible wrong address rather than fail. */
__attribute__((format(printf, 3, 4))) static inline void
kasld_logf(char level, int gated, const char *fmt, ...) {
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

/* Live-probe guard for standalone invocation. A component whose result comes
 * from live runtime state of the executing kernel/CPU (tagged live:1 in
 * KASLD_META — perf, timing side-channels, mmap VA sweeps, ioctl/socket leaks,
 * /proc/self, ...) is meaningless against a captured tree: under KASLD_SYSROOT
 * it would describe the analysis host, not the target. Call it at the top of
 * such a component's main() and return when it returns non-zero:
 *     if (kasld_skip_live_probe("mincore")) return 0;
 * The orchestrator independently filters these components under KASLD_SYSROOT
 * (they never fork); this is the safety net for running the binary directly. */
static inline int kasld_skip_live_probe(const char *what) {
  if (!kasld_sysroot())
    return 0;
  kasld_info("skipping live %s probe under KASLD_SYSROOT", what);
  return 1;
}

/* A component that has no probe budget calls kasld_cli(); one that has a budget
 * calls kasld_cli_timed(), which is the only way to obtain the budget's value.
 * A component therefore cannot advertise -t without consuming it, nor consume
 * one without advertising it -- the two are the same act. That is what keeps
 * the usage text true: it was previously printed by every caller, while four in
 * five ignored the flag, so `-t 1` was accepted and the probe ran to its own
 * default. */
static inline void kasld_cli_usage(const char *prog, FILE *out, int timed) {
  fprintf(out, "usage: %s [-v]%s [-h]\n", prog, timed ? " [-t SECS]" : "");
  fprintf(out, "  -v, --verbose    extra (debug-level) diagnostics\n");
  if (timed)
    fprintf(out, "  -t, --time SECS  probe budget in seconds (0 = component "
                 "default)\n");
  fprintf(out, "  -h, --help       show this message\n");
}

/* Parse the standard options. Call once at the top of main():
 *     int main(int argc, char **argv) { kasld_cli(argc, argv); ... }
 * Unknown option -> usage to stderr + exit 2;  -h/--help -> usage to stdout +
 * exit 0. The component then reads kasld_verbose / kasld_time_s as it cares; it
 * never touches argv itself. */
static inline void kasld_cli_parse(int argc, char **argv, int timed) {
  for (int i = 1; i < argc; i++) {
    const char *a = argv[i];
    if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) {
      kasld_verbose = 1;
    } else if (timed && (!strcmp(a, "-t") || !strcmp(a, "--time"))) {
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
      kasld_cli_usage(argv[0], stdout, timed);
      exit(0);
    } else {
      fprintf(stderr, "[-] %s: unknown option: %s\n", argv[0], a);
      kasld_cli_usage(argv[0], stderr, timed);
      exit(2);
    }
  }
}

/* Parse the standard options for a component with no probe budget: -v and -h.
 * A -t here is an unknown option and is rejected, because there is nothing for
 * it to bound. Call once at the top of main(). */
static inline void kasld_cli(int argc, char **argv) {
  kasld_cli_parse(argc, argv, 0);
}

/* As kasld_cli(), plus -t SECS, and returns the probe budget in MILLISECONDS:
 * the -t value where one was given, else default_ms unchanged.
 *
 * Milliseconds because three of the callers hand the result straight to poll()
 * and one polls on a 250 ms interval, so seconds would round away resolution
 * the components already rely on.
 *
 * No policy clamp is applied. Two callers deliberately accept an unbounded
 * budget today and capping them here would quietly overrule a chosen value; a
 * caller wanting a ceiling applies its own, as the poll() users do. The only
 * bound is against int overflow in the conversion.
 *
 * warn_unused_result is the enforcement: discarding the return advertises -t
 * while ignoring it, which is the defect this split exists to remove. */
__attribute__((warn_unused_result)) static inline int
kasld_cli_timed(int argc, char **argv, int default_ms) {
  kasld_cli_parse(argc, argv, 1);
  if (kasld_time_s <= 0)
    return default_ms;
  if (kasld_time_s > (long)(INT_MAX / 1000))
    return INT_MAX;
  return (int)(kasld_time_s * 1000);
}

#endif /* KASLD_CLI_H */
