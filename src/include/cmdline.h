// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Shared /proc/cmdline parsing helper.
//
// Provides cmdline_has_word(): searches for a whitespace-delimited boot
// parameter in /proc/cmdline with proper word-boundary matching.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_CMDLINE_H
#define KASLD_CMDLINE_H

#include "include/kasld/sysroot.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

/* Check if /proc/cmdline contains a whitespace-delimited word.
 * Handles word boundaries correctly: "nokaslr" won't match
 * "nokaslr_debug" or "xnokaslr".
 * Returns 1 if found, 0 otherwise. */
static int __attribute__((unused)) cmdline_has_word(const char *word) {
  FILE *f = kasld_fopen("/proc/cmdline", "r");
  if (!f)
    return 0;

  char buf[2048];
  if (!fgets(buf, sizeof(buf), f)) {
    fclose(f);
    return 0;
  }
  fclose(f);

  size_t wlen = strlen(word);
  const char *p = buf;
  while ((p = strstr(p, word)) != NULL) {
    /* Check left boundary: must be start of string or whitespace */
    if (p != buf && p[-1] != ' ' && p[-1] != '\t') {
      p += wlen;
      continue;
    }
    /* Check right boundary: must be end of string, whitespace, or '=' */
    char after = p[wlen];
    if (after == '\0' || after == ' ' || after == '\t' || after == '\n' ||
        after == '=')
      return 1;
    p += wlen;
  }
  return 0;
}

/* Check if /proc/cmdline contains a parameter whose key matches the given
 * prefix (e.g. "resume=" matches "resume=/dev/sda"). Only checks the left
 * word boundary — no right boundary check, since the value follows
 * immediately. Mirrors the kernel's own strstr-based check for key= params.
 * Returns 1 if found, 0 otherwise. */
static int __attribute__((unused)) cmdline_has_prefix(const char *prefix) {
  FILE *f = kasld_fopen("/proc/cmdline", "r");
  if (!f)
    return 0;

  char buf[2048];
  if (!fgets(buf, sizeof(buf), f)) {
    fclose(f);
    return 0;
  }
  fclose(f);

  size_t plen = strlen(prefix);
  const char *p = buf;
  while ((p = strstr(p, prefix)) != NULL) {
    if (p == buf || p[-1] == ' ' || p[-1] == '\t')
      return 1;
    p += plen;
  }
  return 0;
}

/* Parse a `memparse` token at *pp: optional 0x/0 prefix, decimal/hex digits,
 * optional K/M/G/T/P/E suffix (×1024 each). Advances *pp past the consumed
 * bytes on success. Mirrors lib/cmdline.c memparse() / simple_strtoull (base
 * 0). Returns 1 on at least one digit consumed, 0 on a no-digit input.
 * Overflow is detected and rejected: the kernel itself silently overflows,
 * but accepting an overflowed value here would emit unsound constraints. */
static int __attribute__((unused)) kasld_memparse(const char **pp,
                                                  unsigned long *out) {
  const char *p = *pp;
  unsigned int base = 10;
  if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
    base = 16;
    p += 2;
  } else if (p[0] == '0' && p[1] >= '0' && p[1] <= '7') {
    base = 8;
    p += 1;
  }
  unsigned long val = 0;
  const char *start = p;
  while (*p) {
    unsigned int d;
    if (*p >= '0' && *p <= '9')
      d = (unsigned int)(*p - '0');
    else if (base == 16 && *p >= 'a' && *p <= 'f')
      d = (unsigned int)(*p - 'a' + 10);
    else if (base == 16 && *p >= 'A' && *p <= 'F')
      d = (unsigned int)(*p - 'A' + 10);
    else
      break;
    if (d >= base)
      break;
    if (val > (ULONG_MAX - d) / base)
      return 0; /* overflow */
    val = val * base + d;
    p++;
  }
  if (p == start)
    return 0; /* no digits */
  /* Suffix multipliers; one shift each at the higher end. */
  unsigned int shift = 0;
  switch (*p) {
  case 'E':
  case 'e':
    shift += 10; /* fallthrough */
  case 'P':
  case 'p':
    shift += 10; /* fallthrough */
  case 'T':
  case 't':
    shift += 10; /* fallthrough */
  case 'G':
  case 'g':
    shift += 10; /* fallthrough */
  case 'M':
  case 'm':
    shift += 10; /* fallthrough */
  case 'K':
  case 'k':
    shift += 10;
    p++;
    break;
  default:
    break;
  }
  if (shift) {
    if (val > (ULONG_MAX >> shift))
      return 0; /* overflow */
    val <<= shift;
  }
  *pp = p;
  *out = val;
  return 1;
}

/* Locate `key=` (e.g. "mem=") on /proc/cmdline with the kernel's word-
 * boundary semantics, then parse the value with kasld_memparse(). Writes the
 * parsed bytes into *out and returns 1; returns 0 when the key is absent or
 * the value fails to parse. The first occurrence wins (the kernel's
 * memparse-based handlers do the same in early-boot order). */
static int __attribute__((unused)) cmdline_get_memparse(const char *key,
                                                        unsigned long *out) {
  FILE *f = kasld_fopen("/proc/cmdline", "r");
  if (!f)
    return 0;
  char buf[2048];
  if (!fgets(buf, sizeof(buf), f)) {
    fclose(f);
    return 0;
  }
  fclose(f);

  size_t klen = strlen(key);
  const char *p = buf;
  int found = 0;
  /* A repeated token is applied by the kernel in LAST-wins order (each parse
   * overwrites the previous — e.g. handle_mem_options for `mem=`), so keep
   * scanning and return the last valid value. Returning the first match could
   * yield a smaller `mem=` than the kernel actually used and, via
   * cmdline_mem_{phys,virt}_ceiling, place a text-base ceiling below the true
   * base. */
  while ((p = strstr(p, key)) != NULL) {
    if (p == buf || p[-1] == ' ' || p[-1] == '\t' || p[-1] == '\n') {
      const char *v = p + klen;
      unsigned long val;
      if (kasld_memparse(&v, &val)) {
        *out = val;
        found = 1;
      }
    }
    p += klen;
  }
  return found;
}

#endif /* KASLD_CMDLINE_H */
