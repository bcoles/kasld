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

#include <stdio.h>
#include <string.h>

/* Check if /proc/cmdline contains a whitespace-delimited word.
 * Handles word boundaries correctly: "nokaslr" won't match
 * "nokaslr_debug" or "xnokaslr".
 * Returns 1 if found, 0 otherwise. */
static int cmdline_has_word(const char *word) {
  FILE *f = fopen("/proc/cmdline", "r");
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

#endif /* KASLD_CMDLINE_H */
