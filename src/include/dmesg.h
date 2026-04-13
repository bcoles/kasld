// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Shared dmesg / kernel log search framework.
//
// Provides dmesg_search(): a dual-source (klogctl + /var/log/dmesg) line
// iterator that deduplicates the search infrastructure shared across all
// dmesg_*.c components.
//
// Callback receives each matched line (null-terminated, mutable).
// Return 1 from the callback to continue, 0 to stop.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_DMESG_H
#define KASLD_DMESG_H

#include "syslog.h"
#include <stdio.h>
#include <string.h>

/* Callback type: receives a null-terminated line containing the needle.
 * Return 1 to continue searching, 0 to stop. */
typedef int (*dmesg_match_fn)(const char *line, void *ctx);

/* Search klogctl syslog buffer, then fall back to /var/log/dmesg log file,
 * for lines containing `needle`.  For each match, call fn(line, ctx).
 * Returns the number of times fn() was called. */
static int dmesg_search(const char *needle, dmesg_match_fn fn, void *ctx) {
  char *syslog;
  int size;
  int calls = 0;

  /* --- Source 1: klogctl syslog ring buffer --- */
  if (!mmap_syslog(&syslog, &size)) {
    char *ptr = syslog;
    while ((ptr = strstr(ptr, needle)) != NULL) {
      /* Walk back to start of this line */
      char *sol = ptr;
      while (sol > syslog && sol[-1] != '\n')
        sol--;

      /* Find end of line and null-terminate temporarily */
      char *eol = strchr(ptr, '\n');
      char saved = 0;
      if (eol) {
        saved = *eol;
        *eol = '\0';
      }

      calls++;
      int cont = fn(sol, ctx);

      if (eol) {
        *eol = saved;
        ptr = eol + 1;
      } else {
        break;
      }

      if (!cont)
        break;
    }
  }

  if (calls > 0)
    return calls;

  /* --- Source 2: /var/log/dmesg log file fallback --- */
  {
    FILE *f;
    char buf[BUFSIZ];
    const char *path = "/var/log/dmesg";

    f = fopen(path, "rb");
    if (f == NULL)
      return 0;

    while (fgets(buf, sizeof(buf), f) != NULL) {
      if (strstr(buf, needle) == NULL)
        continue;

      /* Strip trailing newline */
      char *nl = strchr(buf, '\n');
      if (nl)
        *nl = '\0';

      calls++;
      if (!fn(buf, ctx))
        break;
    }

    fclose(f);
  }

  return calls;
}

#endif /* KASLD_DMESG_H */
