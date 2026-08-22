// This file is part of KASLD - https://github.com/bcoles/kasld
//
// check_hash_parity — verify a component's hashed offset table against the
// shipped kasld_fnv1a64 (include/kasld/hash.h).
//
// Components that key per-build offsets on a uname fingerprint store rows of
// the form
//     {0x<16-hex hash>, <offset(s)>}, // <release> <version>
// where <offset(s)> is one offset or a { ... } array, and the hash was produced
// by the offline table generator. This harness
// recomputes kasld_fnv1a64() over each row's uname comment and asserts it
// equals the stored hash, so the runtime hash and the generator's cannot
// silently drift: a build whose row is present matches its own row exactly. It
// also asserts every hash in a file is distinct (the collision-free invariant
// the generator enforces at emit time), and self-tests kasld_fnv1a64 against
// pinned vectors — including a >= 0x80 byte, to catch a dropped unsigned-char
// cast.
//
// Usage: check_hash_parity <table.inc> [<table.inc> ...]
// Exit 0 iff every file's rows round-trip and are distinct; non-zero otherwise.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L /* strdup */

#include "include/kasld/hash.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> /* isatty */

/* Pinned (input -> hash) vectors, computed independently of this binary. Guards
 * the hash constants and the unsigned-char cast (the last two carry bytes >=
 * 0x80, which sign-extend to a different value without the cast). */
static int selftest(void) {
  static const struct {
    const char *s;
    uint64_t h;
  } v[] = {
      {"", 0xcbf29ce484222325ULL},
      {"6.8.0-134-generic #134-Ubuntu SMP PREEMPT_DYNAMIC Fri Jun 26 "
       "18:43:11 UTC 2026",
       0x99d7d97f07f75fbaULL},
      {"\xff", 0xaf64724c8602eb6eULL},
      {"hi\x80\xa9", 0x720fadcc9a18fba5ULL},
  };
  int bad = 0;
  for (unsigned i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
    uint64_t got = kasld_fnv1a64(v[i].s);
    if (got != v[i].h) {
      fprintf(stderr,
              "  self-test FAIL: kasld_fnv1a64(vector %u) = 0x%016llx, "
              "expected 0x%016llx\n",
              i, (unsigned long long)got, (unsigned long long)v[i].h);
      bad++;
    }
  }
  return bad;
}

struct row {
  uint64_t hash;
  int block; /* per-arch #if block; distinctness is checked within a block */
  char *uname;
};

static int cmp_row(const void *a, const void *b) {
  const struct row *r = a, *s = b;
  if (r->block != s->block)
    return (r->block > s->block) - (r->block < s->block);
  return (r->hash > s->hash) - (r->hash < s->hash);
}

/* Parse one hashed table row "{0x<hash>, <...>}, // <uname>", where <...> is a
 * single offset (qemu) or a { ... } offset array (bpf). Only the hash and the
 * uname comment are checked, so whatever sits between them is ignored. Returns
 * 1 and fills *hash / *uname (into the caller's line buffer) on a match, else
 * 0. */
static int parse_row(char *line, uint64_t *hash, char **uname) {
  char *p = line, *end;
  while (*p == ' ' || *p == '\t')
    p++;
  if (*p != '{' || p[1] != '0' || p[2] != 'x')
    return 0;
  *hash = strtoull(p + 1, &end, 16);
  if (*end != ',') /* a hashed row is "{0x<hash>, <offset(s)>}, // ..." */
    return 0;
  char *c = strstr(end, "// "); /* the uname comment, past any offset(s) */
  if (!c)
    return 0;
  char *u = c + 3;
  size_t n = strlen(u);
  while (n > 0 && (u[n - 1] == '\n' || u[n - 1] == '\r'))
    u[--n] = '\0';
  if (n == 0)
    return 0;
  *uname = u;
  return 1;
}

/* Returns count of problems (mismatches + collisions + structural); reports the
 * number of table rows parsed via *out_rows (0 on any failure). */
static int check_file(const char *path, size_t *out_rows) {
  *out_rows = 0;
  FILE *f = fopen(path, "r");
  if (!f) {
    fprintf(stderr, "  %s: cannot open\n", path);
    return 1;
  }
  struct row *rows = NULL;
  size_t n = 0, cap = 0;
  int bad = 0;
  char line[1024];
  uint64_t hash;
  char *uname;
  int block = 0;
  while (fgets(line, sizeof(line), f)) {
    /* A table may be split into per-arch #if blocks (bpf_verifier_ksym): the
     * same uname then repeats across blocks with the same hash, so distinctness
     * is per-block, not file-wide. A flat table has no directives -> one block
     * -> unchanged. */
    char *t = line;
    while (*t == ' ' || *t == '\t')
      t++;
    if (t[0] == '#' &&
        (strncmp(t + 1, "if", 2) == 0 || strncmp(t + 1, "elif", 4) == 0 ||
         strncmp(t + 1, "else", 4) == 0))
      block++;
    if (!parse_row(line, &hash, &uname))
      continue;
    uint64_t got = kasld_fnv1a64(uname);
    if (got != hash) {
      fprintf(
          stderr,
          "  %s: hash mismatch: stored 0x%016llx, fnv1a64 0x%016llx  // %s\n",
          path, (unsigned long long)hash, (unsigned long long)got, uname);
      bad++;
    }
    if (n == cap) {
      cap = cap ? cap * 2 : 1024;
      rows = realloc(rows, cap * sizeof(*rows));
      if (!rows) {
        fprintf(stderr, "  %s: out of memory\n", path);
        fclose(f);
        return bad + 1;
      }
    }
    rows[n].hash = hash;
    rows[n].block = block;
    rows[n].uname = strdup(uname);
    n++;
  }
  fclose(f);

  if (n == 0) {
    fprintf(stderr, "  %s: no hashed table rows parsed (format drift?)\n",
            path);
    free(rows);
    return bad + 1;
  }

  qsort(rows, n, sizeof(*rows), cmp_row);
  for (size_t i = 1; i < n; i++)
    if (rows[i].hash == rows[i - 1].hash &&
        rows[i].block == rows[i - 1].block) {
      fprintf(stderr, "  %s: hash collision 0x%016llx:\n    // %s\n    // %s\n",
              path, (unsigned long long)rows[i].hash, rows[i - 1].uname,
              rows[i].uname);
      bad++;
    }

  for (size_t i = 0; i < n; i++)
    free(rows[i].uname);
  free(rows);

  *out_rows = n;
  return bad;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <table.inc> [<table.inc> ...]\n", argv[0]);
    return 2;
  }
  int bad = selftest();
  size_t ntables = 0, total_rows = 0;
  for (int i = 1; i < argc; i++) {
    size_t rows = 0;
    bad += check_file(argv[i], &rows);
    if (rows) {
      ntables++;
      total_rows += rows;
    }
  }
  if (bad) {
    fprintf(stderr, "check-hash-parity: FAIL (%d problem(s))\n", bad);
    return 1;
  }
  /* Colour when writing to a terminal, or when the caller states the terminal
     it is writing on behalf of: a runner that captures this output to replay it
     in order leaves stdout a file, and passes its own answer in KASLD_COLOR. */
  const char *colour_env = getenv("KASLD_COLOR");
  int colour = isatty(1) || (colour_env != NULL && colour_env[0] != '\0');
  const char *green = colour ? "\033[32m" : "";
  const char *reset = colour ? "\033[0m" : "";
  printf("%scheck-hash-parity: OK%s (%zu tables, %zu rows)\n", green, reset,
         ntables, total_rows);
  return 0;
}
