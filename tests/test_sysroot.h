// This file is part of KASLD - https://github.com/bcoles/kasld
//
// test_sysroot.h — a staged filesystem for tests that read a fact source.
//
// A test that consults a real path asserts against whatever the machine
// running it happens to hold, or -- harder to notice -- against what it happens
// to LACK, which nothing in the test's text reveals. The fix is to supply the
// tree rather than borrow it: stage a directory, put the files under it, and
// point KASLD_SYSROOT at it, which the kasld_* wrappers resolve every absolute
// path through.
//
// The prefix is cached on first use (kasld_sysroot()), so the root must be
// established before the first read. The CONTENTS are not cached, which is what
// makes per-test staging work: one root for the process, a tree each test
// shapes for itself.
//
// That per-test shaping is the point. A tree staged once in main() is a
// dependency every later test inherits silently -- a test can come to rely on a
// file it never mentions, and reads as if it stood alone. Here a test stages
// what it needs and clears first, so the dependency is written where the
// assertion is.
//
// Absence is a legitimate staging, and often the interesting one: an empty tree
// is how a test says "this source is not present".
// ---
// <bcoles@gmail.com>

#ifndef KASLD_TEST_SYSROOT_H
#define KASLD_TEST_SYSROOT_H

#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TH_SYSROOT_MAX 384

static char th_sysroot_root[128];

/* Every path this header touches is built here, and every caller goes through
 * it. A staged path must be absolute: a relative one would land outside the
 * root, and the recursive clear below would then be pointed somewhere it has no
 * business being. */
static void th_sysroot_path(const char *abs, char *out, size_t outsz) {
  assert(th_sysroot_root[0] != '\0' && "th_sysroot_init() first");
  assert(abs && abs[0] == '/' && "staged paths are absolute");
  assert(strstr(abs, "/..") == NULL && "no traversal in a staged path");
  int n = snprintf(out, outsz, "%s%s", th_sysroot_root, abs);
  assert(n > 0 && (size_t)n < outsz && "staged path too long");
}

/* Create the staged root and point KASLD_SYSROOT at it.
 *
 * Call once, before anything reads a fact. Under the hermeticity probe that
 * ordering is checked rather than trusted: the probe records absolute paths
 * resolved with no root set, so a non-empty record here means a read already
 * escaped to the host and the rest of this file's isolation is a fiction. */
static void th_sysroot_init(void) {
  assert(th_sysroot_root[0] == '\0' && "th_sysroot_init() called twice");
#ifdef KASLD_HERMETIC_PROBE
  assert(kasld_hermetic_n == 0 &&
         "th_sysroot_init() must run before the first fact read");
#endif
  snprintf(th_sysroot_root, sizeof(th_sysroot_root),
           "/tmp/kasld_test_rootXXXXXX");
  assert(mkdtemp(th_sysroot_root) != NULL);
  assert(setenv("KASLD_SYSROOT", th_sysroot_root, 1) == 0);
}

/* mkdir -p over the directory part of a staged path, in place. */
static void th_sysroot_mkparents(char *full) {
  char *slash = strrchr(full, '/');
  if (!slash || slash == full)
    return;
  *slash = '\0';
  for (char *p = full + strlen(th_sysroot_root) + 1; *p; p++) {
    if (*p != '/')
      continue;
    *p = '\0';
    (void)mkdir(full, 0755); /* EEXIST is the common case */
    *p = '/';
  }
  (void)mkdir(full, 0755);
  *slash = '/';
}

/* Stage `abs` with `contents`. A NULL `contents` writes an empty file, which is
 * what a marker like /.dockerenv actually is. */
static void th_sysroot_write(const char *abs, const char *contents) {
  char full[TH_SYSROOT_MAX];
  th_sysroot_path(abs, full, sizeof(full));
  th_sysroot_mkparents(full);
  FILE *f = fopen(full, "w");
  assert(f != NULL);
  if (contents && *contents)
    assert(fputs(contents, f) >= 0);
  assert(fclose(f) == 0);
}

static void th_sysroot_rm(const char *abs) {
  char full[TH_SYSROOT_MAX];
  th_sysroot_path(abs, full, sizeof(full));
  (void)unlink(full);
}

/* Depth-first removal of everything under `dir`, which is always inside the
 * staged root -- the callers below start at the root and recurse only into
 * entries they read from it. Symlinks are unlinked, never followed: nothing
 * here stages one, and following would let a staged tree reach outside itself.
 */
static void th_sysroot_rm_r(const char *dir) {
  DIR *d = opendir(dir);
  if (!d)
    return;
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
      continue;
    char child[TH_SYSROOT_MAX];
    if ((size_t)snprintf(child, sizeof(child), "%s/%s", dir, e->d_name) >=
        sizeof(child))
      continue;
    struct stat st;
    if (lstat(child, &st) != 0)
      continue;
    if (S_ISDIR(st.st_mode))
      th_sysroot_rm_r(child);
    else
      (void)unlink(child);
  }
  closedir(d);
  (void)rmdir(dir);
}

/* Empty the tree, keeping the root itself (and so the cached prefix). Call at
 * the top of a test that stages: it starts from a stated tree rather than
 * whatever ran before it. */
static void th_sysroot_clear(void) {
  assert(th_sysroot_root[0] != '\0' && "th_sysroot_init() first");
  DIR *d = opendir(th_sysroot_root);
  if (!d)
    return;
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
      continue;
    char child[TH_SYSROOT_MAX];
    if ((size_t)snprintf(child, sizeof(child), "%s/%s", th_sysroot_root,
                         e->d_name) >= sizeof(child))
      continue;
    struct stat st;
    if (lstat(child, &st) != 0)
      continue;
    if (S_ISDIR(st.st_mode))
      th_sysroot_rm_r(child);
    else
      (void)unlink(child);
  }
  closedir(d);
}

static void th_sysroot_fini(void) {
  if (th_sysroot_root[0] == '\0')
    return;
  th_sysroot_clear();
  (void)rmdir(th_sysroot_root);
  th_sysroot_root[0] = '\0';
}

#endif /* KASLD_TEST_SYSROOT_H */
