# shellcheck shell=sh
# This file is part of KASLD - https://github.com/bcoles/kasld
#
# host-build.sh — what this host runs, and which build directory holds it.
#
# The Makefile keeps two triples apart and says why (Makefile, HOST_ARCH /
# _ARCH): HOST_ARCH comes from a NATIVE compiler — cc, then gcc, then clang —
# and names what can execute here; _ARCH is `$(CC) -dumpmachine`, may be a cross
# triple, and names the build directory. A harness that wants "the native kasld"
# needs both, because the directory it must look in is _ARCH's while the
# question of whether that binary runs is HOST_ARCH's.
#
# Every harness that needed the answer worked it out again, and they did not
# agree. Five spellings were in the tree: this two-candidate walk; `cc
# -dumpmachine` alone, which misses the build a `make CC=...` wrote and skips;
# an explicit triple list probed by running each candidate; and
# "$(uname -m)-linux-gnu" assembled by hand, which is the host triple only on a
# glibc host — the Makefile's comment names that one as the mistake it is
# avoiding. The divergence is invisible in the ordinary case, because `make`
# with no CC makes all five agree; it shows up under `make test CC=<triple>-gcc`,
# where the guards that ask the narrow question find nothing and skip while
# reporting success.
#
# Probing a candidate by RUNNING it does not identify it either: a build for a
# narrower architecture executes here — an i686 binary runs on x86_64, and sorts
# first — so "the first one that runs" picks the cross build and then asserts
# native behaviour against a kernel that build cannot model.
#
#   host_triple           the native compiler's triple, or empty
#   host_arch             its leading component alone, or empty
#   build_triple          $(CC)'s triple — the build directory's name, or empty
#   host_runs_arch ARCH   whether a binary for ARCH executes here
#   host_triples          candidate build triples, most specific first
#   is_host_triple T      whether T is one of them
#   host_kasld            path to a runnable kasld under $ROOT/build
#
# With no compiler at all every function comes back empty and a caller skips,
# which is what a host that could not have built the tree should do.
# ---
# <bcoles@gmail.com>

# The Makefile's HOST_ARCH: a NATIVE compiler's triple, whatever $(CC) is. The
# three-way fallback is the Makefile's, so a host with no `cc` symlink is not
# misread as cross.
host_triple() {
  cc -dumpmachine 2>/dev/null ||
    gcc -dumpmachine 2>/dev/null ||
    clang -dumpmachine 2>/dev/null
}

# The leading component of the native triple: the architecture this host runs,
# spelled as a triple spells it. Distinct from `uname -m`, which spells several
# of them differently (armv7l against the toolchain's armv7), so the two are not
# interchangeable and this is the one that compares against a build directory.
host_arch() {
  _hb_a=$(host_triple)
  printf '%s\n' "${_hb_a%%-*}"
}

# The Makefile's _ARCH: the triple of the compiler that built the tree, which is
# the build directory's name. CC reaches a guard when make invokes it, which is
# how `make test CC=<triple>-gcc` names its own output.
build_triple() { ${CC:-cc} -dumpmachine 2>/dev/null; }

# Whether a binary built for ARCH (a triple's leading component) executes here.
# An x86_64 host also runs 32-bit x86; every other architecture must match.
host_runs_arch() {
  _hb_host=$(host_arch)
  [ -n "$_hb_host" ] || return 1
  case "$_hb_host" in
  x86_64 | amd64) case "$1" in x86_64 | amd64 | i686 | i586 | i386) return 0 ;; esac ;;
  *) [ "$1" = "$_hb_host" ] && return 0 ;;
  esac
  return 1
}

# Candidate build triples this host can execute, most specific first: what this
# build wrote, then what a native compiler names. Both are filtered through
# host_runs_arch, so a cross $(CC) contributes nothing and a caller skips rather
# than running a foreign binary as though it were native. Prints nothing when no
# candidate qualifies.
host_triples() {
  _hb_seen=
  for _hb_t in "$(build_triple)" "$(host_triple)"; do
    [ -n "$_hb_t" ] || continue
    case " $_hb_seen " in *" $_hb_t "*) continue ;; esac
    host_runs_arch "${_hb_t%%-*}" || continue
    _hb_seen="$_hb_seen $_hb_t"
    printf '%s\n' "$_hb_t"
  done
}

# Whether a build directory is one this tree's own compilers produce, which is
# what a sweep over build/*/ means by "the native one": the target it may run
# directly, and the one an earlier native pass has already covered. Narrower
# than host_runs_arch — an i686 build executes on an x86_64 host but is not that
# host's build, and a sweep that treated it as one would run its extra modes
# twice.
is_host_triple() {
  for _hb_t in $(host_triples); do
    [ "$1" = "$_hb_t" ] && return 0
  done
  return 1
}

# The common case: a kasld a guard can run, under the build root every harness
# already names as $ROOT/build. Prints the path and returns 0, or prints nothing
# and returns 1 — callers report their own SKIP, since what a missing native
# build means differs per guard.
host_kasld() {
  _hb_root=${ROOT:-.}/build
  for _hb_t in $(host_triples); do
    if [ -x "$_hb_root/$_hb_t/kasld" ]; then
      printf '%s\n' "$_hb_root/$_hb_t/kasld"
      return 0
    fi
  done
  return 1
}
