# shellcheck shell=sh
# This file is part of KASLD - https://github.com/bcoles/kasld
#
# guard_scope NAME COUNT FLOOR — refuse to report success on an empty scope.
#
# Every source-invariant guard walks a glob and reports what it found. If that
# glob stops matching — a directory renamed, a path typo, a variable left empty
# under `set -u` — the walk visits nothing, finds no violations, and the guard
# prints OK. It is not a hypothetical: `check-dram-base` pointed at an empty
# tree prints `OK (0 rules, ...)` and exits 0, and `check-image-size`, which
# reports no count at all, passes in complete silence. The suite would go on
# reporting a clean bill of health while enforcing nothing.
#
# The defect is that a guard asserts things about the files it examined and says
# nothing about whether it examined any. This makes the denominator part of the
# claim: below FLOOR the guard fails, loudly, naming the scope rather than the
# invariant — because an empty scope is a broken guard, not a clean tree.
#
# FLOOR is a floor, not a count: it needs updating only if the tree shrinks past
# it, so it does not become a second inventory to maintain alongside the real
# one. Pick something comfortably below the current population and well above
# zero.
# ---
# <bcoles@gmail.com>

guard_scope() {
  _gs_name=$1
  _gs_count=$2
  _gs_floor=$3
  if [ "$_gs_count" -lt "$_gs_floor" ]; then
    printf '%s: FAIL — examined %s file(s), expected at least %s.\n' \
      "$_gs_name" "$_gs_count" "$_gs_floor" >&2
    printf 'The scope is empty or nearly so, which means this guard checked\n' >&2
    printf 'nothing. A glob or path is broken; the tree is not clean, it is\n' >&2
    printf 'unexamined.\n' >&2
    exit 1
  fi
}
