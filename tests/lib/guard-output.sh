# shellcheck shell=sh
# This file is part of KASLD - https://github.com/bcoles/kasld
#
# guard-output.sh — one voice, and one name, for the guard set.
#
# Every guard ends in a line of the same shape: "<name>: OK (what it examined)".
# The shape was already uniform; the NAME was not. Most guards printed their own
# filename, seventeen printed something else — "self-edge guard",
# "truncation guard" — and docs/testing.md documents all of them by filename,
# as does the lint list check-guard-docs compares it against. So a guard could
# be listed, documented, and still un-greppable: searching a run for
# check-self-edges found nothing, because that guard announced itself as
# something else.
#
# The name is therefore taken from $0 rather than passed in. A caller cannot
# supply a name that disagrees with the file it lives in, because it does not
# supply one at all.
#
# Colour follows the terminal, with KASLD_COLOR to force it on when stdout is a
# pipe — which is how run-guards sees it, since it buffers each guard to keep
# the transcript in list order rather than finish order. Three guards had drifted
# off that idiom and printed plain even on a terminal; a shared block is the
# thing that stops the fourth.
#
#   guard_ok   "<detail>"   -> stdout, green
#   guard_fail "<detail>"   -> stderr, red   (the caller still controls exit)
#   guard_skip "<detail>"   -> stdout, yellow
#
# RED / GREEN / YELLOW / RESET are exported too: a guard that prints per-finding
# detail lines of its own already uses those names.
# ---
# <bcoles@gmail.com>

if [ -t 1 ] || [ -n "${KASLD_COLOR:-}" ]; then
  RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m')
  YELLOW=$(printf '\033[33m'); RESET=$(printf '\033[0m')
else
  RED=; GREEN=; YELLOW=; RESET=
fi

# $0 is the guard's path as invoked; the basename is what the docs and the lint
# list call it.
guard_name=${0##*/}

guard_ok() {
  printf '%s%s: OK%s (%s)\n' "$GREEN" "$guard_name" "$RESET" "$1"
}

guard_fail() {
  printf '%s%s: FAIL%s (%s)\n' "$RED" "$guard_name" "$RESET" "$1" >&2
}

guard_skip() {
  printf '%s%s: SKIP%s (%s)\n' "$YELLOW" "$guard_name" "$RESET" "$1"
}
