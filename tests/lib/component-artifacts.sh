# shellcheck shell=sh
# This file is part of KASLD - https://github.com/bcoles/kasld
#
# component_artifacts SRCDIR COMPDIR — what a component build produced.
#
# The component recipe exits 0 whatever the compiler said, on purpose: with a
# hundred-odd independent leaf targets, one that will not compile must not stop
# the rest being built and tested. What it does instead is REMOVE the target, so
# the three states on disk carry the whole answer:
#
#   non-empty file  compiled
#   empty file      architecture-gated, skipped by the `#error "Architecture is
#                   not supported"` path, which writes an empty target on purpose
#   absent          the compiler failed
#
# Two guards ask this: one about the build this host just made, one about a
# build made with a second compiler. The rule is subtle enough that two copies
# would answer differently the first time the recipe changed, so it is written
# once. The SOURCE directory is the inventory and the build answers to it -- a
# count is never used, since a fixed number rots the moment a component is
# added, which is the failure this exists to catch one level up.
#
# Prints one line: "<built> <arch-gated> <sources> <missing...>"
# ---
# <bcoles@gmail.com>

component_artifacts() {
  _ca_missing=; _ca_src=0; _ca_built=0; _ca_gated=0
  for _ca_f in "$1"/*.c; do
    [ -f "$_ca_f" ] || continue
    _ca_src=$((_ca_src + 1))
    _ca_name=$(basename "$_ca_f" .c)
    if [ ! -e "$2/$_ca_name" ]; then
      _ca_missing="$_ca_missing $_ca_name"
    elif [ -s "$2/$_ca_name" ]; then
      _ca_built=$((_ca_built + 1))
    else
      _ca_gated=$((_ca_gated + 1))
    fi
  done
  printf '%s %s %s%s\n' "$_ca_built" "$_ca_gated" "$_ca_src" "$_ca_missing"
}
