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
# A build given a COMPONENTS selection has a smaller inventory, and it records
# which components it was asked for. Where that record exists it is the set the
# build answers to; the source directory still sets the SCOPE, so a guard can
# still tell a deliberately narrow selection from a glob that stopped matching.
# The record is read rather than the variable, because the guard runs from an
# invocation of its own and carries no COMPONENTS.
#
# Prints one line: "<built> <arch-gated> <examined> <sources> <missing...>"
# ---
# <bcoles@gmail.com>

# component_manifest COMPDIR — where a build records its COMPONENTS selection.
component_manifest() {
  printf '%s\n' "${1%/components}/obj/components.selected"
}

component_artifacts() {
  _ca_missing=; _ca_src=0; _ca_examined=0; _ca_built=0; _ca_gated=0
  _ca_sel=$(component_manifest "$2")
  if [ -f "$_ca_sel" ]; then
    _ca_pick=" $(tr '\n' ' ' <"$_ca_sel") "
  else
    _ca_pick=
  fi
  for _ca_f in "$1"/*.c; do
    [ -f "$_ca_f" ] || continue
    _ca_src=$((_ca_src + 1))
    _ca_name=$(basename "$_ca_f" .c)
    if [ -n "$_ca_pick" ]; then
      case "$_ca_pick" in
        *" $_ca_name "*) ;;
        *) continue ;;
      esac
    fi
    _ca_examined=$((_ca_examined + 1))
    if [ ! -e "$2/$_ca_name" ]; then
      _ca_missing="$_ca_missing $_ca_name"
    elif [ -s "$2/$_ca_name" ]; then
      _ca_built=$((_ca_built + 1))
    else
      _ca_gated=$((_ca_gated + 1))
    fi
  done
  printf '%s %s %s %s%s\n' "$_ca_built" "$_ca_gated" "$_ca_examined" \
      "$_ca_src" "$_ca_missing"
}
