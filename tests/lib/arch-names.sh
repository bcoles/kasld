# shellcheck shell=sh
# This file is part of KASLD - https://github.com/bcoles/kasld
#
# arch-names.sh — which architecture does KASLD call this?
#
# KASLD names an architecture one way: the arch header's basename, which is also
# the fixture directory, also the arch column of the cross matrix, and also
# KASLD_ARCH_NAME, which api.h defines beside the #if arm that selects the
# header and owns as the single source of truth. x86_32 rather than i686,
# arm64 rather than aarch64, ppc64 rather than powerpc64le.
#
# Everything else spells architectures differently. `uname -m` says ppc64le and
# aarch64; a compiler triple says powerpc64le and aarch64; a build directory is
# named for the triple. Anything that has to reach a fixture, a build, or an
# arch header from one of those strings has to convert, and five places were
# each doing it with a table of their own -- against three different input
# vocabularies, with nothing in any of their names saying which one it took.
# They disagreed: one mapped a mips host onto fixture directories that do not
# exist, so the containment check it guards silently did not run while the
# guard still reported OK.
#
# ONE TABLE, BOTH VOCABULARIES. The spellings do not collide -- no string means
# one architecture as a machine and another as a triple component -- so a caller
# never has to know which kind it is holding, which is the mistake that produced
# the divergence. ppc64le and powerpc64le both answer ppc64.
#
# That non-collision is what licenses the merge, and it is a property of the two
# vocabularies in the table, not a general truth. Merging a third -- the Debian
# arch names a fixture pipeline speaks, say -- means checking it again against
# both, one spelling at a time, before adding an arm. A vocabulary that does
# collide needs its own entry point, not a wider case.
#
# LOSSY, DELIBERATELY. The answer names an arch header, and one header serves
# both byte orders: mips64 and mips64el are one layout model and two different
# toolchains. Selecting a toolchain or an emulator needs the original string,
# which is what tests/lib/qemu-target.sh takes.
#
# IDEMPOTENT. A name KASLD already uses answers itself, so a caller holding one
# can pass it through without knowing whether it has one yet. Most of them would
# do that anyway -- arm64 and riscv32 are also spellings a machine reports, and
# arm32 falls out of the arm glob -- but x86_32, mips32 and ppc32 are names
# nothing outside the tree uses, and leaving those three to answer nothing while
# the other fourteen answered themselves is the kind of almost-property a caller
# leans on and gets away with until it picks the wrong architecture.
# check-arch-dispatch holds every arch header's basename to it.
#
# Empty for a string it does not recognise. No name is the honest answer, and
# every caller already has somewhere to go with it -- a skip with a printed
# reason, or a fixture glob that matches nothing.
#
#   kasld_arch_for <machine-or-triple-component>  ->  the name, or empty
# ---
# <bcoles@gmail.com>

kasld_arch_for() {
  case "$1" in
  x86_64 | amd64) echo x86_64 ;;
  i386 | i486 | i586 | i686 | x86_32) echo x86_32 ;;
  # aarch64 and arm64 ahead of the arm glob, which would otherwise take them.
  aarch64 | aarch64_be | arm64) echo arm64 ;;
  arm*) echo arm32 ;;
  mips64 | mips64el) echo mips64 ;;
  mips | mipsel | mips32) echo mips32 ;;
  ppc64 | ppc64le | powerpc64 | powerpc64le) echo ppc64 ;;
  ppc | ppcle | powerpc | powerpcle | powerpc32 | ppc32) echo ppc32 ;;
  riscv64) echo riscv64 ;;
  riscv32) echo riscv32 ;;
  loongarch64 | loong64) echo loongarch64 ;;
  s390x | s390) echo s390 ;;
  # The architectures KASLD dispatches to a refusal stub. Named because a
  # capture can come from one, and "sparc" is a better answer than silence.
  sparc64 | sparc) echo sparc ;;
  sh*) echo sh ;;
  m68k) echo m68k ;;
  microblaze | microblazeel) echo microblaze ;;
  openrisc | or1k) echo openrisc ;;
  *) echo "" ;;
  esac
}
