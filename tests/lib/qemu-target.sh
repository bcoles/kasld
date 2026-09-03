# shellcheck shell=sh
# This file is part of KASLD - https://github.com/bcoles/kasld
#
# qemu-target.sh — which qemu-user binary runs a toolchain triple, and where it
# is.
#
# Six harnesses need this same answer, and five of them carried their own copy.
# The copies had already drifted — two orderings of the case arms, three
# spellings of the lookup, one of which alone guards against an empty argument —
# without yet disagreeing on a result. That is the state a shared rule exists to
# end: the next edit to one copy is what makes them differ, and each caller then
# checks a set the others do not agree with.
#
# qemu_for keys on the LEADING component of the triple, so a build directory
# name works as well as a toolchain prefix, and the dev and CI spellings of a
# triple (aarch64-linux-musl vs aarch64-unknown-linux-musl) both resolve.
#
# An architecture with no arm resolves to the empty string and its caller skips
# it. powerpcle is the one built target in that position: qemu's 32-bit
# little-endian PowerPC binary is absent from the toolchain this tree uses, so
# there is nothing to name. A caller that reports its scope will show the target
# missing rather than leaving it silently unswept.
#
# qemu_for <triple-or-arch>  -> prints the qemu binary name, or nothing
# resolve_qemu <binary-name> -> prints its path (QEMU_DIR, else PATH), or nothing
# ---
# <bcoles@gmail.com>

qemu_for() {
  case "${1%%-*}" in
  x86_64)      echo qemu-x86_64 ;;
  i686 | i586) echo qemu-i386 ;;
  aarch64)     echo qemu-aarch64 ;;
  arm | armv7) echo qemu-arm ;;
  armeb)       echo qemu-armeb ;;
  mips)        echo qemu-mips ;;
  mipsel)      echo qemu-mipsel ;;
  mips64)      echo qemu-mips64 ;;
  mips64el)    echo qemu-mips64el ;;
  powerpc)     echo qemu-ppc ;;
  powerpc64)   echo qemu-ppc64 ;;
  powerpc64le) echo qemu-ppc64le ;;
  riscv32)     echo qemu-riscv32 ;;
  riscv64)     echo qemu-riscv64 ;;
  s390x)       echo qemu-s390x ;;
  loongarch64) echo qemu-loongarch64 ;;
  *)           echo "" ;;
  esac
}

# QEMU_DIR pins the build to use; without it the name is resolved on PATH. An
# empty name cannot resolve, and saying so here keeps every caller from having
# to test for it first.
resolve_qemu() {
  [ -n "$1" ] || return 1
  if [ -n "${QEMU_DIR:-}" ]; then
    [ -x "$QEMU_DIR/$1" ] && { echo "$QEMU_DIR/$1"; return 0; }
    return 1
  fi
  command -v "$1" 2>/dev/null
}
