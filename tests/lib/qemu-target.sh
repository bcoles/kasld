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
# The machine a CAPTURE names is a third spelling again: `uname -m` reports
# armv7l where the toolchain says armv7, ppc64le where it says powerpc64le, and
# plain "mips" whichever byte order the kernel was built for. Translating one to
# the other is target_triple_for, and the qemu binary follows from the triple
# rather than being restated beside it, so the two answers cannot disagree.
#
# qemu_for <triple-or-arch>       -> prints the qemu binary name, or nothing
# resolve_qemu <binary-name>      -> prints its path (QEMU_DIR, else PATH)
# effective_machine <machine> [E] -> the machine string with byte order applied
# target_triple_for <machine>     -> the build triple for a captured machine
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

# `uname -m` encodes byte order on most architectures — arm reports armv7b,
# arm64 aarch64_be, powerpc ppc64le — which is why a capture is keyed on the raw
# machine string rather than a coarser canonical arch. MIPS is the exception: it
# reports "mips"/"mips64" whatever the byte order, so a bundle's `endianness:`
# field has to supply what the machine string cannot. SuperH and microblaze are
# equally blind but have no target below and no cross build, so they resolve to
# nothing either way.
#
# $1 = the raw machine string, $2 = endianness (little/big/unknown/empty). A
# capture without the field, or with `unknown`, leaves the raw string standing.
effective_machine() {
  case "$1" in
  mips | mips64) [ "${2:-}" = little ] && { echo "${1}el"; return; } ;;
  esac
  echo "$1"
}

# The build triple for a captured machine string, or nothing where no target
# exists. Callers take ${triple%%-*} to glob build/<arch>-*, since the dev and CI
# toolchains spell the tail differently, and pass the whole triple to qemu_for.
target_triple_for() {
  case "$1" in
  x86_64)                  echo x86_64-linux-musl ;;
  i686 | i386)             echo i686-unknown-linux-musl ;;
  aarch64)                 echo aarch64-linux-musl ;;
  armv7l | armv6l | armhf | arm)
                           echo armv7-unknown-linux-musleabi ;;
  # armv7b/armv6b is a big-endian arm kernel naming itself; armeb is the
  # toolchain name for the same target.
  armeb | armv7b | armv6b) echo armeb-linux-musleabi ;;
  riscv64)                 echo riscv64-linux-musl ;;
  riscv32)                 echo riscv32-linux-musl ;;
  mips)                    echo mips-unknown-linux-musl ;;
  mipsel)                  echo mipsel-unknown-linux-musl ;;
  mips64)                  echo mips64-unknown-linux-musl ;;
  mips64el)                echo mips64el-unknown-linux-musl ;;
  ppc | powerpc)           echo powerpc-linux-musl ;;
  # 32-bit little-endian powerpc: a cross target exists, and qemu ships no
  # ppcle linux-user binary, so qemu_for resolves it to nothing and the caller
  # names the runner that is missing.
  ppcle | powerpcle)       echo powerpcle-unknown-linux-musl ;;
  ppc64 | powerpc64)       echo powerpc64-unknown-linux-musl ;;
  ppc64le | powerpc64le)   echo powerpc64le-unknown-linux-musl ;;
  s390x)                   echo s390x-ibm-linux-musl ;;
  loongarch64)             echo loongarch64-unknown-linux-musl ;;
  *)                       echo "" ;;
  esac
}
