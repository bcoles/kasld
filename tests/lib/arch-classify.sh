# shellcheck shell=sh
# This file is part of KASLD - https://github.com/bcoles/kasld
#
# arch-classify.sh — contract header or refusal stub?
#
# src/include/kasld/arch/ holds two kinds of file. A contract header defines the
# architecture's layout and must satisfy every mandatory axis. A refusal stub
# documents a deliberate non-support decision and is an unconditional #error
# naming the architecture; nothing builds one, so nothing else would notice if
# it stopped refusing.
#
# The two are told apart by the NESTING DEPTH of the #error, not its presence.
# arm64.h carries conditional module-band relation assertions that are #errors a
# level below the include guard and hold on a healthy tree, so a presence test
# reads the most detailed contract header in the tree as a refusal.
#
# Shared rather than copied because more than one guard asks the question, and
# two copies of a classification rule can disagree — which would leave each
# guard confidently checking a different set.
#
# arch_header_kind <path>  ->  prints "contract" or "stub"
# ---
# <bcoles@gmail.com>

arch_header_kind() {
  awk '
    BEGIN { kind = "contract" }
    # Block comments are removed before anything is counted. A directive
    # commented out at column 0 — the ordinary way to park a block of
    # preprocessor code — otherwise reads as a live #if, and every #error below
    # it appears one level deeper than it is. The failure is loud either way
    # (a misread stub fails the axis probe on its own #error, a misread contract
    # header fails the "refuses but compiles" check), but it names the wrong
    # thing, which is the expensive part of a wrong answer.
    { line = $0
      while (1) {
        if (incomment) {
          e = index(line, "*/")
          if (e == 0) { line = ""; break }
          line = substr(line, e + 2); incomment = 0
          continue
        }
        b = index(line, "/*")
        if (b == 0) break
        e = index(substr(line, b + 2), "*/")
        if (e == 0) { line = substr(line, 1, b - 1); incomment = 1; break }
        line = substr(line, 1, b - 1) substr(line, b + 2 + e + 1)
      }
      $0 = line
    }
    /^[ \t]*#[ \t]*(if|ifdef|ifndef)/ { depth++; next }
    /^[ \t]*#[ \t]*endif/             { depth--; next }
    /^[ \t]*#[ \t]*error/ {
      # Depth 1 is inside the include guard and nothing else, so the #error
      # fires on every inclusion.
      if (depth <= 1) { kind = "stub"; exit }
    }
    END { print kind }
  ' "$1"
}
