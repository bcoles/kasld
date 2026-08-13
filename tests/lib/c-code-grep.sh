# shellcheck shell=sh
# This file is part of KASLD - https://github.com/bcoles/kasld
#
# c_code_grep FILE ERE — report lines whose CODE matches ERE, ignoring anything
# inside a comment or a string literal.
#
# Several guards ban a token from C source, and every one of them has to answer
# the same awkward question first: is this occurrence real code, or is it a
# comment discussing the very thing being banned? The rules and components
# discuss PAGE_OFFSET, regions and fact names constantly and legitimately, so a
# plain grep is useless and each guard would otherwise carry its own C lexer.
# Two of them did, byte for byte — a subtle 30-line stripper duplicated, where a
# fix to one would silently leave the other wrong. That is the drift these
# guards exist to catch, occurring inside the guards.
#
# Handles block comments (including continuation across lines), line comments,
# and string literals, in whichever order they appear on the line. Prints
# `LINENO:ORIGINAL_LINE` so a caller can both report the source faithfully and
# post-filter on the raw text — a caller that also wants to exempt preprocessor
# conditionals just drops those lines from the output.
#
# Deliberately not a full C lexer: no line continuations, no character literals,
# no raw strings. Those do not occur in this tree's guarded constructs, and the
# failure mode of the omission is a false POSITIVE, which is noisy rather than
# silent.
#
# ERE reaches awk through the ENVIRONMENT, not through `-v`. An assignment made
# with `-v` undergoes escape processing first, so `a\.b` arrives as `a.b` and
# matches `a_b` — a pattern silently WIDER than the one the caller wrote, which
# in a guard means false positives or a matcher that no longer means what it
# says. gawk warns about it; a POSIX awk need not. ENVIRON does no such
# processing, so the pattern arrives exactly as written and callers may use
# backslash escapes normally.
# ---
# <bcoles@gmail.com>

c_code_grep() {
  kasld_ccg_pat=$2 awk '
    BEGIN { inblock = 0; pat = ENVIRON["kasld_ccg_pat"] }
    {
      line = $0
      out = ""
      while (length(line) > 0) {
        if (inblock) {
          i = index(line, "*/")
          if (i == 0) { line = ""; break }
          line = substr(line, i + 2); inblock = 0; continue
        }
        b = index(line, "/*")
        l = index(line, "//")
        q = index(line, "\"")
        # earliest of the three openers still on the line
        first = 0; kind = ""
        if (b > 0)            { first = b; kind = "b" }
        if (l > 0 && (first == 0 || l < first)) { first = l; kind = "l" }
        if (q > 0 && (first == 0 || q < first)) { first = q; kind = "q" }
        if (first == 0) { out = out line; line = ""; break }
        out = out substr(line, 1, first - 1)
        if (kind == "l") { line = ""; break }
        if (kind == "b") { line = substr(line, first + 2); inblock = 1; continue }
        rest = substr(line, first + 1)          # inside a string literal
        j = index(rest, "\"")
        if (j == 0) { line = ""; break }
        line = substr(rest, j + 1)
      }
      if (out ~ pat)
        printf "%d:%s\n", FNR, $0
    }
  ' "$1"
}
