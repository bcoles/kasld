# shellcheck shell=sh
# This file is part of KASLD - https://github.com/bcoles/kasld
#
# md-table.sh — read a markdown table by its column NAMES.
#
# Sourced by the guards that check a diagram or a summary against the table it
# was drawn from. Those comparisons need one or two columns out of a table that
# sits among several others in the same document.
#
# Addressing a column by position is what this replaces. A positional reader is
# silently wrong the moment a column is inserted, and wrong in the direction
# that passes: it reads some other column, finds it does not look like what it
# wanted, extracts nothing, and a membership check over an empty set succeeds.
# Naming the column makes an edit that breaks the guard fail loudly instead, and
# lets the same table be found after its columns are reordered.
#
# md_table_select <file> <identify> <column>...
#   <identify>  comma-separated column names that together pick out ONE table:
#               every one must appear in its header row. Choose a name the other
#               tables in the file do not share.
#   <column>... the columns to print, tab-separated, one line per data row.
#
# Prints nothing and returns 3 when no table matches, or when a named column is
# absent from the table that did. Callers must treat that as a failure — an
# empty result is the shape a comparison cannot detect.
#
# Cells are trimmed, and a wrapping pair of backticks is removed: a markdown
# code span is how a table writes a literal, not part of the literal.
# ---
# <bcoles@gmail.com>

md_table_select() {
  _mt_file=$1; _mt_ident=$2; shift 2
  [ -f "$_mt_file" ] || return 3
  # Column names may contain spaces ("KASLR Added"), so they are handed to awk
  # tab-separated rather than relying on word splitting.
  _mt_want=""
  for _mt_c in "$@"; do
    _mt_want=$(printf '%s%s%s' "$_mt_want" "${_mt_want:+$(printf '\t')}" "$_mt_c")
  done
  awk -v ident="$_mt_ident" -v want="$_mt_want" '
    function trim(s) {
      gsub(/^[ \t]+|[ \t]+$/, "", s)
      if (s ~ /^`.*`$/) { s = substr(s, 2, length(s) - 2); gsub(/^[ \t]+|[ \t]+$/, "", s) }
      return s
    }
    # Split a table row into arr[1..n]. Pipes delimit; the leading and trailing
    # ones produce empty edge fields, which are dropped.
    function cells(line, arr,   n, i, raw, out) {
      n = split(line, raw, "|")
      out = 0
      for (i = 2; i < n; i++) arr[++out] = trim(raw[i])
      return out
    }
    BEGIN {
      ni = split(ident, idents, ",")
      for (i = 1; i <= ni; i++) idents[i] = trim(idents[i])
      nw = split(want, wants, "\t")
      found = 0
    }
    !found && /^[ \t]*\|/ {
      n = cells($0, hdr)
      if (n == 0) next
      ok = 1
      for (i = 1; i <= ni; i++) {
        hit = 0
        for (j = 1; j <= n; j++) if (hdr[j] == idents[i]) hit = 1
        if (!hit) { ok = 0; break }
      }
      if (!ok) next
      # Resolve each wanted column to its index in THIS header.
      for (i = 1; i <= nw; i++) {
        idx[i] = 0
        for (j = 1; j <= n; j++) if (hdr[j] == wants[i]) idx[i] = j
        if (idx[i] == 0) exit 3
      }
      found = 1; skipsep = 1; next
    }
    found && skipsep { skipsep = 0; next }          # the |---|---| rule row
    found && /^[ \t]*\|/ {
      n = cells($0, row)
      if (n == 0) exit 0
      out = ""
      for (i = 1; i <= nw; i++) out = out (i > 1 ? "\t" : "") (idx[i] <= n ? row[idx[i]] : "")
      print out
      next
    }
    found { exit 0 }                                 # first non-row line ends it
    END { if (!found) exit 3 }
  ' "$_mt_file"
}
