# shellcheck shell=sh
# This file is part of KASLD - https://github.com/bcoles/kasld
#
# coverage-report.sh — per-file and total line coverage from `gcov -t` output.
#
# The reducer keys every line on file:lineno, so a line counts once however many
# times it appears. That is what lets one source compiled into several
# translation units report as one file rather than as twice as much code -- and,
# for the same reason, what lets the output of SEVERAL gcov runs be unioned by
# piping them all in together. A line executed by either run is covered; a line
# neither reached is the gap.
#
# A line arrives as "<count>:<lineno>:<text>", where <count> is ##### for never
# executed, - for a line carrying no code, and a number otherwise. Only src/*.c
# is reported: gcov also emits an entry per included header and per test driver.
#
#   coverage_report "<total label>"   < gcov-output
# ---
# <bcoles@gmail.com>

coverage_report() {
  awk -v label="$1" '
  /^ *-: *0:Source:/ { f=$0; sub(/.*Source:/,"",f)
                       keep = (f ~ /(^|\/)src\/.*\.c$/); next }
  !keep { next }
  {
    split($0, p, ":")
    cnt=p[1]; ln=p[2]+0
    gsub(/[ \t]/,"",cnt)
    if (ln == 0 || cnt == "-") next
    key = f SUBSEP ln
    if (!(key in seen)) { seen[key]=1; total[f]++ }
    if (cnt != "#####" && !(key in hit)) { hit[key]=1; done[f]++ }
  }
  END {
    for (f in total) {
      bn=f; sub(/.*\//,"",bn)
      printf "  %-34s %6.2f%%  of %4d lines\n", bn, 100*done[f]/total[f], total[f]
      ex += done[f]; all += total[f]
    }
    if (all>0) printf "~TOTAL~  %-34s %6.2f%%  of %4d lines\n",
                      "TOTAL (" label ")", 100*ex/all, all
  }' | sort -k1,1 | sed 's/^~TOTAL~//'
}
