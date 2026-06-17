#!/bin/sh
# Extract a seed corpus for each fuzz harness from the fixture tree.
# Run from the repo root:
#   tests/fuzz/seed-from-fixtures.sh
#
# Existing corpus files are preserved; new ones are added with hash-based
# names so reruns are idempotent.

set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
FUZZ_DIR=$ROOT/tests/fuzz
CORPUS_DIR=$FUZZ_DIR/corpus

mkdir -p "$CORPUS_DIR/parse_hex" \
         "$CORPUS_DIR/capture_result" \
         "$CORPUS_DIR/capture_scalar" \
         "$CORPUS_DIR/parse_meta"

# Hash-named seed: write to <dir>/<sha1>.txt; idempotent across runs.
seed() {
  dir=$1
  (
    cd "$dir" || exit 1
    h=$(printf '%s' "$2" | sha1sum | cut -c1-12)
    printf '%s' "$2" > "${h}.txt"
  )
}

# ---- capture_result + parse_hex seeds: every tagged line in the fixture
# verbose.txt files. capture_result calls parse_hex internally; sharing the
# corpus exercises both. ----
for verbose in "$ROOT"/tests/fixtures/*/*/verbose.txt; do
  [ -f "$verbose" ] || continue
  grep -E '^[PV] [a-z_]+' "$verbose" | sort -u | while IFS= read -r line; do
    seed "$CORPUS_DIR/capture_result" "$line"
  done
done

# ---- capture_scalar seeds: scalar wire records that components emit. The
# fixtures may not carry many, so seed with a constructed cover set in
# addition to whatever the corpus tree provides. ----
for fact in memtotal phys_addr_bits image_size va_bits init_size \
            page_size efi_present fdt_kaslr_seed kaslr_disabled \
            kaslr_randomization_failed; do
  for conf in parsed derived inferred heuristic; do
    seed "$CORPUS_DIR/capture_scalar" "S $fact conf=$conf value=0x1"
  done
done

# ---- parse_hex seeds: short hex tokens covering the supported shapes
# and known edge cases. ----
for s in 0x0 0x1 0xff 0xffffffffffffffff 0xDEADBEEF 0X0 0x ""; do
  seed "$CORPUS_DIR/parse_hex" "$s"
done

# ---- parse_meta seeds: realistic .kasld_meta payloads + the empty case
# + a multi-value key (the meta parser supports repeated keys). ----
seed "$CORPUS_DIR/parse_meta" "$(printf 'method:parsed\nphase:inference\naddr:virtual\n')"
seed "$CORPUS_DIR/parse_meta" "$(printf 'method:timing\nhardware:KPTI\n')"
seed "$CORPUS_DIR/parse_meta" "$(printf 'method:parsed\nsysctl:dmesg_restrict>=1\nbypass:CAP_SYSLOG\nfallback:/var/log/dmesg\n')"
seed "$CORPUS_DIR/parse_meta" ""
seed "$CORPUS_DIR/parse_meta" "$(printf 'sysctl:dmesg_restrict>=1\nsysctl:kptr_restrict>=1\n')"

echo "Seeded corpora:"
for d in parse_hex capture_result capture_scalar parse_meta; do
  count=$(find "$CORPUS_DIR/$d" -maxdepth 1 -type f 2>/dev/null | wc -l)
  printf '  %-20s  %s entries\n' "$d" "$count"
done
