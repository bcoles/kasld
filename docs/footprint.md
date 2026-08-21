# Footprint — what running KASLD looks like

KASLD is **loud by design**. A single run fans out to ~100+ short-lived child
processes that collectively touch nearly every KASLR-relevant sensitive
interface on the host, in seconds. It makes no attempt to hide: it runs every
applicable component by default and has no stealth mode.

This document describes that footprint from both sides of the monitored host —
for the detection engineer who wants to recognise it, and for the operator who
wants to know the operational cost before running it on a watched estate. It is
the observability analogue of [limitations.md](limitations.md): where that
document gives an honest bound on what a *result* means, this one gives an
honest bound on what a *run* emits.

## The default footprint is an upper bound, not a baseline

What a full run emits is the **upper bound** of observability, not what a tuned
adversary produces. A default run exercises every technique at once; an attacker
who reimplements a single technique — especially a pure-timing side channel —
emits far less, and a slow, single-technique attack sits under per-technique
detection thresholds. KASLD's footprint bounds the observability of *KASLD as
shipped*, not of the underlying techniques. Treat it as the ceiling, not the
detection baseline for a low-and-slow adversary.

## The behavioural signature

The distinctive shape is a **process-tree burst plus a dense sensitive-syscall
cluster**, not any single primitive:

- **Process fan-out.** One parent spawns ~100+ component binaries (the run
  banner prints `Running N components`), each a separate `execve` of a helper
  out of a `components/` or `libexec/kasld/` directory, each reading a targeted
  source and exiting — all within a few seconds. Very little benign software has
  this shape: one process forking dozens of differently-named children that each
  read one sensitive source and exit.

- **A dense cluster of sensitive interfaces.** Across the component set, one run
  categorically touches:
  - `perf_event_open` (multiple components, including text-poke, ksymbol, and
    LBR-sampling leaks);
  - `bpf()` program / map loads (BTF and verifier-log leaks);
  - `klogctl` / syslog ring reads (the shared dmesg framework — many
    components), with a fallback to world-readable log files;
  - reads of `/proc/kallsyms`, `/proc/kcore`, `/proc/iomem`, `/proc/modules`,
    `/proc/config.gz`;
  - `/sys/firmware/*` (memmap, EFI), `/sys/.../resource`, and device files;
  - device and driver `ioctl`s (GPU, sound, filesystem, and others);
  - tight `rdtsc` / `rdtscp` timing loops in the side-channel components
    (`databounce`, `echoload`, `entrybleed`, `mincore`, `prefetch`,
    `prefetch_directmap`, `zombieload` — compiled `-O0` to preserve the timing).

Any one of these is unremarkable; **all of them from one process subtree in one
burst** is the signal. The detection strength comes from co-occurrence and
volume, not from a distinctive individual call.

For the exact interfaces a *specific* component touches, read its `--explain`
text and its source under [`src/components/`](../src/components/) — always
current, where a hand-maintained per-component table would drift.

## For a detection engineer

- **Write behavioural rules, not signatures.** Alerting on the `kasld` binary
  name or component filenames is trivially defeated by renaming or static-linking
  the interesting techniques into one anonymous ELF. Key rules on the *behaviour*
  — the process fan-out plus the syscall/file cluster, correlated to one process
  lineage — not on names or hashes.
- **The cluster is the high-confidence rule.** File-open telemetry on the
  canonical info-leak set (`/proc/kallsyms`, `/proc/kcore`, `/proc/iomem`,
  `/proc/modules`, `/sys/firmware/memmap`, `/proc/config.gz`) keyed to one
  short-lived process subtree, or the co-occurrence of `perf_event_open` +
  `bpf()` + `klogctl` from one parent in seconds, catches a default run reliably
  with a low false-positive rate.
- **Know the residue.** A distilled single-technique, low-and-slow adversary
  sits under per-technique thresholds, and a pure-timing leak (a userspace
  instruction loop with minimal setup) barely touches syscall telemetry — only
  its `perf`/`mmap` scaffolding is visible. The durable value here is the
  *behaviour catalogue* — the enumeration of which primitives to instrument —
  not a signature for this binary.

## For an operator on a monitored estate

- **KASLD is noisy, and that is the operator's problem, not the tool's.** As an
  offensive-*capability* tool it does everything a vantage allows; a blue team
  watching for anomalous syscalls (`perf_event_open`, `bpf()`, dmesg reads,
  tight timing loops) will see a default run. Know this before running it on a
  client estate.
- **There is no stealth or minimal-touch profile.** The only current lever is
  `--skip` (`-s`), a comma-separated glob that drops components by name — so
  staying quiet means hand-picking the parsed, low-touch `/proc` leaks and
  skipping the timing / perf / bpf components, e.g.:

  ```sh
  kasld -s 'prefetch,entrybleed,zombieload,databounce,echoload,mincore,perf_*,bpf_*'
  ```

  This is a manual, per-run choice. A packaged quiet profile (a curated
  high-yield, low-footprint component set) does not exist today.
