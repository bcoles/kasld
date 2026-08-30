# Extra tools

The `extra/` directory ships standalone helpers built around `kasld`: capture and
replay, soundness validation, security-posture comparison, symbol resolution, and
test setup. Each is a self-contained script with a `--help` / header comment — this
page indexes them and shows how they combine into workflows. (`kasld` itself is in
[usage.md](../docs/usage.md).)

## Table of Contents

- [The tools at a glance](#the-tools-at-a-glance)
- [Workflows](#workflows)
  - [Measure what hardening buys](#measure-what-hardening-buys)
  - [Capture here, verify anywhere](#capture-here-verify-anywhere)
  - [Validate a live run against ground truth](#validate-a-live-run-against-ground-truth)
  - [Watch a fleet, gate CI](#watch-a-fleet-gate-ci)
  - [Turn a recovered base into an exploit](#turn-a-recovered-base-into-an-exploit)
- [Standalone helpers](#standalone-helpers)

## The tools at a glance

| Tool | Purpose | Root? | Deeper reference |
|------|---------|-------|------------------|
| [`collect`](collect) | Capture a portable, self-identifying bundle of this host's KASLD-relevant state (meta, `kasld -v`, dmesg, a path-preserving `sysroot/` mirror) | no ¹ | [reproducibility.md](../docs/reproducibility.md#1-on-the-local-kernel) |
| [`validate-bundle`](validate-bundle) | Offline soundness check over a `collect` bundle — asserts the resolved ranges contain the captured truth | no | [reproducibility.md](../docs/reproducibility.md#1-on-the-local-kernel) |
| [`check-results`](check-results) | Live per-leak validator — compares a `kasld` run against `/proc/kallsyms` · `/proc/iomem` · `/proc/kcore` ground truth | **yes** | [testing.md](../docs/testing.md#validating-captured-bundles) |
| [`posture-diff`](posture-diff) | Compare two `kasld -j` snapshots; exit non-zero if the KASLR **posture** regressed | no | [usage.md](../docs/usage.md#regression-gate-extraposture-diff) |
| [`posture-summary`](posture-summary) | Roll up many `kasld -j` snapshots into one table (text / markdown / csv / json), one row per host | no | [usage.md](../docs/usage.md#fleet-summary-extraposture-summary) |
| [`ksymoff`](ksymoff) | Apply the KASLR slide to kernel symbols; translate physical ↔ virtual and physical → `struct page` | no | [exploitation.md](../docs/exploitation.md#from-a-base-to-runtime-addresses) |
| [`weaken-kernel-hardening`](weaken-kernel-hardening) | Temporarily relax the hardening sysctls for testing; restores the originals on exit | **yes** | below |
| [`sudo-proc-kallsyms`](sudo-proc-kallsyms) | Briefly lower `kptr_restrict`, read the base symbols from `/proc/kallsyms`, restore | sudo | below |
| [`check-hardware-vulnerabilities`](check-hardware-vulnerabilities) | Report the CPU hardware vulnerabilities (Meltdown / MDS / …) that can disclose kernel memory to an unprivileged process | no | [bypass-techniques.md](../docs/bypass-techniques.md#side-channels) |
| [`anonymize-fdt`](anonymize-fdt) | Strip board serial / MAC from a captured device tree before sharing it as a replay fixture | no ² | [testing.md](../docs/testing.md) |

¹ `collect --kallsyms` records ground truth only where `kptr_restrict` is readable
(root, or `kptr_restrict=0`); without it the bundle carries no truth.
² Maintainer / dev-host tool; needs `dtc`.

## Workflows

### Measure what hardening buys

`kasld` recovers less on a hardened host and more on a relaxed one; `posture-diff`
puts a number on the gap. Capture the posture in each state, then diff them.

```sh
# 1. Baseline: the host as it boots (whatever hardening is in effect).
./build/*/kasld -j > hardened.json

# 2. Relax the hardening sysctls. weaken-kernel-hardening holds until Ctrl+C and
#    restores the originals on exit; run kasld from a second terminal meanwhile.
sudo extra/weaken-kernel-hardening          # terminal A — leave it running
./build/*/kasld -j > weakened.json          # terminal B
#    ... then Ctrl+C in terminal A to restore the original sysctls.

# 3. What did the hardening hide? Diff hardened (baseline) -> weakened (current):
extra/posture-diff hardened.json weakened.json
#   REGRESSION: posture is weaker than baseline
#     - guaranteed entropy dropped: 9 -> 0 bits (virtual)
#     - defense turned off: kptr_restrict
#     - defense turned off: perf_event_paranoid
```

The regression findings are exactly what the hardening was buying: the residual
entropy it preserved and the defenses it kept on. `posture-diff` is **directional**
(baseline first) — flip the arguments (`posture-diff weakened.json hardened.json`)
and the same change reads as an improvement (`OK: no posture regression`).

`weaken-kernel-hardening` relaxes `kptr_restrict`, `dmesg_restrict`,
`perf_event_paranoid`, and `unprivileged_bpf_disabled` — a **testing** convenience,
never for production. The sysctls are system-wide, so every process on the host
runs unrestricted while it holds them down. It restores the saved values on
`Ctrl+C`, `SIGTERM`, `SIGHUP`, or normal exit. `SIGKILL` cannot be trapped: a hard
kill leaves the sysctls relaxed until they are restored by hand or the host
reboots.

`posture-diff` compares only the **boot-stable** posture — guaranteed entropy
(virtual and physical), KASLR state, unpatched CVE-class leaks, and disabled
defenses. It never reads the per-boot base address or slide, which re-randomize
every boot, so the same command doubles as a reboot-safe config-drift gate.

### Capture here, verify anywhere

`collect` freezes a host's KASLD-relevant state into a portable bundle that
replays offline on another machine — useful for a bug report, an air-gapped
target, or an architecture the analysis host can only emulate.

```sh
# On the target: capture (add --kallsyms to record ground truth for validation).
extra/collect --kallsyms                    # -> kasld-bundle-<arch>-<rel>-<ts>/

# Anywhere: replay the exact same facts through kasld, no target needed. The
# report names the captured kernel, not the one running the replay.
KASLD_SYSROOT=kasld-bundle-*/sysroot ./build/*/kasld -v

# And check the engine stayed sound over that capture (truth ∈ every range):
extra/validate-bundle kasld-bundle-*
```

`validate-bundle` needs no root — the truth comes from the bundle's captured files,
not the host's `/proc`. It exits `0` (every quantity PASS or N/A), `1` (a soundness
violation — the resolved window excluded the truth, a bug), or `2` (malformed
bundle). See [reproducibility.md](../docs/reproducibility.md#1-on-the-local-kernel).

### Validate a live run against ground truth

Where root is available, `check-results` compares a live `kasld` run
against the kernel's real addresses (`/proc/kallsyms`, `/proc/iomem`, …).
It reads tagged lines from a pipe or a saved report — root covers the
ground-truth reads only, and `kasld` itself stays unprivileged:

```sh
./build/*/kasld -v 2>&1 | sudo extra/check-results         # validate a piped run
sudo extra/check-results results.txt                       # or a saved report
```

It reports PASS / FAIL / SKIP per result and asserts the resolved window contains
the truth. A `sudo-proc-kallsyms` one-liner is the minimal version — it just
lowers `kptr_restrict`, prints the base symbols from `/proc/kallsyms`, and restores.

### Watch a fleet, gate CI

The two `posture-*` tools scale the single-host view to an estate and to CI. They
do no collection or transport themselves — the caller's own fan-out supplies the
snapshots (the file's basename is the host label, since `kasld -j` carries no
hostname):

```sh
# One kasld -j per host, then summarise the whole fleet at a glance. kasld
# exits 1 on a host that yields no results, which is still a valid snapshot;
# anything above that means no snapshot was taken.
for h in $(cat hosts); do
  rc=0; ssh "$h" 'kasld -j' > "snap/$h.json" || rc=$?
  [ "$rc" -le 1 ] || echo "$h: no snapshot (exit $rc)" >&2
done
extra/posture-summary --markdown snap/*.json

# In CI: fail the build if a target's posture regressed against a saved baseline.
rc=0; kasld -j > current.json || rc=$?
[ "$rc" -le 1 ] || exit "$rc"
extra/posture-diff baseline.json current.json || echo "KASLR posture regressed"
```

Both read `kasld -j` snapshots (live, or replayed from a `collect` bundle via
`KASLD_SYSROOT`). Full detail — the entropy-threshold and CVE-leak gates they pair
with — is in [usage.md → Continuous integration](../docs/usage.md#continuous-integration).

### Turn a recovered base into an exploit

`ksymoff` consumes `kasld`'s output to resolve runtime symbol addresses (forward
`base → symbols`, inverse `known symbol → base`) and to translate physical
addresses for data-only pivots (`--phys2virt` / `--virt2phys` / `--phys2page`):

```sh
./build/*/kasld -1 2>/dev/null | extra/ksymoff -s System.map commit_creds
```

The full exploit workflow — control-flow reuse vs data-only, the pwntools
template, and every `ksymoff` mode — is in
[exploitation.md](../docs/exploitation.md#from-a-base-to-runtime-addresses).

## Standalone helpers

These two stand alone rather than chaining into a workflow above:

- **[`check-hardware-vulnerabilities`](check-hardware-vulnerabilities)** *(target
  reconnaissance)* — reports which memory-disclosure CPU bugs (Meltdown, MDS, …)
  the running kernel still exposes, i.e. whether a hardware leak of kernel data
  (and with it a pointer that defeats KASLR) is applicable here at all. These
  differ in power: Meltdown reads arbitrary kernel addresses, while MDS/L1TF-class
  flaws leak only opportunistic in-flight or cache-resident data. Background in
  [bypass-techniques.md](../docs/bypass-techniques.md#side-channels).
- **[`anonymize-fdt`](anonymize-fdt)** *(maintainer / fixtures)* — a dev-host tool: strips
  board-identifying serial / MAC properties from a captured flattened device tree
  (`sysroot/sys/firmware/fdt`) before it is committed as a shared replay fixture. It
  deliberately keeps `chosen/kaslr-seed` (KASLD reads it to infer the KASLR state).
  Needs `dtc`; edits in place with a `.orig` backup.
