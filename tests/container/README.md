# Container / cgroup execution harness

`tests/container/run` — checks how kasld behaves when run inside a container or
cgroup-constrained namespace, where the kernel is the **host's** but the
`/proc`/`/sys` view is masked or virtualized. Run with `make test-container`
(opt-in: it snapshots the live host and runs live probes, so it is not part of
the hermetic `make test`).

## The loop it supports

theorise a container scenario → encode it as a check here → run → fix the code →
re-run (backtest). Checks accumulate as regressions.

## What it checks

Two families of invariant: **soundness** (a restricted/faked input must not
corrupt the GUARANTEED window) and **robustness** (a blocked syscall, killed
child, failed fork, masked file, or memory limit must not crash, hang, or
silently mis-degrade).

- **Soundness (truth-free).** The two-window model says the GUARANTEED window
  depends only on trusted inputs, so faking `/proc/meminfo` (shrink
  `MemTotal`/`LowTotal`, as an lxcfs/cgroup container does) must NOT move it —
  only the speculative LIKELY window may. Run against the host (native, x86_64)
  and the x86_32 fixture (coupled arch, native i686 — where the `MemTotal`-ceiling
  rules live). The cross-arch, whole-corpus version of this invariant lives in
  `make test-fixtures-perturb` (`extra/validate-bundle --perturb`).
- **Degradation.** Masking privileged sources (kcore/iomem/kallsyms/modules)
  must not crash; and every component, run directly against an EMPTY `/proc`
  (all reads → ENOENT), must fail CLOSED — a clean exit, never a signal death.
- **seccomp (LIVE).** A container's syscall filter blocks `perf_event_open`;
  under `SCMP_ACT_ERRNO` (EPERM) and `SCMP_ACT_KILL` (SIGSYS) the orchestrator
  must survive and report the block as `access_denied` (not "found nothing").
  Uses `seccomp-exec` (a raw seccomp-BPF wrapper; x86_64).
- **Real masked /proc (LIVE).** `unshare -Urmpf --mount-proc` + `/dev/null`
  bind-mounted over kcore/iomem/kallsyms/modules — a genuine masked /proc
  (readable-but-empty), distinct from the SYSROOT delete (ENOENT). No crash.
- **Fork starvation / pids limit (LIVE).** `fork-fail.so` (LD_PRELOAD) injects
  `EAGAIN` on a fraction of `fork()`s, as a pids cgroup does; the orchestrator
  must skip the failed components and stay coherent (no hang, valid JSON).
- **Memory cgroup (LIVE).** `systemd-run --user -p MemoryMax=32M` — kasld must
  fit a tight container memory budget without OOM (gated on a delegated
  controller).
- **Operational (LIVE).** A restricted cpuset (`taskset -c`) that excludes the
  preferred pin CPU — exercises `pin_cpu`'s fallback.

## Substrates

- **SYSROOT** — a container-shaped copy of a fact snapshot (via `extra/collect`),
  replayed with `KASLD_SYSROOT`. Strict: an omitted file reads as absent. The
  invariant runs skip live components (`-s`) so the replay is a pure function of
  the files (perf's sampled IP jitters a byte otherwise and false-flags).
- **LIVE** — the real binary under a real restriction (`taskset`, seccomp filter,
  `unshare` namespace, LD_PRELOAD fork gate, memory cgroup) against the live
  kernel, for runtime behaviour a replay cannot exercise. Unprivileged; each
  LIVE check note-skips cleanly when its facility is unavailable.

## Helpers

Built by `make test-container` (paths passed in via env): `seccomp-exec` (the
seccomp-BPF wrapper) and `fork-fail.so` (the fork-EAGAIN shim), both under
`tests/container/`.

## Adding a scenario

Add a section in `run`: for a file invariant, copy the baseline sysroot, apply a
transform (mask a source, rewrite a `/proc` file), run `KASLD_SYSROOT=<dir>
kasld -s "$SKIP" -j`, and assert (guaranteed-window unchanged, or no-crash); for
a runtime invariant, wrap the live binary in the restriction and assert on its
exit / JSON. For a coupled-arch-only bug, run it against the matching
`tests/fixtures/<arch>` with the cross binary from `make cross`.
