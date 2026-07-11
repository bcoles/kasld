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

- **Soundness (truth-free).** The two-window model says the GUARANTEED window
  depends only on trusted inputs, so faking `/proc/meminfo` (shrink
  `MemTotal`/`LowTotal`, as an lxcfs/cgroup container does) must NOT move it —
  only the speculative LIKELY window may. A guaranteed-window change under a fake
  means a fakeable value reached the guaranteed window: a soundness bug. No
  ground truth needed. Run against the host (native, x86_64) and the x86_32
  fixture (coupled arch, native i686 — where the `MemTotal`-ceiling rules live).
- **Degradation.** Masking privileged sources (kcore/iomem/kallsyms/modules)
  must not crash.
- **Operational (LIVE).** A restricted cpuset (`taskset -c`) that excludes the
  hardcoded pin CPU — exercises the `pin_cpu` issue.

## Substrates

- **SYSROOT** — a container-shaped copy of a fact snapshot (via `extra/collect`),
  replayed with `KASLD_SYSROOT`. Strict: an omitted file reads as absent. The
  invariant runs skip live components (`-s`) so the replay is a pure function of
  the files (perf's sampled IP jitters a byte otherwise and false-flags).
- **LIVE** — the real binary wrapped (`taskset -c`) against the live kernel, for
  runtime behaviour a replay cannot exercise. Unprivileged.

## Adding a scenario

Add a profile in `run`: copy the baseline sysroot, apply a transform (mask a
source, rewrite a `/proc` file), run `KASLD_SYSROOT=<dir> kasld -s "$SKIP" -j`,
and assert an invariant (guaranteed-window unchanged, or no-crash). For a
coupled-arch-only bug, run it against the matching `tests/fixtures/<arch>` with
the cross binary from `make cross`.
