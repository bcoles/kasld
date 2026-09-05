# Limitations — interpreting a KASLD result

KASLD is **sound but not complete**. It aims to do everything an unprivileged
local process can: every viable leak component, across every supported
architecture, whether or not KASLR is active. But that breadth is finite, while
the ways to defeat KASLR are open-ended — so what KASLD recovers is a lower bound
on what an attacker can, and what it *fails* to recover says little about a
target's real security.

## Table of Contents

- [Trust the positive; read no security into the negative](#trust-the-positive-read-no-security-into-the-negative)
- [What the guarantee assumes about its inputs](#what-the-guarantee-assumes-about-its-inputs)
- [Why a run may under-recover](#why-a-run-may-under-recover)
- [For defenders](#for-defenders)

## Trust the positive; read no security into the negative

The two directions are not symmetric:

- **A positive result is trustworthy.** The guaranteed window is resolved at the
  sound floor and provably contains the true base (see
  [reproducibility.md](reproducibility.md)). When KASLD pins or bounds the base,
  that result holds.
- **A negative or wide result is not a security assurance.** A failure to recover
  the base — or a wide residual window — means only that KASLD's implemented
  techniques did not succeed *here, now, within its constraints*. It is not
  evidence that the base cannot be recovered. Absence of a KASLD leak is not
  absence of a leak.

The reported residual (surviving slots / bits of entropy) is therefore an **upper
bound on the protection that survives** — the best case for the defender, not a
measured security level. A better-resourced attacker generally strips more.

## What the guarantee assumes about its inputs

The guaranteed window is a statement about the kernel whose `/proc` and `/sys`
were read. It assumes those files are that kernel's own.

Ordinary confinement is accounted for. A memory cgroup reports its limit through
`/proc/meminfo`, so a container reads a `MemTotal` far below the machine's — and
that value is deliberately held below the sound floor, where it shapes only the
speculative window. `make test-fixtures-perturb` asserts exactly this across the
whole fixture corpus: shrinking `MemTotal` must not move the guaranteed window.

A substituted fact source goes further. On x86, the no-KASLR base is fixed
exactly by `CONFIG_PHYSICAL_START` together with a kernel alignment, so a source
supplying that pair narrows the guaranteed window to a single address:

- `CONFIG_PHYSICAL_START` is read only from a kernel configuration —
  `/boot/config-<release>`, `/lib/modules/<release>/{build/.config,config}`, or
  `/proc/config.gz`.
- The alignment may come from one of those or, on x86, from the real
  `boot_params` header — so a substituted configuration setting only
  `CONFIG_PHYSICAL_START` can still complete the pair.

With no alignment from anywhere the value raises a floor instead of pinning,
because the kernel rounds an unaligned `CONFIG_PHYSICAL_START` up.

`/proc/cmdline` carrying `nokaslr` does not reach that far on its own. A kernel
booted that way did not randomise, but the base it settled on is known only when
the pair above is readable; otherwise the compile-time default stands in as a
guess and shapes the speculative window alone, so a build with a non-default
`CONFIG_PHYSICAL_START` never has its true base excluded from the guarantee.

Each inference is correct from a truthful source. What differs is how much reach
substituting one takes. `/proc/config.gz` is not namespaced, so a container
reads the host's real one and overriding it means a deliberate bind-mount by
whoever builds the namespace. The on-disk kernel configurations need no such
thing: they are ordinary files in the analysed filesystem, which in a container
is the image's rather than the kernel's. They are trusted because a
release-keyed path is installed by the running kernel's own package — which
holds on a host, where `/boot` and the kernel are the same system's, and does
not hold for an image that merely contains a file of that name. The release is
readable through `uname`, so the keying identifies the intended kernel; it does
not establish who wrote the file. An unkeyed `/boot/config` is already treated
as a best-effort fallback and cannot move the guaranteed window.

The practical form of the assumption: a result describes the tree the run read.
Where that tree was assembled by someone else — a captured bundle, a container
image, a `/proc` entry mounted over — the result is a statement about that tree,
not about the kernel underneath it.

## Why a run may under-recover

None of the following implies KASLR is secure on the system.

**Coverage gaps — the technique that would work here is not implemented.**

- A real leak path exists but is not built: a niche or out-of-tree / vendor-driver
  ioctl, an exotic filesystem, a rare `/proc` or `/sys` interface, a
  platform-specific subsystem — not worth the development and test cost for the
  coverage it would add.
- A leak from current research, or a not-yet-surveyed CVE, that KASLD has not yet
  incorporated. The frontier moves ahead of the tool.
- A supported architecture may implement a given technique only partially.

**Hardware and microarchitecture specificity — the side channels are generic.**

- KASLD ships portable, fail-closed side channels. An attack tuned to the exact
  CPU (cache and TLB geometry, branch predictor, timer source, a specific
  speculation gadget, tailored eviction sets) can succeed where the generic
  implementation reports no signal.
- KASLD declines marginal, low-amplitude signals rather than emit a wrong base —
  it under-reports by design. More samples or better statistics can extract a
  signal it discards.
- Side-channel research is active; a primitive published later can break hardware
  KASLD cannot touch today.

**Environmental and transient conditions — the same system, a different moment.**

- Timing channels are probabilistic: load, frequency scaling, SMT-neighbour
  noise, thermal throttling, and interrupts can suppress a signal a quieter run
  would surface. One failed run is not a verdict.
- Bare metal and virtualization diverge: a channel may work on real silicon but
  not under an emulator, or produce misleading artifacts under a hypervisor. A
  result from a VM does not characterize the target CPU.
- Data sources are transient: the leaking log line may have scrolled out of the
  kernel ring buffer, a module may not be loaded, `/proc/kcore` may be unmounted,
  a device or service may be absent. The condition can recur or be triggered.
- A build or configuration change can move a parsed format — a log string, a
  struct layout, a `/proc` field — so a parser stops matching a leak that is
  still present.

**Threat-model boundaries — KASLD is deliberately narrower than a real adversary.**

- Vantage: KASLD assumes an unprivileged local process with modest permissions.
  A target may expose a leak only via a capability, a group membership, a user
  namespace, or a sysctl combination the run did not hold.
- Non-destructive and time-bounded: KASLD will not crash the system, brute-force
  destructively, or dwell indefinitely — all of which a real attacker tolerates
  (crash-and-retry, long dwell, repeated attempts that amortize residual
  entropy).
- No chaining with a memory-corruption primitive: real exploits often read the
  base directly out of an out-of-bounds read, use-after-free, or info-leak bug.
  A system carrying such a bug is not safe because KASLD's standalone probes
  failed.
- Partial recovery is often enough: an exploit may need only a few bits removed,
  then a spray, a heap groom, or a one-in-*N* jump. A residual of *N* bits is not
  *N* bits of practical safety.
- KASLR is one layer: recovering, or failing to recover, the text base says
  nothing about heap, stack, module, per-CPU, or page-table secrets, or the rest
  of the attack surface.

**The interpretation asymmetry — the meta-point.**

- Sound is not complete. KASLD's guarantees run one direction only: a resolved
  window contains the truth; a missing leak proves nothing.
- "KASLR off" or "randomization failed" describes a specific boot (a seedless
  machine, a particular firmware), not a universal property of the kernel or
  architecture.
- The guarantee is relative to a point-in-time model of the kernel. KASLD
  captures research, techniques, and per-architecture memory-layout models as of
  its last update; the sound floor rests on that model, not on anything the target
  reports. A later kernel that changes an architecture's layout, widens a KASLR
  range, randomizes a region the architecture previously fixed, or decouples
  quantities that were coupled can move the true base outside a *guaranteed*
  window until the model is re-verified. The soundness direction holds for the
  kernel behavior KASLD models; drift beyond it is a maintenance boundary, not a
  property of the target.

## For defenders

The `--hardening` (`-H`) assessment suggests configuration changes from the leaks
that succeeded and scores each by how much residual entropy it is load-bearing
for. Treat those as a floor on exposure, not a certificate: they close the paths
KASLD exercised, and cannot speak to the paths it does not implement, the side
channels tuned to the specific hardware, or a memory-corruption bug that leaks
the base directly. A clean KASLD run raises the cost of defeating KASLR from a
given vantage; it does not prove KASLR intact.

Where a mandatory access control policy is enforcing, the assessment credits it
with a denial only when the component declares sysctl gates and none of them
accounts for the outcome — so an ordinary file-permission denial is never
reported as a policy decision, and the policy's true contribution is at least
what the report attributes to it.

The same applies to what a run *emits*: [footprint.md](footprint.md) bounds
KASLD's observability — it is loud by design, and its default footprint is an
upper bound on what a monitored host sees, not what a tuned adversary produces.
