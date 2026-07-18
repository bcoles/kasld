<p align="center">
 <img src="logo.png" alt="KASLD logo generated with Copilot (cropped)"/>
</p>

<p align="center">
  <img src="https://github.com/bcoles/kasld/actions/workflows/build.yml/badge.svg" alt="Build Status"/>
  <img src="https://img.shields.io/github/v/release/bcoles/kasld" alt="Release"/>
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"/>
</p>

KASLD recovers the Linux kernel's virtual and physical memory layout —
primarily the kernel text base — from a local process, using as much as
the process's vantage allows: its privileges and capabilities, the
system's configuration, and any container confinement. It recovers the
kernel text base outright where a leak or side channel allows, and
otherwise narrows it to the smallest set of placements the available
evidence supports. The inference engine fuses evidence from dozens of
independent techniques with the architecture's known invariants,
narrowing the kernel's placement to a residual window — reported as the
surviving slot count and bits of entropy: an upper bound on the protection
KASLR retains from this vantage, not a guarantee the base is beyond an
attacker's reach (see [docs/limitations.md](docs/limitations.md)). On a
fully-patched modern kernel — where x86-64 side channels are mitigated
and no direct kernel-text leak survives — full recovery is often impossible,
but the constraint set is rarely empty. On architectures without KASLR, the
engine locates the bootloader-chosen load address.

Supports:

* x86 (i386+, amd64)
* ARM (armv6, armv7, armv8, aarch64)
* MIPS (mipsbe, mipsel, mips64el)
* PowerPC (ppc, ppc64)
* RISC-V (riscv32, riscv64)
* LoongArch (loongarch64)
* s390

## Quick start

```sh
sudo apt install libc-dev make gcc binutils git
git clone https://github.com/bcoles/kasld
cd kasld
make
./build/<arch>/kasld
```

The `build/<arch>/` directory is self-contained and can be deployed to a
target system:

```
build/<arch>/
  kasld              <- run this
  components/        <- leak components
```

A hardened configuration (`kernel.dmesg_restrict=1`,
`kernel.kptr_restrict=1`, `kernel.perf_event_paranoid=2` or higher,
`kernel.unprivileged_bpf_disabled=1`) narrows the filesystem-oracle
path, but is only one axis of the vantage:
side-channel, weak-entropy, and capability-granted techniques are
independent of these sysctls. For testing, the
[extra/weaken-kernel-hardening](extra/weaken-kernel-hardening) script
can temporarily relax these settings (requires root).

## Example output

The default text mode prints an answer-first overview:

```
KASLD 0.3.1-dev  --  Kernel ASLR derandomization
Target: x86_64 / 6.15.6

Running 94 components (3 experimental skipped; use -x to enable)...
[####################] 100%  94/94  13.9s

  Virtual image base  0xffffffff8fe00000   slide +0xee00000
  Physical image base 0x0000000034600000   slide +0x33600000
  Direct map base     >= 0xffff800000000000
  Phys/Virt coupling  physical and virtual text randomize independently

Leaks (6):
  virt kernel text    0xffffffff8ff04104 [interior]   (perf_event_open, proc_kallsyms)
  virt kernel image   0xffffffff8fe00000 [base]       (perf_event_open, prefetch, proc_kallsyms)
  virt directmap      0xffff9eeb80000000 [base]       (prefetch_directmap)
  phys kernel image   0x0000000034600000 [base]       (proc_iomem_kernel)
  phys kernel data    0x0000000036000000 [base]       (proc_iomem_kernel)
  phys kernel BSS     0x0000000036b34000 [base]       (proc_iomem_kernel)

[-v: detailed results, memory map, system info]  [-H: hardening assessment]
```

`-v` adds the full verbose readout (banner, system-config block,
per-component logs, KASLR analysis, memory-layout maps). `-j` emits
machine-readable JSON. `-1` emits a single shell-pipeable line. `-m`
formats for issue trackers. `-H` appends a hardening assessment in any
mode.

See [docs/usage.md](docs/usage.md) for the full CLI, output-mode
details, explain mode, and hardening assessment.

## Vantage

What KASLD can recover depends on the running process's *vantage* — not a
single privilege level, but the combination of three independent things:

* **Privileges, groups, and capabilities** — an unprivileged uid, membership
  in a group such as `adm` (which grants the kernel logs under `/var/log/`),
  a container task holding an extra capability, or root. These do not form a
  single ladder, because filesystem permissions gate each source
  independently: a container granted `CAP_SYS_RAWIO` is init-namespace root
  for that check and can read `/proc/kcore` — a leak an ordinary user cannot
  reach — while distributions differ over whether a file such as
  `/boot/System.map` is world-readable at all.
* **System configuration** — `kptr_restrict`, `dmesg_restrict`,
  `perf_event_paranoid`, unprivileged BPF, kernel lockdown. Configuration is
  independent of privilege: root cannot read `/proc/kallsyms` under
  `kptr_restrict=2`, while a relaxed sysctl or unprivileged BPF can hand a
  plain user a leak that a hardened system would deny.
* **Confinement** — a namespace or seccomp sandbox that masks `/proc`
  oracles or blocks syscalls, narrowing what any privilege level observes.

KASLD assumes few privileges by default and opportunistically uses whatever
the vantage grants. The reported *guaranteed* window never depends on
privilege: elevated access or a weak configuration can widen what is
attempted, never the sound layout the evidence proves. The verbose (`-v`),
JSON (`-j`), and Markdown (`-m`) outputs report the detected vantage —
container, confinement, readable oracles, and the capability-gated leaks
reachable from the current capabilities.

## Documentation

New to KASLD? Read in order: [docs/kaslr.md](docs/kaslr.md) (what KASLR is and
what it randomizes) → [docs/architecture.md → A leak from end to
end](docs/architecture.md#a-leak-from-end-to-end) (how KASLD turns one leak into
an answer) → [CONTRIBUTING.md](CONTRIBUTING.md) (add a leak component or
inference rule). The table below is the per-audience reference.

| Audience | Document |
|---|---|
| End user / operator | [docs/usage.md](docs/usage.md) — CLI, output modes, explain mode, hardening assessment |
| Interpreting a result | [docs/limitations.md](docs/limitations.md) — what a negative or partial result means: sound-but-not-complete, and why a failure is not a security guarantee |
| Exploit developer | [docs/exploitation.md](docs/exploitation.md) — pwntools template, `ksymoff`, function-offset patterns |
| Component / rule author | [CONTRIBUTING.md](CONTRIBUTING.md) — writing a component or rule, emitter API, exit codes, metadata |
| Architecture / internals | [docs/architecture.md](docs/architecture.md) — the inference engine, data-flow seams, tagged-line protocol, cross-region derivation |
| Test runner / CI | [docs/testing.md](docs/testing.md) — host tests, replay fixtures, cross-arch under qemu-user, coverage |
| Reproducibility | [docs/reproducibility.md](docs/reproducibility.md) — independent verification: on the local kernel, live across architectures, or over the captured corpus |
| KASLR primer | [docs/kaslr.md](docs/kaslr.md) — per-arch KASLR history, default text base, vmsplit, FG-KASLR |
| Bypass techniques | [docs/bypass-techniques.md](docs/bypass-techniques.md) — filesystem leaks, side-channels, syscall / ioctl leaks, weak entropy, patched CVEs, arbitrary read |

## Building

A compiler which supports the `_GNU_SOURCE` macro is required due to
use of non-portable code (`MAP_ANONYMOUS`, `getline()`, `popen()`, …).

```
make              # build kasld + components
make run          # build and run
make test         # build and run unit tests
make cross        # cross-compile for all supported architectures
make install      # install to /usr/local (PREFIX=/usr/local)
make uninstall    # remove installed files
make clean        # remove build directory
make help         # show all targets and options
```

KASLD can be cross-compiled with `make` by specifying the appropriate
compiler (`CC`). Static linking is applied automatically when cross-compiling:

```
make CC=aarch64-linux-musl-gcc
```

Build all supported cross-compilation targets (toolchains must be in `PATH`):

```
make cross
```

## License

KASLD is MIT licensed. It incorporates modified third-party code
snippets and proof-of-concept code; those snippets may carry different
license terms. See the reference URLs in each file's comment header
for credits and license details.
