<p align="center">
 <img src="logo.png" alt="KASLD logo generated with Copilot (cropped)"/>
</p>

<p align="center">
  <img src="https://github.com/bcoles/kasld/actions/workflows/build.yml/badge.svg" alt="Build Status"/>
  <img src="https://img.shields.io/github/v/release/bcoles/kasld" alt="Release"/>
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"/>
</p>

KASLD derandomises the Linux kernel's virtual and physical memory layout
as an unprivileged local user. It recovers the kernel text base where a
leak or side channel allows, and otherwise reduces it to the smallest set
of placements the available evidence supports. On a fully-patched modern
kernel — where x86-64 side channels are mitigated and no direct
kernel-text leak survives — full recovery is often impossible, but the
constraint set is rarely empty. The inference engine combines parsed
bootloader artifacts, `dmesg` landmarks, `/proc` and `/sys` facts, and
architectural invariants to narrow the kernel's possible placement to a
residual window, reported as the surviving slot count and bits of
entropy. On architectures without KASLR, the engine derandomises the
bootloader-chosen load address.

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

Fully-patched systems with `kernel.dmesg_restrict=1`,
`kernel.kptr_restrict=1`, and `kernel.perf_event_paranoid=2` (or higher)
return limited results. For testing, the
[extra/weaken-kernel-hardening](extra/weaken-kernel-hardening) script
can temporarily relax these settings (requires root).

## Example output

The default text mode prints an answer-first overview:

```
KASLD 0.2.0  --  Kernel ASLR derandomisation
Target: x86_64 / 6.12.38+deb13-amd64

Running 77 components (10 experimental skipped; use -x to enable)...
[####################] 100%  77/77  10.5s

  Virtual text base   0xffffffffa7a00000   slide +0x26a00000
  Physical text base  not derandomized                                    9 bits
                      0x0000000001000000 - 0x000000002eedbce0   (367 x 2.0 MiB)
  Direct map base     >= 0xffff800000000000

  Coupling            virt and phys text are independent on this arch.
                      A phys leak does NOT reveal the virt text base.

Leaks (1):
  virt kernel text    0xffffffffa7a00000   (prefetch)

[-v: detailed results, memory map, system info]  [-H: hardening assessment]
```

`-v` adds the full verbose readout (banner, system-config block,
per-component logs, KASLR analysis, memory-layout maps). `-j` emits
machine-readable JSON. `-1` emits a single shell-pipeable line. `-m`
formats for issue trackers. `-H` appends a hardening assessment in any
mode.

See [docs/usage.md](docs/usage.md) for the full CLI, output-mode
details, explain mode, and hardening assessment.

## Documentation

| Audience | Document |
|---|---|
| End user / operator | [docs/usage.md](docs/usage.md) — CLI, output modes, explain mode, hardening assessment |
| Exploit developer | [docs/exploitation.md](docs/exploitation.md) — pwntools template, `ksymoff`, function-offset patterns |
| Component / rule author | [CONTRIBUTING.md](CONTRIBUTING.md) — architecture, component model, tagged-line protocol, emitter API |
| Test runner / CI | [TESTING.md](TESTING.md) — host tests, replay fixtures, cross-arch under qemu-user, coverage |
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

## Configuration

Architecture-specific kernel memory layout constants are defined in
[src/include/kasld/api.h](src/include/kasld/api.h). The defaults cover the
common configurations; very old kernels, embedded devices, and systems with
unusual configurations may need adjustment.

Components emit addresses through typed helpers; the orchestrator handles
merging; the inference engine handles bound tightening and consensus. When a
component detects a non-default `PAGE_OFFSET` at runtime (for example a
32-bit system with a 2G/2G vmsplit), `page_offset_from_landmark` pins it and
every other quantity is resolved against the pinned value.

The macro headers in [src/include/kasld/api.h](src/include/kasld/api.h)
document each configuration option.

## License

KASLD is MIT licensed. It incorporates modified third-party code
snippets and proof-of-concept code; those snippets may carry different
license terms. See the reference URLs in each file's comment header
for credits and license details.
