# Live cross-architecture validation (`tests/vm`)

`tests/vm/run` boots a real, publicly-fetchable kernel under `qemu-system`,
captures the kernel's ground-truth text base, runs the cross-built `kasld`
against the running kernel, and checks the invariant the tool rests on:

```
truth ∈ [virt_image_base_min, virt_image_base_max]
```

It is the cross-architecture, end-to-end counterpart of the single-host check
`extra/collect` + `extra/validate-bundle`, and of the offline
[`tests/replay`](../replay) corpus. Where `tests/replay` proves kasld *parses
and runs* over captured fixtures, this proves the inferred window *contains the
real base* on a live kernel, across architectures and attacker profiles.

## Prerequisites

- `make cross` already run, with the same cross toolchains on PATH (see the
  project docs). The static per-arch `build/<triple>/kasld` binaries and the
  matching `<triple>-gcc` (used here to build the tiny init) are both required.
- `qemu-system-<arch>` on PATH. On Debian/Ubuntu:
  `apt install qemu-system-x86 qemu-system-arm qemu-system-misc`.
- `curl`, `cpio`, `gzip`.

No root is required, and nothing on the host is modified — each arch runs in a
throwaway VM.

## Usage

```sh
tests/vm/run                 # every supported arch, default profile
tests/vm/run aarch64         # one arch
tests/vm/run aarch64 hardened
tests/vm/run all hardened    # every arch in one profile
tests/vm/run table           # results matrix + speculative-narrowing table
tests/vm/run spec-table      # only the speculative-narrowing table
```

Each run prints a per-arch verdict and a summary; the exit status is non-zero if
any arch produced an unsound or incomplete result. After running the scenarios,
`tests/vm/run table` reads the boot logs and emits a markdown matrix
(arch × scenario → recovered / residual bits / sound), then a
speculative-narrowing table showing the cells where the likely best-guess window
beats the guaranteed one and what signal drove it — both published tables in
[docs/reproducibility.md](../../docs/reproducibility.md) are generated this way.

```
aarch64     PASS  truth=0xffff800080000000 ∈ [0x...,0x...] recovered=Y
x86_64      PASS  truth=0xffffffff88000000 ∈ [0x...81000000,0x...bd000000] recovered=N
```

`recovered=Y` means the window collapsed to the exact base; `recovered=N` means
it is wider but still contains the truth — the correct outcome under restriction.
`N/A` means the boot produced no comparable window/truth (not a failure).

## Profiles

| mode | reader identity | what it exercises |
|------|-----------------|-------------------|
| `default`  | root, `kptr_restrict=0` | the easy case — kallsyms readable |
| `hidden`   | root, `kptr_restrict=2` | the pin must come from inference |
| `hardened` | uid 1000, `kptr=2` + `dmesg_restrict=1` + `perf=3` | the realistic unprivileged floor (file-derived facts only) |
| `stock`    | uid 1000, kernel-default sysctls (`kptr=0`, `dmesg_restrict=0`, `perf=2`) | an unprivileged user on an out-of-the-box kernel — nothing weakened or hardened |
| `nokaslr`  | `nokaslr` on the cmdline | the KASLR-disabled pin |

## Architectures

Alpine kernels cover the arches it ports (below); arches it doesn't are built
from kernel.org by `tests/vm/build-kernel` (see "Gap architectures"). Kernels
come from a netboot image where one exists, otherwise the `linux-lts` apk
(`flavor=apk`). An arch is skipped (not failed) when its `qemu-system-*` or its
static `build/<prefix>-*/kasld` is unavailable.

| arch | kernel source | qemu |
|------|---------------|------|
| x86_64 | netboot `virt` | `qemu-system-x86_64` |
| i686 | netboot `lts` | `qemu-system-i386` |
| aarch64 | netboot `virt` | `qemu-system-aarch64` |
| armv7 | netboot `lts` | `qemu-system-arm` |
| riscv64 | `linux-lts` apk | `qemu-system-riscv64` |
| loongarch64 | `linux-lts` apk | `qemu-system-loongarch64` + UEFI firmware |
| ppc64le | netboot `lts` | `qemu-system-ppc64` |
| s390x | netboot `lts` | `qemu-system-s390x` |

All eight have been verified PASS. `ppc64le`/`s390x` need `qemu-system-misc` (or
any qemu with those targets on PATH). `loongarch64` needs an edk2 firmware image:
the recipe auto-discovers one next to the qemu binary (`pc-bios/`) or in the
usual `share` dirs, or set `LOONGARCH_BIOS` explicitly — and the firmware must
match the qemu that loads it.

### Gap architectures (built from kernel.org)

Alpine has no port for some arches; their kernel is built from source by
`tests/vm/build-kernel` — a pinned kernel.org tarball + a stock upstream
defconfig + a fixed one-line endianness overlay where the byte order differs
from the base defconfig. The result is staged into the cache and booted by
`tests/vm/run` with the same `init.c` as the Alpine flavors. Reproducible but
slow; run it once per arch, manually. The arch-gated rule logic is covered
per-push by `tests/test-cross`.

```sh
tests/vm/build-kernel mipsel    # download source + cross-build -> cache (slow)
tests/vm/run mipsel             # boot it, verdict
```

| arch | kernel-ARCH / defconfig | qemu |
|------|-------------------------|------|
| mips | `mips` / `malta_defconfig` + BE | `qemu-system-mips -M malta` |
| mipsel | `mips` / `malta_defconfig` (LE) | `qemu-system-mipsel -M malta` |
| riscv32 | `riscv` / `rv32_defconfig` | `qemu-system-riscv32 -M virt` |
| ppc32 | `powerpc` / `pmac32_defconfig` (BE) | `qemu-system-ppc -M g3beige` |
| armeb (blocked) | `arm` / `multi_v7_defconfig` + BE | `qemu-system-arm -M virt` |

Validation status of the gap arches (built fresh from kernel.org, booted here):

- `mips`, `mipsel`, `riscv32`, `ppc32` — verified end-to-end, boots PASS, base
  recovered exactly. `malta_defconfig` is little-endian, so `mips` exercises the
  big-endian overlay (and `mipsel` boots the native byte order); `riscv32` is
  staged as the flat `Image` (the `virt` board rejects the raw `vmlinux` ELF) and
  needs the 32-bit OpenSBI firmware (auto-discovered, see below); `ppc32` needs
  `qemu-system-ppc` (the `qemu-system-misc`/`-ppc` package) and its console is
  `ttyS0` (pmac zilog registers in the `ttyS` namespace).
- `armeb` — blocked on both ends, by the toolchain and by qemu, not the recipe.
  The only big-endian arm toolchain `make cross` provides
  (`armeb-linux-musleabi`) emits **ARMv5 BE32** code, so: against an ARMv7 **BE8**
  `multi_v7` kernel every instruction is byte-swapped and init SIGILLs; against a
  byte-order-matched v5 kernel (`versatile_defconfig` on `-M versatilepb`) qemu
  produces no output at all — it cannot boot a BE32 ARM Linux kernel (confirmed
  with an uncompressed `Image` + `earlycon`). Validating armeb needs a BE8-capable
  armv7 toolchain, which is not among the musl-cross set.

These rows skip cleanly in `tests/vm/run` until `build-kernel` populates the
cache, so the Alpine arches are unaffected. Stock upstream defconfigs are used
throughout; fall back to a Buildroot `qemu_*` defconfig if a vanilla one won't
boot.

The pinned source is a 6.15.x tarball: the 6.12 LTS tree does not build with a
C23-default compiler (gcc 15 makes `true`/`false`/`bool` keywords, which the
pre-6.13 MIPS vdso clashes with). Override with `LINUX_VERSION` if needed.

## Notes and limitations

- Soundness, not tightness: the check is that the truth is inside the window,
  not how small the window is. A wider-but-sound window under `hardened` is the
  expected result.
- One stock kernel config per arch. Config-gated paths (VA-bits, endianness,
  VMSPLIT, `CONFIG_*` toggles) need purpose-built kernels and are out of scope
  here.
- `loongarch64` boots via UEFI; the firmware is auto-discovered next to the qemu
  binary or set via `LOONGARCH_BIOS`. Under `qemu -M virt` some arches (e.g.
  riscv64) are seedless, so KASLR is off and the result is the disabled-base
  pin — still a soundness point.
- `riscv32` needs 32-bit OpenSBI, which most qemu builds do not bundle (only the
  riscv64 image). It is auto-discovered next to the qemu binary, in the system
  share dir, or in the distro cross package
  (`/usr/lib/riscv32-linux-gnu/opensbi/generic/fw_dynamic.bin`), or set via
  `RISCV32_BIOS`.
- Useful overrides: `QEMU_DIR` (qemu not on PATH), `ALPINE_VER`, `BUILD_DIR`,
  `TIMEOUT`, `LOONGARCH_BIOS`, `RISCV32_BIOS`, and `LINUX_VERSION` (for
  `build-kernel`).
