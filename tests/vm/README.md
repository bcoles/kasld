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
tests/vm/run table           # render the results matrix from the boot logs
```

Each run prints a per-arch verdict and a summary; the exit status is non-zero if
any arch produced an unsound or incomplete result. After running the scenarios,
`tests/vm/run table` reads the boot logs and emits a markdown matrix
(arch × scenario → recovered / residual bits / sound) — the published table in
[docs/reproducibility.md](../../docs/reproducibility.md) is generated this way.

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
| `hide`     | root, `kptr_restrict=2` | the pin must come from inference |
| `hardened` | uid 1000, `kptr=2` + `dmesg_restrict=1` + `perf=3` | the realistic unprivileged floor (file-derived facts only) |
| `nokaslr`  | `nokaslr` on the cmdline | the KASLR-disabled pin |

## Architectures

Kernels come from Alpine: a netboot image where one exists, otherwise the
`linux-lts` apk (`flavor=apk`). An arch is skipped (not failed) when its
`qemu-system-*` or its static `build/<prefix>-*/kasld` is unavailable.

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
- Useful overrides: `QEMU_DIR` (qemu not on PATH), `ALPINE_VER`, `BUILD_DIR`,
  `TIMEOUT`.
