# Third-party notices

KASLD is licensed under the MIT License (see [LICENSE](LICENSE)). Most of the
code is original. Some leak components adapt third-party proof-of-concept code,
and some implement a technique first published by others; each such component
credits its origin in its file header. This file collects those credits, and
lists the external libraries KASLD links against, with the license or reuse
basis for each.

## Adapted and reimplemented code

| Component | Original author(s) | Source | Basis for reuse |
|---|---|---|---|
| `kernelsnitch` | IAIK, Graz University of Technology | https://github.com/IAIK/KernelSnitch | Upstream is MIT — honored; attribution retained. |
| `echoload` | Claudio Canella, Michael Schwarz, Martin Haubenwallner, Martin Schwarzl, Daniel Gruss | https://github.com/cc0x1f/store-to-leak-forwarding | Used with the authors' permission. |
| `databounce` | Claudio Canella, Michael Schwarz, Martin Haubenwallner, Martin Schwarzl, Daniel Gruss | https://github.com/cc0x1f/store-to-leak-forwarding | Used with the authors' permission. |
| `qemu_tcg_iret` | @_leave07 and @prosti | https://kqx.io/post/qemu-nday/ | Used with the authors' permission. |
| `perf_event_open` | lizzie | https://blog.lizzie.io/kaslr-and-perf.html | Adapted with the author's knowledge; substantially reworked since. |
| `entrybleed` | Will (William Liu) | https://www.willsroot.io/2022/12/entrybleed.html | Adapted with the author's knowledge (the EntryBleed paper references KASLD). |
| `proc_kallsyms` | spender (Brad Spengler) | https://grsecurity.net/~spender/exploits/exploit.txt | Rewritten; used with the author's knowledge. |
| `mincore` | Jann Horn | https://bugs.chromium.org/p/project-zero/issues/detail?id=1431 | Adapted from the author's minimal bug reproducer (CVE-2017-16994) and reimplemented. |
| `bcm_msg_head_struct` | Norbert Slusarek | https://www.openwall.com/lists/oss-security/2021/06/15/1/2 | Adapted from the author's minimal bug reproducer (CVE-2021-34693) and reimplemented. |
| `sysfs_kernel_notes_xen` | Nassim-Asrir (@p1k4l4) | https://github.com/Nassim-Asrir/ZDI-24-020 | Technique credit; reimplemented in KASLD's own code. |
| `prefetch` | Daniel Gruss et al. (technique); Will (timing asm) | https://gruss.cc/files/prefetch.pdf ; EntryBleed | Implements the published technique; adapts the EntryBleed timing asm. |
| `arm64_tlb_fault_timing` | Milad Seddigh, Mahdi Esfahani, Sarani Bhattacharya, Mohammad Reza Aref, Hadi Soleimany | https://dl.acm.org/doi/10.1145/3560834.3563823 | Implements the published technique in KASLD's own code; no upstream code used. |
| `zombieload` | ZombieLoad authors (Michael Schwarz, Moritz Lipp, et al., IAIK) | https://github.com/IAIK/ZombieLoad | Implements the published technique in KASLD's own code (`src/include/sidechannel.h`). |

Each component's full credit and reference URLs are in its file header under
`src/components/`. Upstream licenses, where they exist, are honored;
adaptations used with permission are noted above.

## Linked dependencies

KASLD links a few external libraries; none is vendored or modified. Their
licenses:

| Library | License | Used for |
|---|---|---|
| C library — musl | MIT | Released and cross builds link musl statically. |
| C library — glibc | LGPL-2.1-or-later | A local build on a typical Linux distribution links the system glibc dynamically instead. |
| zlib | zlib License | Native `/proc/config.gz` decompression. Linked by the `proc_config` component alone, and only when detected at build time — no other component and not the `kasld` binary. Cross and release builds supply a pinned static zlib; a host build links the system one where present. |

`pthread` (the parallel inference pool and `kernelsnitch`) is part of the C
library on both musl and glibc and carries no separate license. The released
tarballs are statically linked against musl, so the only external library code
they can embed is musl (MIT) and, in the single `proc_config` component,
zlib (zlib License) — both permissive, and neither imposing a condition on
the binaries that do not contain it. zlib is not vendored: it is built from
upstream source, pinned by version and checksum.
