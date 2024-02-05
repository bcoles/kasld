<p align="center">
 <img src="logo.png" alt="KASLD logo generated with Stable Diffusion (modified)"/>
</p>

# Kernel Address Space Layout Derandomization [ KASLD ]

A collection of various techniques to infer the Linux kernel base virtual
address as an unprivileged local user, for the purpose of bypassing Kernel
Address Space Layout Randomization (KASLR).

Supports:

* x86 (i386+, amd64)
* ARM (armv6, armv7, armv8)
* MIPS (mipsbe, mipsel, mips64el)
* PowerPC (ppc, ppc64)
* RISC-V (riscv32, riscv64)

## Usage

```
sudo apt install libc-dev make gcc binutils git
git clone https://github.com/bcoles/kasld
cd kasld
./kasld
```

KASLD is written in C and structured for easy re-use. Each file in the `./src`
directory uses a different technique to retrieve or infer kernel addresses
and can be compiled individually.

`./kasld` is a lazy shell script wrapper which simply builds and executes each
of these files, offering a quick and easy method to check for address leaks
on a target system. This script requires `make`.

Refer to [output.md](output.md) for example output from various distros.

## Building

A compiler which supports the `_GNU_SOURCE` macro is required due to
use of non-portable code (`MAP_ANONYMOUS`, `getline()`, `popen()`, ...).

KASLD components can be cross-compiled with `make` by specfying the approriate
compiler (`CC`) with `LDFLAGS=-static`. For example:

```
make CC=aarch64-linux-musl-gcc LDFLAGS=-static
```

## Configuration

Common default kernel config options are defined in [src/kasld.h](src/kasld.h).
The default values should work on most systems, but may need to be tweaked for
the target system - especially old kernels, embedded devices (ie, armv7), or
systems with a non-default memory layout.

Leaked addresses may need to be bit masked off appropriately for the target kernel,
depending on kernel alignment. Once bitmasked, the address may need to be adjusted
based on text offset, although on x86_64 and arm64 (since 2020-04-15) the text
offset is zero.

The configuration options should be fairly self-explanatory. Refer to the comment
headers in [src/kasld.h](src/kasld.h):

https://github.com/bcoles/kasld/blob/5dc63024d08c152b84359a7cd76a95fb10b6b9dc/src/kasld.h#L5-L25


## Function Offsets

As the entire kernel code text is mapped with only the base address randomized,
a single kernel pointer leak can be used to infer the location of the kernel
virtual address space and offset of the kernel base address.

Offsets to useful kernel functions (`commit_creds`, `prepare_kernel_cred`,
`native_write_cr4`, etc) from the base address can be pre-calculated on other
systems with the same kernel - an easy task for publicly available kernels
(ie, distro kernels).

Offsets may also be retrieved from various file system locations (`/proc/kallsyms`,
`vmlinux`, `System.map`, etc) depending on file system permissions.
[jonoberheide/ksymhunter](https://github.com/jonoberheide/ksymhunter) automates
this process.


## Function Granular KASLR (FG-KASLR)

Function Granular KASLR (aka "finer grained KASLR") patches for the 5.5.0-rc7
kernel were [proposed in February 2020](https://lwn.net/Articles/811685/)
(but have not been merged as of 2024-01-01).

This optional non-mainline mitigation ["rearranges your kernel code at load time on a per-function level granularity"](https://lwn.net/Articles/811685/)
and can be enabled with the [CONFIG_FG_KASLR](https://patchwork.kernel.org/project/linux-hardening/patch/20211223002209.1092165-8-alexandr.lobakin@intel.com/) flag.

FG-KASLR ensures the location of kernel and module functions are independently
randomized and no longer located at a constant offset from the kernel `.text`
base.

On systems which support FG-KASLR patches (x86_64 from 2020, arm64 from 2023),
this makes calculating offsets to useful functions more difficult and renders
kernel pointer leaks significantly less useful.

However, some regions of the kernel are not randomized (such as symbols before
`__startup_secondary_64` on x86_64) and offsets remain consistent across reboots.
Additionally, FG-KASLR randomizes only kernel functions, leaving other useful
kernel data (such as [modprobe_path](https://sam4k.com/like-techniques-modprobe_path/)
and `core_pattern` usermode helpers) unchanged at a static offset.


## Addendum

KASLD serves as a non-exhaustive collection and reference for techniques
useful in KASLR bypass; however, it is far from complete. There are many
additional noteworthy techniques not included for various reasons.


### System Logs

Kernel and system logs (`dmesg` / `syslog`) offer a wealth of information, including
kernel pointers and the layout of virtual and physical memory.

Several KASLD components search the kernel message ring buffer for kernel addresses.
The following KASLD components read from `dmesg` and `/var/log/dmesg`:

* [dmesg_android_ion_snapshot.c](src/dmesg_android_ion_snapshot.c)
* [dmesg_backtrace.c](src/dmesg_backtrace.c)
* [dmesg_check_for_initrd.c](src/dmesg_check_for_initrd.c)
* [dmesg_driver_component_ops.c](src/dmesg_driver_component_ops.c)
* [dmesg_early_init_dt_add_memory_arch.c](src/dmesg_early_init_dt_add_memory_arch.c)
* [dmesg_ex_handler_msr.c](src/dmesg_ex_handler_msr.c)
* [dmesg_fake_numa_init.c](src/dmesg_fake_numa_init.c)
* [dmesg_free_area_init_node.c](src/dmesg_free_area_init_node.c)
* [dmesg_free_reserved_area.c](src/dmesg_free_reserved_area.c)
* [dmesg_kaslr-disabled.c](src/dmesg_kaslr-disabled.c)
* [dmesg_mem_init_kernel_layout.c](src/dmesg_mem_init_kernel_layout.c)
* [dmesg_mmu_idmap.c](src/dmesg_mmu_idmap.c)

Historically, raw kernel pointers were frequently printed to the system log
without using the [`%pK` printk format](https://www.kernel.org/doc/html/latest/core-api/printk-formats.html).

* https://github.com/torvalds/linux/search?p=1&q=%25pK&type=Commits

Bugs which trigger a kernel oops can be used to leak kernel pointers by reading
the associated backtrace from system logs (on systems with `kernel.panic_on_oops = 0`).

There are countless examples. A few simple examples are available in the [extra](extra/) directory:

* [extra/oops_inet_csk_listen_stop.c](extra/oops_inet_csk_listen_stop.c)
* [extra/oops_netlink_getsockbyportid_null_ptr.c](extra/oops_netlink_getsockbyportid_null_ptr.c)

Most modern distros ship with `kernel.dmesg_restrict` enabled by default to
prevent unprivileged users from accessing the kernel debug log. Similarly,
grsecurity hardened kernels support `kernel.grsecurity.dmesg` to prevent
unprivileged access.

System log files (ie, `/var/log/syslog`) are readable only by privileged users
on modern distros. On Debian/Ubuntu systems, users in the `adm` group also have
read permissions on various system log files in `/var/log/`:

```
$ ls -la /var/log/syslog /var/log/kern.log /var/log/dmesg
-rw-r----- 1 root   adm 147726 Jan  8 01:43 /var/log/dmesg
-rw-r----- 1 syslog adm    230 Jan 15 00:00 /var/log/kern.log
-rw-r----- 1 syslog adm   8322 Jan 15 04:26 /var/log/syslog
```

Typically the first user created during installation of an Ubuntu system
is a member of the `adm` group and will have read access to these files.

Additionally, [an initscript bug](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=867747)
present from 2017-2019 caused the `/var/log/dmesg` log file to be generated
with world-readable permissions (`644`) and may still be world-readable on
some systems.


### DebugFS

Various areas of [DebugFS](https://en.wikipedia.org/wiki/Debugfs)
(`/sys/kernel/debug/*`) may disclose kernel pointers.

DebugFS is [no longer readable by unprivileged users by default](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=82aceae4f0d42f03d9ad7d1e90389e731153898f)
since kernel version `v3.7-rc1~174^2~57` on 2012-08-27.

This change pre-dates Linux KASLR by 2 years. However, DebugFS may still be
readable in some non-default configurations.


### Hardware Bugs

There are a plethora of viable hardware-related attacks which can be used to break
KASLR, in particular timing side-channels and transient execution attacks.

KASLD includes the following hardware-related KASLR breaks:

* [EntryBleed (CVE-2022-4543)](src/entrybleed.c)

The [extra/check-hardware-vulnerabilities](extra/check-hardware-vulnerabilities)
script performs rudimentary checks for several known hardware vulnerabilities,
but does not implement these techniques.

Refer to the [Hardware Side-Channels](#hardware-side-channels) section for more information.


### Weak Entropy

The kernel is loaded at an aligned memory address, usually between `PAGE_SIZE` (4096 KiB)
and 2MiB on modern systems (see `KERNEL_ALIGN` definitions in [kasld.h](src/kasld.h)).
This limits the number of possible kernel locations. For example, on x86_64 with
`RANDOMIZE_BASE_MAX_OFFSET` of 1GiB and 2MiB alignment, this limited the kernel load
address to `0x4000_0000 / 0x20_0000 = 512` possible locations.
 
Weaknesses in randomisation can decrease entropy, further limiting the possible kernel
locations in memory and making the kernel easier to locate.

KASLR may be disabled if insufficient randomness is generated during boot
(for example, if `get_kaslr_seed()` fails on ARM64).

Refer to the [Weak Entropy](#weak-entropy) section for more information.


## References

### Linux KASLR History and Implementation

* [grsecurity - KASLR: An Exercise in Cargo Cult Security](https://grsecurity.net/kaslr_an_exercise_in_cargo_cult_security) (grsecurity, 2013)
* [An Info-Leak Resistant Kernel Randomization for Virtualized Systems | IEEE Journals & Magazine | IEEE Xplore](https://ieeexplore.ieee.org/document/9178757) (Fernando Vano-Garcia, Hector Marco-Gisbert, 2020)
* Kernel Address Space Layout Randomization (LWN.net)
  * [Kernel address space layout randomization [LWN.net]](https://lwn.net/Articles/569635/)
  * [Randomize kernel base address on boot [LWN.net]](https://lwn.net/Articles/444556/)
  * [arm64: implement support for KASLR [LWN.net]](https://lwn.net/Articles/673598/)
* Function Granular KASLR (FG-KASLR) (kernel.org)
  * [[PATCH v10 00/15] Function Granular KASLR](https://lore.kernel.org/lkml/20220209185752.1226407-1-alexandr.lobakin@intel.com/)

### Linux KASLR Configuration

* Linux Kernel Driver DataBase
  * [CONFIG_RANDOMIZE_BASE: Randomize the address of the kernel image (KASLR)](https://cateee.net/lkddb/web-lkddb/RANDOMIZE_BASE.html)
  * [CONFIG_RANDOMIZE_BASE_MAX_OFFSET: Maximum kASLR offset](https://cateee.net/lkddb/web-lkddb/RANDOMIZE_BASE_MAX_OFFSET.html)
  * [CONFIG_RANDOMIZE_MEMORY: Randomize the kernel memory sections](https://cateee.net/lkddb/web-lkddb/RANDOMIZE_MEMORY.html)
  * [CONFIG_RELOCATABLE: Build a relocatable kernel](https://cateee.net/lkddb/web-lkddb/RELOCATABLE.html)


### Linux Memory Management

* [0xAX/linux-insides](https://github.com/0xAX/linux-insides)
  * https://github.com/0xAX/linux-insides/tree/master/Initialization
  * https://github.com/0xAX/linux-insides/blob/master/Theory/linux-theory-1.md
  * https://github.com/0xAX/linux-insides/tree/master/MM
* [Virtual Memory and Linux](https://elinux.org/images/b/b0/Introduction_to_Memory_Management_in_Linux.pdf) (Matt Porter, 2016)
* [Understanding the Linux Virtual Memory Manager](https://www.kernel.org/doc/gorman/html/understand/index.html) (Mel Gorman, 2004)
* Linux Kernel Programming (Kaiwan N Billimoria, 2021)


### Hardware Side-Channels

[Practical Timing Side Channel Attacks Against Kernel Space ASLR](https://openwall.info/wiki/_media/archive/TR-HGI-2013-001.pdf) (Ralf Hund, Carsten Willems, Thorsten Holz, 2013)

[google/safeside](https://github.com/google/safeside)

[Micro architecture attacks on KASLR](https://cyber.wtf/2016/10/25/micro-architecture-attacks-on-kasrl/) (Anders Fogh, 2016)

[PLATYPUS: Software-based Power Side-Channel Attacks on x86](https://platypusattack.com/platypus.pdf) (Moritz Lipp, Andreas Kogler, David Oswald†, Michael Schwarz, Catherine Easdon, Claudio Canella, and Daniel Gruss, 2020)

[LVI: Hijacking Transient Execution through Microarchitectural Load Value Injection](https://www.semanticscholar.org/paper/LVI:-Hijacking-Transient-Execution-through-Load-Bulck-Moghimi/5cbf634d4308a30b2cddb4c769056750233ddaf6) (Jo Van Bulck, Daniel Moghimi, Michael Schwarz, Moritz Lipp, Marina Minkin, Daniel Genkin, Yuval Yarom, Berk Sunar, Daniel Gruss, and Frank Piessens, 2020)

[Exploiting Microarchitectural Optimizations from Software](https://diglib.tugraz.at/download.php?id=61adc85670183&location=browse) (Moritz Lipp. 2021)

[Hardening the Kernel Against Unprivileged Attacks](https://www.cc0x1f.net/publications/thesis.pdf) (Claudio Canella, 2022)

[ThermalBleed: A Practical Thermal Side-Channel Attack](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=9727162) (Taehun Kim, Youngjoo Shin. 2022)

AMD prefetch and power-based side channel attacks (CVE-2021-26318):

  * https://www.amd.com/en/corporate/product-security/bulletin/amd-sb-1017
  * [AMD Prefetch Attacks through Power and Time](https://www.usenix.org/conference/usenixsecurity22/presentation/lipp) (Moritz Lipp, Daniel Gruss, Michael Schwarz. 2022)
    * https://www.usenix.org/system/files/sec22-lipp.pdf
    * USENIX Security 2022 Presentation: https://www.youtube.com/watch?v=bTV-9-B26_w
    * https://github.com/amdprefetch/amd-prefetch-attacks/tree/master/case-studies/kaslr-break

Microarchitectural Data Sampling (MDS) side-channel attacks:

  * [Fallout: Leaking Data on Meltdown-resistant CPUs](https://mdsattacks.com/files/fallout.pdf) (Claudio Canella, Daniel Genkin, Lukas Giner, Daniel Gruss, Moritz Lipp, Marina Minkin, Daniel Moghimi, Frank Piessens, Michael Schwarz, Berk Sunar, Jo Van Bulck, Yuval Yarom, 2019)
    * https://github.com/wbowling/cpu.fail/blob/master/zombieload_kaslr.c (wbowling, 2019)
  * [RIDL: Rogue In-Flight Data Load](https://mdsattacks.com/files/ridl.pdf) (Stephan van Schaik, Alyssa Milburn, Sebastian Österlund, Pietro Frigo, Giorgi Maisuradze, Kaveh Razavi, Herbert Bos, and Cristiano Giuffrida, 2019)
    * [vusec/ridl](https://github.com/vusec/ridl) - Intel CPUs (VUSec, 2019)
  * [ZombieLoad](https://zombieloadattack.com/):
    * [IAIK/ZombieLoad](https://github.com/IAIK/ZombieLoad)
    * https://github.com/wbowling/cpu.fail/blob/master/fallout_kaslr.c (wbowling, 2019)

EchoLoad:

  * [KASLR: Break It, Fix It, Repeat](https://gruss.cc/files/kaslrbfr.pdf) (Claudio Canella, Michael Schwarz, Martin Haubenwallner, 2020)
  * [Store-to-Leak Forwarding: There and Back Again](https://i.blackhat.com/asia-20/Friday/asia-20-Canella-Store-To-Leak-Forwarding-There-And-Back-Again-wp.pdf) (Claudio Canella, Lukas Giner, Michael Schwarz, 2020)
    * Slides: https://misc0110.net/files/store2leak_blackhat_slides.pdf
    * Blackhat Asia 2020 Presentation: https://www.youtube.com/watch?v=Yc1AXkCu2AA
    * https://github.com/cc0x1f/store-to-leak-forwarding-there-and-back-again/tree/master/echoload

Data Bounce:

  * [Store-to-Leak Forwarding: Leaking Data on Meltdown-resistant CPUs](https://cpu.fail/store_to_leak_forwarding.pdf) (Michael Schwarz, Claudio Canella, Lukas Giner, Daniel Gruss, 2019)
    * https://github.com/cc0x1f/store-to-leak-forwarding-there-and-back-again/tree/master/data_bounce

Prefetch side-channel attacks:

  * [Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR](https://gruss.cc/files/prefetch.pdf) (Daniel Gruss, Clémentine Maurice, Anders Fogh, 2016)
    * [xairy/kernel-exploits/prefetch-side-channel](https://github.com/xairy/kernel-exploits/tree/master/prefetch-side-channel) (xairy, 2020)
  * [Using Undocumented CPU Behaviour to See into Kernel Mode and Break KASLR in the Process](https://www.blackhat.com/docs/us-16/materials/us-16-Fogh-Using-Undocumented-CPU-Behaviour-To-See-Into-Kernel-Mode-And-Break-KASLR-In-The-Process.pdf) (Anders Fogh, Daniel Gruss, 2016)
    * Blackhat USA 2015 Presentation: https://www.youtube.com/watch?v=Pwq0vv4X7m4
  * [Fetching the KASLR slide with prefetch](https://googleprojectzero.blogspot.com/2022/12/exploiting-CVE-2022-42703-bringing-back-the-stack-attack.html) (Seth Jenkins, 2022)
    * [prefetch_poc.zip](https://bugs.chromium.org/p/project-zero/issues/detail?id=2351) - Intel x86_64 CPUs with kPTI disabled (`pti=off`)
  * EntryBleed
    * Intel x86_64 CPUs; AMD x86_64 CPUs with kPTI disabled (`pti=off`)
    * [EntryBleed: Breaking KASLR under KPTI with Prefetch (CVE-2022-4543)](https://www.willsroot.io/2022/12/entrybleed.html) (willsroot, 2022)
    * [EntryBleed: A Universal KASLR Bypass against KPTI on Linux](https://dl.acm.org/doi/pdf/10.1145/3623652.3623669) (William Liu, Joseph Ravichandran, Mengjia Yan, 2023)
  * SLAM: Spectre based on Linear Address Masking
    * [Leaky Address Masking: Exploiting Unmasked Spectre Gadgets with Noncanonical Address Translation](https://download.vusec.net/papers/slam_sp24.pdf) (Mathé Hertogh, Sander Wiebing, Cristiano Giuffrida, 2024)
    * [https://www.vusec.net/projects/slam/](https://www.vusec.net/projects/slam/)
    * [vusec/slam](https://github.com/vusec/slam)

Straight-line Speculation (SLS):

  * [The AMD Branch (Mis)predictor Part 2: Where No CPU has Gone Before (CVE-2021-26341)](https://grsecurity.net/amd_branch_mispredictor_part_2_where_no_cpu_has_gone_before) (Pawel Wieczorkiewicz, 2022)
  * [Straight-line Speculation Whitepaper](https://developer.arm.com/documentation/102825/0100/?lang=en) (ARM, 2020)

Transactional Synchronization eXtensions (TSX) side-channel timing attacks:

  * [TSX improves timing attacks against KASLR](http://web.archive.org/web/20141107045306/http://labs.bromium.com/2014/10/27/tsx-improves-timing-attacks-against-kaslr/) (Rafal Wojtczuk, 2014)
  * [DrK: Breaking Kernel Address Space Layout Randomization with Intel TSX](https://www.blackhat.com/docs/us-16/materials/us-16-Jang-Breaking-Kernel-Address-Space-Layout-Randomization-KASLR-With-Intel-TSX.pdf) (Yeongjin Jang, Sangho Lee, Taesoo Kim, 2016)
    * Slides: https://www.blackhat.com/docs/us-16/materials/us-16-Jang-Breaking-Kernel-Address-Space-Layout-Randomization-KASLR-With-Intel-TSX.pdf
    * Blackhat USA 2015 Presentation: https://www.youtube.com/watch?v=rtuXG28g0CU
  * [vnik5287/kaslr_tsx_bypass](https://github.com/vnik5287/kaslr_tsx_bypass) (Vitaly Nikolenko, 2017)

Branch Target Buffer (BTB) based side-channel attacks:

  * [Jump Over ASLR: Attacking Branch Predictors to Bypass ASLR](https://www.cs.ucr.edu/~nael/pubs/micro16.pdf) (Dmitry Evtyushkin, Dmitry Ponomarev, Nael Abu-Ghazaleh, 2016)
    * [felixwilhelm/mario_baslr](https://github.com/felixwilhelm/mario_baslr) - Intel CPUs (Felix Wilhelm, 2016)

Transient Execution / Speculative Execution:

  * The [transient.fail](https://transient.fail/) website offers a good overview of speculative execution / transient execution attacks.
  * [SPECULOSE: Analyzing the Security Implications of Speculative Execution in CPUs](https://arxiv.org/pdf/1801.04084v1.pdf) (Giorgi Maisuradze, Christian Rossow, 2018)
  * [A Systematic Evaluation of Transient Execution Attacks and Defenses](https://www.cc0x1f.net/publications/transient_sytematization.pdf) (Claudio Canella, Jo Van Bulck, Michael Schwarz, Moritz Lipp, Benjamin von Berg, Philipp Ortner, Frank Piessens, Dmitry Evtyushkin3, Daniel Gruss, 2019)
  * [Meltdown](https://meltdownattack.com)
    * [Meltdown: Reading Kernel Memory from User Space](https://meltdownattack.com/meltdown.pdf) (Moritz Lipp, Michael Schwarz, Daniel Gruss, Thomas Prescher, Werner Haas, Anders Fogh, Jann Horn, Stefan Mangard, Paul Kocher, Daniel Genkin, Yuval Yarom, Mike Hamburg, 2018)
    * USENIX Security 2018 Video: https://www.usenix.org/conference/usenixsecurity18/presentation/lipp
    * [paboldin/meltdown-exploit](https://github.com/paboldin/meltdown-exploit)
    * [IAIK/meltdown](https://github.com/IAIK/meltdown)
    * https://github.com/IAIK/transientfail/tree/master/pocs/meltdown
  * [Spectre Attacks: Exploiting Speculative Execution](https://spectreattack.com/spectre.pdf) (Paul Kocher, Jann Horn, Anders Fogh, Daniel Genkin, Daniel Gruss, Werner Haas, Mike Hamburg, Moritz Lipp, Stefan Mangard, Thomas Prescher, Michael Schwarz, Yuval Yarom, 2018)
    * https://github.com/IAIK/transientfail/tree/master/pocs/spectre
  * [Reading privileged memory with a side-channel](https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html) (Jann Horn, 2018)
  * [speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker)
  * [VDSO As A Potential KASLR Oracle](https://www.longterm.io/vdso_sidechannel.html) (Philip Pettersson, Alex Radocea, 2021)
  * [RETBLEED: Arbitrary Speculative Code Execution with Return Instructions](https://comsec.ethz.ch/wp-content/files/retbleed_sec22.pdf) (Johannes Wikner, Kaveh Razavi, 2022)
    * [comsec-group/retbleed](https://github.com/comsec-group/retbleed) - Intel/AMD x86_64 CPUs
  * [Timing the Transient Execution: A New Side-Channel Attack on Intel CPUs](https://arxiv.org/pdf/2304.10877.pdf) (Yu Jin, Pengfei Qiu, Chunlu Wang, Yihao Yang, Dongsheng Wang, Gang Qu, 2023)

Speculative Data Gathering / Gather Data Sampling:

  * [Downfall](https://downfall.page/) (CVE-2022-40982)
    * [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/media/downfall.pdf) (Daniel Moghimi), 2023)

TagBleed: Tagged Translation Lookaside Buffer (TLB) side-channel attacks:

  * [TagBleed: Breaking KASLR on the Isolated Kernel Address Space using Tagged TLBs](https://download.vusec.net/papers/tagbleed_eurosp20.pdf) (Jakob Koschel, Cristiano Giuffrida, Herbert Bos, Kaveh Razavi, 2020)
    * [renorobert/tagbleedvmm](https://github.com/renorobert/tagbleedvmm) (Reno Robert, 2020)

[RAMBleed](https://rambleed.com/) side-channel attack (CVE-2019-0174):

  * [RAMBleed: Reading Bits in Memory Without Accessing Them](https://rambleed.com/docs/20190603-rambleed-web.pdf) (Andrew Kwong, Daniel Genkin, Daniel Gruss, Yuval Yarom, 2019)
  * [google/rowhammer-test](https://github.com/google/rowhammer-test) (Google, 2015)

Memory deduplication timing side-channel attacks:

  * [Memory deduplication as a threat to the guest OS](https://kth.diva-portal.org/smash/get/diva2:1060434/FULLTEXT01) (Kuniyasu Suzaki, Kengo Iijima, Toshiki Yagi, Cyrille Artho. 2011)
  * [Breaking KASLR Using Memory Deduplication in Virtualized Environments](https://www.mdpi.com/2079-9292/10/17/2174) (Taehun Kim, Taehyun Kim, Youngjoo Shin. 2021)
  * [Remote Memory-Deduplication Attacks](https://pure.tugraz.at/ws/portalfiles/portal/38441480/main.pdf) (Martin Schwarzl, Erik Kraft, Moritz Lipp, Daniel Gruss. 2022)


### Kernel Info Leaks

Patched kernel info leak bugs:

  * [https://github.com/torvalds/linux/search?p=1&type=Commits&q=kernel-infoleak](https://github.com/torvalds/linux/search?p=1&type=Commits&q=kernel-infoleak)
  * `git clone https://github.com/torvalds/linux && cd linux && git log | grep 'kernel-infoleak'`

Patched kernel info leak bugs caught by KernelMemorySanitizer (KMSAN):

  * [https://github.com/torvalds/linux/search?p=1&type=Commits&q=BUG: KMSAN: kernel-infoleak](https://github.com/torvalds/linux/search?p=1&type=Commits&q=BUG:%20KMSAN:%20kernel-infoleak)
  * `git clone https://github.com/torvalds/linux && cd linux && git log | grep "BUG: KMSAN: kernel-infoleak"`

Netfilter info leak (CVE-2022-1972):

  * [Yet another bug into Netfilter](https://www.randorisec.fr/yet-another-bug-netfilter/)
    * https://github.com/randorisec/CVE-2022-1972-infoleak-PoC

Remote uninitialized stack variables leaked via Bluetooth (L2CAP `l2cap_conf_efs` struct):

  * [Linux Kernel: Infoleak in Bluetooth L2CAP Handling](https://seclists.org/oss-sec/2022/q4/188) (CVE-2022-42895)
  * [Info Leak in the Linux Kernel via Bluetooth](https://seclists.org/oss-sec/2017/q4/357) (CVE-2017-1000410)

Remote kernel pointer leak via IP packet headers (CVE-2019-10639):

  * [From IP ID to Device ID and KASLR Bypass](https://arxiv.org/pdf/1906.10478.pdf)

floppy block driver `show_floppy` kernel function pointer leak (CVE-2018-7273) (requires `floppy` driver and access to `dmesg`).

  * [Linux Kernel < 4.15.4 - 'show_floppy' KASLR Address Leak](https://www.exploit-db.com/exploits/44325) (Gregory Draperi. 2018)
  * https://xorl.wordpress.com/2018/03/18/cve-2018-7273-linux-kernel-floppy-information-leak/

`kernel_waitid` leak (CVE-2017-14954) (affects kernels 4.13-rc1 to 4.13.4):

  * [wait_for_kaslr_to_be_effective.c](https://grsecurity.net/~spender/exploits/wait_for_kaslr_to_be_effective.c) (spender, 2017)
  * https://github.com/salls/kernel-exploits/blob/master/CVE-2017-5123/exploit_no_smap.c (salls, 2017)

`snd_timer_user_read` uninitialized kernel heap memory disclosure (CVE-2017-1000380):

  * [Linux kernel 2.6.0 to 4.12-rc4 infoleak due to a data race in ALSA timer](https://seclists.org/oss-sec/2017/q2/455) (Alexander Potapenko, 2017)
    * [snd_timer_c.bin](https://seclists.org/oss-sec/2017/q2/att-529/snd_timer_c.bin) (Alexander Potapenko, 2017)

PPTP sockets `pptp_bind()` / `pptp_connect()` kernel stack leak (CVE-2015-8569):
  * https://lkml.org/lkml/2015/12/14/252

Exploiting uninitialized stack variables:

  * [Structure holes and information leaks](https://lwn.net/Articles/417989/) (Jonathan Corbet. 2010)
  * [C Structure Padding Initialization](https://interrupt.memfault.com/blog/c-struct-padding-initialization) (Noah Pendleton. 2022)
  * [DCL39-C. Avoid information leakage when passing a structure across a trust boundary - SEI CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c/DCL39-C.+Avoid+information+leakage+when+passing+a+structure+across+a+trust+boundary)
  * [Exploiting Uses of Uninitialized Stack Variables in Linux Kernels to Leak Kernel Pointers](https://sefcom.asu.edu/publications/leak-kptr-woot20.pdf) (Haehyun Cho, Jinbum Park, Joonwon Kang, Tiffany Bao, Ruoyu Wang, Yan Shoshitaishvili, Adam Doupé, Gail-Joon Ahn. 2020)
    * [Leak kernel pointer by exploiting uninitialized uses in Linux kernel](https://jinb-park.github.io/leak-kptr.html)
    * [jinb-park/leak-kptr](https://github.com/jinb-park/leak-kptr)
    * [compat_get_timex kernel stack pointer leak](https://github.com/jinb-park/leak-kptr/blob/master/exploit/CVE-2018-11508/poc.c) (CVE-2018-11508).
    * [sctp_af_inet kernel pointer leak](https://github.com/jinb-park/leak-kptr/tree/master/exploit/sctp-leak) (CVE-2017-7558) (requires `libsctp-dev`).
    * [rtnl_fill_link_ifmap kernel stack pointer leak](https://github.com/jinb-park/leak-kptr/tree/master/exploit/CVE-2016-4486) (CVE-2016-4486).
    * [snd_timer_user_params kernel stack pointer leak](https://github.com/jinb-park/leak-kptr/tree/master/exploit/CVE-2016-4569) (CVE-2016-4569).


### Kernel Bugs

Leaking kernel addresses using `msg_msg` struct for arbitrary read (for `KMALLOC_CGROUP` objects):

  * [Four Bytes of Power: Exploiting CVE-2021-26708 in the Linux kernel | Alexander Popov](https://a13xp0p0v.github.io/2021/02/09/CVE-2021-26708.html)
  * [CVE-2021-22555: Turning \x00\x00 into 10000$ | security-research](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html)
  * [Exploiting CVE-2021-43267 - Haxxin](https://haxx.in/posts/pwning-tipc/)
  * [Will's Root: pbctf 2021 Nightclub Writeup: More Fun with Linux Kernel Heap Notes!](https://www.willsroot.io/2021/10/pbctf-2021-nightclub-writeup-more-fun.html)
  * [Will's Root: corCTF 2021 Fire of Salvation Writeup: Utilizing msg_msg Objects for Arbitrary Read and Arbitrary Write in the Linux Kernel](https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html)
  * [[corCTF 2021] Wall Of Perdition: Utilizing msg_msg Objects For Arbitrary Read And Arbitrary Write In The Linux Kernel](https://syst3mfailure.io/wall-of-perdition)
  * [[CVE-2021-42008] Exploiting A 16-Year-Old Vulnerability In The Linux 6pack Driver](https://syst3mfailure.io/sixpack-slab-out-of-bounds)

Leaking kernel addresses using privileged arbitrary read (or write) in kernel space:

  * [kptr_restrict – Finding kernel symbols for shell code](https://ryiron.wordpress.com/2013/09/05/kptr_restrict-finding-kernel-symbols-for-shell-code/) (ryiron, 2013)
  * CVE-2017-18344: Exploiting an arbitrary-read vulnerability in the Linux kernel timer subsystem (xairy, 2017):
    * https://www.openwall.com/lists/oss-security/2018/08/09/6
    * https://xairy.io/articles/cve-2017-18344
    * [xairy/kernel-exploits/CVE-2017-18344](https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-18344)


### Weak Entropy

[Another look at two Linux KASLR patches](https://www.kryptoslogic.com/blog/2020/03/another-look-at-two-linux-kaslr-patches/index.html) (Kryptos Logic, 2020)

[arm64: efi: kaslr: Fix occasional random alloc (and boot) failure](https://github.com/torvalds/linux/commit/4152433c397697acc4b02c4a10d17d5859c2730d)


## License

KASLD is MIT licensed but borrows heavily from modified
third-party code snippets and proof of concept code.

Various code snippets were taken from third-parties and may
have different license restrictions. Refer to the reference
URLs in the comment headers available in each file for credits
and more information.
