# [ KASLD ] Kernel Address Space Layout Derandomization

A collection of various techniques to infer the Linux kernel base virtual
address as an unprivileged local user, for the purpose of bypassing Kernel
Address Space Layout Randomization (KASLR).


## Usage

KASLD is written in C and structured for easy re-use. Each file in the `./src`
directory uses a different technique to retrieve or infer kernel addresses
and can be compiled individually.

In some instances a compiler which supports the `_GNU_SOURCE` macro is required.

`./kasld` is a lazy shell script wrapper which simply builds and executes each
of these files, offering a quick and easy method to check for address leaks
on a target system. This script requires `make`.

Refer to [examples.md](examples.md) for example output from various distros.

Leaked addresses may need to be bit masked off appropriately for the target kernel,
depending on kernel alignment. Once bitmasked, the address may need to be adjusted
based on text offset, although on x86_64 and arm64 (since 2020-04-15) the text
offset is zero.

Common default kernel config options are defined in [src/kasld.h](src/kasld.h).


## Extra

Bugs which trigger a kernel oops can be used to leak kernel pointers by reading
the kernel debug log (`dmesg` / `syslog`) on systems without `kernel.dmesg_restrict`
(and `kernel.grsecurity.dmesg`) and without `kernel.panic_on_oops`. There are
countless examples. A few simple examples are available in the [extra/](extra/)
directory.

Traditionally, kernel pointers were frequently printed to the kernel debug log
[without using `%pK`](https://github.com/torvalds/linux/search?p=1&q=%25pK&type=Commits).
Modern distros now use `kernel.dmesg_restrict` to prevent unprivileged users from
accessing the kernel debug log by default.


## Function Offsets

A single kernel pointer leak can be used to infer the location of the kernel virtual address space and offset of the kernel base address.

Prior to the introduction of Function Granular KASLR (aka "finer grained KASLR") in early 5.x kernels in 2020, the entire kernel code text was mapped with only the base address randomized.

Offsets to useful kernel functions (`commit_creds`, `prepare_kernel_cred`, `native_write_cr4`, etc) from the base address could be pre-calculated on other systems with the same kernel - an easy task for publicly available kernels (ie, distro kernels).

Offsets may also be retrieved from various file system locations (`/proc/kallsyms`, `vmlinux`, `System.map`, etc) depending on file system permissions. [jonoberheide/ksymhunter](https://github.com/jonoberheide/ksymhunter) automates this process.

FG KASLR ["rearranges your kernel code at load time on a per-function level granularity"](https://lwn.net/Articles/811685/) and can be enabled with the [CONFIG_FG_KASLR](https://patchwork.kernel.org/project/linux-hardening/patch/20211223002209.1092165-8-alexandr.lobakin@intel.com/) flag. Following the introduction of FG KASLR, the location of kernel and module functions are independently randomized and no longer located at a constant offset from the kernel `.text` base.

This makes calculating offset to useful functions more difficult and renders kernel pointer leaks significantly less useful.


## Addendum

KASLD serves as a non-exhaustive collection and reference for address leaks
useful in KASLR bypass; however, it is far from complete. There are many additional
noteworthy techniques not included for various reasons.

KASLD performs rudimentary checks for several hardware vulnerabilities,
such as TSX/RTM support and Spectre / Meltdown vulnerabilities,
but does not implement these techniques. Refer to:

* [vnik5287/kaslr_tsx_bypass](https://github.com/vnik5287/kaslr_tsx_bypass)
* [paboldin/meltdown-exploit](https://github.com/paboldin/meltdown-exploit)
* [speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker)

Prefetch side-channel attacks:

* [xairy/kernel-exploits/prefetch-side-channel](https://github.com/xairy/kernel-exploits/tree/master/prefetch-side-channel)
* [Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR](https://gruss.cc/files/prefetch.pdf)

Branch Target Buffer (BTB) based side-channel attacks:

* [Jump Over ASLR: Attacking Branch Predictors to Bypass ASLR](https://www.cs.ucr.edu/~nael/pubs/micro16.pdf)

RAMBleed side-channel attack (CVE-2019-0174):

* [RAMBleed](https://rambleed.com/)
* [google/rowhammer-test](https://github.com/google/rowhammer-test)

Remote kernel pointer leak via IP packet headers:

* [From IP ID to Device ID and KASLR Bypass](https://arxiv.org/pdf/1906.10478.pdf) (CVE-2019-10639).

`waitid` (CVE-2017-14954):

  * [wait_for_kaslr_to_be_effective.c](https://grsecurity.net/~spender/exploits/wait_for_kaslr_to_be_effective.c).
  * https://github.com/salls/kernel-exploits/blob/master/CVE-2017-5123/exploit_no_smap.c

[sctp_af_inet kernel pointer leak](https://www.exploit-db.com/exploits/45919) (CVE-2017-7558) (requires `libsctp-dev`).

Exploiting an arbitrary read using `msg_msg` struct:

  * [CVE-2021-22555: Turning \x00\x00 into 10000$ | security-research](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html)
  * [Exploiting CVE-2021-43267 - Haxxin](https://haxx.in/posts/pwning-tipc/)
  * [Will's Root: pbctf 2021 Nightclub Writeup: More Fun with Linux Kernel Heap Notes!](https://www.willsroot.io/2021/10/pbctf-2021-nightclub-writeup-more-fun.html)

Privileged arbitrary read (or write) in kernel space can bypass KASLR:

* https://ryiron.wordpress.com/2013/09/05/kptr_restrict-finding-kernel-symbols-for-shell-code/
* Arbitrary-read vulnerability in the timer subsystem (CVE-2017-18344):
  * [xairy/kernel-exploits/CVE-2017-18344](https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-18344)
  * http://www.openwall.com/lists/oss-security/2018/08/09/6

Various areas of [DebugFS](https://en.wikipedia.org/wiki/Debugfs) (`/sys/kernel/debug/*`) may disclose kernel pointers; however, [DebugFS is not readable by unprivileged users](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=82aceae4f0d42f03d9ad7d1e90389e731153898f) by default (since 2012). This change pre-dates Linux KASLR by 2 years.


## License

KASLD is MIT licensed but borrows heavily from modified
third-party code snippets and proof of concept code.

Various code snippets were taken from third-parties and may
have different license restrictions. Refer to the reference
URLs in the comment headers available in each file for credits
and more information.


## Additional References

* [grsecurity - KASLR: An Exercise in Cargo Cult Security](https://grsecurity.net/kaslr_an_exercise_in_cargo_cult_security)
* [Randomize kernel base address on boot [LWN.net]](https://lwn.net/Articles/444556/)
* Function Granular KASLR (LWN.net):
  * https://lwn.net/Articles/811685/
  * https://lwn.net/Articles/824307/
  * https://lwn.net/Articles/826539/
  * https://lwn.net/Articles/877487/
* [An Info-Leak Resistant Kernel Randomization for Virtualized Systems | IEEE Journals & Magazine | IEEE Xplore](https://ieeexplore.ieee.org/document/9178757)
* [Linux Kernel Driver DataBase: CONFIG_RANDOMIZE_BASE: Randomize the address of the kernel image (KASLR)](https://cateee.net/lkddb/web-lkddb/RANDOMIZE_BASE.html)
* [Linux Kernel Driver DataBase: CONFIG_RANDOMIZE_BASE_MAX_OFFSET: Maximum kASLR offset](https://cateee.net/lkddb/web-lkddb/RANDOMIZE_BASE_MAX_OFFSET.html)
* [Linux Kernel Driver DataBase: CONFIG_RANDOMIZE_MEMORY: Randomize the kernel memory sections](https://cateee.net/lkddb/web-lkddb/RANDOMIZE_MEMORY.html)
* [Linux Kernel Driver DataBase: CONFIG_RELOCATABLE: Build a relocatable kernel](https://cateee.net/lkddb/web-lkddb/RELOCATABLE.html)
