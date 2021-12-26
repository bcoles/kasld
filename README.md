# [ KASLD ] Kernel Address Space Layout Derandomization

A collection of various techniques to infer the Linux kernel base virtual
address as an unprivileged local user, for the purpose of bypassing Kernel
Address Space Layout Randomization (KASLR).

The code is structed for easy re-use; however, leaked addresses
may need to be bit masked appropriately for the target kernel.

Various code snippets were taken from third-parties and may
have license restrictions. Refer to the reference URLs in the
comment headers available in each file for more information.

Refer to [examples.md](examples.md) for example output from
various distros.


## Addendum

Additional noteworthy techniques not included for various reasons.

KASLD performs rudimentary checks for several hardware vulnerabilities, such as TSX/RTM support and Spectre / Meltdown vulnerabilities, but does not implement these techniques. Refer to:

* [vnik5287/kaslr_tsx_bypass](https://github.com/vnik5287/kaslr_tsx_bypass)
* [paboldin/meltdown-exploit](https://github.com/paboldin/meltdown-exploit)

Prefetch side-channel attacks. Refer to:

* [xairy/kernel-exploits/prefetch-side-channel](https://github.com/xairy/kernel-exploits/tree/master/prefetch-side-channel)
* [Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR](https://gruss.cc/files/prefetch.pdf)

[From IP ID to Device ID and KASLR Bypass](https://arxiv.org/pdf/1906.10478.pdf) (CVE-2019-10639).

[sctp_af_inet kernel pointer leak](https://www.exploit-db.com/exploits/45919) (CVE-2017-7558) requires `libsctp-dev`.

[wait_for_kaslr_to_be_effective.c](https://grsecurity.net/~spender/exploits/wait_for_kaslr_to_be_effective.c) (CVE-2017-14954).

Bugs which trigger a kernel oops can be used to leak kernel pointers by reading `dmesg` / `syslog` on systems without `kernel.dmesg_restrict` (and `kernel.grsecurity.dmesg`) and without `kernel.panic_on_oops`. There are countless examples. A few simple examples are available in the `extra` directory.

Traditionally, kernel pointers were frequently [printed without using `%pK`](https://github.com/torvalds/linux/search?p=1&q=%25pK&type=Commits).

Various areas of [DebugFS](https://en.wikipedia.org/wiki/Debugfs) (`/sys/kernel/debug/*`) may disclose kernel pointers; however, [DebugFS is not readable by unprivileged users](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=82aceae4f0d42f03d9ad7d1e90389e731153898f) by default (since 2012).

Offsets to useful functions (`commit_creds`, `prepare_kernel_cred`, `native_write_cr4`, etc) from the base address can be pre-calculated for publicly available kernels, or retrieved from various locations (`kallsyms`, `vmlinux`, `System.map`, etc) using [jonoberheide/ksymhunter](https://github.com/jonoberheide/ksymhunter).

Privileged arbitrary read/write in kernel space can be used to bypass KASLR:

* https://github.com/salls/kernel-exploits/blob/master/CVE-2017-5123/exploit_no_smap.c
* https://ryiron.wordpress.com/2013/09/05/kptr_restrict-finding-kernel-symbols-for-shell-code/

Arbitrary-read vulnerability in the timer subsystem (CVE-2017-18344):

* [xairy/kernel-exploits/CVE-2017-18344](https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-18344)
* http://www.openwall.com/lists/oss-security/2018/08/09/6


## References

* [grsecurity - KASLR: An Exercise in Cargo Cult Security](https://grsecurity.net/kaslr_an_exercise_in_cargo_cult_security)
* [get_kernel_sym /proc/kallsyms](https://grsecurity.net/~spender/exploits/exploit.txt)
* [Randomize kernel base address on boot [LWN.net]](https://lwn.net/Articles/444556/)
* [Linux Kernel Driver DataBase: CONFIG_RANDOMIZE_BASE: Randomize the address of the kernel image (KASLR)](https://cateee.net/lkddb/web-lkddb/RANDOMIZE_BASE.html)
* [Linux Kernel Driver DataBase: CONFIG_RELOCATABLE: Build a relocatable kernel](https://cateee.net/lkddb/web-lkddb/RELOCATABLE.html)
* [nf_conntrack net_inet leak](https://www.openwall.com/lists/kernel-hardening/2017/10/05/5)
* [dmesg free_reserved_area() info leak](https://lore.kernel.org/patchwork/patch/728905/)
* [mincore heap page disclosure (CVE-2017-16994)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1431)
* [Breaking KASLR with perf](https://blog.lizzie.io/kaslr-and-perf.html)
* [pppd kptr_restrict bypass](https://www.openwall.com/lists/kernel-hardening/2013/10/14/2)
* [wchan info leak](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b2f73922d119686323f14fbbe46587f863852328)
* [speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker)

