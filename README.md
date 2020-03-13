# [ KASLD ] Kernel Address Space Layout Derandomization

A collection of various techniques to bypass Linux Kernel Address Space
Layout Randomization (KASLR) and retrieve the kernel base virtual address
on x86 / x86_64 architectures as an unprivileged local user.

The code is structed for easy re-use; however, leaked addresses
may need to be bit masked appropriately for the target kernel.

Various code snippets were taken from third-parties and may
have license restrictions. Refer to the reference URLs in the
comment headers available in each file for more information.

Android is not supported.


## Example Output

### Ubuntu 16.04 (x64)

```
$ ./kasld 
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release: 4.4.0-21-generic
Kernel version: #37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016
Kernel arch:    x86_64

kernel base (arch default): ffffffff81000000

[.] checking /boot/config ...

[.] trying /proc/cmdline ...

[.] trying /proc/kallsyms...
[-] kernel symbol 'startup_64' not found in /proc/kallsyms

[.] trying /sys/kernel/slab/ ...
leaked init_net: ffffffff81ef3cc0
kernel base (possible): ffffffff81e00000
kernel base (possible): ffffffff81000000

[.] trying perf_event_open sampling ...
lowest leaked address: ffffffff810031e8
kernel base (likely): ffffffff81000000

[.] checking dmesg for free_reserved_area() info ...
leaked address: ffffffff820b2000
kernel base (likely): ffffffff82000000
kernel base (likely): ffffffff81000000

[.] checking /var/log/syslog for free_reserved_area() info ...
leaked address: ffffffff820b2000
kernel base (likely): ffffffff82000000
kernel base (likely): ffffffff81000000

[.] searching dmesg ...

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/2091/stat 'wchan' field ...

[.] trying mincore info leak...
leaked address: ffffffff81220df0
kernel base (possible): ffffffff81200000
kernel base (possible): ffffffff81000000

[.] checking CPU TSX/RTM support ...
[-] CPU does not support TSX/RTM

[.] checking /sys/devices/system/cpu/vulnerabilities ...
[.] for more accurate results, try spectre-meldown-checker:
- https://github.com/speed47/spectre-meltdown-checker

```

### Ubuntu 12.04 (i686)

```
$ ./kasld 
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release: 3.2.0-23-generic-pae
Kernel version: #36-Ubuntu SMP Tue Apr 10 22:19:09 UTC 2012
Kernel arch:    i686

src/default.c: In function ‘get_kernel_addr_default’:
src/default.c:25:5: warning: large integer implicitly truncated to unsigned type [-Woverflow]
kernel base (arch default): c1000000

src/boot-config.c: In function ‘get_kernel_addr_cmdline’:
src/boot-config.c:38:5: warning: large integer implicitly truncated to unsigned type [-Woverflow]
[.] checking /boot/config ...
[.] Kernel appears to have been compiled without CONFIG_RELOCATABLE and CONFIG_RANDOMIZE_BASE
kernel base (likely): c1000000

src/cmdline.c: In function ‘get_kernel_addr_cmdline’:
src/cmdline.c:48:5: warning: large integer implicitly truncated to unsigned type [-Woverflow]
[.] trying /proc/cmdline ...

[.] trying /proc/kallsyms...
kernel base (certain): c1000000

src/nf_conntrack.c:16:1: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/nf_conntrack.c:17:1: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/nf_conntrack.c: In function ‘main’:
src/nf_conntrack.c:89:5: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
src/nf_conntrack.c:91:5: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
src/nf_conntrack.c:92:5: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
[-] unsupported: system is not 64-bit.

src/perf_event_open.c:20:1: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/perf_event_open.c:21:1: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/perf_event_open.c: In function ‘main’:
src/perf_event_open.c:157:5: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
src/perf_event_open.c:159:5: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
src/perf_event_open.c:160:5: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
[.] trying perf_event_open sampling ...
lowest leaked address: c106f684
kernel base (likely): c1000000

src/free_reserved_area_dmesg.c:22:1: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/free_reserved_area_dmesg.c:23:1: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/free_reserved_area_dmesg.c: In function ‘main’:
src/free_reserved_area_dmesg.c:104:3: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
src/free_reserved_area_dmesg.c:107:3: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
[.] checking dmesg for free_reserved_area() info ...
[-] unsupported: system is not 64-bit.

src/free_reserved_area_syslog.c:28:1: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/free_reserved_area_syslog.c:29:1: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/free_reserved_area_syslog.c: In function ‘main’:
src/free_reserved_area_syslog.c:103:3: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
src/free_reserved_area_syslog.c:106:3: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
[-] unsupported: system is not 64-bit.

src/dmesg.c:20:1: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/dmesg.c:21:1: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/dmesg.c: In function ‘main’:
src/dmesg.c:102:3: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
src/dmesg.c:103:3: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
[.] searching dmesg ...
[-] unsupported: system is not 64-bit.

[.] trying 'pppd file /proc/kallsyms 2>&1' ...
kernel base (likely): c1000000

src/proc-stat-wchan.c:19:1: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/proc-stat-wchan.c:20:1: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/proc-stat-wchan.c: In function ‘main’:
src/proc-stat-wchan.c:87:5: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
src/proc-stat-wchan.c:89:5: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
src/proc-stat-wchan.c:90:5: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
[-] unsupported: system is not 64-bit.

src/mincore.c:14:1: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/mincore.c:15:1: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/mincore.c: In function ‘get_kernel_addr_mincore’:
src/mincore.c:33:11: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/mincore.c:51:17: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/mincore.c:58:5: warning: large integer implicitly truncated to unsigned type [-Woverflow]
src/mincore.c: In function ‘main’:
src/mincore.c:81:5: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
src/mincore.c:83:5: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
src/mincore.c:84:5: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘long long unsigned int’ [-Wformat]
[.] trying mincore info leak...
[-] unsupported: system is not 64-bit.

[.] checking CPU TSX/RTM support ...
[-] CPU does not support TSX/RTM

[.] checking /sys/devices/system/cpu/vulnerabilities ...
[.] for more accurate results, try spectre-meldown-checker:
- https://github.com/speed47/spectre-meltdown-checker


```

### RHEL 7.6 (x64)

```
$ ./kasld 
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release: 3.10.0-957.el7.x86_64
Kernel version: #1 SMP Thu Oct 4 20:48:51 UTC 2018
Kernel arch:    x86_64

kernel base (arch default): ffffffff81000000

[.] checking /boot/config ...

[.] trying /proc/cmdline ...

[.] trying /proc/kallsyms...
[-] kernel symbol 'startup_64' not found in /proc/kallsyms

[.] trying /sys/kernel/slab/ ...
leaked init_net: ffffffff98511640
kernel base (possible): ffffffff98500000
kernel base (possible): ffffffff98000000

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied

[.] checking dmesg for free_reserved_area() info ...

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): No such file or directory

[.] searching dmesg ...

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/49818/stat 'wchan' field ...
leaked wchan address: ffffffff9789d516
kernel base (possible): ffffffff97800000
kernel base (possible): ffffffff97000000

[.] trying mincore info leak...
[-] kernel base not found in mincore info leak

[.] checking CPU TSX/RTM support ...
[-] CPU does not support TSX/RTM

[.] checking /sys/devices/system/cpu/vulnerabilities ...
[.] for more accurate results, try spectre-meldown-checker:
- https://github.com/speed47/spectre-meltdown-checker

```

### Debian 9.6 (x64)

```
$ ./kasld 
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release: 4.9.0-9-amd64
Kernel version: #1 SMP Debian 4.9.168-1 (2019-04-12)
Kernel arch:    x86_64

kernel base (arch default): ffffffff81000000

[.] checking /boot/config ...

[.] trying /proc/cmdline ...

[.] trying /proc/kallsyms...
kernel base (certain): ffffffff8d000000

[.] trying /sys/kernel/slab/ ...
opendir(/sys/kernel/slab/): No such file or directory

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied

[.] checking dmesg for free_reserved_area() info ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): Permission denied

[.] searching dmesg ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/113030/stat 'wchan' field ...

[.] trying mincore info leak...
[-] kernel base not found in mincore info leak

[.] checking CPU TSX/RTM support ...
[-] CPU does not support TSX/RTM

[.] checking /sys/devices/system/cpu/vulnerabilities ...
[.] for more accurate results, try spectre-meldown-checker:
- https://github.com/speed47/spectre-meltdown-checker

```

### Fedora 27 (x64)

```
$ ./kasld
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release: 4.13.9-300.fc27.x86_64
Kernel version: #1 SMP Mon Oct 23 13:41:58 UTC 2017
Kernel arch:    x86_64

kernel base (arch default): ffffffff81000000

[.] checking /boot/config ...

[.] trying /proc/cmdline ...

[.] trying /proc/kallsyms...
kernel base (certain): ffffffffa3000000

[.] trying /sys/kernel/slab/ ...

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied

[.] checking dmesg for free_reserved_area() info ...

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): No such file or directory

[.] searching dmesg ...

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/9723/stat 'wchan' field ...

[.] trying mincore info leak...
leaked address: ffffffffa32fca94
kernel base (possible): ffffffffa3200000
kernel base (possible): ffffffffa3000000

[.] checking CPU TSX/RTM support ...
[-] CPU does not support TSX/RTM

[.] checking /sys/devices/system/cpu/vulnerabilities ...
[.] for more accurate results, try spectre-meldown-checker:
- https://github.com/speed47/spectre-meltdown-checker

```

### Amazon Linux 20200207 (x64)

```
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release: 4.14.171-136.231.amzn2.x86_64
Kernel version: #1 SMP Thu Feb 27 20:22:48 UTC 2020
Kernel arch:    x86_64

kernel base (arch default): ffffffff81000000

[.] checking /boot/config ...
[.] Kernel appears to have been compiled without CONFIG_RELOCATABLE and CONFIG_RANDOMIZE_BASE
kernel base (likely): ffffffff81000000

[.] trying /proc/cmdline ...

[.] trying /proc/kallsyms...
kernel base (certain): ffffffff81000000

[.] trying /sys/kernel/slab/ ...

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied

[.] checking dmesg for free_reserved_area() info ...

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): No such file or directory

[.] searching dmesg ...

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/7767/stat 'wchan' field ...

[.] trying mincore info leak...
[-] kernel base not found in mincore info leak

[.] checking CPU TSX/RTM support ...
[-] CPU does not support TSX/RTM

[.] checking /sys/devices/system/cpu/vulnerabilities ...
[.] for more accurate results, try spectre-meldown-checker:
- https://github.com/speed47/spectre-meltdown-checker

```

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

