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
