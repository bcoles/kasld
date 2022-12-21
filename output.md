### Ubuntu 16.04 LTS (x86_64)

<details>

```
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release:   4.4.0-21-generic
Kernel version:   #37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016
Kernel arch:      x86_64
Kernel platform:  x86_64

kernel.kptr_restrict:        1
kernel.dmesg_restrict:       0
kernel.panic_on_oops:        0
kernel.perf_event_paranoid:  1

Readable /var/log/syslog:  yes
Readable DebugFS:          no

Building ...

mkdir -p ./build
cc -Wall -std=c99 ./src/bcm_msg_head_struct.c -o ./build/bcm_msg_head_struct.o
./src/bcm_msg_head_struct.c: In function ‘rxsetup_sock’:
./src/bcm_msg_head_struct.c:43:17: error: ‘CAN_FD_FRAME’ undeclared (first use in this function)
   msg.b.flags = CAN_FD_FRAME | SETTIMER | STARTTIMER;
                 ^
./src/bcm_msg_head_struct.c:43:17: note: each undeclared identifier is reported only once for each function it appears in
Makefile:11: recipe for target 'all' failed
make: [all] Error 1 (ignored)
cc -Wall -std=c99 ./src/boot-config.c -o ./build/boot-config.o
cc -Wall -std=c99 ./src/cmdline.c -o ./build/cmdline.o
cc -Wall -std=c99 ./src/default.c -o ./build/default.o
cc -Wall -std=c99 ./src/dmesg_android_ion_snapshot.c -o ./build/dmesg_android_ion_snapshot.o
cc -Wall -std=c99 ./src/dmesg_backtrace.c -o ./build/dmesg_backtrace.o
cc -Wall -std=c99 ./src/dmesg_driver_component_ops.c -o ./build/dmesg_driver_component_ops.o
cc -Wall -std=c99 ./src/dmesg_mem_init_kernel_layout.c -o ./build/dmesg_mem_init_kernel_layout.o
cc -Wall -std=c99 ./src/dmesg_mmu_idmap.c -o ./build/dmesg_mmu_idmap.o
cc -Wall -std=c99 ./src/free_reserved_area_dmesg.c -o ./build/free_reserved_area_dmesg.o
cc -Wall -std=c99 ./src/free_reserved_area_syslog.c -o ./build/free_reserved_area_syslog.o
cc -Wall -std=c99 ./src/mincore.c -o ./build/mincore.o
cc -Wall -std=c99 ./src/mmap-brute-vmsplit.c -o ./build/mmap-brute-vmsplit.o
cc -Wall -std=c99 ./src/perf_event_open.c -o ./build/perf_event_open.o
cc -Wall -std=c99 ./src/proc-config.c -o ./build/proc-config.o
cc -Wall -std=c99 ./src/pppd_kallsyms.c -o ./build/pppd_kallsyms.o
cc -Wall -std=c99 ./src/proc-kallsyms.c -o ./build/proc-kallsyms.o
cc -Wall -std=c99 ./src/proc-stat-wchan.c -o ./build/proc-stat-wchan.o
cc -Wall -std=c99 ./src/sysfs_iscsi_transport_handle.c -o ./build/sysfs_iscsi_transport_handle.o
cc -Wall -std=c99 ./src/sysfs-module-sections.c -o ./build/sysfs-module-sections.o
cc -Wall -std=c99 ./src/sysfs_nf_conntrack.c -o ./build/sysfs_nf_conntrack.o

Running build ...

common default kernel text for arch: ffffffff81000000

[.] checking /boot/config-4.4.0-21-generic ...
[.] checking /boot/config-4.4.0-21-generic ...

[.] trying /proc/cmdline ...
[-] Kernel was not booted with nokaslr flag.

[.] searching dmesg for 'ion_snapshot: ' ...

[.] searching dmesg for call trace kernel pointers ...

[.] searching dmesg for driver component ops pointers ...

[.] searching dmesg for ' kernel memory layout:' ...

[.] searching dmesg for ' static identity map for ' ...

[.] checking dmesg for free_reserved_area() info ...
leaked __init_begin: ffffffff81f41000
possible kernel base: ffffffff81f00000
kernel base (ubuntu trusty): ffffffff81000000
kernel base (ubuntu xenial): ffffffff80f00000

[.] checking /var/log/syslog for free_reserved_area() info ...

[.] searching for kernel virtual address space start ...
[-] Could not locate kernel virtual address space

[.] trying perf_event_open sampling ...
lowest leaked address: ffffffff81094f86
possible kernel base: ffffffff81000000

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/config.gz ...
[-] Could not read /proc/config.gz

[.] checking /proc/kallsyms...
[-] kernel symbol '_stext' not found in /proc/kallsyms

[.] checking /proc/25084/stat 'wchan' field ...

[.] checking /sys/class/iscsi_transport/iser/handle ...
[-] open/read(/sys/class/iscsi_transport/iser/handle): No such file or directory
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] open/read(/sys/class/iscsi_transport/tcp/handle): No such file or directory

[.] trying /sys/modules/*/sections/.text ...

[.] trying /sys/kernel/slab/nf_contrack_* ...
leaked init_net: ffffffff81ef3cc0
possible kernel base: ffffffff81e00000

[.] trying mincore info leak...
[-] kernel base not found in mincore info leak
```
</details>


### Ubuntu 16.04.6 LTS (i686)

<details>

```
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release:   4.15.0-142-generic
Kernel version:   #146~16.04.1-Ubuntu SMP Tue Apr 13 09:26:57 UTC 2021
Kernel arch:      i686
Kernel platform:  i686

kernel.kptr_restrict:        1
kernel.dmesg_restrict:       0
kernel.panic_on_oops:        0
kernel.perf_event_paranoid:  3

Readable /var/log/syslog:  yes
Readable DebugFS:          no

Building ...

mkdir -p ./build
cc -Wall -std=c99 ./src/bcm_msg_head_struct.c -o ./build/bcm_msg_head_struct.o
./src/bcm_msg_head_struct.c: In function ‘rxsetup_sock’:
./src/bcm_msg_head_struct.c:43:17: error: ‘CAN_FD_FRAME’ undeclared (first use in this function)
   msg.b.flags = CAN_FD_FRAME | SETTIMER | STARTTIMER;
                 ^
./src/bcm_msg_head_struct.c:43:17: note: each undeclared identifier is reported only once for each function it appears in
Makefile:11: recipe for target 'all' failed
make: [all] Error 1 (ignored)
cc -Wall -std=c99 ./src/boot-config.c -o ./build/boot-config.o
cc -Wall -std=c99 ./src/cmdline.c -o ./build/cmdline.o
cc -Wall -std=c99 ./src/default.c -o ./build/default.o
cc -Wall -std=c99 ./src/dmesg_android_ion_snapshot.c -o ./build/dmesg_android_ion_snapshot.o
cc -Wall -std=c99 ./src/dmesg_backtrace.c -o ./build/dmesg_backtrace.o
cc -Wall -std=c99 ./src/dmesg_driver_component_ops.c -o ./build/dmesg_driver_component_ops.o
cc -Wall -std=c99 ./src/dmesg_mem_init_kernel_layout.c -o ./build/dmesg_mem_init_kernel_layout.o
cc -Wall -std=c99 ./src/dmesg_mmu_idmap.c -o ./build/dmesg_mmu_idmap.o
cc -Wall -std=c99 ./src/free_reserved_area_dmesg.c -o ./build/free_reserved_area_dmesg.o
cc -Wall -std=c99 ./src/free_reserved_area_syslog.c -o ./build/free_reserved_area_syslog.o
cc -Wall -std=c99 ./src/mincore.c -o ./build/mincore.o
cc -Wall -std=c99 ./src/mmap-brute-vmsplit.c -o ./build/mmap-brute-vmsplit.o
cc -Wall -std=c99 ./src/perf_event_open.c -o ./build/perf_event_open.o
cc -Wall -std=c99 ./src/proc-config.c -o ./build/proc-config.o
cc -Wall -std=c99 ./src/pppd_kallsyms.c -o ./build/pppd_kallsyms.o
cc -Wall -std=c99 ./src/proc-kallsyms.c -o ./build/proc-kallsyms.o
cc -Wall -std=c99 ./src/proc-stat-wchan.c -o ./build/proc-stat-wchan.o
cc -Wall -std=c99 ./src/sysfs_iscsi_transport_handle.c -o ./build/sysfs_iscsi_transport_handle.o
cc -Wall -std=c99 ./src/sysfs-module-sections.c -o ./build/sysfs-module-sections.o
cc -Wall -std=c99 ./src/sysfs_nf_conntrack.c -o ./build/sysfs_nf_conntrack.o

Running build ...

common default kernel text for arch: c0000000

[.] checking /boot/config-4.15.0-142-generic ...
[.] checking /boot/config-4.15.0-142-generic ...

[.] trying /proc/cmdline ...
[-] Kernel was not booted with nokaslr flag.

[.] trying bcm_msg_head struct stack pointer leak ...

[.] searching dmesg for 'ion_snapshot: ' ...

[.] searching dmesg for call trace kernel pointers ...

[.] searching dmesg for driver component ops pointers ...

[.] searching dmesg for ' kernel memory layout:' ...
kernel text start: dc000000
possible kernel base: dc000000

[.] searching dmesg for ' static identity map for ' ...

[.] checking dmesg for free_reserved_area() info ...

[.] checking /var/log/syslog for free_reserved_area() info ...

[.] searching for kernel virtual address space start ...
kernel virtual address start: c0000000

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/config.gz ...
[-] Could not read /proc/config.gz

[.] checking /proc/kallsyms...
[-] kernel symbol '_stext' not found in /proc/kallsyms

[.] checking /proc/3731/stat 'wchan' field ...

[.] checking /sys/class/iscsi_transport/iser/handle ...
[-] fgets(/sys/class/iscsi_transport/iser/handle): Permission denied
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] fgets(/sys/class/iscsi_transport/tcp/handle): Permission denied

[.] trying /sys/modules/*/sections/.text ...

[.] trying /sys/kernel/slab/nf_contrack_* ...
```
</details>


### Debian 9.6 (x86_64)

<details>

```
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release:   4.9.0-9-amd64
Kernel version:   #1 SMP Debian 4.9.168-1 (2019-04-12)
Kernel arch:      x86_64
Kernel platform:  unknown

kernel.kptr_restrict:        0
kernel.dmesg_restrict:       1
kernel.panic_on_oops:        0
kernel.perf_event_paranoid:  3

Readable /var/log/syslog:  no
Readable DebugFS:          no

Building ...

mkdir -p ./build
cc -Wall -std=c99 ./src/bcm_msg_head_struct.c -o ./build/bcm_msg_head_struct.o
cc -Wall -std=c99 ./src/boot-config.c -o ./build/boot-config.o
cc -Wall -std=c99 ./src/cmdline.c -o ./build/cmdline.o
cc -Wall -std=c99 ./src/default.c -o ./build/default.o
cc -Wall -std=c99 ./src/dmesg_android_ion_snapshot.c -o ./build/dmesg_android_ion_snapshot.o
cc -Wall -std=c99 ./src/dmesg_backtrace.c -o ./build/dmesg_backtrace.o
cc -Wall -std=c99 ./src/dmesg_driver_component_ops.c -o ./build/dmesg_driver_component_ops.o
cc -Wall -std=c99 ./src/dmesg_mem_init_kernel_layout.c -o ./build/dmesg_mem_init_kernel_layout.o
cc -Wall -std=c99 ./src/dmesg_mmu_idmap.c -o ./build/dmesg_mmu_idmap.o
cc -Wall -std=c99 ./src/free_reserved_area_dmesg.c -o ./build/free_reserved_area_dmesg.o
cc -Wall -std=c99 ./src/free_reserved_area_syslog.c -o ./build/free_reserved_area_syslog.o
cc -Wall -std=c99 ./src/mincore.c -o ./build/mincore.o
cc -Wall -std=c99 ./src/mmap-brute-vmsplit.c -o ./build/mmap-brute-vmsplit.o
cc -Wall -std=c99 ./src/perf_event_open.c -o ./build/perf_event_open.o
cc -Wall -std=c99 ./src/proc-config.c -o ./build/proc-config.o
cc -Wall -std=c99 ./src/pppd_kallsyms.c -o ./build/pppd_kallsyms.o
cc -Wall -std=c99 ./src/proc-kallsyms.c -o ./build/proc-kallsyms.o
cc -Wall -std=c99 ./src/proc-stat-wchan.c -o ./build/proc-stat-wchan.o
cc -Wall -std=c99 ./src/sysfs_iscsi_transport_handle.c -o ./build/sysfs_iscsi_transport_handle.o
cc -Wall -std=c99 ./src/sysfs-module-sections.c -o ./build/sysfs-module-sections.o
cc -Wall -std=c99 ./src/sysfs_nf_conntrack.c -o ./build/sysfs_nf_conntrack.o

Running build ...

common default kernel text for arch: ffffffff81000000

[.] checking /boot/config-4.9.0-9-amd64 ...
[.] checking /boot/config-4.9.0-9-amd64 ...

[.] trying /proc/cmdline ...
[-] Kernel was not booted with nokaslr flag.

[.] trying bcm_msg_head struct stack pointer leak ...

[.] searching dmesg for 'ion_snapshot: ' ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted

[.] searching dmesg for call trace kernel pointers ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted

[.] searching dmesg for driver component ops pointers ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted

[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted

[.] searching dmesg for ' static identity map for ' ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted

[.] checking dmesg for free_reserved_area() info ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): Permission denied

[.] searching for kernel virtual address space start ...
[-] Could not locate kernel virtual address space

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/config.gz ...
[-] Could not read /proc/config.gz

[.] checking /proc/kallsyms...
kernel text start: ffffffff8d0002b8
possible kernel base: ffffffff8d000000

[.] checking /proc/115191/stat 'wchan' field ...

[.] checking /sys/class/iscsi_transport/iser/handle ...
[-] open/read(/sys/class/iscsi_transport/iser/handle): No such file or directory
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] open/read(/sys/class/iscsi_transport/tcp/handle): No such file or directory

[.] trying /sys/modules/*/sections/.text ...
lowest leaked module text address: ffffffffc00a3000

[.] trying /sys/kernel/slab/nf_contrack_* ...
opendir(/sys/kernel/slab/): No such file or directory

[.] trying mincore info leak...
[-] kernel base not found in mincore info leak
```
</details>


### Debian 11.0 (x86_64)

<details>
   
```
[ KASLD ] Kernel Address Space Layout Derandomization
Kernel release:   5.10.0-8-amd64
Kernel version:   #1 SMP Debian 5.10.46-5 (2021-09-23)
Kernel arch:      x86_64
Kernel platform:  unknown

kernel.kptr_restrict:        0
kernel.dmesg_restrict:       1
kernel.panic_on_oops:        0
kernel.perf_event_paranoid:  3

Readable /var/log/syslog:  no
Readable DebugFS:          no

Building ...

mkdir -p ./build
cc -Wall -std=c99 ./src/bcm_msg_head_struct.c -o ./build/bcm_msg_head_struct.o
cc -Wall -std=c99 ./src/boot-config.c -o ./build/boot-config.o
cc -Wall -std=c99 ./src/cmdline.c -o ./build/cmdline.o
cc -Wall -std=c99 ./src/default.c -o ./build/default.o
cc -Wall -std=c99 ./src/dmesg_android_ion_snapshot.c -o ./build/dmesg_android_ion_snapshot.o
cc -Wall -std=c99 ./src/dmesg_backtrace.c -o ./build/dmesg_backtrace.o
cc -Wall -std=c99 ./src/dmesg_driver_component_ops.c -o ./build/dmesg_driver_component_ops.o
cc -Wall -std=c99 ./src/dmesg_mem_init_kernel_layout.c -o ./build/dmesg_mem_init_kernel_layout.o
cc -Wall -std=c99 ./src/dmesg_mmu_idmap.c -o ./build/dmesg_mmu_idmap.o
cc -Wall -std=c99 ./src/entrybleed.c -o ./build/entrybleed.o
cc -Wall -std=c99 ./src/free_reserved_area_dmesg.c -o ./build/free_reserved_area_dmesg.o
cc -Wall -std=c99 ./src/free_reserved_area_syslog.c -o ./build/free_reserved_area_syslog.o
cc -Wall -std=c99 ./src/mincore.c -o ./build/mincore.o
cc -Wall -std=c99 ./src/mmap-brute-vmsplit.c -o ./build/mmap-brute-vmsplit.o
cc -Wall -std=c99 ./src/perf_event_open.c -o ./build/perf_event_open.o
cc -Wall -std=c99 ./src/proc-config.c -o ./build/proc-config.o
cc -Wall -std=c99 ./src/pppd_kallsyms.c -o ./build/pppd_kallsyms.o
cc -Wall -std=c99 ./src/proc-kallsyms.c -o ./build/proc-kallsyms.o
cc -Wall -std=c99 ./src/proc-stat-wchan.c -o ./build/proc-stat-wchan.o
cc -Wall -std=c99 ./src/sysfs_iscsi_transport_handle.c -o ./build/sysfs_iscsi_transport_handle.o
cc -Wall -std=c99 ./src/sysfs-module-sections.c -o ./build/sysfs-module-sections.o
cc -Wall -std=c99 ./src/sysfs_nf_conntrack.c -o ./build/sysfs_nf_conntrack.o

Running build ...

common default kernel text for arch: ffffffff81000000

[.] checking /boot/config-5.10.0-8-amd64 ...
[.] checking /boot/config-5.10.0-8-amd64 ...

[.] trying /proc/cmdline ...
[-] Kernel was not booted with nokaslr flag.

[.] trying bcm_msg_head struct stack pointer leak ...

[.] searching dmesg for 'ion_snapshot: ' ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted

[.] searching dmesg for call trace kernel pointers ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted

[.] searching dmesg for driver component ops pointers ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted

[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted

[.] searching dmesg for ' static identity map for ' ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted

[.] trying EntryBleed (CVE-2022-4543) ...
[.] Intel CPU with KPTI enabled
[.] kernel version '5.10.0-8-amd64 #1 SMP Debian 5.10.46-5 (2021-09-23)' detected
possible kernel base: ffffffffb0000000

[.] checking dmesg for free_reserved_area() info ...
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): Operation not permitted

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): Permission denied

[.] searching for kernel virtual address space start ...
[-] Could not locate kernel virtual address space

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/config.gz ...
[-] Could not read /proc/config.gz

[.] checking /proc/kallsyms...
[-] kernel symbol '_stext' not found in /proc/kallsyms

[.] checking /proc/1788/stat 'wchan' field ...

[.] checking /sys/class/iscsi_transport/iser/handle ...
[-] open/read(/sys/class/iscsi_transport/iser/handle): No such file or directory
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] open/read(/sys/class/iscsi_transport/tcp/handle): No such file or directory

[.] trying /sys/modules/*/sections/.text ...

[.] trying /sys/kernel/slab/nf_contrack_* ...

[.] trying mincore info leak...
[-] kernel base not found in mincore info leak
```
</details>


### Fedora 27 (x86_64)

<details>

```
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release:   4.13.9-300.fc27.x86_64
Kernel version:   #1 SMP Mon Oct 23 13:41:58 UTC 2017
Kernel arch:      x86_64
Kernel platform:  x86_64

kernel.kptr_restrict:        0
kernel.dmesg_restrict:       0
kernel.panic_on_oops:        0
kernel.perf_event_paranoid:  2

Readable /var/log/syslog:  no
Readable DebugFS:          no

Building ...

mkdir -p ./build
cc -Wall -std=c99 ./src/bcm_msg_head_struct.c -o ./build/bcm_msg_head_struct.o
cc -Wall -std=c99 ./src/boot-config.c -o ./build/boot-config.o
cc -Wall -std=c99 ./src/cmdline.c -o ./build/cmdline.o
cc -Wall -std=c99 ./src/default.c -o ./build/default.o
cc -Wall -std=c99 ./src/dmesg_android_ion_snapshot.c -o ./build/dmesg_android_ion_snapshot.o
cc -Wall -std=c99 ./src/dmesg_backtrace.c -o ./build/dmesg_backtrace.o
cc -Wall -std=c99 ./src/dmesg_driver_component_ops.c -o ./build/dmesg_driver_component_ops.o
cc -Wall -std=c99 ./src/dmesg_mem_init_kernel_layout.c -o ./build/dmesg_mem_init_kernel_layout.o
cc -Wall -std=c99 ./src/dmesg_mmu_idmap.c -o ./build/dmesg_mmu_idmap.o
cc -Wall -std=c99 ./src/free_reserved_area_dmesg.c -o ./build/free_reserved_area_dmesg.o
cc -Wall -std=c99 ./src/free_reserved_area_syslog.c -o ./build/free_reserved_area_syslog.o
cc -Wall -std=c99 ./src/mincore.c -o ./build/mincore.o
cc -Wall -std=c99 ./src/mmap-brute-vmsplit.c -o ./build/mmap-brute-vmsplit.o
cc -Wall -std=c99 ./src/perf_event_open.c -o ./build/perf_event_open.o
cc -Wall -std=c99 ./src/proc-config.c -o ./build/proc-config.o
cc -Wall -std=c99 ./src/pppd_kallsyms.c -o ./build/pppd_kallsyms.o
cc -Wall -std=c99 ./src/proc-kallsyms.c -o ./build/proc-kallsyms.o
cc -Wall -std=c99 ./src/proc-stat-wchan.c -o ./build/proc-stat-wchan.o
cc -Wall -std=c99 ./src/sysfs_iscsi_transport_handle.c -o ./build/sysfs_iscsi_transport_handle.o
cc -Wall -std=c99 ./src/sysfs-module-sections.c -o ./build/sysfs-module-sections.o
cc -Wall -std=c99 ./src/sysfs_nf_conntrack.c -o ./build/sysfs_nf_conntrack.o

Running build ...

common default kernel text for arch: ffffffff81000000

[.] checking /boot/config-4.13.9-300.fc27.x86_64 ...
[.] checking /boot/config-4.13.9-300.fc27.x86_64 ...

[.] trying /proc/cmdline ...
[-] Kernel was not booted with nokaslr flag.

[.] trying bcm_msg_head struct stack pointer leak ...

[.] searching dmesg for 'ion_snapshot: ' ...

[.] searching dmesg for call trace kernel pointers ...

[.] searching dmesg for driver component ops pointers ...

[.] searching dmesg for ' kernel memory layout:' ...

[.] searching dmesg for ' static identity map for ' ...

[.] checking dmesg for free_reserved_area() info ...

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): No such file or directory

[.] searching for kernel virtual address space start ...
[-] Could not locate kernel virtual address space

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/config.gz ...
[-] Could not read /proc/config.gz

[.] checking /proc/kallsyms...
kernel text start: ffffffffa3000000
possible kernel base: ffffffffa3000000

[.] checking /proc/10190/stat 'wchan' field ...

[.] checking /sys/class/iscsi_transport/iser/handle ...
[-] open/read(/sys/class/iscsi_transport/iser/handle): No such file or directory
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] open/read(/sys/class/iscsi_transport/tcp/handle): No such file or directory

[.] trying /sys/modules/*/sections/.text ...
lowest leaked module text address: ffffffffc01d2000

[.] trying /sys/kernel/slab/nf_contrack_* ...

[.] trying mincore info leak...
leaked address: ffffffffa32892d0
possible kernel base: ffffffffa3200000
```
</details>


### Fedora 15 (i686)

<details>

```
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release:   2.6.38.6-26.rc1.fc15.i686.PAE
Kernel version:   #1 SMP Mon May 9 20:36:50 UTC 2011
Kernel arch:      i686
Kernel platform:  i386

kernel.kptr_restrict:        1
kernel.dmesg_restrict:       0
kernel.panic_on_oops:        0
kernel.perf_event_paranoid:  1

Readable /var/log/syslog:  no
Readable DebugFS:          yes

Building ...

mkdir -p ./build
cc -Wall -std=c99 ./src/bcm_msg_head_struct.c -o ./build/bcm_msg_head_struct.o
In file included from ./src/bcm_msg_head_struct.c:17:0:
/usr/include/linux/can.h:81:2: error: unknown type name ‘sa_family_t’
In file included from ./src/bcm_msg_head_struct.c:18:0:
/usr/include/linux/can/bcm.h:34:17: error: field ‘ival1’ has incomplete type
/usr/include/linux/can/bcm.h:34:24: error: field ‘ival2’ has incomplete type
./src/bcm_msg_head_struct.c: In function ‘rxsetup_sock’:
./src/bcm_msg_head_struct.c:32:24: error: field ‘f’ has incomplete type
./src/bcm_msg_head_struct.c:43:17: error: ‘CAN_FD_FRAME’ undeclared (first use in this function)
./src/bcm_msg_head_struct.c:43:17: note: each undeclared identifier is reported only once for each function it appears in
./src/bcm_msg_head_struct.c: In function ‘get_kernel_addr_from_bcm_msg_head_struct’:
./src/bcm_msg_head_struct.c:58:24: error: field ‘f’ has incomplete type
make: [all] Error 1 (ignored)
cc -Wall -std=c99 ./src/boot-config.c -o ./build/boot-config.o
cc -Wall -std=c99 ./src/cmdline.c -o ./build/cmdline.o
cc -Wall -std=c99 ./src/default.c -o ./build/default.o
cc -Wall -std=c99 ./src/dmesg_android_ion_snapshot.c -o ./build/dmesg_android_ion_snapshot.o
cc -Wall -std=c99 ./src/dmesg_backtrace.c -o ./build/dmesg_backtrace.o
cc -Wall -std=c99 ./src/dmesg_driver_component_ops.c -o ./build/dmesg_driver_component_ops.o
cc -Wall -std=c99 ./src/dmesg_mem_init_kernel_layout.c -o ./build/dmesg_mem_init_kernel_layout.o
cc -Wall -std=c99 ./src/dmesg_mmu_idmap.c -o ./build/dmesg_mmu_idmap.o
cc -Wall -std=c99 ./src/free_reserved_area_dmesg.c -o ./build/free_reserved_area_dmesg.o
cc -Wall -std=c99 ./src/free_reserved_area_syslog.c -o ./build/free_reserved_area_syslog.o
cc -Wall -std=c99 ./src/mincore.c -o ./build/mincore.o
cc -Wall -std=c99 ./src/mmap-brute-vmsplit.c -o ./build/mmap-brute-vmsplit.o
cc -Wall -std=c99 ./src/perf_event_open.c -o ./build/perf_event_open.o
cc -Wall -std=c99 ./src/proc-config.c -o ./build/proc-config.o
cc -Wall -std=c99 ./src/pppd_kallsyms.c -o ./build/pppd_kallsyms.o
cc -Wall -std=c99 ./src/proc-kallsyms.c -o ./build/proc-kallsyms.o
cc -Wall -std=c99 ./src/proc-stat-wchan.c -o ./build/proc-stat-wchan.o
cc -Wall -std=c99 ./src/sysfs_iscsi_transport_handle.c -o ./build/sysfs_iscsi_transport_handle.o
cc -Wall -std=c99 ./src/sysfs-module-sections.c -o ./build/sysfs-module-sections.o
cc -Wall -std=c99 ./src/sysfs_nf_conntrack.c -o ./build/sysfs_nf_conntrack.o

Running build ...

common default kernel text for arch: c0000000

[.] checking /boot/config-2.6.38.6-26.rc1.fc15.i686.PAE ...
[.] checking /boot/config-2.6.38.6-26.rc1.fc15.i686.PAE ...

[.] trying /proc/cmdline ...
[-] Kernel was not booted with nokaslr flag.

[.] searching dmesg for 'ion_snapshot: ' ...

[.] searching dmesg for call trace kernel pointers ...
lowest leaked address: c00f6a70
possible kernel base: c0000000

[.] searching dmesg for driver component ops pointers ...

[.] searching dmesg for ' kernel memory layout:' ...
kernel text start: c0400000
possible kernel base: c0400000

[.] searching dmesg for ' static identity map for ' ...

[.] checking dmesg for free_reserved_area() info ...

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): No such file or directory

[.] searching for kernel virtual address space start ...
kernel virtual address start: c0000000

[.] trying perf_event_open sampling ...
lowest leaked address: c040965f
possible kernel base: c0400000

[.] trying 'pppd file /proc/kallsyms 2>&1' ...
leaked kernel symbol: c0400000
possible kernel base: c0400000

[.] checking /proc/config.gz ...
[-] Could not read /proc/config.gz

[.] checking /proc/kallsyms...
kernel text start: c04010e8
possible kernel base: c0400000

[.] checking /proc/25762/stat 'wchan' field ...
leaked wchan address: c044496c
possible kernel base: c0400000

[.] checking /sys/class/iscsi_transport/iser/handle ...
[-] open/read(/sys/class/iscsi_transport/iser/handle): No such file or directory
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] open/read(/sys/class/iscsi_transport/tcp/handle): No such file or directory

[.] trying /sys/modules/*/sections/.text ...
lowest leaked module text address: f7a40000

[.] trying /sys/kernel/slab/nf_contrack_* ...
leaked init_net: c0bfddc0
possible kernel base: c0b00000

```
</details>


### RHEL 7.6 (x86_64)

<details>

```
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release:   3.10.0-957.el7.x86_64
Kernel version:   #1 SMP Thu Oct 4 20:48:51 UTC 2018
Kernel arch:      x86_64
Kernel platform:  x86_64

kernel.kptr_restrict:        0
kernel.dmesg_restrict:       0
kernel.panic_on_oops:        1
kernel.perf_event_paranoid:  2

Readable /var/log/syslog:  no
Readable DebugFS:          no

Building ...

mkdir -p ./build
cc -Wall -std=c99 ./src/bcm_msg_head_struct.c -o ./build/bcm_msg_head_struct.o
cc -Wall -std=c99 ./src/boot-config.c -o ./build/boot-config.o
cc -Wall -std=c99 ./src/cmdline.c -o ./build/cmdline.o
cc -Wall -std=c99 ./src/default.c -o ./build/default.o
cc -Wall -std=c99 ./src/dmesg_android_ion_snapshot.c -o ./build/dmesg_android_ion_snapshot.o
cc -Wall -std=c99 ./src/dmesg_backtrace.c -o ./build/dmesg_backtrace.o
cc -Wall -std=c99 ./src/dmesg_driver_component_ops.c -o ./build/dmesg_driver_component_ops.o
cc -Wall -std=c99 ./src/dmesg_mem_init_kernel_layout.c -o ./build/dmesg_mem_init_kernel_layout.o
cc -Wall -std=c99 ./src/dmesg_mmu_idmap.c -o ./build/dmesg_mmu_idmap.o
cc -Wall -std=c99 ./src/free_reserved_area_dmesg.c -o ./build/free_reserved_area_dmesg.o
cc -Wall -std=c99 ./src/free_reserved_area_syslog.c -o ./build/free_reserved_area_syslog.o
cc -Wall -std=c99 ./src/mincore.c -o ./build/mincore.o
cc -Wall -std=c99 ./src/mmap-brute-vmsplit.c -o ./build/mmap-brute-vmsplit.o
cc -Wall -std=c99 ./src/perf_event_open.c -o ./build/perf_event_open.o
cc -Wall -std=c99 ./src/proc-config.c -o ./build/proc-config.o
cc -Wall -std=c99 ./src/pppd_kallsyms.c -o ./build/pppd_kallsyms.o
cc -Wall -std=c99 ./src/proc-kallsyms.c -o ./build/proc-kallsyms.o
cc -Wall -std=c99 ./src/proc-stat-wchan.c -o ./build/proc-stat-wchan.o
cc -Wall -std=c99 ./src/sysfs_iscsi_transport_handle.c -o ./build/sysfs_iscsi_transport_handle.o
cc -Wall -std=c99 ./src/sysfs-module-sections.c -o ./build/sysfs-module-sections.o
cc -Wall -std=c99 ./src/sysfs_nf_conntrack.c -o ./build/sysfs_nf_conntrack.o

Running build ...

common default kernel text for arch: ffffffff81000000

[.] checking /boot/config-3.10.0-957.el7.x86_64 ...
[.] checking /boot/config-3.10.0-957.el7.x86_64 ...

[.] trying /proc/cmdline ...
[-] Kernel was not booted with nokaslr flag.

[.] searching dmesg for 'ion_snapshot: ' ...

[.] searching dmesg for call trace kernel pointers ...

[.] searching dmesg for driver component ops pointers ...

[.] searching dmesg for ' kernel memory layout:' ...

[.] searching dmesg for ' static identity map for ' ...

[.] checking dmesg for free_reserved_area() info ...

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): No such file or directory

[.] searching for kernel virtual address space start ...
[-] Could not locate kernel virtual address space

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/config.gz ...
[-] Could not read /proc/config.gz

[.] checking /proc/kallsyms...
[-] kernel symbol '_stext' not found in /proc/kallsyms

[.] checking /proc/8810/stat 'wchan' field ...
leaked wchan address: ffffffffb869d516
possible kernel base: ffffffffb8600000

[.] checking /sys/class/iscsi_transport/iser/handle ...
[-] open/read(/sys/class/iscsi_transport/iser/handle): No such file or directory
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] open/read(/sys/class/iscsi_transport/tcp/handle): No such file or directory

[.] trying /sys/modules/*/sections/.text ...
lowest leaked module text address: ffffffffc03ec000

[.] trying /sys/kernel/slab/nf_contrack_* ...
leaked init_net: ffffffffb9311640
possible kernel base: ffffffffb9300000

[.] trying mincore info leak...
[-] kernel base not found in mincore info leak
```
</details>


### RHEL 9.1 (x86_64)

<details>

```
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release:   5.14.0-162.6.1.el9_1.x86_64
Kernel version:   #1 SMP PREEMPT_DYNAMIC Fri Sep 30 07:36:03 EDT 2022
Kernel arch:      x86_64
Kernel platform:  x86_64

kernel.kptr_restrict:        1
kernel.dmesg_restrict:       0
kernel.panic_on_oops:        1
kernel.perf_event_paranoid:  2

Readable /var/log/syslog:  no
Readable DebugFS:          no

Building ...

mkdir -p ./build
cc -Wall -std=c99 ./src/bcm_msg_head_struct.c -o ./build/bcm_msg_head_struct.o
cc -Wall -std=c99 ./src/boot-config.c -o ./build/boot-config.o
cc -Wall -std=c99 ./src/cmdline.c -o ./build/cmdline.o
cc -Wall -std=c99 ./src/default.c -o ./build/default.o
cc -Wall -std=c99 ./src/dmesg_android_ion_snapshot.c -o ./build/dmesg_android_ion_snapshot.o
cc -Wall -std=c99 ./src/dmesg_backtrace.c -o ./build/dmesg_backtrace.o
cc -Wall -std=c99 ./src/dmesg_driver_component_ops.c -o ./build/dmesg_driver_component_ops.o
cc -Wall -std=c99 ./src/dmesg_mem_init_kernel_layout.c -o ./build/dmesg_mem_init_kernel_layout.o
cc -Wall -std=c99 ./src/dmesg_mmu_idmap.c -o ./build/dmesg_mmu_idmap.o
cc -Wall -std=c99 ./src/entrybleed.c -o ./build/entrybleed.o
cc -Wall -std=c99 ./src/free_reserved_area_dmesg.c -o ./build/free_reserved_area_dmesg.o
cc -Wall -std=c99 ./src/free_reserved_area_syslog.c -o ./build/free_reserved_area_syslog.o
cc -Wall -std=c99 ./src/mincore.c -o ./build/mincore.o
cc -Wall -std=c99 ./src/mmap-brute-vmsplit.c -o ./build/mmap-brute-vmsplit.o
cc -Wall -std=c99 ./src/perf_event_open.c -o ./build/perf_event_open.o
cc -Wall -std=c99 ./src/proc-config.c -o ./build/proc-config.o
cc -Wall -std=c99 ./src/pppd_kallsyms.c -o ./build/pppd_kallsyms.o
cc -Wall -std=c99 ./src/proc-kallsyms.c -o ./build/proc-kallsyms.o
cc -Wall -std=c99 ./src/proc-stat-wchan.c -o ./build/proc-stat-wchan.o
cc -Wall -std=c99 ./src/sysfs_iscsi_transport_handle.c -o ./build/sysfs_iscsi_transport_handle.o
cc -Wall -std=c99 ./src/sysfs-module-sections.c -o ./build/sysfs-module-sections.o
cc -Wall -std=c99 ./src/sysfs_nf_conntrack.c -o ./build/sysfs_nf_conntrack.o

Running build ...

common default kernel text for arch: ffffffff81000000

[.] checking /boot/config-5.14.0-162.6.1.el9_1.x86_64 ...
[.] checking /boot/config-5.14.0-162.6.1.el9_1.x86_64 ...

[.] trying /proc/cmdline ...
[-] Kernel was not booted with nokaslr flag.

[.] trying bcm_msg_head struct stack pointer leak ...

[.] searching dmesg for 'ion_snapshot: ' ...

[.] searching dmesg for call trace kernel pointers ...

[.] searching dmesg for driver component ops pointers ...

[.] searching dmesg for ' kernel memory layout:' ...

[.] searching dmesg for ' static identity map for ' ...

[.] trying EntryBleed (CVE-2022-4543) ...
[.] AMD CPU with KPTI disabled
[.] kernel version '5.14.0-162.6.1.el9_1.x86_64 #1 SMP PREEMPT_DYNAMIC Fri Sep 30 07:36:03 EDT 2022' detected
possible kernel base: ffffffffa4e00000

[.] checking dmesg for free_reserved_area() info ...

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): No such file or directory

[.] searching for kernel virtual address space start ...
[-] Could not locate kernel virtual address space

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/config.gz ...
[-] Could not read /proc/config.gz

[.] checking /proc/kallsyms...
[-] kernel symbol '_stext' not found in /proc/kallsyms

[.] checking /proc/38466/stat 'wchan' field ...

[.] checking /sys/class/iscsi_transport/iser/handle ...
[-] open/read(/sys/class/iscsi_transport/iser/handle): No such file or directory
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] open/read(/sys/class/iscsi_transport/tcp/handle): No such file or directory

[.] trying /sys/modules/*/sections/.text ...

[.] trying /sys/kernel/slab/nf_contrack_* ...

[.] trying mincore info leak...
[-] kernel base not found in mincore info leak
```
</details>


### CentOS 8.1.1911 (x86_64)

<details>

```
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release:   4.18.0-147.el8.x86_64
Kernel version:   #1 SMP Wed Dec 4 21:51:45 UTC 2019
Kernel arch:      x86_64
Kernel platform:  x86_64

kernel.kptr_restrict:        0
kernel.dmesg_restrict:       0
kernel.panic_on_oops:        1
kernel.perf_event_paranoid:  2

Readable /var/log/syslog:  no
Readable DebugFS:          no

Building ...

mkdir -p ./build
cc -Wall -std=c99 ./src/bcm_msg_head_struct.c -o ./build/bcm_msg_head_struct.o
cc -Wall -std=c99 ./src/boot-config.c -o ./build/boot-config.o
cc -Wall -std=c99 ./src/cmdline.c -o ./build/cmdline.o
cc -Wall -std=c99 ./src/default.c -o ./build/default.o
cc -Wall -std=c99 ./src/dmesg_android_ion_snapshot.c -o ./build/dmesg_android_ion_snapshot.o
cc -Wall -std=c99 ./src/dmesg_backtrace.c -o ./build/dmesg_backtrace.o
cc -Wall -std=c99 ./src/dmesg_driver_component_ops.c -o ./build/dmesg_driver_component_ops.o
cc -Wall -std=c99 ./src/dmesg_mem_init_kernel_layout.c -o ./build/dmesg_mem_init_kernel_layout.o
cc -Wall -std=c99 ./src/dmesg_mmu_idmap.c -o ./build/dmesg_mmu_idmap.o
cc -Wall -std=c99 ./src/free_reserved_area_dmesg.c -o ./build/free_reserved_area_dmesg.o
cc -Wall -std=c99 ./src/free_reserved_area_syslog.c -o ./build/free_reserved_area_syslog.o
cc -Wall -std=c99 ./src/mincore.c -o ./build/mincore.o
cc -Wall -std=c99 ./src/mmap-brute-vmsplit.c -o ./build/mmap-brute-vmsplit.o
cc -Wall -std=c99 ./src/perf_event_open.c -o ./build/perf_event_open.o
cc -Wall -std=c99 ./src/proc-config.c -o ./build/proc-config.o
cc -Wall -std=c99 ./src/pppd_kallsyms.c -o ./build/pppd_kallsyms.o
cc -Wall -std=c99 ./src/proc-kallsyms.c -o ./build/proc-kallsyms.o
cc -Wall -std=c99 ./src/proc-stat-wchan.c -o ./build/proc-stat-wchan.o
cc -Wall -std=c99 ./src/sysfs_iscsi_transport_handle.c -o ./build/sysfs_iscsi_transport_handle.o
cc -Wall -std=c99 ./src/sysfs-module-sections.c -o ./build/sysfs-module-sections.o
cc -Wall -std=c99 ./src/sysfs_nf_conntrack.c -o ./build/sysfs_nf_conntrack.o

Running build ...

common default kernel text for arch: ffffffff81000000

[.] checking /boot/config-4.18.0-147.el8.x86_64 ...
[.] checking /boot/config-4.18.0-147.el8.x86_64 ...

[.] trying /proc/cmdline ...
[-] Kernel was not booted with nokaslr flag.

[.] trying bcm_msg_head struct stack pointer leak ...

[.] searching dmesg for 'ion_snapshot: ' ...

[.] searching dmesg for call trace kernel pointers ...

[.] searching dmesg for driver component ops pointers ...

[.] searching dmesg for ' kernel memory layout:' ...

[.] searching dmesg for ' static identity map for ' ...

[.] checking dmesg for free_reserved_area() info ...

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): No such file or directory

[.] searching for kernel virtual address space start ...
[-] Could not locate kernel virtual address space

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/config.gz ...
[-] Could not read /proc/config.gz

[.] checking /proc/kallsyms...
[-] kernel symbol '_stext' not found in /proc/kallsyms

[.] checking /proc/17991/stat 'wchan' field ...

[.] checking /sys/class/iscsi_transport/iser/handle ...
[-] open/read(/sys/class/iscsi_transport/iser/handle): No such file or directory
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] open/read(/sys/class/iscsi_transport/tcp/handle): No such file or directory

[.] trying /sys/modules/*/sections/.text ...

[.] trying /sys/kernel/slab/nf_contrack_* ...

[.] trying mincore info leak...
[-] kernel base not found in mincore info leak
```
</details>


### OpenSUSE Leap 15.1 (x86_64)

<details>

```
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release:   4.12.14-lp151.28.10-default
Kernel version:   #1 SMP Sat Jul 13 17:59:31 UTC 2019 (0ab03b7)
Kernel arch:      x86_64
Kernel platform:  x86_64

kernel.kptr_restrict:        1
kernel.dmesg_restrict:       0
kernel.panic_on_oops:        0
kernel.perf_event_paranoid:  2

Readable /var/log/syslog:  no
Readable DebugFS:          no

Building ...

mkdir -p ./build
cc -Wall -std=c99 ./src/bcm_msg_head_struct.c -o ./build/bcm_msg_head_struct.o
cc -Wall -std=c99 ./src/boot-config.c -o ./build/boot-config.o
cc -Wall -std=c99 ./src/cmdline.c -o ./build/cmdline.o
cc -Wall -std=c99 ./src/default.c -o ./build/default.o
cc -Wall -std=c99 ./src/dmesg_android_ion_snapshot.c -o ./build/dmesg_android_ion_snapshot.o
cc -Wall -std=c99 ./src/dmesg_backtrace.c -o ./build/dmesg_backtrace.o
cc -Wall -std=c99 ./src/dmesg_driver_component_ops.c -o ./build/dmesg_driver_component_ops.o
cc -Wall -std=c99 ./src/dmesg_mem_init_kernel_layout.c -o ./build/dmesg_mem_init_kernel_layout.o
cc -Wall -std=c99 ./src/dmesg_mmu_idmap.c -o ./build/dmesg_mmu_idmap.o
cc -Wall -std=c99 ./src/free_reserved_area_dmesg.c -o ./build/free_reserved_area_dmesg.o
cc -Wall -std=c99 ./src/free_reserved_area_syslog.c -o ./build/free_reserved_area_syslog.o
cc -Wall -std=c99 ./src/mincore.c -o ./build/mincore.o
cc -Wall -std=c99 ./src/mmap-brute-vmsplit.c -o ./build/mmap-brute-vmsplit.o
cc -Wall -std=c99 ./src/perf_event_open.c -o ./build/perf_event_open.o
cc -Wall -std=c99 ./src/proc-config.c -o ./build/proc-config.o
cc -Wall -std=c99 ./src/pppd_kallsyms.c -o ./build/pppd_kallsyms.o
cc -Wall -std=c99 ./src/proc-kallsyms.c -o ./build/proc-kallsyms.o
cc -Wall -std=c99 ./src/proc-stat-wchan.c -o ./build/proc-stat-wchan.o
cc -Wall -std=c99 ./src/sysfs_iscsi_transport_handle.c -o ./build/sysfs_iscsi_transport_handle.o
cc -Wall -std=c99 ./src/sysfs-module-sections.c -o ./build/sysfs-module-sections.o
cc -Wall -std=c99 ./src/sysfs_nf_conntrack.c -o ./build/sysfs_nf_conntrack.o

Running build ...

common default kernel text for arch: ffffffff81000000

[.] checking /boot/config-4.12.14-lp151.28.10-default ...
[.] checking /boot/config-4.12.14-lp151.28.10-default ...

[.] trying /proc/cmdline ...
[-] Kernel was not booted with nokaslr flag.

[.] trying bcm_msg_head struct stack pointer leak ...

[.] searching dmesg for 'ion_snapshot: ' ...

[.] searching dmesg for call trace kernel pointers ...

[.] searching dmesg for driver component ops pointers ...

[.] searching dmesg for ' kernel memory layout:' ...

[.] searching dmesg for ' static identity map for ' ...

[.] checking dmesg for free_reserved_area() info ...

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): No such file or directory

[.] searching for kernel virtual address space start ...
[-] Could not locate kernel virtual address space

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/config.gz ...
[.] Kernel appears to have been compiled without CONFIG_RELOCATABLE and CONFIG_RANDOMIZE_BASE
common default kernel text for arch: ffffffff81000000

[.] checking /proc/kallsyms...
[-] kernel symbol '_stext' not found in /proc/kallsyms

[.] checking /proc/5342/stat 'wchan' field ...

[.] checking /sys/class/iscsi_transport/iser/handle ...
[-] open/read(/sys/class/iscsi_transport/iser/handle): No such file or directory
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] open/read(/sys/class/iscsi_transport/tcp/handle): No such file or directory

[.] trying /sys/modules/*/sections/.text ...

[.] trying /sys/kernel/slab/nf_contrack_* ...
opendir(/sys/kernel/slab/): No such file or directory

[.] trying mincore info leak...
[-] kernel base not found in mincore info leak
```
</details>


### Amazon Linux 20200207 (x86_64)

<details>

```
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release:   4.14.171-136.231.amzn2.x86_64
Kernel version:   #1 SMP Thu Feb 27 20:22:48 UTC 2020
Kernel arch:      x86_64
Kernel platform:  x86_64

kernel.kptr_restrict:        0
kernel.dmesg_restrict:       0
kernel.panic_on_oops:        0
kernel.perf_event_paranoid:  2

Readable /var/log/syslog:  no
Readable DebugFS:          no

Building ...

mkdir -p ./build
cc -Wall -std=c99 ./src/bcm_msg_head_struct.c -o ./build/bcm_msg_head_struct.o
cc -Wall -std=c99 ./src/boot-config.c -o ./build/boot-config.o
cc -Wall -std=c99 ./src/cmdline.c -o ./build/cmdline.o
cc -Wall -std=c99 ./src/default.c -o ./build/default.o
cc -Wall -std=c99 ./src/dmesg_android_ion_snapshot.c -o ./build/dmesg_android_ion_snapshot.o
cc -Wall -std=c99 ./src/dmesg_backtrace.c -o ./build/dmesg_backtrace.o
cc -Wall -std=c99 ./src/dmesg_driver_component_ops.c -o ./build/dmesg_driver_component_ops.o
cc -Wall -std=c99 ./src/dmesg_mem_init_kernel_layout.c -o ./build/dmesg_mem_init_kernel_layout.o
cc -Wall -std=c99 ./src/dmesg_mmu_idmap.c -o ./build/dmesg_mmu_idmap.o
cc -Wall -std=c99 ./src/free_reserved_area_dmesg.c -o ./build/free_reserved_area_dmesg.o
cc -Wall -std=c99 ./src/free_reserved_area_syslog.c -o ./build/free_reserved_area_syslog.o
cc -Wall -std=c99 ./src/mincore.c -o ./build/mincore.o
cc -Wall -std=c99 ./src/mmap-brute-vmsplit.c -o ./build/mmap-brute-vmsplit.o
cc -Wall -std=c99 ./src/perf_event_open.c -o ./build/perf_event_open.o
cc -Wall -std=c99 ./src/proc-config.c -o ./build/proc-config.o
cc -Wall -std=c99 ./src/pppd_kallsyms.c -o ./build/pppd_kallsyms.o
cc -Wall -std=c99 ./src/proc-kallsyms.c -o ./build/proc-kallsyms.o
cc -Wall -std=c99 ./src/proc-stat-wchan.c -o ./build/proc-stat-wchan.o
cc -Wall -std=c99 ./src/sysfs_iscsi_transport_handle.c -o ./build/sysfs_iscsi_transport_handle.o
cc -Wall -std=c99 ./src/sysfs-module-sections.c -o ./build/sysfs-module-sections.o
cc -Wall -std=c99 ./src/sysfs_nf_conntrack.c -o ./build/sysfs_nf_conntrack.o

Running build ...

common default kernel text for arch: ffffffff81000000

[.] checking /boot/config-4.14.171-136.231.amzn2.x86_64 ...
[.] checking /boot/config-4.14.171-136.231.amzn2.x86_64 ...

[.] trying /proc/cmdline ...
[-] Kernel was not booted with nokaslr flag.

[.] trying bcm_msg_head struct stack pointer leak ...

[.] searching dmesg for 'ion_snapshot: ' ...

[.] searching dmesg for call trace kernel pointers ...

[.] searching dmesg for driver component ops pointers ...

[.] searching dmesg for ' kernel memory layout:' ...

[.] searching dmesg for ' static identity map for ' ...

[.] checking dmesg for free_reserved_area() info ...

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): No such file or directory

[.] searching for kernel virtual address space start ...
[-] Could not locate kernel virtual address space

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/config.gz ...
[-] Could not read /proc/config.gz

[.] checking /proc/kallsyms...
kernel text start: ffffffff81000000
possible kernel base: ffffffff81000000

[.] checking /proc/116986/stat 'wchan' field ...

[.] checking /sys/class/iscsi_transport/iser/handle ...
[-] open/read(/sys/class/iscsi_transport/iser/handle): No such file or directory
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] open/read(/sys/class/iscsi_transport/tcp/handle): No such file or directory

[.] trying /sys/modules/*/sections/.text ...
lowest leaked module text address: ffffffffa0002000

[.] trying /sys/kernel/slab/nf_contrack_* ...

[.] trying mincore info leak...
[-] kernel base not found in mincore info leak
```
</details>


### Scientific Linux release 7.6 (x86_64)

<details>

```
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release:   3.10.0-957.1.3.el7.x86_64
Kernel version:   #1 SMP Mon Nov 26 12:36:06 CST 2018
Kernel arch:      x86_64
Kernel platform:  x86_64

kernel.kptr_restrict:        0
kernel.dmesg_restrict:       0
kernel.panic_on_oops:        1
kernel.perf_event_paranoid:  2

Readable /var/log/syslog:  no
Readable DebugFS:          no

Building ...

mkdir -p ./build
cc -Wall -std=c99 ./src/bcm_msg_head_struct.c -o ./build/bcm_msg_head_struct.o
In file included from ./src/bcm_msg_head_struct.c:18:0:
/usr/include/linux/can/bcm.h:33:17: error: field ‘ival1’ has incomplete type
  struct timeval ival1, ival2;
                 ^
/usr/include/linux/can/bcm.h:33:24: error: field ‘ival2’ has incomplete type
  struct timeval ival1, ival2;
                        ^
./src/bcm_msg_head_struct.c: In function ‘rxsetup_sock’:
./src/bcm_msg_head_struct.c:43:17: error: ‘CAN_FD_FRAME’ undeclared (first use in this function)
   msg.b.flags = CAN_FD_FRAME | SETTIMER | STARTTIMER;
                 ^
./src/bcm_msg_head_struct.c:43:17: note: each undeclared identifier is reported only once for each function it appears in
make: [all] Error 1 (ignored)
cc -Wall -std=c99 ./src/boot-config.c -o ./build/boot-config.o
cc -Wall -std=c99 ./src/cmdline.c -o ./build/cmdline.o
cc -Wall -std=c99 ./src/default.c -o ./build/default.o
cc -Wall -std=c99 ./src/dmesg_android_ion_snapshot.c -o ./build/dmesg_android_ion_snapshot.o
cc -Wall -std=c99 ./src/dmesg_backtrace.c -o ./build/dmesg_backtrace.o
cc -Wall -std=c99 ./src/dmesg_driver_component_ops.c -o ./build/dmesg_driver_component_ops.o
cc -Wall -std=c99 ./src/dmesg_mem_init_kernel_layout.c -o ./build/dmesg_mem_init_kernel_layout.o
cc -Wall -std=c99 ./src/dmesg_mmu_idmap.c -o ./build/dmesg_mmu_idmap.o
cc -Wall -std=c99 ./src/free_reserved_area_dmesg.c -o ./build/free_reserved_area_dmesg.o
cc -Wall -std=c99 ./src/free_reserved_area_syslog.c -o ./build/free_reserved_area_syslog.o
cc -Wall -std=c99 ./src/mincore.c -o ./build/mincore.o
cc -Wall -std=c99 ./src/mmap-brute-vmsplit.c -o ./build/mmap-brute-vmsplit.o
cc -Wall -std=c99 ./src/perf_event_open.c -o ./build/perf_event_open.o
cc -Wall -std=c99 ./src/proc-config.c -o ./build/proc-config.o
cc -Wall -std=c99 ./src/pppd_kallsyms.c -o ./build/pppd_kallsyms.o
cc -Wall -std=c99 ./src/proc-kallsyms.c -o ./build/proc-kallsyms.o
cc -Wall -std=c99 ./src/proc-stat-wchan.c -o ./build/proc-stat-wchan.o
cc -Wall -std=c99 ./src/sysfs_iscsi_transport_handle.c -o ./build/sysfs_iscsi_transport_handle.o
cc -Wall -std=c99 ./src/sysfs-module-sections.c -o ./build/sysfs-module-sections.o
cc -Wall -std=c99 ./src/sysfs_nf_conntrack.c -o ./build/sysfs_nf_conntrack.o

Running build ...

common default kernel text for arch: ffffffff81000000

[.] checking /boot/config-3.10.0-957.1.3.el7.x86_64 ...
[.] checking /boot/config-3.10.0-957.1.3.el7.x86_64 ...

[.] trying /proc/cmdline ...
[-] Kernel was not booted with nokaslr flag.

[.] searching dmesg for 'ion_snapshot: ' ...

[.] searching dmesg for call trace kernel pointers ...

[.] searching dmesg for driver component ops pointers ...

[.] searching dmesg for ' kernel memory layout:' ...

[.] searching dmesg for ' static identity map for ' ...

[.] checking dmesg for free_reserved_area() info ...

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): No such file or directory

[.] searching for kernel virtual address space start ...
[-] Could not locate kernel virtual address space

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/config.gz ...
[-] Could not read /proc/config.gz

[.] checking /proc/kallsyms...
[-] kernel symbol '_stext' not found in /proc/kallsyms

[.] checking /proc/7696/stat 'wchan' field ...
leaked wchan address: ffffffffb729d516
possible kernel base: ffffffffb7200000

[.] checking /sys/class/iscsi_transport/iser/handle ...
[-] open/read(/sys/class/iscsi_transport/iser/handle): No such file or directory
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] open/read(/sys/class/iscsi_transport/tcp/handle): No such file or directory

[.] trying /sys/modules/*/sections/.text ...
lowest leaked module text address: ffffffffc03d2000

[.] trying /sys/kernel/slab/nf_contrack_* ...
leaked init_net: ffffffffb7f11640
possible kernel base: ffffffffb7f00000

[.] trying mincore info leak...
[-] kernel base not found in mincore info leak

```
</details>


### Android 7.1.2 (armv7l)

Hardware: BLUME Android Smart TV Box Media Player 4K

<details>

```
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release:   3.10.104
Kernel version:   #26 SMP PREEMPT Fri Dec 20 01:47:35 EST 2019
Kernel arch:      armv7l
Kernel platform:  unknown

kernel.kptr_restrict:        2
kernel.dmesg_restrict:       0
kernel.panic_on_oops:        1
kernel.perf_event_paranoid:  3

Readable /var/log/syslog:  no
Readable DebugFS:          yes

Building ...

./kasld[36]: make: not found
build failed!

Running build ...

common default kernel text for arch: c0008000

[.] checking /boot/config-3.10.104 ...
[-] open/read(/boot/config-3.10.104): No such file or directory

[.] trying /proc/cmdline ...
[-] open/read(/proc/cmdline): Permission denied

[.] trying bcm_msg_head struct stack pointer leak ...

[.] searching dmesg for 'ion_snapshot: ' ...
leaked last_ion_buf: c0e5d374
possible kernel base: c0e00000

[.] searching dmesg for call trace kernel pointers ...
lowest leaked address: ce010098
possible kernel base: ce000000

[.] searching dmesg for driver component ops pointers ...

[.] searching dmesg for ' kernel memory layout:' ...
kernel text start: c0008000
possible kernel base: c0000000

[.] searching dmesg for ' static identity map for ' ...
leaked __turn_mmu_on: c086dc18
possible kernel base: c0800000

[.] checking dmesg for free_reserved_area() info ...
leaked __init_begin: c0c1d000
possible kernel base: c0c00000

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): No such file or directory

[.] searching for kernel virtual address space start ...
kernel virtual address start: c0000000

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied

[.] trying 'pppd file /proc/kallsyms 2>&1' ...
[-] fgets(pppd file /proc/kallsyms 2>&1): Success

[.] checking /proc/config.gz ...
[-] Could not read /proc/config.gz

[.] checking /proc/kallsyms...
[-] kernel symbol '_stext' not found in /proc/kallsyms

[.] checking /proc/7212/stat 'wchan' field ...
leaked wchan address: c00519f0
possible kernel base: c0000000

[.] checking /sys/class/iscsi_transport/iser/handle ...
[-] open/read(/sys/class/iscsi_transport/iser/handle): No such file or directory
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] open/read(/sys/class/iscsi_transport/tcp/handle): No such file or directory

[.] trying /sys/modules/*/sections/.text ...

[.] trying /sys/kernel/slab/nf_contrack_* ...
leaked init_net: c0d43f40
possible kernel base: c0d00000
```
</details>


### Ubuntu 18.04.3 LTS (armv7l)

Hardware: ODROID-XU4

<details>

```
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release:   4.14.141-169
Kernel version:   #1 SMP PREEMPT Sat Aug 31 23:19:59 -03 2019
Kernel arch:      armv7l
Kernel platform:  armv7l

kernel.kptr_restrict:        1
kernel.dmesg_restrict:       0
kernel.panic_on_oops:        0
kernel.perf_event_paranoid:  2

Readable /var/log/syslog:  no
Readable DebugFS:          no

Building ...

mkdir -p ./build
cc -Wall -std=c99 ./src/bcm_msg_head_struct.c -o ./build/bcm_msg_head_struct.o
cc -Wall -std=c99 ./src/boot-config.c -o ./build/boot-config.o
cc -Wall -std=c99 ./src/cmdline.c -o ./build/cmdline.o
cc -Wall -std=c99 ./src/default.c -o ./build/default.o
cc -Wall -std=c99 ./src/dmesg_android_ion_snapshot.c -o ./build/dmesg_android_ion_snapshot.o
cc -Wall -std=c99 ./src/dmesg_backtrace.c -o ./build/dmesg_backtrace.o
cc -Wall -std=c99 ./src/dmesg_driver_component_ops.c -o ./build/dmesg_driver_component_ops.o
cc -Wall -std=c99 ./src/dmesg_mem_init_kernel_layout.c -o ./build/dmesg_mem_init_kernel_layout.o
cc -Wall -std=c99 ./src/dmesg_mmu_idmap.c -o ./build/dmesg_mmu_idmap.o
cc -Wall -std=c99 ./src/free_reserved_area_dmesg.c -o ./build/free_reserved_area_dmesg.o
cc -Wall -std=c99 ./src/free_reserved_area_syslog.c -o ./build/free_reserved_area_syslog.o
cc -Wall -std=c99 ./src/mincore.c -o ./build/mincore.o
cc -Wall -std=c99 ./src/mmap-brute-vmsplit.c -o ./build/mmap-brute-vmsplit.o
cc -Wall -std=c99 ./src/perf_event_open.c -o ./build/perf_event_open.o
cc -Wall -std=c99 ./src/proc-config.c -o ./build/proc-config.o
cc -Wall -std=c99 ./src/pppd_kallsyms.c -o ./build/pppd_kallsyms.o
cc -Wall -std=c99 ./src/proc-kallsyms.c -o ./build/proc-kallsyms.o
cc -Wall -std=c99 ./src/proc-stat-wchan.c -o ./build/proc-stat-wchan.o
cc -Wall -std=c99 ./src/sysfs_iscsi_transport_handle.c -o ./build/sysfs_iscsi_transport_handle.o
cc -Wall -std=c99 ./src/sysfs-module-sections.c -o ./build/sysfs-module-sections.o
cc -Wall -std=c99 ./src/sysfs_nf_conntrack.c -o ./build/sysfs_nf_conntrack.o

Running build ...

common default kernel text for arch: c0008000

[.] checking /boot/config-4.14.141-169 ...
[-] open/read(/boot/config-4.14.141-169): No such file or directory

[.] trying /proc/cmdline ...
[-] Kernel was not booted with nokaslr flag.

[.] trying bcm_msg_head struct stack pointer leak ...
leaked stack pointer: c0152218
possible kernel base: c0100000

[.] searching dmesg for 'ion_snapshot: ' ...

[.] searching dmesg for call trace kernel pointers ...

[.] searching dmesg for driver component ops pointers ...
lowest leaked address: c0966344
possible kernel base: c0900000

[.] searching dmesg for ' kernel memory layout:' ...
kernel text start: c0008000
possible kernel base: c0000000

[.] searching dmesg for ' static identity map for ' ...

[.] checking dmesg for free_reserved_area() info ...

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): Permission denied

[.] searching for kernel virtual address space start ...
kernel virtual address start: c0000000

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Permission denied

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/config.gz ...
[.] Kernel appears to have been compiled without CONFIG_RELOCATABLE and CONFIG_RANDOMIZE_BASE
common default kernel text for arch: c0008000

[.] checking /proc/kallsyms...
[-] kernel symbol '_stext' not found in /proc/kallsyms

[.] checking /proc/3374/stat 'wchan' field ...

[.] checking /sys/class/iscsi_transport/iser/handle ...
[-] open/read(/sys/class/iscsi_transport/iser/handle): No such file or directory
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] open/read(/sys/class/iscsi_transport/tcp/handle): No such file or directory

[.] trying /sys/modules/*/sections/.text ...

[.] trying /sys/kernel/slab/nf_contrack_* ...
```
</details>


### Raspbian GNU/Linux 11 (armv6l)

Hardware: QEMU (`-cpu arm1176 -kernel kernel-qemu-4.19.50-buster`)

<details>

```
[ KASLD ] Kernel Address Space Layout Derandomization

Kernel release:   4.19.50+
Kernel version:   #1 Tue Nov 26 01:49:16 CET 2019
Kernel arch:      armv6l
Kernel platform:  unknown

kernel.kptr_restrict:        0
kernel.dmesg_restrict:       0
kernel.panic_on_oops:        0
cat: /proc/sys/kernel/perf_event_paranoid: No such file or directory
kernel.perf_event_paranoid:  

Readable /var/log/syslog:  no
Readable DebugFS:          no

Building ...

mkdir -p ./build
cc -Wall -std=c99 ./src/bcm_msg_head_struct.c -o ./build/bcm_msg_head_struct.o
cc -Wall -std=c99 ./src/boot-config.c -o ./build/boot-config.o
cc -Wall -std=c99 ./src/cmdline.c -o ./build/cmdline.o
cc -Wall -std=c99 ./src/default.c -o ./build/default.o
cc -Wall -std=c99 ./src/dmesg_android_ion_snapshot.c -o ./build/dmesg_android_ion_snapshot.o
cc -Wall -std=c99 ./src/dmesg_backtrace.c -o ./build/dmesg_backtrace.o
cc -Wall -std=c99 ./src/dmesg_driver_component_ops.c -o ./build/dmesg_driver_component_ops.o
cc -Wall -std=c99 ./src/dmesg_mem_init_kernel_layout.c -o ./build/dmesg_mem_init_kernel_layout.o
cc -Wall -std=c99 ./src/dmesg_mmu_idmap.c -o ./build/dmesg_mmu_idmap.o
cc -Wall -std=c99 ./src/free_reserved_area_dmesg.c -o ./build/free_reserved_area_dmesg.o
cc -Wall -std=c99 ./src/free_reserved_area_syslog.c -o ./build/free_reserved_area_syslog.o
cc -Wall -std=c99 ./src/mincore.c -o ./build/mincore.o
cc -Wall -std=c99 ./src/mmap-brute-vmsplit.c -o ./build/mmap-brute-vmsplit.o
cc -Wall -std=c99 ./src/perf_event_open.c -o ./build/perf_event_open.o
cc -Wall -std=c99 ./src/proc-config.c -o ./build/proc-config.o
cc -Wall -std=c99 ./src/pppd_kallsyms.c -o ./build/pppd_kallsyms.o
cc -Wall -std=c99 ./src/proc-kallsyms.c -o ./build/proc-kallsyms.o
cc -Wall -std=c99 ./src/proc-stat-wchan.c -o ./build/proc-stat-wchan.o
cc -Wall -std=c99 ./src/sysfs_iscsi_transport_handle.c -o ./build/sysfs_iscsi_transport_handle.o
cc -Wall -std=c99 ./src/sysfs-module-sections.c -o ./build/sysfs-module-sections.o
cc -Wall -std=c99 ./src/sysfs_nf_conntrack.c -o ./build/sysfs_nf_conntrack.o

Running build ...

common default kernel text for arch: c0008000

[.] checking /boot/config-4.19.50+ ...
[-] open/read(/boot/config-4.19.50+): No such file or directory

[.] trying /proc/cmdline ...
[-] Kernel was not booted with nokaslr flag.

[.] trying bcm_msg_head struct stack pointer leak ...

[.] searching dmesg for 'ion_snapshot: ' ...

[.] searching dmesg for call trace kernel pointers ...

[.] searching dmesg for driver component ops pointers ...

[.] searching dmesg for ' kernel memory layout:' ...

[.] searching dmesg for ' static identity map for ' ...

[.] checking dmesg for free_reserved_area() info ...

[.] checking /var/log/syslog for free_reserved_area() info ...
[-] open/read(/var/log/syslog): Permission denied

[.] searching for kernel virtual address space start ...
kernel virtual address start: c0000000

[.] trying perf_event_open sampling ...
[-] syscall(SYS_perf_event_open): Function not implemented

[.] trying 'pppd file /proc/kallsyms 2>&1' ...

[.] checking /proc/config.gz ...
[.] Kernel appears to have been compiled without CONFIG_RELOCATABLE and CONFIG_RANDOMIZE_BASE
common default kernel text for arch: c0008000

[.] checking /proc/kallsyms...
[-] kernel symbol '_stext' not found in /proc/kallsyms

[.] checking /proc/2602/stat 'wchan' field ...

[.] checking /sys/class/iscsi_transport/iser/handle ...
[-] open/read(/sys/class/iscsi_transport/iser/handle): No such file or directory
[.] checking /sys/class/iscsi_transport/tcp/handle ...
[-] open/read(/sys/class/iscsi_transport/tcp/handle): No such file or directory

[.] trying /sys/modules/*/sections/.text ...

[.] trying /sys/kernel/slab/nf_contrack_* ...
opendir(/sys/kernel/slab/): No such file or directory
```
</details>
