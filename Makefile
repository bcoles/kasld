SHELL = /bin/sh
.SUFFIXES: .c .o

CC = cc
# Warning: Do not compile with -O
FLAGS = -Wall -std=c99

BUILD_DIR := ./build
SRC_DIR := ./src

all :
	mkdir -p $(BUILD_DIR)
	-$(CC) $(FLAGS) $(SRC_DIR)/bcm_msg_head_struct.c -o $(BUILD_DIR)/bcm_msg_head_struct.o
	-$(CC) $(FLAGS) $(SRC_DIR)/boot-config.c -o $(BUILD_DIR)/boot-config.o
	-$(CC) $(FLAGS) $(SRC_DIR)/cmdline.c -o $(BUILD_DIR)/cmdline.o
	-$(CC) $(FLAGS) $(SRC_DIR)/default.c -o $(BUILD_DIR)/default.o
	-$(CC) $(FLAGS) $(SRC_DIR)/dmesg_android_ion_snapshot.c -o $(BUILD_DIR)/dmesg_android_ion_snapshot.o
	-$(CC) $(FLAGS) $(SRC_DIR)/dmesg_backtrace.c -o $(BUILD_DIR)/dmesg_backtrace.o
	-$(CC) $(FLAGS) $(SRC_DIR)/dmesg_check_for_initrd.c -o $(BUILD_DIR)/dmesg_check_for_initrd.o
	-$(CC) $(FLAGS) $(SRC_DIR)/dmesg_driver_component_ops.c -o $(BUILD_DIR)/dmesg_driver_component_ops.o
	-$(CC) $(FLAGS) $(SRC_DIR)/dmesg_ex_handler_msr.c -o $(BUILD_DIR)/dmesg_ex_handler_msr.o
	-$(CC) $(FLAGS) $(SRC_DIR)/dmesg_free_reserved_area.c -o $(BUILD_DIR)/dmesg_free_reserved_area.o
	-$(CC) $(FLAGS) $(SRC_DIR)/dmesg_mem_init_kernel_layout.c -o $(BUILD_DIR)/dmesg_mem_init_kernel_layout.o
	-$(CC) $(FLAGS) $(SRC_DIR)/dmesg_mmu_idmap.c -o $(BUILD_DIR)/dmesg_mmu_idmap.o
	-$(CC) $(FLAGS) $(SRC_DIR)/entrybleed.c -o $(BUILD_DIR)/entrybleed.o
	-$(CC) $(FLAGS) $(SRC_DIR)/mincore.c -o $(BUILD_DIR)/mincore.o
	-$(CC) $(FLAGS) $(SRC_DIR)/mmap-brute-vmsplit.c -o $(BUILD_DIR)/mmap-brute-vmsplit.o
	-$(CC) $(FLAGS) $(SRC_DIR)/perf_event_open.c -o $(BUILD_DIR)/perf_event_open.o
	-$(CC) $(FLAGS) $(SRC_DIR)/proc-config.c -o $(BUILD_DIR)/proc-config.o
	-$(CC) $(FLAGS) $(SRC_DIR)/pppd_kallsyms.c -o $(BUILD_DIR)/pppd_kallsyms.o
	-$(CC) $(FLAGS) $(SRC_DIR)/proc-kallsyms.c -o $(BUILD_DIR)/proc-kallsyms.o
	-$(CC) $(FLAGS) $(SRC_DIR)/proc-pid-syscall.c -o $(BUILD_DIR)/proc-pid-syscall.o
	-$(CC) $(FLAGS) $(SRC_DIR)/proc-stat-wchan.c -o $(BUILD_DIR)/proc-stat-wchan.o
	-$(CC) $(FLAGS) $(SRC_DIR)/sysfs_iscsi_transport_handle.c -o $(BUILD_DIR)/sysfs_iscsi_transport_handle.o
	-$(CC) $(FLAGS) $(SRC_DIR)/sysfs-module-sections.c -o $(BUILD_DIR)/sysfs-module-sections.o
	-$(CC) $(FLAGS) $(SRC_DIR)/sysfs_nf_conntrack.c -o $(BUILD_DIR)/sysfs_nf_conntrack.o
	-$(CC) $(FLAGS) $(SRC_DIR)/syslog_backtrace.c -o $(BUILD_DIR)/syslog_backtrace.o
	-$(CC) $(FLAGS) $(SRC_DIR)/syslog_free_reserved_area.c -o $(BUILD_DIR)/syslog_free_reserved_area.o

clean :
	rm -f $(BUILD_DIR)/*.o
