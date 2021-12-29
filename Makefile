SHELL = /bin/sh
.SUFFIXES: .c .o

CC = cc
FLAGS = -Wall

BUILD_DIR := ./build
SRC_DIR := ./src

all :
	mkdir -p $(BUILD_DIR)
	-$(CC) $(FLAGS) $(SRC_DIR)/bcm_msg_head_struct.c -o $(BUILD_DIR)/bcm_msg_head_struct.o
	-$(CC) $(FLAGS) $(SRC_DIR)/boot-config.c -o $(BUILD_DIR)/boot-config.o
	-$(CC) $(FLAGS) $(SRC_DIR)/cmdline.c -o $(BUILD_DIR)/cmdline.o
	-$(CC) $(FLAGS) $(SRC_DIR)/default.c -o $(BUILD_DIR)/default.o
	-$(CC) $(FLAGS) $(SRC_DIR)/dmesg_backtrace.c -o $(BUILD_DIR)/dmesg_backtrace.o
	-$(CC) $(FLAGS) $(SRC_DIR)/dmesg_mem_init_kernel_layout.c -o $(BUILD_DIR)/dmesg_mem_init_kernel_layout.o
	-$(CC) $(FLAGS) $(SRC_DIR)/dmesg_mmu_idmap.c -o $(BUILD_DIR)/dmesg_mmu_idmap.o
	-$(CC) $(FLAGS) $(SRC_DIR)/free_reserved_area_dmesg.c -o $(BUILD_DIR)/free_reserved_area_dmesg.o
	-$(CC) $(FLAGS) $(SRC_DIR)/free_reserved_area_syslog.c -o $(BUILD_DIR)/free_reserved_area_syslog.o
	-$(CC) $(FLAGS) $(SRC_DIR)/sysfs_iscsi_transport_handle.c -o $(BUILD_DIR)/sysfs_iscsi_transport_handle.o
	-$(CC) $(FLAGS) $(SRC_DIR)/kallsyms.c -o $(BUILD_DIR)/kallsyms.o
	-$(CC) $(FLAGS) $(SRC_DIR)/mincore.c -o $(BUILD_DIR)/mincore.o
	-$(CC) $(FLAGS) $(SRC_DIR)/nf_conntrack.c -o $(BUILD_DIR)/nf_conntrack.o
	-$(CC) $(FLAGS) $(SRC_DIR)/perf_event_open.c -o $(BUILD_DIR)/perf_event_open.o
	-$(CC) $(FLAGS) $(SRC_DIR)/pppd_kallsyms.c -o $(BUILD_DIR)/pppd_kallsyms.o
	-$(CC) $(FLAGS) $(SRC_DIR)/proc-stat-wchan.c -o $(BUILD_DIR)/proc-stat-wchan.o
	-$(CC) $(FLAGS) extra/oops_inet_csk_listen_stop.c -o $(BUILD_DIR)/oops_inet_csk_listen_stop.o
	-$(CC) $(FLAGS) extra/oops_netlink_getsockbyportid_null_ptr.c -o $(BUILD_DIR)/oops_netlink_getsockbyportid_null_ptr.o

64bit :
	mkdir -p $(BUILD_DIR)
	-$(CC) $(FLAGS) $(SRC_DIR)/boot-config.c -o $(BUILD_DIR)/boot-config.o
	-$(CC) $(FLAGS) $(SRC_DIR)/cmdline.c -o $(BUILD_DIR)/cmdline.o
	-$(CC) $(FLAGS) $(SRC_DIR)/default.c -o $(BUILD_DIR)/default.o
	-$(CC) $(FLAGS) $(SRC_DIR)/dmesg_backtrace.c -o $(BUILD_DIR)/dmesg_backtrace.o
	-$(CC) $(FLAGS) $(SRC_DIR)/free_reserved_area_dmesg.c -o $(BUILD_DIR)/free_reserved_area_dmesg.o
	-$(CC) $(FLAGS) $(SRC_DIR)/free_reserved_area_syslog.c -o $(BUILD_DIR)/free_reserved_area_syslog.o
	-$(CC) $(FLAGS) $(SRC_DIR)/sysfs_iscsi_transport_handle.c -o $(BUILD_DIR)/sysfs_iscsi_transport_handle.o
	-$(CC) $(FLAGS) $(SRC_DIR)/kallsyms.c -o $(BUILD_DIR)/kallsyms.o
	-$(CC) $(FLAGS) $(SRC_DIR)/mincore.c -o $(BUILD_DIR)/mincore.o
	-$(CC) $(FLAGS) $(SRC_DIR)/nf_conntrack.c -o $(BUILD_DIR)/nf_conntrack.o
	-$(CC) $(FLAGS) $(SRC_DIR)/perf_event_open.c -o $(BUILD_DIR)/perf_event_open.o
	-$(CC) $(FLAGS) $(SRC_DIR)/proc-stat-wchan.c -o $(BUILD_DIR)/proc-stat-wchan.o

32bit :
	mkdir -p $(BUILD_DIR)
	-$(CC) $(FLAGS) $(SRC_DIR)/bcm_msg_head_struct.c -o $(BUILD_DIR)/bcm_msg_head_struct.o
	-$(CC) $(FLAGS) $(SRC_DIR)/boot-config.c -o $(BUILD_DIR)/boot-config.o
	-$(CC) $(FLAGS) $(SRC_DIR)/cmdline.c -o $(BUILD_DIR)/cmdline.o
	-$(CC) $(FLAGS) $(SRC_DIR)/default.c -o $(BUILD_DIR)/default.o
	-$(CC) $(FLAGS) $(SRC_DIR)/dmesg_mem_init_kernel_layout.c -o $(BUILD_DIR)/dmesg_mem_init_kernel_layout.o
	-$(CC) $(FLAGS) $(SRC_DIR)/dmesg_mmu_idmap.c -o $(BUILD_DIR)/dmesg_mmu_idmap.o
	-$(CC) $(FLAGS) $(SRC_DIR)/sysfs_iscsi_transport_handle.c -o $(BUILD_DIR)/sysfs_iscsi_transport_handle.o
	-$(CC) $(FLAGS) $(SRC_DIR)/kallsyms.c -o $(BUILD_DIR)/kallsyms.o
	-$(CC) $(FLAGS) $(SRC_DIR)/nf_conntrack.c -o $(BUILD_DIR)/nf_conntrack.o
	-$(CC) $(FLAGS) $(SRC_DIR)/perf_event_open.c -o $(BUILD_DIR)/perf_event_open.o
	-$(CC) $(FLAGS) $(SRC_DIR)/pppd_kallsyms.c -o $(BUILD_DIR)/pppd_kallsyms.o
	-$(CC) $(FLAGS) $(SRC_DIR)/proc-stat-wchan.c -o $(BUILD_DIR)/proc-stat-wchan.o

extra :
	mkdir -p $(BUILD_DIR)
	-$(CC) $(FLAGS) extra/oops_inet_csk_listen_stop.c -o $(BUILD_DIR)/oops_inet_csk_listen_stop.o
	-$(CC) $(FLAGS) extra/oops_netlink_getsockbyportid_null_ptr.c -o $(BUILD_DIR)/oops_netlink_getsockbyportid_null_ptr.o

clean :
	rm -f $(BUILD_DIR)/*.o
