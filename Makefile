SHELL = /bin/sh
.SUFFIXES: .c .o

CC = cc
FLAGS = -Wall

BUILD_DIR := ./build
SRC_DIR := ./src

all :
	mkdir -p $(BUILD_DIR)
	$(CC) $(FLAGS) $(SRC_DIR)/boot-config.c -o $(BUILD_DIR)/boot-config.o
	$(CC) $(FLAGS) $(SRC_DIR)/cmdline.c -o $(BUILD_DIR)/cmdline.o
	$(CC) $(FLAGS) $(SRC_DIR)/default.c -o $(BUILD_DIR)/default.o
	$(CC) $(FLAGS) $(SRC_DIR)/dmesg.c -o $(BUILD_DIR)/dmesg.o
	$(CC) $(FLAGS) $(SRC_DIR)/kallsyms.c -o $(BUILD_DIR)/kallsyms.o
	$(CC) $(FLAGS) $(SRC_DIR)/mincore.c -o $(BUILD_DIR)/mincore.o
	$(CC) $(FLAGS) $(SRC_DIR)/free_reserved_area_dmesg.c -o $(BUILD_DIR)/free_reserved_area_dmesg.o
	$(CC) $(FLAGS) $(SRC_DIR)/free_reserved_area_syslog.c -o $(BUILD_DIR)/free_reserved_area_syslog.o
	$(CC) $(FLAGS) $(SRC_DIR)/nf_conntrack.c -o $(BUILD_DIR)/nf_conntrack.o
	$(CC) $(FLAGS) $(SRC_DIR)/perf_event_open.c -o $(BUILD_DIR)/perf_event_open.o
	$(CC) $(FLAGS) $(SRC_DIR)/pppd_kallsyms.c -o $(BUILD_DIR)/pppd_kallsyms.o
	$(CC) $(FLAGS) $(SRC_DIR)/tsx-rtm.c -o $(BUILD_DIR)/tsx-rtm.o
	$(CC) $(FLAGS) extra/iscsi_transport_handle.c -o $(BUILD_DIR)/iscsi_transport_handle.o
	$(CC) $(FLAGS) extra/oops_inet_csk_listen_stop.c -o $(BUILD_DIR)/oops_inet_csk_listen_stop.o
	$(CC) $(FLAGS) extra/oops_netlink_getsockbyportid_null_ptr.c -o $(BUILD_DIR)/oops_netlink_getsockbyportid_null_ptr.o

64bit :
	mkdir -p $(BUILD_DIR)
	$(CC) $(FLAGS) $(SRC_DIR)/boot-config.c -o $(BUILD_DIR)/boot-config.o
	$(CC) $(FLAGS) $(SRC_DIR)/cmdline.c -o $(BUILD_DIR)/cmdline.o
	$(CC) $(FLAGS) $(SRC_DIR)/default.c -o $(BUILD_DIR)/default.o
	$(CC) $(FLAGS) $(SRC_DIR)/dmesg.c -o $(BUILD_DIR)/dmesg.o
	$(CC) $(FLAGS) $(SRC_DIR)/kallsyms.c -o $(BUILD_DIR)/kallsyms.o
	$(CC) $(FLAGS) $(SRC_DIR)/mincore.c -o $(BUILD_DIR)/mincore.o
	$(CC) $(FLAGS) $(SRC_DIR)/free_reserved_area_dmesg.c -o $(BUILD_DIR)/free_reserved_area_dmesg.o
	$(CC) $(FLAGS) $(SRC_DIR)/free_reserved_area_syslog.c -o $(BUILD_DIR)/free_reserved_area_syslog.o
	$(CC) $(FLAGS) $(SRC_DIR)/nf_conntrack.c -o $(BUILD_DIR)/nf_conntrack.o
	$(CC) $(FLAGS) $(SRC_DIR)/perf_event_open.c -o $(BUILD_DIR)/perf_event_open.o
	$(CC) $(FLAGS) $(SRC_DIR)/tsx-rtm.c -o $(BUILD_DIR)/tsx-rtm.o

32bit :
	mkdir -p $(BUILD_DIR)
	$(CC) $(FLAGS) $(SRC_DIR)/boot-config.c -o $(BUILD_DIR)/boot-config.o
	$(CC) $(FLAGS) $(SRC_DIR)/cmdline.c -o $(BUILD_DIR)/cmdline.o
	$(CC) $(FLAGS) $(SRC_DIR)/default.c -o $(BUILD_DIR)/default.o
	$(CC) $(FLAGS) $(SRC_DIR)/kallsyms.c -o $(BUILD_DIR)/kallsyms.o
	$(CC) $(FLAGS) $(SRC_DIR)/pppd_kallsyms.c -o $(BUILD_DIR)/pppd_kallsyms.o

extra :
	$(CC) $(FLAGS) extra/iscsi_transport_handle.c -o $(BUILD_DIR)/iscsi_transport_handle.o
	$(CC) $(FLAGS) extra/oops_inet_csk_listen_stop.c -o $(BUILD_DIR)/oops_inet_csk_listen_stop.o
	$(CC) $(FLAGS) extra/oops_netlink_getsockbyportid_null_ptr.c -o $(BUILD_DIR)/oops_netlink_getsockbyportid_null_ptr.o

clean :
	rm -f $(BUILD_DIR)/*.o
