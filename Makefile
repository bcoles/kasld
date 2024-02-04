# This file is part of KASLD - https://github.com/bcoles/kasld
# ---
# <bcoles@gmail.com>

SHELL = /bin/sh
.SUFFIXES: .c .o

CC = cc
# Warning: Do not compile with -O
CFLAGS = -g -Wall -Wextra -pedantic
ALL_CFLAGS = -std=c99 $(CFLAGS)
LDFLAGS = -static
ALL_LDFLAGS = $(LDFLAGS)

ifndef _ARCH
_ARCH := $(shell $(CC) -dumpmachine)
export _ARCH
endif

BUILD_DIR := ./build
OBJ_DIR := $(BUILD_DIR)/$(_ARCH)
SRC_DIR := ./src
SRC_FILES := $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRC_FILES))

.PHONY: all
all : build

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	-$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) $< -o $@

.PHONY: pre-build
pre-build :
	@echo "Building $(OBJ_DIR) ..."
	mkdir -p "$(OBJ_DIR)"

.PHONY: build
build : pre-build $(OBJ_FILES)

.PHONY: run
run : build
	@echo "Running build ..."
	@echo

# run default first
	-$(OBJ_DIR)/default.o
	@echo
	-$(OBJ_DIR)/bcm_msg_head_struct.o
	@echo
	-$(OBJ_DIR)/boot-config.o
	@echo
	-$(OBJ_DIR)/cmdline.o
	@echo
	-$(OBJ_DIR)/dmesg_android_ion_snapshot.o
	@echo
	-$(OBJ_DIR)/dmesg_backtrace.o
	@echo
	-$(OBJ_DIR)/dmesg_check_for_initrd.o
	@echo
	-$(OBJ_DIR)/dmesg_driver_component_ops.o
	@echo
	-$(OBJ_DIR)/dmesg_early_init_dt_add_memory_arch.o
	@echo
	-$(OBJ_DIR)/dmesg_ex_handler_msr.o
	@echo
	-$(OBJ_DIR)/dmesg_fake_numa_init.o
	@echo
	-$(OBJ_DIR)/dmesg_free_area_init_node.o
	@echo
	-$(OBJ_DIR)/dmesg_free_reserved_area.o
	@echo
	-$(OBJ_DIR)/dmesg_kaslr-disabled.o
	@echo
	-$(OBJ_DIR)/dmesg_mem_init_kernel_layout.o
	@echo
	-$(OBJ_DIR)/dmesg_mmu_idmap.o
	@echo
	-$(OBJ_DIR)/entrybleed.o
	@echo
	-$(OBJ_DIR)/mmap-brute-vmsplit.o
	@echo
	-$(OBJ_DIR)/perf_event_open.o
	@echo
	-$(OBJ_DIR)/proc-config.o
	@echo
	-$(OBJ_DIR)/pppd_kallsyms.o
	@echo
	-$(OBJ_DIR)/proc-kallsyms.o
	@echo
	-$(OBJ_DIR)/proc-modules.o
	@echo
	-$(OBJ_DIR)/proc-pid-syscall.o
	@echo
	-$(OBJ_DIR)/proc-stat-wchan.o
	@echo
	-$(OBJ_DIR)/sysfs_iscsi_transport_handle.o
	@echo
	-$(OBJ_DIR)/sysfs-kernel-notes-xen.o
	@echo
	-$(OBJ_DIR)/sysfs-module-sections.o
	@echo
	-$(OBJ_DIR)/sysfs_nf_conntrack.o
	@echo
# slow - leave this one last
	-$(OBJ_DIR)/mincore.o
	@echo


.PHONY: clean
clean :
	@echo "Cleaning $(BUILD_DIR) ..."
	rm -rf "$(BUILD_DIR)"


.PHONY: help
help:
	@echo
	@echo "  make [target] [OPTIONS]"
	@echo
	@echo "  Targets:"
	@echo "      run             Build and run"
	@echo "      all             Build all from src directory"
	@echo "      clean           Remove build directory"
	@echo
	@echo "  Options:"
	@echo "      CC=compiler     Compiler executable"
	@echo "      CFLAGS=flags    Compiler flags"
	@echo "      LDFLAGS=flags   Linker flags"
	@echo
