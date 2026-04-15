# This file is part of KASLD - https://github.com/bcoles/kasld
# ---
# <bcoles@gmail.com>

SHELL = /bin/sh

CC = cc
# Warning: Do not compile with -O2 (known to cause issues)
CFLAGS = -g -Wall -Wextra -pedantic
ALL_CFLAGS = -std=c99 $(CFLAGS)
LDFLAGS =
ALL_LDFLAGS = $(LDFLAGS)

VERSION := $(shell cat VERSION 2>/dev/null || echo unknown)

HOST_ARCH := $(shell cc -dumpmachine)
_ARCH := $(shell $(CC) -dumpmachine)

# Auto-static when cross-compiling
ifneq ($(_ARCH),$(HOST_ARCH))
ALL_LDFLAGS += -static
endif

BUILD_DIR := ./build
OBJ_DIR := $(BUILD_DIR)/$(_ARCH)
COMP_DIR := $(OBJ_DIR)/components
SRC_DIR := ./src

# Header dependencies: rebuild when any header changes
HDRS := $(wildcard $(SRC_DIR)/include/*.h $(SRC_DIR)/include/arch/*.h)

# Detect zlib (optional, for native gzip decompression in proc-config)
HAVE_ZLIB := $(shell echo 'int main(void){return 0;}' | $(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -xc - -lz -o /dev/null 2>/dev/null && echo 1)

# kasld orchestrator (not a leak component)
KASLD_SRC := $(SRC_DIR)/orchestrator.c
RENDER_SRC := $(SRC_DIR)/render.c
KASLD_BIN := $(OBJ_DIR)/kasld

# Leak components: standalone binaries in src/components/
COMP_SRC_DIR := $(SRC_DIR)/components
SRC_FILES := $(wildcard $(COMP_SRC_DIR)/*.c)
BIN_FILES := $(patsubst $(COMP_SRC_DIR)/%.c,$(COMP_DIR)/%,$(SRC_FILES))

PREFIX ?= /usr/local

.PHONY: all
all : build

# Create build directories (order-only prerequisite)
$(COMP_DIR):
	@echo "Building $(OBJ_DIR) ..."
	mkdir -p "$(COMP_DIR)"

# Validate headers before building components
.PHONY: check-headers
check-headers: | $(COMP_DIR)
	@$(CC) $(ALL_CFLAGS) -fsyntax-only $(SRC_DIR)/include/kasld.h

$(COMP_DIR)/%: $(COMP_SRC_DIR)/%.c $(HDRS) | $(COMP_DIR)
	-$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $< -o $@

# proc-config: link with zlib when available for native gzip decompression
ifeq ($(HAVE_ZLIB),1)
$(COMP_DIR)/proc-config: $(COMP_SRC_DIR)/proc-config.c $(HDRS) | $(COMP_DIR)
	-$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) -DHAVE_ZLIB $< -lz -o $@
endif

# kernelsnitch: needs -lpthread and -O2 for brute-force hash performance
$(COMP_DIR)/kernelsnitch: $(COMP_SRC_DIR)/kernelsnitch.c $(HDRS) | $(COMP_DIR)
	-$(CC) $(ALL_CFLAGS) -O2 $(ALL_LDFLAGS) -I$(SRC_DIR) $< -lpthread -o $@

.PHONY: build
build : check-headers $(BIN_FILES) $(KASLD_BIN)

$(OBJ_DIR)/orchestrator.o: $(KASLD_SRC) $(HDRS) | $(COMP_DIR)
	$(CC) $(ALL_CFLAGS) -DVERSION='"$(VERSION)"' -c $< -o $@

$(OBJ_DIR)/render.o: $(RENDER_SRC) $(HDRS) | $(COMP_DIR)
	$(CC) $(ALL_CFLAGS) -DVERSION='"$(VERSION)"' -c $< -o $@

$(KASLD_BIN): $(OBJ_DIR)/orchestrator.o $(OBJ_DIR)/render.o | $(COMP_DIR)
	$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) $^ -o $@

.PHONY: run
run : build
	$(KASLD_BIN)

# Unit tests
TEST_DIR := ./tests
TEST_BIN := $(OBJ_DIR)/test_kasld

$(TEST_BIN): $(TEST_DIR)/test_kasld.c $(KASLD_SRC) $(RENDER_SRC) $(HDRS) | $(COMP_DIR)
	$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -DKASLD_TESTING -I$(SRC_DIR) $(TEST_DIR)/test_kasld.c -o $@

.PHONY: test
test : $(TEST_BIN)
	$(TEST_BIN)


.PHONY: clean
clean :
	@echo "Cleaning $(BUILD_DIR) ..."
	rm -rf "$(BUILD_DIR)"


.PHONY: install
install : build
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 755 $(KASLD_BIN) "$(DESTDIR)$(PREFIX)/bin/kasld"
	install -d "$(DESTDIR)$(PREFIX)/libexec/kasld"
	install -m 755 $(COMP_DIR)/* "$(DESTDIR)$(PREFIX)/libexec/kasld/"

.PHONY: uninstall
uninstall :
	rm -f "$(DESTDIR)$(PREFIX)/bin/kasld"
	rm -rf "$(DESTDIR)$(PREFIX)/libexec/kasld"


# Cross-compile for all supported architectures.
# Expects <triple>-gcc to be in PATH for each target.

CROSS_TARGETS := \
	aarch64-linux-musl \
	arm-unknown-linux-musleabi armeb-linux-musleabi \
	armv7-unknown-linux-musleabi \
	arm-linux-gnueabihf \
	i686-unknown-linux-musl \
	mips-linux-gnu mipsel-linux-gnu \
	mips-unknown-linux-musl mipsel-unknown-linux-musl \
	mips64-linux-gnuabi64 mips64el-linux-gnuabi64 \
	mips64-unknown-linux-musl mips64el-unknown-linux-musl \
	loongarch64-unknown-linux-musl \
	powerpc-linux-gnu powerpc64le-linux-gnu \
	powerpc64-unknown-linux-musl powerpc64le-unknown-linux-musl \
	powerpcle-unknown-linux-musl \
	riscv32-linux-musl riscv64-linux-musl \
	riscv64-linux-gnu \
	s390x-linux-gnu s390x-ibm-linux-musl \
	x86_64-linux-musl \
	aarch64-linux-gnu

.PHONY: cross
cross :
	@for triple in $(CROSS_TARGETS); do \
		if command -v $${triple}-gcc >/dev/null 2>&1; then \
			echo "=== Building for $$triple ==="; \
			$(MAKE) build CC=$${triple}-gcc || true; \
			echo; \
		else \
			echo "=== Skipping $$triple (toolchain not found) ==="; \
		fi; \
	done


.PHONY: help
help:
	@echo
	@echo "  make [target] [OPTIONS]"
	@echo
	@echo "  Targets:"
	@echo "      build           Build kasld and all components (default)"
	@echo "      run             Build and run kasld"
	@echo "      test            Build and run unit tests"
	@echo "      cross           Cross-compile for all supported architectures"
	@echo "      install         Install to PREFIX (default: /usr/local)"
	@echo "      uninstall       Remove installed files"
	@echo "      clean           Remove build directory"
	@echo
	@echo "  Options:"
	@echo "      CC=compiler     Compiler executable"
	@echo "      CFLAGS=flags    Compiler flags"
	@echo "      LDFLAGS=flags   Linker flags"
	@echo "      PREFIX=path     Install prefix (default: /usr/local)"
	@echo
