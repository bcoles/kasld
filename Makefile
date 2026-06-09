# This file is part of KASLD - https://github.com/bcoles/kasld
# ---
# <bcoles@gmail.com>

SHELL = /bin/sh

CC = cc
# -O2 is safe for most components (pure C parsers, syscall wrappers).
# Side-channel components that rely on precise timing or speculative
# execution are compiled with -O0 below: the compiler may reorder memory
# operations around rdtsc/rdtscp timing, eliminate volatile accesses used
# for Flush+Reload cache probing, or reschedule instructions across
# mfence/lfence serialization barriers — destroying the timing signal.
CFLAGS = -g -O2 -Wall -Wextra -pedantic

# Diagnostics layer. Each flag is probed against $(CC) at make-time via
# cc-option; flags the compiler doesn't recognise simply drop out instead
# of generating per-file noise. This keeps the build portable across:
#   - older gcc (pre-6 lacks -Wnull-dereference, -Wduplicated-cond,
#     -Wrestrict; pre-7 lacks -Wduplicated-branches, -Walloca; pre-4.9
#     lacks -fstack-protector-strong)
#   - clang (lacks -Wlogical-op, -Wduplicated-cond, -Wduplicated-branches,
#     -Wrestrict — gcc-only diagnostics)
#   - musl (silently ignores -D_FORTIFY_SOURCE; gcc accepts the flag)
#
# Warning surface:
#   -Wshadow / -Wcast-qual / -Wcast-align / -Wpointer-arith   real-bug catches
#   -Wstrict-prototypes / -Wmissing-prototypes /
#   -Wmissing-declarations / -Wold-style-definition /
#   -Wnested-externs / -Wredundant-decls / -Wbad-function-cast prototype hygiene
#   -Wwrite-strings                                            string-literal const
#   -Wundef                                                    undefined macro in #if
#   -Wnull-dereference / -Wlogical-op / -Wduplicated-cond /
#   -Wduplicated-branches / -Wrestrict                         flow/aliasing bugs
#   -Wfloat-equal                                              == on floats
#   -Wvla / -Walloca / -Wstack-protector                       no runtime-sized stack
#
# Promoted-to-error: catches real bugs that are easy to ignore as warnings
# (missing #include, mismatched pointer types, missing return, non-literal
# format with no args).
#
# Hardening: -fstack-protector-strong + -D_FORTIFY_SOURCE=2 add stack
# canaries and libc-side str/mem/printf runtime checks. _FORTIFY_SOURCE
# needs -O >= 1 (we have -O2).

# cc-option <flag>: emits <flag> if $(CC) accepts it on this toolchain, else
# nothing. Same shape as the kernel's cc-option. -Werror so a "unknown
# option" warning fails the probe; -x c /dev/null so neither preprocessor
# input nor a real file is needed. One $(CC) invocation per probed flag at
# make startup (cheap; the probes run once for the whole build).
cc-option = $(shell $(CC) -Werror $(1) -E -x c /dev/null -o /dev/null \
                    >/dev/null 2>&1 && echo $(1))

KASLD_WARN_FLAGS_WANTED := \
    -Wshadow -Wstrict-prototypes -Wmissing-prototypes \
    -Wmissing-declarations -Wpointer-arith -Wcast-align \
    -Wcast-qual -Wwrite-strings -Wundef \
    -Wold-style-definition -Wredundant-decls \
    -Wbad-function-cast -Wfloat-equal -Wnested-externs \
    -Wnull-dereference -Wlogical-op -Wduplicated-cond \
    -Wduplicated-branches -Wrestrict -Wvla -Walloca \
    -Wstack-protector \
    -Werror=implicit-function-declaration \
    -Werror=incompatible-pointer-types \
    -Werror=return-type \
    -Werror=format-security
KASLD_HARDEN_FLAGS_WANTED := -fstack-protector-strong -D_FORTIFY_SOURCE=2

KASLD_WARN_FLAGS   := $(foreach f,$(KASLD_WARN_FLAGS_WANTED),$(call cc-option,$(f)))
KASLD_HARDEN_FLAGS := $(foreach f,$(KASLD_HARDEN_FLAGS_WANTED),$(call cc-option,$(f)))

ALL_CFLAGS = -std=c99 $(CFLAGS) $(KASLD_WARN_FLAGS) $(KASLD_HARDEN_FLAGS)
LDFLAGS =
ALL_LDFLAGS = $(LDFLAGS)

VERSION := $(shell cat VERSION 2>/dev/null || echo unknown)

# Target triple ($(CC)) vs. the host's native triple (always plain `cc`). When
# they differ we are cross-compiling, so link static — the target loader/libs
# are not on this host. $(_ARCH) also names the per-arch build subdirectory.
HOST_ARCH := $(shell cc -dumpmachine)
_ARCH := $(shell $(CC) -dumpmachine)

ifneq ($(_ARCH),$(HOST_ARCH))
ALL_LDFLAGS += -static
endif

BUILD_DIR := ./build
OBJ_DIR := $(BUILD_DIR)/$(_ARCH)
COMP_DIR := $(OBJ_DIR)/components
# Test executables live apart from the deployable product (kasld + components)
# so `make install` never sees them and they are obviously not shippable.
TEST_OBJ_DIR := $(BUILD_DIR)/tests
SRC_DIR := ./src

# Header dependencies: rebuild when any header changes
HDRS := $(wildcard $(SRC_DIR)/include/*.h $(SRC_DIR)/include/kasld/*.h \
                    $(SRC_DIR)/include/kasld/arch/*.h)

# Detect zlib (optional, for native gzip decompression in proc_config)
HAVE_ZLIB := $(shell echo 'int main(void){return 0;}' | $(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -xc - -lz -o /dev/null 2>/dev/null && echo 1)

# Detect pthread (optional, for parallel inference worker pool in orchestrator)
HAVE_PTHREAD := $(shell echo 'int main(void){return 0;}' | $(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -xc - -lpthread -o /dev/null 2>/dev/null && echo 1)

ifeq ($(HAVE_PTHREAD),1)
PTHREAD_CFLAGS := -DHAVE_PTHREAD
PTHREAD_LIBS   := -lpthread
else
PTHREAD_CFLAGS :=
PTHREAD_LIBS   :=
endif

# kasld orchestrator (not a leak component)
KASLD_SRC      := $(SRC_DIR)/orchestrator.c
RENDER_SRC     := $(SRC_DIR)/render.c
# Per-output-mode renderer translation units. The wildcard means adding a new
# mode (e.g. src/render/yaml.c) needs no Makefile edit; the cross-file glue
# (shared helpers, per-mode entry points) lives in include/kasld/render_internal.h.
RENDER_MODE_SRCS := $(wildcard $(SRC_DIR)/render/*.c)
RENDER_MODE_OBJS := $(patsubst $(SRC_DIR)/render/%.c,$(OBJ_DIR)/render_%.o,$(RENDER_MODE_SRCS))
REGIONS_SRC    := $(SRC_DIR)/region_info.c
KASLD_BIN      := $(OBJ_DIR)/kasld

# Layered inference engine: core translation units + the pure rules, all linked
# into the orchestrator (the sole inference path). Declared once here so the
# engine test targets below reuse the same lists — no second copy to keep in
# sync. The rules are a wildcard, so adding a rule needs no Makefile edit.
ESTIMATE_SRC     := $(SRC_DIR)/estimate.c
QUANTITIES_SRC   := $(SRC_DIR)/quantities.c
EVIDENCE_SRC     := $(SRC_DIR)/evidence.c
ENGINE_SRC       := $(SRC_DIR)/engine.c
ENGINE_RULES_SRC := $(SRC_DIR)/engine_rules.c
RULE_SRCS        := $(wildcard $(SRC_DIR)/rules/*.c)

# ENGINE_CORE = the engine minus its rule registry (estimate/quantities/
# evidence/engine); ENGINE_CORE_SRCS adds the registry — the full product path.
ENGINE_CORE      := $(ESTIMATE_SRC) $(QUANTITIES_SRC) $(EVIDENCE_SRC) $(ENGINE_SRC)
ENGINE_CORE_SRCS := $(ENGINE_CORE) $(ENGINE_RULES_SRC)
ENGINE_OBJS      := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(ENGINE_CORE_SRCS)) \
                    $(patsubst $(SRC_DIR)/rules/%.c,$(OBJ_DIR)/rule_%.o,$(RULE_SRCS))

# Leak components: standalone binaries in src/components/
COMP_SRC_DIR := $(SRC_DIR)/components
SRC_FILES := $(wildcard $(COMP_SRC_DIR)/*.c)
BIN_FILES := $(patsubst $(COMP_SRC_DIR)/%.c,$(COMP_DIR)/%,$(SRC_FILES))

# cc-component <cmd...>: run the compiler. Three outcomes:
#   - Success: print `[built] <component>` so per-arch builds (especially
#     `make cross`) make visible which components landed on this arch.
#   - Failure caused ONLY by the arch-gate `#error "Architecture is not
#     supported"` (and nothing else): print a single
#     `[skip] <component> (architecture-gated)` line. The build of *this*
#     component is not actually a failure — the source explicitly opts out
#     for the target arch — so reporting it as an error was misleading.
#   - Any other failure: print the full diagnostic verbatim.
# In every case the recipe itself exits 0 so a broken component never
# stops the wider build (preserves the previous `-cc ...` tolerate-all
# semantic).
define cc-component
	@out=$$($(1) 2>&1); st=$$?; \
	if [ $$st -eq 0 ]; then \
	  echo "[built] $(notdir $@)"; \
	  if [ -n "$$out" ]; then printf '%s\n' "$$out" >&2; fi; \
	elif echo "$$out" | grep -q '#error.*Architecture is not supported'; then \
	  echo "[skip]  $(notdir $@) (architecture-gated)"; \
	elif [ -n "$$out" ]; then \
	  printf '%s\n' "$$out" >&2; \
	fi
endef

PREFIX ?= /usr/local

.PHONY: all
all : build

# Create build directories (order-only prerequisite)
$(COMP_DIR):
	@echo "Building $(OBJ_DIR) ..."
	mkdir -p "$(COMP_DIR)"

$(TEST_OBJ_DIR):
	mkdir -p "$(TEST_OBJ_DIR)"

# Validate headers before building components
.PHONY: check-headers
check-headers: | $(COMP_DIR)
	@$(CC) $(ALL_CFLAGS) -xc -fsyntax-only $(SRC_DIR)/include/kasld/api.h

$(COMP_DIR)/%: $(COMP_SRC_DIR)/%.c $(HDRS) | $(COMP_DIR)
	$(call cc-component, $(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $< -o $@)

# proc_config: link with zlib when available for native gzip decompression
ifeq ($(HAVE_ZLIB),1)
$(COMP_DIR)/proc_config: $(COMP_SRC_DIR)/proc_config.c $(HDRS) | $(COMP_DIR)
	$(call cc-component, $(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) -DHAVE_ZLIB $< -lz -o $@)
endif

# Side-channel components: compile without optimization (-O0 overrides -O2).
# These rely on precise instruction ordering around timing measurements
# (rdtsc/rdtscp + mfence/lfence), speculative execution gadgets (asm goto),
# or Flush+Reload cache probing via volatile pointer accesses.
$(COMP_DIR)/databounce: $(COMP_SRC_DIR)/databounce.c $(HDRS) | $(COMP_DIR)
	$(call cc-component, $(CC) $(ALL_CFLAGS) -O0 $(ALL_LDFLAGS) -I$(SRC_DIR) $< -o $@)

$(COMP_DIR)/echoload: $(COMP_SRC_DIR)/echoload.c $(HDRS) | $(COMP_DIR)
	$(call cc-component, $(CC) $(ALL_CFLAGS) -O0 $(ALL_LDFLAGS) -I$(SRC_DIR) $< -o $@)

$(COMP_DIR)/entrybleed: $(COMP_SRC_DIR)/entrybleed.c $(HDRS) | $(COMP_DIR)
	$(call cc-component, $(CC) $(ALL_CFLAGS) -O0 $(ALL_LDFLAGS) -I$(SRC_DIR) $< -o $@)

$(COMP_DIR)/mincore: $(COMP_SRC_DIR)/mincore.c $(HDRS) | $(COMP_DIR)
	$(call cc-component, $(CC) $(ALL_CFLAGS) -O0 $(ALL_LDFLAGS) -I$(SRC_DIR) $< -o $@)

$(COMP_DIR)/prefetch: $(COMP_SRC_DIR)/prefetch.c $(HDRS) | $(COMP_DIR)
	$(call cc-component, $(CC) $(ALL_CFLAGS) -O0 $(ALL_LDFLAGS) -I$(SRC_DIR) $< -o $@)

$(COMP_DIR)/zombieload: $(COMP_SRC_DIR)/zombieload.c $(HDRS) | $(COMP_DIR)
	$(call cc-component, $(CC) $(ALL_CFLAGS) -O0 $(ALL_LDFLAGS) -I$(SRC_DIR) $< -o $@)

# kernelsnitch: needs -lpthread (uses default -O2 for hash timing performance)
$(COMP_DIR)/kernelsnitch: $(COMP_SRC_DIR)/kernelsnitch.c $(HDRS) | $(COMP_DIR)
	$(call cc-component, $(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $< $(PTHREAD_LIBS) -o $@)

.PHONY: build
build : check-headers $(BIN_FILES) $(KASLD_BIN)

$(OBJ_DIR)/orchestrator.o: $(KASLD_SRC) $(HDRS) | $(COMP_DIR)
	$(CC) $(ALL_CFLAGS) $(PTHREAD_CFLAGS) -DVERSION='"$(VERSION)"' -c $< -o $@

$(OBJ_DIR)/render.o: $(RENDER_SRC) $(HDRS) | $(COMP_DIR)
	$(CC) $(ALL_CFLAGS) -DVERSION='"$(VERSION)"' -I$(SRC_DIR) -c $< -o $@

# Per-mode render translation units (src/render/<mode>.c). Each gets its own
# object so editing one mode does not force the others to recompile.
$(OBJ_DIR)/render_%.o: $(SRC_DIR)/render/%.c $(HDRS) | $(COMP_DIR)
	$(CC) $(ALL_CFLAGS) -DVERSION='"$(VERSION)"' -I$(SRC_DIR) -c $< -o $@

$(OBJ_DIR)/region_info.o: $(REGIONS_SRC) $(HDRS) | $(COMP_DIR)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

# Engine core (estimate/quantities/evidence/engine) and ported rules.
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(HDRS) | $(COMP_DIR)
	$(CC) $(ALL_CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(OBJ_DIR)/rule_%.o: $(SRC_DIR)/rules/%.c $(HDRS) | $(COMP_DIR)
	$(CC) $(ALL_CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(KASLD_BIN): $(OBJ_DIR)/orchestrator.o $(OBJ_DIR)/render.o $(RENDER_MODE_OBJS) $(OBJ_DIR)/region_info.o $(ENGINE_OBJS) | $(COMP_DIR)
	$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) $^ $(PTHREAD_LIBS) -o $@

.PHONY: run
run : build
	$(KASLD_BIN)

# Unit tests
TEST_DIR := ./tests
TEST_BIN := $(TEST_OBJ_DIR)/test_kasld

# Unit tests of orchestrator internals (parsing, merge, anchor selection,
# render helpers). The orchestrator's main() and engine hooks are excluded
# under -DKASLD_TESTING; engine-rule coverage lives in test_engine* below.
# test_kasld.c #includes render.c and each src/render/*.c so the renderer's
# static helpers (e.g. json_print_escaped, section_consensus) are reachable
# without exporting them across the public API.
$(TEST_BIN): $(TEST_DIR)/test_kasld.c $(KASLD_SRC) $(RENDER_SRC) $(RENDER_MODE_SRCS) $(HDRS) | $(TEST_OBJ_DIR)
	$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) $(PTHREAD_CFLAGS) -DKASLD_TESTING -I$(SRC_DIR) $(TEST_DIR)/test_kasld.c $(PTHREAD_LIBS) -o $@

# Renderer unit tests (split from test_kasld.c). Same single-TU model — it
# #includes the orchestrator + render translation units directly, hence
# -DKASLD_TESTING + the pthread flags — but exercises render.c / render/*.c.
TEST_RENDER_BIN := $(TEST_OBJ_DIR)/test_render

$(TEST_RENDER_BIN): $(TEST_DIR)/test_render.c $(KASLD_SRC) $(RENDER_SRC) $(RENDER_MODE_SRCS) $(HDRS) | $(TEST_OBJ_DIR)
	$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) $(PTHREAD_CFLAGS) -DKASLD_TESTING -I$(SRC_DIR) $(TEST_DIR)/test_render.c $(PTHREAD_LIBS) -o $@

# Estimate-core test (Stage A): standalone, links only estimate.c + quantities.c.
TEST_EST_BIN := $(TEST_OBJ_DIR)/test_estimate

$(TEST_EST_BIN): $(TEST_DIR)/test_estimate.c $(ESTIMATE_SRC) $(QUANTITIES_SRC) $(HDRS) | $(TEST_OBJ_DIR)
	$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_estimate.c $(ESTIMATE_SRC) $(QUANTITIES_SRC) -o $@

# Evidence-store test (Stage B): standalone, links only evidence.c.
TEST_EV_BIN := $(TEST_OBJ_DIR)/test_evidence

$(TEST_EV_BIN): $(TEST_DIR)/test_evidence.c $(EVIDENCE_SRC) $(HDRS) | $(TEST_OBJ_DIR)
	$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_evidence.c $(EVIDENCE_SRC) -o $@

# Engine test (Stage C/D): links the engine core + ALL ported rules. Linking the
# whole rules/ wildcard (rather than a hand-maintained subset) means adding a
# rule + its test needs no Makefile edit, and a rule can never be silently left
# out of the test build. Unreferenced rules just link unused.
TEST_ENG_BIN := $(TEST_OBJ_DIR)/test_engine

$(TEST_ENG_BIN): $(TEST_DIR)/test_engine.c $(ENGINE_CORE) $(RULE_SRCS) $(HDRS) | $(TEST_OBJ_DIR)
	$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_engine.c $(ENGINE_CORE) $(RULE_SRCS) -o $@

# Integration test: the FULL production rule registry (engine_rules.c + every
# rules/*.c) against leak-bearing synthetic evidence.
TEST_INT_BIN := $(TEST_OBJ_DIR)/test_engine_integration
$(TEST_INT_BIN): $(TEST_DIR)/test_engine_integration.c $(ENGINE_CORE) $(ENGINE_RULES_SRC) $(RULE_SRCS) $(HDRS) | $(TEST_OBJ_DIR)
	$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_engine_integration.c $(ENGINE_CORE) $(ENGINE_RULES_SRC) $(RULE_SRCS) -o $@

.PHONY: test
test : $(TEST_BIN) $(TEST_RENDER_BIN) $(TEST_EST_BIN) $(TEST_EV_BIN) $(TEST_ENG_BIN) $(TEST_INT_BIN)
	@$(TEST_DIR)/run-all
	@$(TEST_DIR)/check-self-edges
	@$(TEST_DIR)/check-truncation
	@$(TEST_DIR)/check-component-output

.PHONY: test-integration
test-integration : $(TEST_INT_BIN)
	$(TEST_INT_BIN)

.PHONY: test-estimate
test-estimate : $(TEST_EST_BIN)
	$(TEST_EST_BIN)

.PHONY: test-evidence
test-evidence : $(TEST_EV_BIN)
	$(TEST_EV_BIN)

# Cross-architecture engine test: runs the integration test under qemu-user for
# each 64-bit target (exercises arch-gated rules on their arch). Needs the
# musl-cross toolchains on PATH + qemu-user in QEMU_DIR;
# silently skips any target whose toolchain/qemu is absent. Not part of `make
# test` (host-only, no qemu dependency).
.PHONY: test-cross
test-cross :
	$(TEST_DIR)/test-cross

# Optional line-coverage report for the engine + rules (build/coverage/). Uses
# --coverage (gcc and clang) + the compiler's own gcov — no extra package for
# the text summary; HTML appears only if lcov+genhtml are installed. The normal
# build/test never use --coverage, so this adds no dependency to them. For a
# clang toolchain: make coverage GCOV="llvm-cov gcov".
.PHONY: coverage
coverage :
	CC="$(CC)" $(TEST_DIR)/coverage

# End-to-end coverage of the real kasld binary (orchestrator engine-bridge +
# main + render — the parts -DKASLD_TESTING hides from `make coverage`). Runs
# the instrumented binary live + over the x86_64 fixtures, natively; x86_64 host
# only. Same optional/no-extra-dep story as `coverage`.
.PHONY: coverage-e2e
coverage-e2e :
	CC="$(CC)" $(TEST_DIR)/coverage-e2e

# CI entrypoint: the full host test suite. Deterministic, no qemu/cross needed;
# `make` halts on the first failing test binary (each returns non-zero on
# failure). For cross-arch coverage run `make test-cross` and `tests/replay`.
.PHONY: check
check : test
	@echo "OK: host test suite passed."

.PHONY: test-engine
test-engine : $(TEST_ENG_BIN)
	$(TEST_ENG_BIN)


# Parser fuzz harnesses (tests/fuzz/, opt-in). Each builds against libFuzzer
# with ASan + UBSan. Requires clang or another compiler shipping
# -fsanitize=fuzzer; the host build never touches these. The default build
# graph does NOT depend on fuzz, so the absence of clang/libFuzzer is invisible
# unless the operator asks for it. See tests/fuzz/README.md for run options.
FUZZ_CC      ?= clang
FUZZ_CFLAGS  ?= -O1 -g -fsanitize=fuzzer,address,undefined -DKASLD_TESTING -I src
FUZZ_OUT     := $(BUILD_DIR)/fuzz
FUZZ_TARGETS := fuzz_parse_hex fuzz_capture_result fuzz_capture_scalar fuzz_parse_meta
FUZZ_BINS    := $(addprefix $(FUZZ_OUT)/,$(FUZZ_TARGETS))

$(FUZZ_OUT)/% : tests/fuzz/%.c
	@mkdir -p "$(FUZZ_OUT)"
	$(FUZZ_CC) $(FUZZ_CFLAGS) "$<" -o "$@"

.PHONY: fuzz
fuzz : $(FUZZ_BINS)
	@echo "Fuzz harnesses built in $(FUZZ_OUT)."
	@echo "Run e.g.: $(FUZZ_OUT)/fuzz_capture_result tests/fuzz/corpus/capture_result/"


.PHONY: clean
clean :
	@echo "Cleaning $(BUILD_DIR) ..."
	rm -rf "$(BUILD_DIR)"


# Install the orchestrator binary and the component executables.
#
# Test binaries live in $(BUILD_DIR)/tests/ and fuzz harnesses in
# $(BUILD_DIR)/fuzz/ — both are siblings of $(OBJ_DIR), so the install
# globs below ($(KASLD_BIN) names exactly one path; $(COMP_DIR)/* matches
# only the components/ subdir) cannot reach them. The install target also
# depends on `build`, not on `test` or `fuzz`, so neither is even built
# by an install-only invocation.
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


# Cross-compile all supported architectures with `make cross` — a local,
# musl-only mirror of the CI / release matrices. Expects <triple>-gcc on PATH;
# absent toolchains are skipped. Both the cross-tools/musl-cross triple names and
# the short musl-cross-make names are listed so either musl toolchain set works.
# GNU is intentionally absent (releases are built with musl). armeb is
# musl-cross-make-only — cross-tools/musl-cross provides no armeb toolchain.

CROSS_TARGETS := \
	x86_64-unknown-linux-musl x86_64-linux-musl \
	i686-unknown-linux-musl \
	aarch64-unknown-linux-musl aarch64-linux-musl \
	arm-unknown-linux-musleabi armv7-unknown-linux-musleabi \
	armeb-linux-musleabi \
	mips-unknown-linux-musl mipsel-unknown-linux-musl \
	mips64-unknown-linux-musl mips64el-unknown-linux-musl \
	powerpc-unknown-linux-musl powerpc-linux-musl \
	powerpcle-unknown-linux-musl \
	powerpc64-unknown-linux-musl powerpc64le-unknown-linux-musl \
	riscv32-unknown-linux-musl riscv32-linux-musl \
	riscv64-unknown-linux-musl riscv64-linux-musl \
	s390x-ibm-linux-musl \
	loongarch64-unknown-linux-musl

# Skip targets whose toolchain is absent, but FAIL if any present target fails
# to build (so CI is a real gate). All present targets are attempted first, so
# a single run surfaces every breakage rather than stopping at the first.
.PHONY: cross
cross :
	@rc=0; for triple in $(CROSS_TARGETS); do \
		if command -v $${triple}-gcc >/dev/null 2>&1; then \
			echo "=== Building for $$triple ==="; \
			$(MAKE) build CC=$${triple}-gcc || { rc=1; echo "!!! FAILED: $$triple"; }; \
			echo; \
		else \
			echo "=== Skipping $$triple (toolchain not found) ==="; \
		fi; \
	done; \
	[ $$rc -eq 0 ] || echo "cross: one or more present targets FAILED"; \
	exit $$rc


.PHONY: help
help:
	@echo
	@echo "  make [target] [OPTIONS]"
	@echo
	@echo "  Targets:"
	@echo "      build           Build kasld and all components (default)"
	@echo "      run             Build and run kasld"
	@echo "      test            Build and run unit tests"
	@echo "      check           Alias for test"
	@echo "      cross           Cross-compile for all supported architectures"
	@echo "      coverage        Host unit-test coverage report (gcov)"
	@echo "      coverage-e2e    End-to-end coverage over x86 fixtures (gcov)"
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
