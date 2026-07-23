# This file is part of KASLD - https://github.com/bcoles/kasld
# ---
# <bcoles@gmail.com>

SHELL = /bin/sh

# If a recipe fails after it has begun writing its target, delete the partial
# output so make does not treat a truncated file as up-to-date on the next run.
# (Component recipes exit 0 by design and are unaffected; this guards the object
# and link steps, which do fail on error.)
.DELETE_ON_ERROR:

CC = cc
# -O2 is safe for most components (pure C parsers, syscall wrappers).
# Side-channel components that rely on precise timing or speculative
# execution are compiled with -O0 below: the compiler may reorder memory
# operations around rdtsc/rdtscp timing, eliminate volatile accesses used
# for Flush+Reload cache probing, or reschedule instructions across
# mfence/lfence serialization barriers — destroying the timing signal.
CFLAGS = -g -O2 -Wall -Wextra -pedantic

# Diagnostics layer. Each flag is probed against $(CC) at make-time via
# cc-option; flags the compiler doesn't recognize simply drop out instead
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
# make startup, once for the whole build (and skipped entirely for goals that
# never compile — see kasld_compiling below).
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
    -Werror=format-security \
    -Werror=frame-larger-than=2097152
KASLD_HARDEN_FLAGS_WANTED := -fstack-protector-strong -D_FORTIFY_SOURCE=2

# 2 MiB frame cap: a single ~1.35 MiB `struct engine` on the stack is fine, but
# two or more (a multi-engine test) would overflow — those must be `static`
# (engine_init() resets each before use). Catches the engine, and any other
# oversized stack frame, at compile time. Dropped by cc-option on toolchains
# that lack the flag.

# The cc-option probes and the zlib/pthread feature tests below fork $(CC) at
# make startup — dozens of times. Targets that never compile (clean, help,
# uninstall) do not need any of it, so skip the whole lot when every requested
# goal is one of those. `$(or $(MAKECMDGOALS),build)` treats a bare `make` as a
# build. A slow or minimal host then runs `make clean`/`make help` without
# invoking the compiler at all.
kasld_compiling := 1
ifeq ($(filter-out clean help uninstall,$(or $(MAKECMDGOALS),build)),)
  kasld_compiling :=
endif

ifdef kasld_compiling
KASLD_WARN_FLAGS   := $(foreach f,$(KASLD_WARN_FLAGS_WANTED),$(call cc-option,$(f)))
KASLD_HARDEN_FLAGS := $(foreach f,$(KASLD_HARDEN_FLAGS_WANTED),$(call cc-option,$(f)))
endif

ALL_CFLAGS = -std=c99 $(CFLAGS) $(KASLD_WARN_FLAGS) $(KASLD_HARDEN_FLAGS)
LDFLAGS =
ALL_LDFLAGS = $(LDFLAGS)

# Quiet build. The default prints a short kernel-style tag ("  CC  <path>")
# BEFORE each step runs, so any compiler diagnostics that follow are always
# attributable to a named target instead of appearing with no context.
# `make V=1` restores the full command lines.
#   Q   — prefixes every real command; '@' hides it in quiet mode, empty in V=1
#         (where make echoes the command itself instead).
#   ccv — prints the "  TAG  <path>" progress line; expands to nothing under
#         V=1 so the echoed command is the only output.
#   disp — drops the leading "./" from a build path for a cleaner tag.
disp = $(patsubst ./%,%,$(1))

# Colorized progress tags, on only when stdout is a terminal. GNU make sets
# MAKE_TERMOUT to the terminal name when its stdout is a tty and leaves it empty
# when output is piped or redirected (CI logs, `make | tee`, the `make cross`
# capture), so those stay plain automatically. NO_COLOR (present, any value)
# forces plain; COLOR=1 / COLOR=0 override the auto-detection either way. The
# codes are portable octal ESC sequences so the /bin/sh printf renders them.
# COLOR=0 (or empty) forces off; COLOR set to any other value forces on.
KASLD_COLOR :=
ifeq ($(origin COLOR),undefined)
  ifndef NO_COLOR
    ifneq ($(MAKE_TERMOUT),)
      KASLD_COLOR := 1
    endif
  endif
else ifneq ($(filter-out 0,$(COLOR)),)
  KASLD_COLOR := 1
endif

ifeq ($(KASLD_COLOR),1)
  C_TAG  := \033[32m
  C_SKIP := \033[33m
  C_RST  := \033[0m
else
  C_TAG  :=
  C_SKIP :=
  C_RST  :=
endif

ifeq ($(V),1)
  Q   :=
  ccv  =
else
  Q   := @
  ccv  = @printf '  $(C_TAG)%-5s$(C_RST) %s\n' '$(1)' '$(call disp,$(2))'
endif

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
# The per-arch directory is the deployable product: the kasld binary plus the
# components/ subdir it discovers at runtime. Build intermediates (.o) go in a
# sibling obj/ subdir so they do not clutter that deployable tree — the same
# separation components/ already has.
ARCH_DIR := $(BUILD_DIR)/$(_ARCH)
OBJ_DIR := $(ARCH_DIR)/obj
COMP_DIR := $(ARCH_DIR)/components
# Test executables live apart from the deployable product (kasld + components)
# so `make install` never sees them and they are obviously not shippable.
TEST_OBJ_DIR := $(BUILD_DIR)/tests
SRC_DIR := ./src

# Header dependencies: rebuild when any header changes
HDRS := $(wildcard $(SRC_DIR)/include/*.h $(SRC_DIR)/include/kasld/*.h \
                    $(SRC_DIR)/include/kasld/arch/*.h)

# Detect zlib (optional, for native gzip decompression in proc_config) and
# pthread (optional, for the parallel inference worker pool in the orchestrator).
# Guarded by kasld_compiling so non-compiling goals (clean/help/uninstall) do not
# fork the compiler to link these probe programs.
ifdef kasld_compiling
HAVE_ZLIB := $(shell echo 'int main(void){return 0;}' | $(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -xc - -lz -o /dev/null 2>/dev/null && echo 1)
HAVE_PTHREAD := $(shell echo 'int main(void){return 0;}' | $(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -xc - -lpthread -o /dev/null 2>/dev/null && echo 1)
endif

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
KASLD_BIN      := $(ARCH_DIR)/kasld

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

# cc-component <cmd...>: compile one leak component. One line per component.
# The compiler's output is captured so ordering is fully controlled, and the
# outcome decides what prints:
#   - Arch-gate `#error "Architecture is not supported"` (and nothing else):
#     print one "  SKIP <path> (architecture-gated)" line and drop a
#     non-executable stamp at $@. The source explicitly opts out for this arch,
#     so it is not a failure — and the stamp makes the target up-to-date, so the
#     (always-failing) compile is not re-run on the next build and an
#     already-built tree stays silent. The orchestrator only runs executable
#     regular files, so the stamp is invisible to it.
#   - Success: print one "  CC   <path>" line.
#   - Any other diagnostics (warnings, or a real error): print the "  CC <path>"
#     line and the captured output together in one write, so the diagnostic is
#     always attributed to its component. A real failure is NOT stamped, so a
#     genuine breakage keeps surfacing on every build instead of being memoised.
# The recipe always exits 0 so one broken component never halts the wider build.
# Under V=1 the raw command is echoed and run directly (error ignored via the
# leading '-'), so the full invocation is visible.
ifeq ($(V),1)
define cc-component
	-$(1)
endef
else
define cc-component
	@out=$$($(1) 2>&1); st=$$?; \
	if [ $$st -ne 0 ] && printf '%s' "$$out" | grep -q '#error.*Architecture is not supported'; then \
	  printf '  $(C_SKIP)%-5s$(C_RST) %s (architecture-gated)\n' SKIP '$(call disp,$@)'; \
	  : > '$@'; \
	elif [ -n "$$out" ]; then \
	  printf '  $(C_TAG)%-5s$(C_RST) %s\n%s\n' CC '$(call disp,$@)' "$$out" >&2; \
	else \
	  printf '  $(C_TAG)%-5s$(C_RST) %s\n' CC '$(call disp,$@)'; \
	fi
endef
endif

PREFIX ?= /usr/local

.PHONY: all
all : build

# Create build directories (order-only prerequisites). mkdir -p also creates the
# parent $(ARCH_DIR), so making obj/ or components/ brings the arch dir with it.
$(COMP_DIR):
	@echo "Building $(call disp,$(ARCH_DIR)) ..."
	@mkdir -p "$(COMP_DIR)"

$(OBJ_DIR):
	@mkdir -p "$(OBJ_DIR)"

$(TEST_OBJ_DIR):
	@mkdir -p "$(TEST_OBJ_DIR)"

# Validate headers before building components
.PHONY: check-headers
check-headers: | $(COMP_DIR)
	$(Q)$(CC) $(ALL_CFLAGS) -xc -fsyntax-only $(SRC_DIR)/include/kasld/api.h

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

$(COMP_DIR)/prefetch_directmap: $(COMP_SRC_DIR)/prefetch_directmap.c $(HDRS) | $(COMP_DIR)
	$(call cc-component, $(CC) $(ALL_CFLAGS) -O0 $(ALL_LDFLAGS) -I$(SRC_DIR) $< -o $@)

$(COMP_DIR)/zombieload: $(COMP_SRC_DIR)/zombieload.c $(HDRS) | $(COMP_DIR)
	$(call cc-component, $(CC) $(ALL_CFLAGS) -O0 $(ALL_LDFLAGS) -I$(SRC_DIR) $< -o $@)

# kernelsnitch: needs -lpthread (uses default -O2 for hash timing performance)
$(COMP_DIR)/kernelsnitch: $(COMP_SRC_DIR)/kernelsnitch.c $(HDRS) | $(COMP_DIR)
	$(call cc-component, $(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $< $(PTHREAD_LIBS) -o $@)

.PHONY: build
build : check-headers $(BIN_FILES) $(KASLD_BIN)

$(OBJ_DIR)/orchestrator.o: $(KASLD_SRC) $(HDRS) | $(OBJ_DIR)
	$(call ccv,CC,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(PTHREAD_CFLAGS) -DVERSION='"$(VERSION)"' -c $< -o $@

$(OBJ_DIR)/render.o: $(RENDER_SRC) $(HDRS) | $(OBJ_DIR)
	$(call ccv,CC,$@)
	$(Q)$(CC) $(ALL_CFLAGS) -DVERSION='"$(VERSION)"' -I$(SRC_DIR) -c $< -o $@

# Per-mode render translation units (src/render/<mode>.c). Each gets its own
# object so editing one mode does not force the others to recompile.
$(OBJ_DIR)/render_%.o: $(SRC_DIR)/render/%.c $(HDRS) | $(OBJ_DIR)
	$(call ccv,CC,$@)
	$(Q)$(CC) $(ALL_CFLAGS) -DVERSION='"$(VERSION)"' -I$(SRC_DIR) -c $< -o $@

$(OBJ_DIR)/region_info.o: $(REGIONS_SRC) $(HDRS) | $(OBJ_DIR)
	$(call ccv,CC,$@)
	$(Q)$(CC) $(ALL_CFLAGS) -c $< -o $@

# Engine core (estimate/quantities/evidence/engine) and ported rules.
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(HDRS) | $(OBJ_DIR)
	$(call ccv,CC,$@)
	$(Q)$(CC) $(ALL_CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(OBJ_DIR)/rule_%.o: $(SRC_DIR)/rules/%.c $(HDRS) | $(OBJ_DIR)
	$(call ccv,CC,$@)
	$(Q)$(CC) $(ALL_CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(KASLD_BIN): $(OBJ_DIR)/orchestrator.o $(OBJ_DIR)/render.o $(RENDER_MODE_OBJS) $(OBJ_DIR)/region_info.o $(ENGINE_OBJS) | $(OBJ_DIR)
	$(call ccv,LD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) $^ $(PTHREAD_LIBS) -o $@

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
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) $(PTHREAD_CFLAGS) -DKASLD_TESTING -I$(SRC_DIR) $(TEST_DIR)/test_kasld.c $(PTHREAD_LIBS) -o $@

# Renderer unit tests (split from test_kasld.c). Same single-TU model — it
# #includes the orchestrator + render translation units directly, hence
# -DKASLD_TESTING + the pthread flags — but exercises render.c / render/*.c.
TEST_RENDER_BIN := $(TEST_OBJ_DIR)/test_render

$(TEST_RENDER_BIN): $(TEST_DIR)/test_render.c $(KASLD_SRC) $(RENDER_SRC) $(RENDER_MODE_SRCS) $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) $(PTHREAD_CFLAGS) -DKASLD_TESTING -I$(SRC_DIR) $(TEST_DIR)/test_render.c $(PTHREAD_LIBS) -o $@

# Estimate-core test (Stage A): standalone, links only estimate.c + quantities.c.
TEST_EST_BIN := $(TEST_OBJ_DIR)/test_estimate

$(TEST_EST_BIN): $(TEST_DIR)/test_estimate.c $(ESTIMATE_SRC) $(QUANTITIES_SRC) $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_estimate.c $(ESTIMATE_SRC) $(QUANTITIES_SRC) -o $@

# Evidence-store test (Stage B): standalone, links only evidence.c.
TEST_EV_BIN := $(TEST_OBJ_DIR)/test_evidence

$(TEST_EV_BIN): $(TEST_DIR)/test_evidence.c $(EVIDENCE_SRC) $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_evidence.c $(EVIDENCE_SRC) -o $@

# Align-helper test (header-only): exercises kasld_floor_text_base() and its
# pure core against every arch's sub-offset on the host. No .c sources to link.
TEST_ALIGN_BIN := $(TEST_OBJ_DIR)/test_align

$(TEST_ALIGN_BIN): $(TEST_DIR)/test_align.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_align.c -o $@

# Prefetch scan edge-detection test (header-only): drives
# prefetch_scan_find_edge() with synthetic timing profiles. The x86_64-only
# header makes the suite inert on other hosts. No .c sources to link.
TEST_PREFETCH_SCAN_BIN := $(TEST_OBJ_DIR)/test_prefetch_scan

$(TEST_PREFETCH_SCAN_BIN): $(TEST_DIR)/test_prefetch_scan.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_prefetch_scan.c -o $@

# pin_cpu() cpuset-aware affinity test (header-only, x86_64-only cpu.h; inert
# elsewhere). No .c sources to link.
TEST_CPU_BIN := $(TEST_OBJ_DIR)/test_cpu

$(TEST_CPU_BIN): $(TEST_DIR)/test_cpu.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_cpu.c -o $@

# Component outcome classifier test (header-only): exercises
# kasld_classify_outcome() (outcome.h) — the reaped-status -> outcome mapping,
# incl. the SIGSYS-denial and exit-77/69 paths. No .c sources to link.
TEST_OUTCOME_BIN := $(TEST_OBJ_DIR)/test_outcome

$(TEST_OUTCOME_BIN): $(TEST_DIR)/test_outcome.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_outcome.c -o $@

# seccomp-exec: installs a minimal seccomp-BPF filter then execs its argv, so
# tests/container/run can run kasld under a container-shaped syscall gate
# (perf_event_open → EPERM or SIGSYS) without a container runtime. Standalone
# helper, no kasld sources to link.
SECCOMP_EXEC_BIN := $(TEST_OBJ_DIR)/seccomp-exec

$(SECCOMP_EXEC_BIN): $(TEST_DIR)/container/seccomp-exec.c | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) $(TEST_DIR)/container/seccomp-exec.c -o $@

# fork-fail.so: LD_PRELOAD shim that fails a fraction of fork() calls with
# EAGAIN, so tests/container/run can verify kasld stays coherent under a pids
# cgroup limit (docker --pids-limit / k8s pids.max) without a real cgroup.
FORK_FAIL_LIB := $(TEST_OBJ_DIR)/fork-fail.so

$(FORK_FAIL_LIB): $(TEST_DIR)/container/fork-fail.c | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) -O2 -fPIC -shared $(TEST_DIR)/container/fork-fail.c -o $@ -ldl

# Text-order classifier test (header-only): exercises classify_text_order().
TEST_TEXT_ORDER_BIN := $(TEST_OBJ_DIR)/test_text_order

$(TEST_TEXT_ORDER_BIN): $(TEST_DIR)/test_text_order.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_text_order.c -o $@

# Kernel image-size readers test (header-only): exercises the Image header / ELF
# / System.map / gzip-ISIZE parsers in kasld/kernel_image.h against crafted
# fixtures under a temporary KASLD_SYSROOT. No .c sources to link.
TEST_KIMG_BIN := $(TEST_OBJ_DIR)/test_kernel_image

$(TEST_KIMG_BIN): $(TEST_DIR)/test_kernel_image.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_kernel_image.c -o $@

# Engine test (Stage C/D): links the engine core + ALL ported rules. Linking the
# whole rules/ wildcard (rather than a hand-maintained subset) means adding a
# rule + its test needs no Makefile edit, and a rule can never be silently left
# out of the test build. Unreferenced rules just link unused.
TEST_ENG_BIN := $(TEST_OBJ_DIR)/test_engine

$(TEST_ENG_BIN): $(TEST_DIR)/test_engine.c $(ENGINE_CORE) $(RULE_SRCS) $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_engine.c $(ENGINE_CORE) $(RULE_SRCS) -o $@

# Integration test: the FULL production rule registry (engine_rules.c + every
# rules/*.c) against leak-bearing synthetic evidence.
TEST_INT_BIN := $(TEST_OBJ_DIR)/test_engine_integration
$(TEST_INT_BIN): $(TEST_DIR)/test_engine_integration.c $(ENGINE_CORE) $(ENGINE_RULES_SRC) $(RULE_SRCS) $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_engine_integration.c $(ENGINE_CORE) $(ENGINE_RULES_SRC) $(RULE_SRCS) -o $@

# Component parser test: dmesg_mem_init_kernel_layout's layout-dump parser,
# exercised by #including the component (its main renamed). No extra link inputs
# — the component pulls its helpers from headers.
TEST_DMESG_BIN := $(TEST_OBJ_DIR)/test_dmesg_layout
$(TEST_DMESG_BIN): $(TEST_DIR)/test_dmesg_layout.c $(SRC_DIR)/components/dmesg_mem_init_kernel_layout.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_dmesg_layout.c -o $@

# BTF reader parser test: btf_struct_page_size's struct-size parser, exercised
# by #including the component (its main renamed) against hand-built BTF blobs.
TEST_BTF_BIN := $(TEST_OBJ_DIR)/test_btf
$(TEST_BTF_BIN): $(TEST_DIR)/test_btf.c $(SRC_DIR)/components/btf_struct_page_size.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_btf.c -o $@

# dmesg_backtrace block parser: #includes the component (main renamed), driven
# over a staged KASLD_SYSROOT /var/log/dmesg covering the CR3 context tagging.
TEST_BACKTRACE_BIN := $(TEST_OBJ_DIR)/test_dmesg_backtrace
$(TEST_BACKTRACE_BIN): $(TEST_DIR)/test_dmesg_backtrace.c $(SRC_DIR)/components/dmesg_backtrace.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_dmesg_backtrace.c -o $@

# proc_net_sock_ptr hashed-pointer rejection: the component is #included (main
# renamed) so its classify_sock_ptr() is unit-tested, and it is driven over a
# staged KASLD_SYSROOT /proc/net/unix to assert the batch-decline + real-emit.
TEST_SOCKPTR_BIN := $(TEST_OBJ_DIR)/test_proc_net_sock_ptr
$(TEST_SOCKPTR_BIN): $(TEST_DIR)/test_proc_net_sock_ptr.c $(SRC_DIR)/components/proc_net_sock_ptr.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_proc_net_sock_ptr.c -o $@

# proc_timer_list hashed-pointer rejection: same slab/pointer-alignment gate as
# proc_net_sock_ptr, unit-tested (classify_timer_base) + staged /proc/timer_list.
TEST_TIMERLIST_BIN := $(TEST_OBJ_DIR)/test_proc_timer_list
$(TEST_TIMERLIST_BIN): $(TEST_DIR)/test_proc_timer_list.c $(SRC_DIR)/components/proc_timer_list.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_proc_timer_list.c -o $@

# dmesg physical-reservation parsers: the four restructured components
# (reserved_mem / swiotlb / crashkernel / cma) #included (main renamed) and
# driven over a staged KASLD_SYSROOT /var/log/dmesg; asserts per-region ranges.
TEST_DMESG_RESV_SRCS := $(SRC_DIR)/components/dmesg_reserved_mem.c \
	$(SRC_DIR)/components/dmesg_swiotlb.c \
	$(SRC_DIR)/components/dmesg_crashkernel.c \
	$(SRC_DIR)/components/dmesg_cma_reserved.c
TEST_DMESG_RESV_BIN := $(TEST_OBJ_DIR)/test_dmesg_reservations
$(TEST_DMESG_RESV_BIN): $(TEST_DIR)/test_dmesg_reservations.c $(TEST_DMESG_RESV_SRCS) $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_dmesg_reservations.c -o $@

# boot_params_e820 RAM-covering test: the component #included (main renamed) and
# driven over a staged KASLD_SYSROOT zero-page; asserts the per-RAM-entry extents.
TEST_BPE820_BIN := $(TEST_OBJ_DIR)/test_boot_params_e820
$(TEST_BPE820_BIN): $(TEST_DIR)/test_boot_params_e820.c $(SRC_DIR)/components/boot_params_e820.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_boot_params_e820.c -o $@

# proc_kcore ELF program-header scan: the component #included (main renamed) and
# driven over a staged KASLD_SYSROOT /proc/kcore; the only coverage of the parse
# (the live component is CAP_SYS_RAWIO-gated, so it is dark in the fixtures).
TEST_KCORE_BIN := $(TEST_OBJ_DIR)/test_kcore
$(TEST_KCORE_BIN): $(TEST_DIR)/test_kcore.c $(SRC_DIR)/components/proc_kcore.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_kcore.c -o $@

# sysfs / ACPI / DT leak-parser tests: each component #included (main renamed)
# and driven over a staged KASLD_SYSROOT fixture tree reproducing the kernel ABI.
TEST_PARSERS_SRCS := $(SRC_DIR)/components/sysfs_efi_runtime_map.c \
	$(SRC_DIR)/components/acpi_mrrm.c \
	$(SRC_DIR)/components/sysfs_cbmem_address.c \
	$(SRC_DIR)/components/sysfs_cxl_region.c \
	$(SRC_DIR)/components/sysfs_qcom_rmtfs_mem.c \
	$(SRC_DIR)/components/sysfs_iommu_reserved_regions.c \
	$(SRC_DIR)/components/sysfs_devicetree_elfcorehdr.c \
	$(SRC_DIR)/components/sysfs_nd_region.c \
	$(SRC_DIR)/components/sysfs_uio_map.c \
	$(SRC_DIR)/components/sysfs_iscsi_transport_handle.c \
	$(SRC_DIR)/components/sysfs_devicetree_mmio.c \
	$(SRC_DIR)/components/sysfs_pci_resource.c \
	$(SRC_DIR)/components/tracefs_printk_formats.c \
	$(SRC_DIR)/components/sysfs_devicetree_reserved_memory.c
TEST_PARSERS_BIN := $(TEST_OBJ_DIR)/test_sysfs_parsers
$(TEST_PARSERS_BIN): $(TEST_DIR)/test_sysfs_parsers.c $(TEST_PARSERS_SRCS) $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_sysfs_parsers.c -o $@

.PHONY: test
test : $(TEST_BIN) $(TEST_RENDER_BIN) $(TEST_EST_BIN) $(TEST_EV_BIN) $(TEST_ALIGN_BIN) $(TEST_PREFETCH_SCAN_BIN) $(TEST_CPU_BIN) $(TEST_OUTCOME_BIN) $(TEST_TEXT_ORDER_BIN) $(TEST_KIMG_BIN) $(TEST_ENG_BIN) $(TEST_INT_BIN) $(TEST_DMESG_BIN) $(TEST_BACKTRACE_BIN) $(TEST_SOCKPTR_BIN) $(TEST_TIMERLIST_BIN) $(TEST_BTF_BIN) $(TEST_DMESG_RESV_BIN) $(TEST_BPE820_BIN) $(TEST_PARSERS_BIN) $(TEST_KCORE_BIN)
	@$(TEST_DIR)/run-all
	@$(MAKE) --no-print-directory lint

# Static guards ("lint"): source-invariant greps, the 32-bit narrowing check,
# and shellcheck over all shipped shell scripts (extra/ + tests/) — no compiled
# unit-test binaries. Run after the unit tests by `make test`, and standalone by
# `make lint`. Each guard exits non-zero on failure; make halts on the first.
.PHONY: lint
lint :
	@$(TEST_DIR)/check-rule-registry
	@$(TEST_DIR)/check-self-edges
	@$(TEST_DIR)/check-extent-callers
	@$(TEST_DIR)/check-truncation
	@$(TEST_DIR)/check-component-output
	@$(TEST_DIR)/check-component-meta
	@$(TEST_DIR)/check-live-probes
	@$(TEST_DIR)/check-text-floor
	@$(TEST_DIR)/check-text-region
	@$(TEST_DIR)/check-confidence-floor
	@$(TEST_DIR)/check-image-size
	@$(TEST_DIR)/check-fdt-unflatten
	@$(TEST_DIR)/check-shellcheck
	@$(TEST_DIR)/hardening-fixtures
	@$(TEST_DIR)/cli-flags

.PHONY: test-integration
test-integration : $(TEST_INT_BIN)
	$(TEST_INT_BIN)

# Container / cgroup execution harness (opt-in: snapshots the live host and runs
# live cpuset probes, so it is not part of the hermetic `make test`). The x86_32
# coupled-arch soundness case needs the i686 cross binary (`make cross`); it
# skips cleanly if absent.
.PHONY: test-container
test-container : build $(SECCOMP_EXEC_BIN) $(FORK_FAIL_LIB)
	@SECCOMP_EXEC=$(SECCOMP_EXEC_BIN) FORK_FAIL_LIB=$(FORK_FAIL_LIB) $(TEST_DIR)/container/run

.PHONY: test-estimate
test-estimate : $(TEST_EST_BIN)
	$(TEST_EST_BIN)

.PHONY: test-evidence
test-evidence : $(TEST_EV_BIN)
	$(TEST_EV_BIN)

.PHONY: test-dmesg-layout
test-dmesg-layout : $(TEST_DMESG_BIN)
	$(TEST_DMESG_BIN)

.PHONY: test-btf
test-btf : $(TEST_BTF_BIN)
	$(TEST_BTF_BIN)

.PHONY: test-dmesg-reservations
test-dmesg-reservations : $(TEST_DMESG_RESV_BIN)
	$(TEST_DMESG_RESV_BIN)

.PHONY: test-boot-params-e820
test-boot-params-e820 : $(TEST_BPE820_BIN)
	$(TEST_BPE820_BIN)

.PHONY: test-sysfs-parsers
test-sysfs-parsers : $(TEST_PARSERS_BIN)
	$(TEST_PARSERS_BIN)

# Cross-architecture engine test: runs the integration test under qemu-user for
# each 64-bit target (exercises arch-gated rules on their arch). Needs the
# musl-cross toolchains on PATH + qemu-user in QEMU_DIR;
# silently skips any target whose toolchain/qemu is absent. Not part of `make
# test` (host-only, no qemu dependency).
.PHONY: test-cross
test-cross :
	$(TEST_DIR)/test-cross

# Offline soundness gate: run extra/validate-bundle over the truth-bearing
# fixtures (meta anonymized: 0) and assert the resolved window contains the real
# base. Standalone (needs jq, the per-arch binaries from `make cross`, and
# qemu-user in QEMU_DIR for foreign arches) — the reproducible, boot-free
# complement to tests/vm/run.
.PHONY: test-fixtures
test-fixtures :
	$(TEST_DIR)/validate-fixtures

# Truth-free complement: assert the GUARANTEED window does not move when a
# fakeable input (MemTotal/LowTotal) is shrunk, across the WHOLE fixture corpus
# (incl. anonymized) — catches the "container-faked value reaches the guaranteed
# window" class on every coupled arch, not just the truth-bearing captures.
.PHONY: test-fixtures-perturb
test-fixtures-perturb :
	$(TEST_DIR)/validate-fixtures --perturb

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
FUZZ_TARGETS := fuzz_parse_hex fuzz_capture_result fuzz_capture_scalar fuzz_parse_meta fuzz_btf
FUZZ_BINS    := $(addprefix $(FUZZ_OUT)/,$(FUZZ_TARGETS))

$(FUZZ_OUT)/% : tests/fuzz/%.c
	@mkdir -p "$(FUZZ_OUT)"
	$(call ccv,CCLD,$@)
	$(Q)$(FUZZ_CC) $(FUZZ_CFLAGS) "$<" -o "$@"

.PHONY: fuzz
fuzz : $(FUZZ_BINS)
	@echo "Fuzz harnesses built in $(FUZZ_OUT)."
	@echo "Run e.g.: $(FUZZ_OUT)/fuzz_capture_result tests/fuzz/corpus/capture_result/"


.PHONY: clean
clean :
	@echo "Cleaning $(call disp,$(BUILD_DIR)) ..."
	@rm -rf "$(BUILD_DIR)"


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
	install -m 755 extra/ksymoff "$(DESTDIR)$(PREFIX)/bin/ksymoff"
	install -d "$(DESTDIR)$(PREFIX)/libexec/kasld"
	@# Install only real component binaries. Arch-gated components leave a
	@# non-executable stamp at their target path (so make treats them as
	@# up-to-date and does not re-run the failing compile); the -x test keeps
	@# those stamps out of the install tree.
	for f in $(COMP_DIR)/*; do \
	  [ -x "$$f" ] || continue; \
	  install -m 755 "$$f" "$(DESTDIR)$(PREFIX)/libexec/kasld/"; \
	done
	install -d "$(DESTDIR)$(PREFIX)/share/doc/kasld"
	cp -R docs README.md LICENSE "$(DESTDIR)$(PREFIX)/share/doc/kasld/"

.PHONY: uninstall
uninstall :
	rm -f "$(DESTDIR)$(PREFIX)/bin/kasld"
	rm -f "$(DESTDIR)$(PREFIX)/bin/ksymoff"
	rm -rf "$(DESTDIR)$(PREFIX)/libexec/kasld"
	rm -rf "$(DESTDIR)$(PREFIX)/share/doc/kasld"


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
	@echo "      cross           Cross-compile for all supported architectures"
	@echo "      coverage        Host unit-test coverage report (gcov)"
	@echo "      coverage-e2e    End-to-end coverage over x86 fixtures (gcov)"
	@echo "      install         Install to PREFIX (default: /usr/local)"
	@echo "      uninstall       Remove installed files"
	@echo "      clean           Remove build directory"
	@echo
	@echo "  Test targets:"
	@echo "      test                   Build and run the unit suite + lint"
	@echo "      check                  Alias for test"
	@echo "      lint                   Static guards (shellcheck, self-edge, floors, ...)"
	@echo "      test-integration       End-to-end integration test"
	@echo "      test-cross             Arch-gated engine tests under qemu-user (QEMU_DIR)"
	@echo "      test-fixtures          Offline soundness: resolved window contains truth"
	@echo "      test-fixtures-perturb  Truth-free soundness: window stable vs faked container inputs"
	@echo "      test-container         Container/cgroup execution checks (live; seccomp/ns/cpuset)"
	@echo
	@echo "  Options:"
	@echo "      CC=compiler     Compiler executable"
	@echo "      CFLAGS=flags    Compiler flags"
	@echo "      LDFLAGS=flags   Linker flags"
	@echo "      PREFIX=path     Install prefix (default: /usr/local)"
	@echo "      V=1             Verbose build (show full command lines)"
	@echo "      COLOR=1|0       Force colored tags on/off (default: auto by tty)"
	@echo
