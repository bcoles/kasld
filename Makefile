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
    -Wold-style-definition -Wredundant-decls -Wformat=2 \
    -Wbad-function-cast -Wfloat-equal -Wnested-externs \
    -Wnull-dereference -Wlogical-op -Wduplicated-cond \
    -Wduplicated-branches -Wrestrict -Wvla -Walloca \
    -Wstack-protector \
    -Werror=implicit-function-declaration \
    -Werror=incompatible-pointer-types \
    -Werror=return-type \
    -Werror=format-security \
    -Werror=format \
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

# Appended, not substituted: a caller adding a flag for one target must not have
# to restate CFLAGS and lose the warning and hardening sets with it. `make cross`
# uses these to carry a per-triple requirement.
EXTRA_CFLAGS =
EXTRA_LDFLAGS =

ALL_CFLAGS = -std=c99 $(CFLAGS) $(EXTRA_CFLAGS) $(KASLD_WARN_FLAGS) $(KASLD_HARDEN_FLAGS)
LDFLAGS =
ALL_LDFLAGS = $(LDFLAGS) $(EXTRA_LDFLAGS)

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

# Target triple ($(CC)) vs. the host's native triple. When they differ the build
# is a cross-compile, so link static — the target loader/libs are not on this host.
# $(_ARCH) also names the per-arch build subdirectory. The native triple comes
# from a native compiler, not from $(CC) (which may itself be a cross compiler):
# try `cc`, then gcc/clang, so a host with no `cc` symlink does not misread a
# native build as cross (and add a spurious -static) or print `cc: not found`.
HOST_ARCH := $(shell cc -dumpmachine 2>/dev/null || gcc -dumpmachine 2>/dev/null || clang -dumpmachine 2>/dev/null)
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
# Cross-build dependencies, one prefix per target triple (see cross-deps).
# Defined here rather than beside that target because the proc_config rule
# expands it far earlier in this file, and a prerequisite is expanded when the
# rule is read.
DEPS_DIR := $(BUILD_DIR)/deps
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
# What components said, recorded verbatim: the wire parsers and the three
# evidence stores they file into. Its own translation unit because it is the
# only code that touches untrusted component output, and a fuzz harness should
# be able to reach it without compiling the orchestrator around it.
CAPTURE_SRC    := $(SRC_DIR)/capture.c
# What left the pipeline, and why. Its own translation unit because it is a leaf
# every layer writes to -- the orchestrator's buffers directly, the engine's caps
# projected in after the run -- and because a reader of the ledger should not
# have to take the orchestrator with it.
DISCARD_SRC    := $(SRC_DIR)/discard.c
# What a component declares about itself, read out of its own binary. Its own
# translation unit because reading a declaration is not running a component:
# it takes no lock and holds no state, so a caller that only wants to know what
# a component claims does not compile the orchestrator to find out.
META_SRC       := $(SRC_DIR)/meta.c
# The observing environment (hardening settings + this process's vantage).
# Its own translation unit because it answers a different question from the
# rest: what can be seen from here, rather than where the kernel is.
ENV_SRC        := $(SRC_DIR)/environment.c
RENDER_SRC     := $(SRC_DIR)/render.c
# The report model: one finished description of a run, built from the engine and
# consumed by every format. Its own translation unit because it is neither the
# engine nor a renderer -- it is the seam between them, and the only place that
# decides what a run reports.
REPORT_SRC     := $(SRC_DIR)/report.c
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
# The sources a whole-program test reaches by #including orchestrator.c: the
# lattice, the quantity table, the region table and the report builder. Named as
# a group because two test binaries pull in all four, and a rule that lists the
# orchestrator without them relinks on an orchestrator edit but not on a change
# to what the orchestrator calls -- leaving a test that passes against code that
# is no longer there. tests/check-make-deps holds every such rule to this.
ENGINE_MODEL_SRCS := $(ESTIMATE_SRC) $(QUANTITIES_SRC) $(REGIONS_SRC) \
                     $(REPORT_SRC)

ENGINE_CORE      := $(ESTIMATE_SRC) $(QUANTITIES_SRC) $(EVIDENCE_SRC) $(ENGINE_SRC)
ENGINE_CORE_SRCS := $(ENGINE_CORE) $(ENGINE_RULES_SRC)
ENGINE_OBJS      := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(ENGINE_CORE_SRCS)) \
                    $(patsubst $(SRC_DIR)/rules/%.c,$(OBJ_DIR)/rule_%.o,$(RULE_SRCS))

# Leak components: standalone binaries in src/components/
COMP_SRC_DIR := $(SRC_DIR)/components
SRC_FILES := $(wildcard $(COMP_SRC_DIR)/*.c)
BIN_FILES := $(patsubst $(COMP_SRC_DIR)/%.c,$(COMP_DIR)/%,$(SRC_FILES))

# Side-channel components opt out of optimization by carrying the marker
# KASLD_BUILD_NO_OPTIMIZE in their source header; they are discovered by grep so
# adding one needs no Makefile edit (matching the drop-in component model). The
# same list feeds the build rule below and `make print-deps`. Whole-file -O0 is
# deliberate: it reliably stops the optimizer reordering or eliding the
# rdtsc/mfence timing loops, which a per-function attribute does not guarantee
# (gcc's optimize attribute is documented debugging-only).
SIDECHANNEL_COMPONENTS := $(patsubst $(COMP_SRC_DIR)/%.c,%,\
    $(shell grep -l KASLD_BUILD_NO_OPTIMIZE $(COMP_SRC_DIR)/*.c 2>/dev/null))
SIDECHANNEL_BINS := $(addprefix $(COMP_DIR)/,$(SIDECHANNEL_COMPONENTS))

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
#   - A real failure also REMOVES the target. The build still does not halt, but
#     a broken component becomes absent rather than stale: whatever runs it next
#     fails loudly instead of silently exercising the last binary that compiled.
#     Without this a component can fail to build while `make` reports success and
#     the previous binary keeps being tested, which is indistinguishable from the
#     edit having worked.
ifeq ($(V),1)
define cc-component
	-$(1) || rm -f '$@'
endef
else
define cc-component
	@out=$$($(1) 2>&1); st=$$?; \
	if [ $$st -ne 0 ] && printf '%s' "$$out" | grep -q '#error.*Architecture is not supported'; then \
	  printf '  $(C_SKIP)%-5s$(C_RST) %s (architecture-gated)\n' SKIP '$(call disp,$@)'; \
	  : > '$@'; \
	elif [ -n "$$out" ]; then \
	  printf '  $(C_TAG)%-5s$(C_RST) %s\n%s\n' CC '$(call disp,$@)' "$$out" >&2; \
	  [ $$st -eq 0 ] || rm -f '$@'; \
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

# Validate headers before building components. -Wno-unused-function because the
# point of this check is to compile the header as a translation unit of its own,
# where every static inline it defines is unused by construction; the check stays
# live for every real compile.
.PHONY: check-headers
check-headers: | $(COMP_DIR)
	$(Q)$(CC) $(ALL_CFLAGS) -Wno-unused-function -xc -fsyntax-only \
	    $(SRC_DIR)/include/kasld/api.h

$(COMP_DIR)/%: $(COMP_SRC_DIR)/%.c $(HDRS) | $(COMP_DIR)
	$(call cc-component, $(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $< -o $@)

# Offset-table components #include a generated offsets/<name>.inc; add it as a
# prerequisite (the pattern rule above only sees the .c + $(HDRS)) so a regen
# rebuilds the component.
$(COMP_DIR)/bpf_verifier_ksym: $(COMP_SRC_DIR)/offsets/bpf_verifier_ksym.inc
$(COMP_DIR)/dmesg_ex_handler_msr: $(COMP_SRC_DIR)/offsets/dmesg_ex_handler_msr.inc
$(COMP_DIR)/entrybleed: $(COMP_SRC_DIR)/offsets/entrybleed.inc
$(COMP_DIR)/qemu_tcg_iret: $(COMP_SRC_DIR)/offsets/qemu_tcg_iret.inc

# proc_config: link with zlib when available for native gzip decompression.
#
# The cross-deps prefix is a prerequisite where it exists, so populating it
# rebuilds this component. Without that, gaining zlib changes which RULE applies
# and leaves the object alone: the build reports success while shipping the
# binary that shells out to zcat. $(wildcard) yields nothing when the prefix is
# absent, which is every host build and every cross build before cross-deps.
ZLIB_DEP := $(wildcard $(DEPS_DIR)/$(_ARCH)/lib/libz.a)
ifeq ($(HAVE_ZLIB),1)
$(COMP_DIR)/proc_config: $(COMP_SRC_DIR)/proc_config.c $(HDRS) $(ZLIB_DEP) | $(COMP_DIR)
	$(call cc-component, $(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) -DHAVE_ZLIB $< -lz -o $@)
endif

# Side-channel components: compile without optimization (-O0 overrides -O2).
# These rely on precise instruction ordering around timing measurements
# (rdtsc/rdtscp + mfence/lfence), speculative execution gadgets (asm goto),
# or Flush+Reload cache probing via volatile pointer accesses. The static
# pattern rule takes precedence over the generic $(COMP_DIR)/% rule above for
# the SIDECHANNEL_BINS (discovered by the KASLD_BUILD_NO_OPTIMIZE marker above).
# -U_FORTIFY_SOURCE drops the fortify define inherited from ALL_CFLAGS: it is a
# no-op at -O0 and glibc otherwise warns "_FORTIFY_SOURCE requires -O".
$(SIDECHANNEL_BINS): $(COMP_DIR)/%: $(COMP_SRC_DIR)/%.c $(HDRS) | $(COMP_DIR)
	$(call cc-component, $(CC) $(ALL_CFLAGS) -O0 -U_FORTIFY_SOURCE $(ALL_LDFLAGS) -I$(SRC_DIR) $< -o $@)

# kernelsnitch: needs -lpthread (uses default -O2 for hash timing performance)
$(COMP_DIR)/kernelsnitch: $(COMP_SRC_DIR)/kernelsnitch.c $(HDRS) | $(COMP_DIR)
	$(call cc-component, $(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $< $(PTHREAD_LIBS) -o $@)

.PHONY: build
build : check-headers $(BIN_FILES) $(KASLD_BIN)

# -I$(SRC_DIR) so the orchestrator can include the component-side fact headers
# (task_size.h and target_width.h use the same "include/kasld/..." form the
# components do).
$(OBJ_DIR)/orchestrator.o: $(KASLD_SRC) $(HDRS) | $(OBJ_DIR)
	$(call ccv,CC,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(PTHREAD_CFLAGS) -I$(SRC_DIR) -DVERSION='"$(VERSION)"' -c $< -o $@

$(OBJ_DIR)/discard.o: $(DISCARD_SRC) $(HDRS) | $(OBJ_DIR)
	$(call ccv,CC,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(PTHREAD_CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(OBJ_DIR)/meta.o: $(META_SRC) $(HDRS) | $(OBJ_DIR)
	$(call ccv,CC,$@)
	$(Q)$(CC) $(ALL_CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(OBJ_DIR)/capture.o: $(CAPTURE_SRC) $(HDRS) | $(OBJ_DIR)
	$(call ccv,CC,$@)
	$(Q)$(CC) $(ALL_CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(OBJ_DIR)/environment.o: $(ENV_SRC) $(HDRS) | $(OBJ_DIR)
	$(call ccv,CC,$@)
	$(Q)$(CC) $(ALL_CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(OBJ_DIR)/render.o: $(RENDER_SRC) $(HDRS) | $(OBJ_DIR)
	$(call ccv,CC,$@)
	$(Q)$(CC) $(ALL_CFLAGS) -DVERSION='"$(VERSION)"' -I$(SRC_DIR) -c $< -o $@

# Per-mode render translation units (src/render/<mode>.c). Each gets its own
# object so editing one mode does not force the others to recompile.
$(OBJ_DIR)/render_%.o: $(SRC_DIR)/render/%.c $(HDRS) | $(OBJ_DIR)
	$(call ccv,CC,$@)
	$(Q)$(CC) $(ALL_CFLAGS) -DVERSION='"$(VERSION)"' -I$(SRC_DIR) -c $< -o $@

$(OBJ_DIR)/report.o: $(REPORT_SRC) $(HDRS) | $(OBJ_DIR)
	$(call ccv,CC,$@)
	$(Q)$(CC) $(ALL_CFLAGS) -I$(SRC_DIR) -c $< -o $@

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

$(KASLD_BIN): $(OBJ_DIR)/orchestrator.o $(OBJ_DIR)/capture.o $(OBJ_DIR)/discard.o $(OBJ_DIR)/meta.o $(OBJ_DIR)/environment.o $(OBJ_DIR)/render.o $(OBJ_DIR)/report.o $(RENDER_MODE_OBJS) $(OBJ_DIR)/region_info.o $(ENGINE_OBJS) | $(OBJ_DIR)
	$(call ccv,LD,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) $^ $(PTHREAD_LIBS) -o $@

.PHONY: run
run : build
	$(KASLD_BIN)

# Unit tests
TEST_DIR := ./tests

# Test binaries carry the hermeticity probe: kasld_resolve records any kernel
# fact path resolved with no KASLD_SYSROOT set, and the harness fails the binary
# on it. A test that reads the machine it runs on is asserting against that
# machine's contents -- or against what that machine happens to lack, which its
# source does not reveal. Never set for a shipped build.
TEST_ALL_CFLAGS = $(ALL_CFLAGS) -DKASLD_HERMETIC_PROBE
TEST_BIN := $(TEST_OBJ_DIR)/test_kasld

# Unit tests of orchestrator internals (parsing, merge, anchor selection,
# render helpers). The orchestrator's main() and engine hooks are excluded
# under -DKASLD_TESTING; engine-rule coverage lives in test_engine* below.
# test_kasld.c #includes render.c and each src/render/*.c so the renderer's
# static helpers (e.g. json_print_escaped, section_consensus) are reachable
# without exporting them across the public API.
$(TEST_BIN): $(TEST_DIR)/test_kasld.c $(KASLD_SRC) $(CAPTURE_SRC) $(DISCARD_SRC) $(META_SRC) $(ENV_SRC) $(RENDER_SRC) $(RENDER_MODE_SRCS) $(ENGINE_MODEL_SRCS) $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) $(PTHREAD_CFLAGS) -DKASLD_TESTING -I$(SRC_DIR) $(TEST_DIR)/test_kasld.c $(PTHREAD_LIBS) -o $@

# Renderer unit tests (split from test_kasld.c). Same single-TU model — it
# #includes the orchestrator + render translation units directly, hence
# -DKASLD_TESTING + the pthread flags — but exercises render.c / render/*.c.
TEST_RENDER_BIN := $(TEST_OBJ_DIR)/test_render

$(TEST_RENDER_BIN): $(TEST_DIR)/test_render.c $(KASLD_SRC) $(CAPTURE_SRC) $(DISCARD_SRC) $(META_SRC) $(ENV_SRC) $(RENDER_SRC) $(RENDER_MODE_SRCS) $(ENGINE_MODEL_SRCS) $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) $(PTHREAD_CFLAGS) -DKASLD_TESTING -I$(SRC_DIR) $(TEST_DIR)/test_render.c $(PTHREAD_LIBS) -o $@

# Estimate-core test (Stage A): standalone, links only estimate.c + quantities.c.
TEST_EST_BIN := $(TEST_OBJ_DIR)/test_estimate

$(TEST_EST_BIN): $(TEST_DIR)/test_estimate.c $(ESTIMATE_SRC) $(QUANTITIES_SRC) $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_estimate.c $(ESTIMATE_SRC) $(QUANTITIES_SRC) -o $@

# Evidence-store test (Stage B): standalone, links only evidence.c.
TEST_EV_BIN := $(TEST_OBJ_DIR)/test_evidence

$(TEST_EV_BIN): $(TEST_DIR)/test_evidence.c $(EVIDENCE_SRC) $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_evidence.c $(EVIDENCE_SRC) -o $@

# Align-helper test (header-only): exercises kasld_floor_text_base() and its
# pure core against every arch's sub-offset on the host. No .c sources to link.
TEST_ALIGN_BIN := $(TEST_OBJ_DIR)/test_align

$(TEST_ALIGN_BIN): $(TEST_DIR)/test_align.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_align.c -o $@

# Address-parser test (header-only): drives kasld_addr_parse()'s refusal paths,
# deriving the too-wide inputs from the build's own word so the same source is a
# real overflow on the 32-bit cross targets. No .c sources to link.
TEST_ADDRP_BIN := $(TEST_OBJ_DIR)/test_addr_parse

$(TEST_ADDRP_BIN): $(TEST_DIR)/test_addr_parse.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_addr_parse.c -o $@

# TASK_SIZE probe test (header-only): drives the boundary search and gap
# detection in task_size.h with a synthetic address space (an injected step, no
# mmap), so the pure logic runs on any host. Covers the porous / untrusted paths
# a normal-kernel VM boot cannot reach. No .c sources to link.
TEST_TS_BIN := $(TEST_OBJ_DIR)/test_task_size

$(TEST_TS_BIN): $(TEST_DIR)/test_task_size.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_task_size.c -o $@

# Prefetch scan edge-detection test (header-only): drives
# prefetch_scan_find_edge() with synthetic timing profiles. The x86_64-only
# header makes the suite inert on other hosts. No .c sources to link.
TEST_PREFETCH_SCAN_BIN := $(TEST_OBJ_DIR)/test_prefetch_scan

$(TEST_PREFETCH_SCAN_BIN): $(TEST_DIR)/test_prefetch_scan.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_prefetch_scan.c -o $@

# pin_cpu() cpuset-aware affinity test (header-only, x86_64-only cpu.h; inert
# elsewhere). No .c sources to link.
TEST_CPU_BIN := $(TEST_OBJ_DIR)/test_cpu

$(TEST_CPU_BIN): $(TEST_DIR)/test_cpu.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_cpu.c -o $@

# Component outcome classifier test (header-only): exercises
# kasld_classify_outcome() (outcome.h) — the reaped-status -> outcome mapping,
# incl. the SIGSYS-denial and exit-77/69 paths. No .c sources to link.
TEST_OUTCOME_BIN := $(TEST_OBJ_DIR)/test_outcome

$(TEST_OUTCOME_BIN): $(TEST_DIR)/test_outcome.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_outcome.c -o $@

# seccomp-exec: installs a minimal seccomp-BPF filter then execs its argv, so
# tests/container/run can run kasld under a container-shaped syscall gate
# (perf_event_open → EPERM or SIGSYS) without a container runtime. Standalone
# helper, no kasld sources to link.
SECCOMP_EXEC_BIN := $(TEST_OBJ_DIR)/seccomp-exec

$(SECCOMP_EXEC_BIN): $(TEST_DIR)/container/seccomp-exec.c | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) $(TEST_DIR)/container/seccomp-exec.c -o $@

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
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_text_order.c -o $@

# Kernel image-size readers test (header-only): exercises the Image header / ELF
# / System.map / gzip-ISIZE parsers in kasld/kernel_image.h against crafted
# fixtures under a temporary KASLD_SYSROOT. No .c sources to link.
TEST_KIMG_BIN := $(TEST_OBJ_DIR)/test_kernel_image

$(TEST_KIMG_BIN): $(TEST_DIR)/test_kernel_image.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_kernel_image.c -o $@

# Engine test (Stage C/D): links the engine core + ALL ported rules. Linking the
# whole rules/ wildcard (rather than a hand-maintained subset) means adding a
# rule + its test needs no Makefile edit, and a rule can never be silently left
# out of the test build. Unreferenced rules just link unused.
TEST_ENG_BIN := $(TEST_OBJ_DIR)/test_engine

$(TEST_ENG_BIN): $(TEST_DIR)/test_engine.c $(ENGINE_CORE) $(RULE_SRCS) $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_engine.c $(ENGINE_CORE) $(RULE_SRCS) -o $@

# Integration test: the FULL production rule registry (engine_rules.c + every
# rules/*.c) against leak-bearing synthetic evidence.
TEST_INT_BIN := $(TEST_OBJ_DIR)/test_engine_integration
$(TEST_INT_BIN): $(TEST_DIR)/test_engine_integration.c $(ENGINE_CORE) $(ENGINE_RULES_SRC) $(RULE_SRCS) $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_engine_integration.c $(ENGINE_CORE) $(ENGINE_RULES_SRC) $(RULE_SRCS) -o $@

# Component parser test: dmesg_mem_init_kernel_layout's layout-dump parser,
# exercised by #including the component (its main renamed). No extra link inputs
# — the component pulls its helpers from headers.
TEST_DMESG_BIN := $(TEST_OBJ_DIR)/test_dmesg_layout
$(TEST_DMESG_BIN): $(TEST_DIR)/test_dmesg_layout.c $(SRC_DIR)/components/dmesg_mem_init_kernel_layout.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_dmesg_layout.c -o $@

# BTF reader parser test: btf_struct_page_size's struct-size parser, exercised
# by #including the component (its main renamed) against hand-built BTF blobs.
TEST_BTF_BIN := $(TEST_OBJ_DIR)/test_btf
$(TEST_BTF_BIN): $(TEST_DIR)/test_btf.c $(SRC_DIR)/components/btf_struct_page_size.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_btf.c -o $@

# dmesg_backtrace block parser: #includes the component (main renamed), driven
# over a staged KASLD_SYSROOT /var/log/dmesg covering the CR3 context tagging.
TEST_BACKTRACE_BIN := $(TEST_OBJ_DIR)/test_dmesg_backtrace
$(TEST_BACKTRACE_BIN): $(TEST_DIR)/test_dmesg_backtrace.c $(SRC_DIR)/components/dmesg_backtrace.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_dmesg_backtrace.c -o $@

# boot_config provenance: #includes the component (main renamed), driven over a
# staged KASLD_SYSROOT to assert keyed configs stay CONF_PARSED while the
# unkeyed /boot/config is demoted to CONF_HEURISTIC (and never shadows a keyed).
TEST_BOOTCFG_BIN := $(TEST_OBJ_DIR)/test_boot_config
$(TEST_BOOTCFG_BIN): $(TEST_DIR)/test_boot_config.c $(SRC_DIR)/components/boot_config.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_boot_config.c -o $@

# dmesg_kaslr_disabled classification: #includes the component (main renamed),
# driven over a staged KASLD_SYSROOT /var/log/dmesg to assert only whitelisted
# opt-out phrases pin to default and unrecognized lines emit nothing.
TEST_KASLRDIS_BIN := $(TEST_OBJ_DIR)/test_dmesg_kaslr_disabled
$(TEST_KASLRDIS_BIN): $(TEST_DIR)/test_dmesg_kaslr_disabled.c $(SRC_DIR)/components/dmesg_kaslr_disabled.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_dmesg_kaslr_disabled.c -o $@

# sysfs_devicetree_memory covering completeness: #includes the component (main
# renamed), driven over a staged KASLD_SYSROOT binary device tree to assert a
# complete map emits hull+extents, a buffer-filling reg withholds the map, and
# >64 banks falls back to hull-only.
TEST_DTMEM_BIN := $(TEST_OBJ_DIR)/test_sysfs_devicetree_memory
$(TEST_DTMEM_BIN): $(TEST_DIR)/test_sysfs_devicetree_memory.c $(SRC_DIR)/components/sysfs_devicetree_memory.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_sysfs_devicetree_memory.c -o $@

# proc_net_sock_ptr hashed-pointer rejection: the component is #included (main
# renamed) so its classify_sock_ptr() is unit-tested, and it is driven over a
# staged KASLD_SYSROOT /proc/net/unix to assert the batch-decline + real-emit.
TEST_SOCKPTR_BIN := $(TEST_OBJ_DIR)/test_proc_net_sock_ptr
$(TEST_SOCKPTR_BIN): $(TEST_DIR)/test_proc_net_sock_ptr.c $(SRC_DIR)/components/proc_net_sock_ptr.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_proc_net_sock_ptr.c -o $@

# ptdump_kernel_page_tables / kmemleak: each component is #included (main
# renamed) and driven over a staged KASLD_SYSROOT debugfs file to assert the
# page-table image-base recovery and the kmemleak direct-map witness.
TEST_PTDUMP_BIN := $(TEST_OBJ_DIR)/test_ptdump
$(TEST_PTDUMP_BIN): $(TEST_DIR)/test_ptdump.c $(SRC_DIR)/components/ptdump_kernel_page_tables.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_ptdump.c -o $@

TEST_KMEMLEAK_BIN := $(TEST_OBJ_DIR)/test_kmemleak
$(TEST_KMEMLEAK_BIN): $(TEST_DIR)/test_kmemleak.c $(SRC_DIR)/components/kmemleak.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_kmemleak.c -o $@

TEST_IOMEM_BIN := $(TEST_OBJ_DIR)/test_proc_iomem_kernel
$(TEST_IOMEM_BIN): $(TEST_DIR)/test_proc_iomem_kernel.c $(SRC_DIR)/components/proc_iomem_kernel.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_proc_iomem_kernel.c -o $@

TEST_ZFSDBG_BIN := $(TEST_OBJ_DIR)/test_zfs_dbgmsg
$(TEST_ZFSDBG_BIN): $(TEST_DIR)/test_zfs_dbgmsg.c $(SRC_DIR)/components/zfs_dbgmsg.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_zfs_dbgmsg.c -o $@

TEST_FWMEMMAP_BIN := $(TEST_OBJ_DIR)/test_sysfs_firmware_memmap
$(TEST_FWMEMMAP_BIN): $(TEST_DIR)/test_sysfs_firmware_memmap.c $(SRC_DIR)/components/sysfs_firmware_memmap.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_sysfs_firmware_memmap.c -o $@

TEST_MEMINFO_FACTS_BIN := $(TEST_OBJ_DIR)/test_meminfo_facts
$(TEST_MEMINFO_FACTS_BIN): $(TEST_DIR)/test_meminfo_facts.c $(SRC_DIR)/components/meminfo_facts.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_meminfo_facts.c -o $@

TEST_CPUINFO_FACTS_BIN := $(TEST_OBJ_DIR)/test_cpuinfo_facts
$(TEST_CPUINFO_FACTS_BIN): $(TEST_DIR)/test_cpuinfo_facts.c $(SRC_DIR)/components/cpuinfo_facts.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_cpuinfo_facts.c -o $@

TEST_FIRMWARE_MEMMAP_BIN := $(TEST_OBJ_DIR)/test_firmware_memmap
$(TEST_FIRMWARE_MEMMAP_BIN): $(TEST_DIR)/test_firmware_memmap.c $(SRC_DIR)/components/firmware_memmap.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_firmware_memmap.c -o $@

TEST_PROC_CPUINFO_BIN := $(TEST_OBJ_DIR)/test_proc_cpuinfo
$(TEST_PROC_CPUINFO_BIN): $(TEST_DIR)/test_proc_cpuinfo.c $(SRC_DIR)/components/proc_cpuinfo.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_proc_cpuinfo.c -o $@

TEST_ZONEINFO_BIN := $(TEST_OBJ_DIR)/test_proc_zoneinfo
$(TEST_ZONEINFO_BIN): $(TEST_DIR)/test_proc_zoneinfo.c $(SRC_DIR)/components/proc_zoneinfo.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_proc_zoneinfo.c -o $@

TEST_PROCMOD_BIN := $(TEST_OBJ_DIR)/test_proc_modules
$(TEST_PROCMOD_BIN): $(TEST_DIR)/test_proc_modules.c $(SRC_DIR)/components/proc_modules.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_proc_modules.c -o $@

TEST_MEMBLK_BIN := $(TEST_OBJ_DIR)/test_sysfs_memory_blocks
$(TEST_MEMBLK_BIN): $(TEST_DIR)/test_sysfs_memory_blocks.c $(SRC_DIR)/components/sysfs_memory_blocks.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_sysfs_memory_blocks.c -o $@

# proc_timer_list hashed-pointer rejection: same slab/pointer-alignment gate as
# proc_net_sock_ptr, unit-tested (classify_timer_base) + staged /proc/timer_list.
TEST_TIMERLIST_BIN := $(TEST_OBJ_DIR)/test_proc_timer_list
$(TEST_TIMERLIST_BIN): $(TEST_DIR)/test_proc_timer_list.c $(SRC_DIR)/components/proc_timer_list.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_proc_timer_list.c -o $@

# Build/target width check (header-only): the two mismatch signals and, mostly,
# the paths that must NOT report one. Driven over a staged KASLD_SYSROOT.
TEST_TWIDTH_BIN := $(TEST_OBJ_DIR)/test_target_width

$(TEST_TWIDTH_BIN): $(TEST_DIR)/test_target_width.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_target_width.c -o $@

# Kernel identity under KASLD_SYSROOT (header-only): release and version taken
# from a captured /proc/version, the environment override, and the fallbacks
# that must leave uname(2)'s own fields alone.
TEST_UNAME_BIN := $(TEST_OBJ_DIR)/test_uname

$(TEST_UNAME_BIN): $(TEST_DIR)/test_uname.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_uname.c -o $@

# proc_kallsyms masked-probe + address width: the kptr_restrict all-zero
# detection and the refusal of a symbol address wider than this build's word,
# over a staged /proc/kallsyms (main renamed).
TEST_KALLSYMS_BIN := $(TEST_OBJ_DIR)/test_proc_kallsyms
$(TEST_KALLSYMS_BIN): $(TEST_DIR)/test_proc_kallsyms.c $(SRC_DIR)/components/proc_kallsyms.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_proc_kallsyms.c -o $@

# tracefs_available_filter_addrs bounding + record skip + address width: the
# lowest/highest kernel-text witnesses, the __ftrace_invalid_address___ skip,
# and the refusal of an over-wide address, over a staged KASLD_SYSROOT
# available_filter_functions_addrs (main renamed).
TEST_AVAILFILTER_BIN := $(TEST_OBJ_DIR)/test_tracefs_available_filter_addrs
$(TEST_AVAILFILTER_BIN): $(TEST_DIR)/test_tracefs_available_filter_addrs.c $(SRC_DIR)/components/tracefs_available_filter_addrs.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_tracefs_available_filter_addrs.c -o $@

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
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_dmesg_reservations.c -o $@

# boot_params_e820 RAM-covering test: the component #included (main renamed) and
# driven over a staged KASLD_SYSROOT zero-page; asserts the per-RAM-entry extents.
TEST_BPE820_BIN := $(TEST_OBJ_DIR)/test_boot_params_e820
$(TEST_BPE820_BIN): $(TEST_DIR)/test_boot_params_e820.c $(SRC_DIR)/components/boot_params_e820.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_boot_params_e820.c -o $@

# boot_params_facts setup-header test: the component #included (main renamed) and
# driven over a staged KASLD_SYSROOT boot_params; asserts that a header the EFI
# stub synthesized yields no build-time fact, and that a copied one still does.
TEST_BPFACTS_BIN := $(TEST_OBJ_DIR)/test_boot_params_facts
$(TEST_BPFACTS_BIN): $(TEST_DIR)/test_boot_params_facts.c $(SRC_DIR)/components/boot_params_facts.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_boot_params_facts.c -o $@

# proc_kcore ELF program-header scan: the component #included (main renamed) and
# driven over a staged KASLD_SYSROOT /proc/kcore; the only coverage of the parse
# (the live component is CAP_SYS_RAWIO-gated, so it is dark in the fixtures).
# The report model builder. Pure data in, pure data out -- no engine, no
# renderer, no host -- so the test needs neither a staged sysroot nor a built
# component, and asserts invariants rather than agreement with any format.
TEST_REPORT_BIN := $(TEST_OBJ_DIR)/test_report
$(TEST_REPORT_BIN): $(TEST_DIR)/test_report.c $(REPORT_SRC) $(ESTIMATE_SRC) $(QUANTITIES_SRC) $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_report.c -o $@

TEST_KCORE_BIN := $(TEST_OBJ_DIR)/test_kcore
$(TEST_KCORE_BIN): $(TEST_DIR)/test_kcore.c $(SRC_DIR)/components/proc_kcore.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_kcore.c -o $@

# kernfs_ns_hash salt recovery: the component #included (main renamed) and its
# pure recovery functions exercised over synthesised cookies — unique recovery,
# the offset-table base pin, the patched-kernel no-op, and salt discrimination.
# Host-agnostic (no live getdents64; the seek-cookie path cannot be staged).
TEST_KERNFS_BIN := $(TEST_OBJ_DIR)/test_kernfs_ns_hash
$(TEST_KERNFS_BIN): $(TEST_DIR)/test_kernfs_ns_hash.c $(SRC_DIR)/components/kernfs_ns_hash.c $(HDRS) | $(TEST_OBJ_DIR)
	$(call ccv,CCLD,$@)
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_kernfs_ns_hash.c -o $@

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
	$(Q)$(CC) $(TEST_ALL_CFLAGS) $(ALL_LDFLAGS) -I$(SRC_DIR) $(TEST_DIR)/test_sysfs_parsers.c -o $@

.PHONY: test
# Test headers carry behaviour, not just declarations: test_harness.h runs the
# suite, and test_sysroot.h makes the staged tree and registers its removal.
# They are not in $(HDRS), which is the product's headers, so a test binary had
# no dependency on them at all -- editing one left every binary stale while the
# build reported success, and a measurement of the edit measured the build
# before it.
TEST_HDRS := $(wildcard $(TEST_DIR)/*.h)

TEST_ALL_BINS := $(TEST_BIN) \
  $(TEST_RENDER_BIN) \
  $(TEST_EST_BIN) \
  $(TEST_EV_BIN) \
  $(TEST_ALIGN_BIN) \
  $(TEST_ADDRP_BIN) \
  $(TEST_TWIDTH_BIN) \
  $(TEST_UNAME_BIN) \
  $(TEST_TS_BIN) \
  $(TEST_PREFETCH_SCAN_BIN) \
  $(TEST_CPU_BIN) \
  $(TEST_OUTCOME_BIN) \
  $(TEST_TEXT_ORDER_BIN) \
  $(TEST_KIMG_BIN) \
  $(TEST_ENG_BIN) \
  $(TEST_INT_BIN) \
  $(TEST_DMESG_BIN) \
  $(TEST_BACKTRACE_BIN) \
  $(TEST_BOOTCFG_BIN) \
  $(TEST_KASLRDIS_BIN) \
  $(TEST_DTMEM_BIN) \
  $(TEST_SOCKPTR_BIN) \
  $(TEST_TIMERLIST_BIN) \
  $(TEST_KALLSYMS_BIN) \
  $(TEST_AVAILFILTER_BIN) \
  $(TEST_BTF_BIN) \
  $(TEST_DMESG_RESV_BIN) \
  $(TEST_BPE820_BIN) \
  $(TEST_BPFACTS_BIN) \
  $(TEST_PARSERS_BIN) \
  $(TEST_KCORE_BIN) \
  $(TEST_REPORT_BIN) \
  $(TEST_PTDUMP_BIN) \
  $(TEST_KMEMLEAK_BIN) \
  $(TEST_IOMEM_BIN) \
  $(TEST_ZFSDBG_BIN) \
  $(TEST_FWMEMMAP_BIN) \
  $(TEST_ZONEINFO_BIN) \
  $(TEST_MEMINFO_FACTS_BIN) \
  $(TEST_CPUINFO_FACTS_BIN) \
  $(TEST_FIRMWARE_MEMMAP_BIN) \
  $(TEST_PROC_CPUINFO_BIN) \
  $(TEST_PROCMOD_BIN) \
  $(TEST_MEMBLK_BIN) \
  $(TEST_KERNFS_BIN)

$(TEST_ALL_BINS): $(TEST_HDRS)

test : $(KASLD_BIN) $(TEST_ALL_BINS)
	@$(TEST_DIR)/run-all
	@$(TEST_DIR)/check-render-width
	@$(MAKE) --no-print-directory lint

# Static guards ("lint"): source-invariant greps, the 32-bit narrowing check,
# and shellcheck over all shipped shell scripts (extra/ + tests/) — no compiled
# unit-test binaries. Run after the unit tests by `make test`, and standalone by
# `make lint`.
#
# The guards are independent of each other, so run-guards runs them JOBS at a
# time (one per core by default, JOBS=1 for one at a time) and prints each one's
# output in the order listed here rather than the order they finish, so the
# transcript does not depend on the scheduling. Every guard runs even after one
# fails, and lint's exit status is non-zero if any did.
LINT_RUNNER := $(TEST_DIR)/run-guards

.PHONY: lint
lint :
	@$(LINT_RUNNER) \
	    $(TEST_DIR)/check-rule-registry \
	    $(TEST_DIR)/check-self-edges \
	    $(TEST_DIR)/check-extent-callers \
	    $(TEST_DIR)/check-covering-consumers \
	    $(TEST_DIR)/check-discard-ledger \
	    $(TEST_DIR)/check-discard-accounting \
	    $(TEST_DIR)/check-discard-report \
	    $(TEST_DIR)/check-scalar-seed-order \
	    $(TEST_DIR)/check-vantage-coverage \
	    $(TEST_DIR)/check-test-staging \
	    $(TEST_DIR)/check-truncation \
	    $(TEST_DIR)/check-addr-parse \
	    $(TEST_DIR)/check-hostname-scrub \
	    $(TEST_DIR)/check-absence-vs-denial \
	    $(TEST_DIR)/check-component-output \
	    $(TEST_DIR)/check-component-meta \
	    $(TEST_DIR)/check-component-tests \
	    $(TEST_DIR)/check-component-cap \
	    $(TEST_DIR)/check-components-built \
	    $(TEST_DIR)/check-component-sections \
	    $(TEST_DIR)/check-log-prefixes \
	    $(TEST_DIR)/check-live-probes \
	    $(TEST_DIR)/check-hash-parity \
	    $(TEST_DIR)/check-text-floor \
	    $(TEST_DIR)/check-text-region \
	    $(TEST_DIR)/check-confidence-floor \
	    $(TEST_DIR)/check-text-provenance \
	    $(TEST_DIR)/check-arch-macros \
	    $(TEST_DIR)/check-lattice-seam \
	    $(TEST_DIR)/check-page-offset-substitution \
	    $(TEST_DIR)/check-render-default \
	    $(TEST_DIR)/check-image-size \
	    $(TEST_DIR)/check-image-align \
	    $(TEST_DIR)/check-doc-alignment \
	    $(TEST_DIR)/check-dram-base \
	    $(TEST_DIR)/check-fdt-unflatten \
	    $(TEST_DIR)/check-ksymoff \
	    $(TEST_DIR)/check-manpages \
	    $(TEST_DIR)/check-readout-docs \
	    $(TEST_DIR)/check-doc-structure \
	    $(TEST_DIR)/check-doc-identifiers \
	    $(TEST_DIR)/check-diagram-data \
	    $(TEST_DIR)/check-arch-axes \
	    $(TEST_DIR)/check-arch-headers \
	    $(TEST_DIR)/check-arch-dispatch \
	    $(TEST_DIR)/check-macro-claims \
	    $(TEST_DIR)/check-fail-closed \
	    $(TEST_DIR)/check-guard-docs \
	    $(TEST_DIR)/check-matrix-summary \
	    $(TEST_DIR)/check-version \
	    $(TEST_DIR)/check-posture-diff \
	    $(TEST_DIR)/check-posture-summary \
	    $(TEST_DIR)/check-validators \
	    $(TEST_DIR)/check-env-docs \
	    $(TEST_DIR)/check-shellcheck \
	    $(TEST_DIR)/check-fuzz-harnesses \
	    $(TEST_DIR)/check-make-deps \
	    $(TEST_DIR)/check-suite-registry \
	    $(TEST_DIR)/check-render-model-only \
	    $(TEST_DIR)/check-render-no-acquire \
	    $(TEST_DIR)/check-property-arches \
	    $(TEST_DIR)/check-stext-gap \
	    $(TEST_DIR)/check-baseline \
	    $(TEST_DIR)/check-render-parity \
	    $(TEST_DIR)/check-render-color \
	    $(TEST_DIR)/check-wire-text \
	    $(TEST_DIR)/check-sysroot-containment \
	    $(TEST_DIR)/check-uname-release \
	    $(TEST_DIR)/hardening-fixtures \
	    $(TEST_DIR)/cli-flags

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

.PHONY: test-boot-params-facts
test-boot-params-facts : $(TEST_BPFACTS_BIN)
	$(TEST_BPFACTS_BIN)

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
# Derived from the tree, not listed: a hand-maintained list is a second
# inventory, and a harness missing from it is never built — which reads as
# "nothing to report" rather than as a harness nobody compiles.
FUZZ_TARGETS := $(patsubst tests/fuzz/%.c,%,$(wildcard tests/fuzz/fuzz_*.c))
FUZZ_BINS    := $(addprefix $(FUZZ_OUT)/,$(FUZZ_TARGETS))

# A harness names the parser it drives by #including the source file holding
# it, so most of the program arrives through that one translation unit. What
# does not is the estimate lattice, the quantity table and the report builder:
# the orchestrator reads all three, they live in their own objects, and a
# harness that includes orchestrator.c will not link without them.
FUZZ_SRCS    := src/estimate.c src/quantities.c src/report.c

# Everything a harness could pull in through its #include, plus the headers
# those read. Prerequisites, not inputs: the sources arrive through the
# harness's own translation unit, but without naming them here a harness never
# relinks when one of them changes -- an edit to the orchestrator leaves a stale
# binary in place, the guard links nothing, and it passes. That is how a missing
# object reached CI from a green local run.
#
# Deliberately a wildcard rather than the list of files today's harnesses name.
# A hand-kept list has to be extended whenever a harness includes something new,
# and forgetting reinstates exactly the silent staleness this exists to prevent
# -- a failure that shows up as a guard passing, which is the hardest kind to
# notice. Relinking every harness costs a few seconds.
FUZZ_DEPS    := $(wildcard src/*.c src/render/*.c src/rules/*.c \
                           src/components/*.c src/include/kasld/*.h \
                           src/include/kasld/arch/*.h)

# Makefile included: the link line itself lives here, so a change to which
# objects are linked has to invalidate the binaries too. Without it, dropping an
# object from FUZZ_SRCS leaves working binaries in place and the guard passes on
# a link that would no longer succeed.
$(FUZZ_OUT)/% : tests/fuzz/%.c $(FUZZ_SRCS) $(FUZZ_DEPS) Makefile
	@mkdir -p "$(FUZZ_OUT)"
	$(call ccv,CCLD,$@)
	$(Q)$(FUZZ_CC) $(FUZZ_CFLAGS) "$<" $(FUZZ_SRCS) -o "$@"

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
	cp -R docs README.md LICENSE THIRD-PARTY-NOTICES.md "$(DESTDIR)$(PREFIX)/share/doc/kasld/"
	install -d "$(DESTDIR)$(PREFIX)/share/man/man1"
	install -m 644 man/kasld.1 man/ksymoff.1 "$(DESTDIR)$(PREFIX)/share/man/man1/"

# STRIP defaults to the toolchain's, so a cross-installed tree gets binutils
# matching the binaries rather than the host's. CROSS_COMPILE is honoured for
# the same reason: applying the host strip to a foreign ELF fails, and failing
# loudly at install time is better than shipping whatever it left behind.
STRIP ?= $(CROSS_COMPILE)strip

# install-strip — install, then strip what was installed. The GNU Coding
# Standards name, since that is what packaging tooling already looks for.
#
# Debug info is 70% of the tree: an unstripped aarch64 build is 18 MiB against
# 5.4 MiB stripped, which on a small flash rootfs decides whether it fits. What
# makes this safe is that a component's metadata lives in .kasld_meta and
# .kasld_explain, ELF SECTIONS that strip preserves -- not in the symbol table.
# So --explain and the hardening report survive; installcheck proves it rather
# than this comment asserting it.
#
# The installed copy is stripped, never build/: stripping there would leave make
# holding up-to-date targets whose debug info is gone, and every later debugging
# session would pay for it silently.
#
# Only ELF files are passed to strip. ksymoff installs into the same bin/ and is
# a shell script, which strip rejects outright -- and a future script alongside
# it would break this target the same way, so the type is tested rather than the
# name being special-cased.
.PHONY: install-strip
install-strip : install
	@n=0; \
	for f in "$(DESTDIR)$(PREFIX)/bin"/* "$(DESTDIR)$(PREFIX)/libexec/kasld"/*; do \
	  [ -f "$$f" ] || continue; \
	  case "$$(od -An -c -N4 "$$f" 2>/dev/null | tr -d ' ')" in \
	    177ELF*) ;; \
	    *) continue ;; \
	  esac; \
	  $(STRIP) "$$f" || exit 1; \
	  n=$$((n + 1)); \
	done; \
	echo "install-strip: stripped $$n binaries in $(DESTDIR)$(PREFIX)" 

.PHONY: uninstall
uninstall :
	rm -f "$(DESTDIR)$(PREFIX)/bin/kasld"
	rm -f "$(DESTDIR)$(PREFIX)/bin/ksymoff"
	rm -rf "$(DESTDIR)$(PREFIX)/libexec/kasld"
	rm -rf "$(DESTDIR)$(PREFIX)/share/doc/kasld"
	rm -f "$(DESTDIR)$(PREFIX)/share/man/man1/kasld.1"
	rm -f "$(DESTDIR)$(PREFIX)/share/man/man1/ksymoff.1"

# Post-install smoke test (GNU `installcheck` convention). Runs the INSTALLED
# bin/kasld and confirms it discovers its components via the FHS
# ../libexec/kasld path — the split-install layout `install` produces. Assumes
# `install` already ran with the same PREFIX/DESTDIR; it validates an installed
# tree (possibly a DESTDIR staging root before packaging), so it deliberately
# does not depend on the `install` target. Runs unprivileged and keys on the
# JSON per-component `outcome` records — emitted for every discovered component
# that executed, whatever leaks the host actually yields — so it asserts the
# discovery path, not leak success or the process exit code. Uses only grep, no
# JSON parser. On a broken layout the binary prints "cannot find component
# directory" and emits no records, so the count is 0 and the check fails.
.PHONY: installcheck
# Component metadata lives in the .kasld_explain / .kasld_meta ELF sections, which
# is what makes install-strip safe -- but discovery proves only that the binaries
# RUN. Removing both sections leaves every component executable and the count
# unchanged, so this check reported OK while --explain was gutted to nothing. The
# two assertions after it hold the sections themselves, against whatever the
# packaging pipeline did -- ours or a distro's.
installcheck :
	@bin="$(DESTDIR)$(PREFIX)/bin/kasld"; \
	if [ ! -x "$$bin" ]; then \
	  echo "installcheck: FAIL - $$bin not found or not executable" >&2; \
	  echo "  run 'make install' with a matching PREFIX/DESTDIR first" >&2; \
	  exit 1; \
	fi; \
	out=$$("$$bin" -j -f -q 2>/dev/null) || true; \
	n=$$(printf '%s\n' "$$out" | grep -c '"outcome"'); \
	if [ "$$n" -gt 0 ]; then \
	  echo "installcheck: OK ($$n components discovered via libexec/kasld/)"; \
	else \
	  echo "installcheck: FAIL - bin/kasld discovered no components" >&2; \
	  echo "  expected component binaries in $(DESTDIR)$(PREFIX)/libexec/kasld/" >&2; \
	  exit 1; \
	fi; \
	e=$$("$$bin" --explain 2>/dev/null | grep -c 'Reads\|Parses\|Probes\|Searches'); \
	if [ "$$e" -lt 20 ]; then \
	  echo "installcheck: FAIL - --explain yielded $$e technique lines" >&2; \
	  echo "  the .kasld_explain section is missing from the installed components;" >&2; \
	  echo "  a strip that removes ELF sections, not just symbols, will do this" >&2; \
	  exit 1; \
	fi; \
	h=$$("$$bin" -H 2>/dev/null | wc -l); \
	if [ "$$h" -lt 20 ]; then \
	  echo "installcheck: FAIL - hardening report was $$h lines" >&2; \
	  echo "  the .kasld_meta section is missing from the installed components" >&2; \
	  exit 1; \
	fi; \
	echo "installcheck: OK (metadata intact: $$e explain lines, $$h hardening lines)"


# Cross-compile all supported architectures with `make cross` — a local,
# musl-only mirror of the CI / release matrices. Expects <triple>-gcc on PATH;
# absent toolchains are skipped. Both the cross-tools/musl-cross triple names and
# the short musl-cross-make names are listed so either musl toolchain set works.
# GNU is intentionally absent (releases are built with musl). armeb is
# musl-cross-make-only — cross-tools/musl-cross provides no armeb toolchain.

# Per-triple build requirements, echoed for the cross loop.
#
# armeb: the toolchain defaults to BE32 (word-invariant), and a big-endian arm
# kernel from ARMv6 on runs its userspace BE8 (byte-invariant). A BE32 binary
# faults on its first instruction there and dies before main(), so an armeb
# build without -mbe8 cannot run on the kernels it is built to inspect. Under
# qemu-user it runs either way, which is why the difference goes unnoticed
# without a VM boot.
.PHONY: cross-arch-flags
cross-arch-flags :
	@case '$(TRIPLE)' in \
	armeb-*) echo '-mbe8' ;; \
	*) echo '' ;; \
	esac

# What the cross loop passes: the arch flags above, plus the dependency prefix
# for this triple when `cross-deps` has populated one. Absent, the flags are the
# arch flags alone and the zlib probe simply fails, which is the state every
# cross build was in before: proc_config decompresses by running zcat instead.
# Kept separate from cross-arch-flags because zlib itself is compiled with the
# arch flags and must not be told to search a prefix it is being built into.
.PHONY: cross-extra-flags
cross-extra-flags :
	@af=$$($(MAKE) --no-print-directory cross-arch-flags TRIPLE='$(TRIPLE)'); \
	pfx='$(DEPS_DIR)/$(TRIPLE)'; \
	if [ -f "$$pfx/lib/libz.a" ]; then \
	  echo "$$af -I$(CURDIR)/$$pfx/include -L$(CURDIR)/$$pfx/lib"; \
	else \
	  echo "$$af"; \
	fi

# Static zlib for the cross targets. No musl toolchain ships one, so without
# this every cross build has HAVE_ZLIB empty and proc_config decompresses
# /proc/config.gz by running zcat from the target's PATH — which a minimal or
# embedded userland need not have, in a binary whose whole point is to be
# self-contained.
#
# Pinned by version and checksum: the build must not vary with whatever upstream
# publishes today. Set KASLD_ZLIB_TARBALL to a local copy to build offline; the
# checksum is verified either way.
#
# Not part of `cross`. Building a dependency is a separate, network-touching
# step, and `cross` stays usable without it.
#
# TRIPLE=<triple> builds one target instead of every present toolchain. The
# release matrix carries float and ABI variants that CROSS_TARGETS does not
# list, so it names its triple rather than relying on that list.
ZLIB_VERSION := 1.3.1
ZLIB_SHA256  := 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
# Two sources, same bytes. The GitHub release is first because the release
# matrix fans out twenty-two jobs that all fetch this at once, which zlib.net
# is a single host serving; it stays as the fallback.
ZLIB_URLS    := https://github.com/madler/zlib/releases/download/v$(ZLIB_VERSION)/zlib-$(ZLIB_VERSION).tar.gz \
                https://zlib.net/fossils/zlib-$(ZLIB_VERSION).tar.gz

.PHONY: cross-deps
cross-deps :
	@set -e; \
	command -v sha256sum >/dev/null 2>&1 || \
	  { echo "cross-deps: sha256sum not found" >&2; exit 1; }; \
	src='$(DEPS_DIR)/src'; mkdir -p "$$src"; \
	tb="$${KASLD_ZLIB_TARBALL:-$$src/zlib-$(ZLIB_VERSION).tar.gz}"; \
	ok() { [ -f "$$1" ] && \
	  [ "$$(sha256sum <"$$1" | cut -d' ' -f1)" = '$(ZLIB_SHA256)' ]; }; \
	if ! ok "$$tb"; then \
	  if [ -n "$${KASLD_ZLIB_TARBALL:-}" ]; then \
	    echo "cross-deps: KASLD_ZLIB_TARBALL=$$tb is not zlib-$(ZLIB_VERSION)" >&2; \
	    echo "  expected $(ZLIB_SHA256)" >&2; \
	    echo "  got      $$(sha256sum <"$$tb" 2>/dev/null | cut -d' ' -f1)" >&2; \
	    exit 1; \
	  fi; \
	  command -v curl >/dev/null 2>&1 || \
	    { echo "cross-deps: curl not found; set KASLD_ZLIB_TARBALL" >&2; exit 1; }; \
	  rm -f "$$tb"; \
	  for url in $(ZLIB_URLS); do \
	    echo "  FETCH zlib-$(ZLIB_VERSION) ($$url)"; \
	    curl -fsSL --retry 3 --retry-delay 2 -o "$$tb.part" "$$url" || continue; \
	    if ok "$$tb.part"; then mv -f "$$tb.part" "$$tb"; break; fi; \
	    echo "  checksum mismatch from $$url" >&2; \
	    echo "    expected $(ZLIB_SHA256)" >&2; \
	    echo "    got      $$(sha256sum <"$$tb.part" | cut -d' ' -f1)" >&2; \
	    rm -f "$$tb.part"; \
	  done; \
	  rm -f "$$tb.part"; \
	fi; \
	ok "$$tb" || \
	  { echo "cross-deps: no source matching $(ZLIB_SHA256)" >&2; exit 1; }; \
	built=0; have=0; absent=0; \
	for triple in $${TRIPLE:-$(CROSS_TARGETS)}; do \
	  command -v $${triple}-gcc >/dev/null 2>&1 || { absent=$$((absent+1)); continue; }; \
	  pfx='$(DEPS_DIR)'/$$triple; \
	  if [ -f "$$pfx/lib/libz.a" ]; then have=$$((have+1)); continue; fi; \
	  af=$$($(MAKE) --no-print-directory cross-arch-flags TRIPLE=$$triple); \
	  wd='$(DEPS_DIR)'/work/$$triple; rm -rf "$$wd"; mkdir -p "$$wd"; \
	  tar xzf "$$tb" -C "$$wd" --strip-components=1; \
	  ( cd "$$wd" && CHOST=$$triple CC=$${triple}-gcc AR=$${triple}-ar \
	      RANLIB=$${triple}-ranlib CFLAGS="-O2 $$af" \
	      ./configure --static --prefix='$(CURDIR)'/$$pfx >configure.log 2>&1 \
	    && $(MAKE) libz.a >build.log 2>&1 \
	    && $(MAKE) install >>build.log 2>&1 ) \
	    || { echo "!!! zlib FAILED: $$triple (logs in $$wd)" >&2; exit 1; }; \
	  rm -rf "$$wd"; \
	  echo "  ZLIB  $$triple"; built=$$((built+1)); \
	done; \
	echo "cross-deps: $$built built, $$have already present, $$absent toolchain-absent"

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
			xf=$$($(MAKE) --no-print-directory cross-extra-flags TRIPLE=$$triple); \
			$(MAKE) build CC=$${triple}-gcc EXTRA_CFLAGS="$$xf" EXTRA_LDFLAGS="$$xf" \
				|| { rc=1; echo "!!! FAILED: $$triple"; }; \
			echo; \
		else \
			echo "=== Skipping $$triple (toolchain not found) ==="; \
		fi; \
	done; \
	[ $$rc -eq 0 ] || echo "cross: one or more present targets FAILED"; \
	exit $$rc


# Dependency manifest for packagers: the required toolchain, the two optional
# libraries (with their auto-detection result for the current $(CC)), and the
# per-component compile/link flag exceptions — so a distro control file can be
# populated without reverse-engineering the feature-probe logic above. The lib
# lines report the same HAVE_ZLIB / HAVE_PTHREAD probes the real build uses, so
# they cannot drift from what actually links; the flag lines read from the same
# variables the build recipes consume.
.PHONY: print-deps
print-deps:
	@echo "KASLD build dependencies"
	@echo "========================"
	@echo
	@echo "Toolchain:"
	@echo "  C99 compiler (CC=$(CC)); built with -std=c99 and _GNU_SOURCE."
	@echo "  Cross builds (target triple != host) link -static automatically."
	@echo
	@echo "Libraries (both OPTIONAL, auto-detected at build time):"
	@printf '  pthread   present: %-3s  parallel inference pool (kasld) + kernelsnitch\n' "$(if $(HAVE_PTHREAD),yes,no)"
	@echo "                          kasld runs sequentially without it;"
	@echo "                          kernelsnitch is skipped without it."
	@printf '  zlib      present: %-3s  native /proc/config.gz decompression (proc_config)\n' "$(if $(HAVE_ZLIB),yes,no)"
	@echo "                          proc_config still builds without it, running"
	@echo "                          zcat instead. Cross builds get it from"
	@echo "                          make cross-deps; no musl toolchain ships one."
	@echo
	@echo "Per-component compile/link flag exceptions:"
	@echo "  -O0 (timing-sensitive side channels):"
	@echo "      $(SIDECHANNEL_COMPONENTS)"
	@echo "  -DHAVE_ZLIB -lz:   proc_config (when zlib present)"
	@echo "  -lpthread:         kernelsnitch; kasld orchestrator (adds -DHAVE_PTHREAD)"
	@echo
	@echo "Debian control mapping:"
	@echo "  Build-Depends:            gcc, make, libc-dev"
	@echo "  Build-Depends (optional): zlib1g-dev   (pthread ships in libc6)"

# Stamp a new version across the files that carry it as metadata: the VERSION
# file (injected into the build as -DVERSION), the man-page .TH lines (version +
# date), and — for a real release only — CITATION.cff (version + date-released;
# a -dev string is not a citable identifier). The usage.md example output is
# illustrative and intentionally not stamped. tests/check-version enforces that
# these stay in step. Uses GNU sed -i.
#   make bump-version NEW=0.3.1        # cut a release
#   make bump-version NEW=0.3.2-dev    # open the next dev cycle
.PHONY: bump-version
bump-version :
	@[ -n "$(NEW)" ] || { echo 'usage: make bump-version NEW=x.y.z  (append -dev for a dev cycle)' >&2; exit 2; }
	@new='$(NEW)'; d=$$(date +%F); old=$$(cat VERSION 2>/dev/null); \
	printf '%s\n' "$$new" > VERSION; \
	for m in man/kasld.1 man/ksymoff.1; do \
	  sed -i -E "1s/\"[0-9]{4}-[0-9]{2}-[0-9]{2}\"/\"$$d\"/; 1s/\"kasld [^\"]*\"/\"kasld $$new\"/" "$$m"; \
	done; \
	case "$$new" in \
	*-dev) echo "  note: '$$new' is a dev version — CITATION.cff left at the last release" ;; \
	*) sed -i -E "s/^version: .*/version: \"$$new\"/; s/^date-released: .*/date-released: \"$$d\"/" CITATION.cff; \
	   echo "  CITATION.cff -> version $$new, date-released $$d" ;; \
	esac; \
	echo "  VERSION: $${old:-?} -> $$new   (man pages dated $$d)"; \
	echo "  next: review the diff, commit, and 'git tag v$$new' for a release"

.PHONY: help
help:
	@echo
	@echo "  make [target] [OPTIONS]"
	@echo
	@echo "  Targets:"
	@echo "      build           Build kasld and all components (default)"
	@echo "      run             Build and run kasld"
	@echo "      cross           Cross-compile for all supported architectures"
	@echo "      cross-deps      Build static zlib for the cross targets (network)"
	@echo "      coverage        Host unit-test coverage report (gcov)"
	@echo "      coverage-e2e    End-to-end coverage over x86 fixtures (gcov)"
	@echo "      install         Install to PREFIX (default: /usr/local)"
	@echo "      installcheck    Smoke-test the installed bin/kasld + libexec/kasld/"
	@echo "      uninstall       Remove installed files"
	@echo "      clean           Remove build directory"
	@echo "      print-deps      List build dependencies (libs + per-component flags)"
	@echo "      bump-version    Stamp NEW=x.y.z across VERSION, man pages, CITATION.cff"
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
