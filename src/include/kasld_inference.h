// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin interface.
//
// An inference plugin is a plain C function compiled directly into the
// orchestrator. Plugins run at defined phase transition points and may read
// component results and tighten analysis bounds. They do not fork() or exec().
//
// To add a plugin:
//   1. Create src/inference/<name>.c
//   2. Define a static struct kasld_inference and call KASLD_REGISTER_INFERENCE
//   3. No other file changes are required
//
// Commutativity invariant: plugins within a phase must only tighten bounds
// (raise text_base_min, lower text_base_max). This makes execution order
// within a phase irrelevant.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_INFERENCE_H
#define KASLD_INFERENCE_H

#include "kasld_internal.h"

/* Three phase points where inference plugins can fire. */
enum kasld_inference_phase {
  KASLD_INFER_PHASE_PRE_COLLECTION, /* setup state on_exit: before any component
                                       runs */
  KASLD_INFER_PHASE_POST_COLLECTION, /* inference state on_exit: after each
                                      * sequential component, or once after the
                                      * parallel join */
  KASLD_INFER_PHASE_POST_PROBING, /* probing state on_exit: after each probing
                                     component */
};

/* Architecture constants — compile-time values, set once at startup.
 * Plugins treat this as read-only. */
struct kasld_arch_params {
  unsigned long kaslr_base_min;
  unsigned long kaslr_base_max;
  unsigned long kaslr_align;
  /* Physical-to-virtual mapping constants for PHYS/DRAM bound inference.
   * phys_virt_decoupled: 1 when physical and virtual KASLR are independent;
   * on decoupled arches physical leaks do not constrain the text range. */
  int phys_virt_decoupled;
  unsigned long phys_offset; /* PHYS_OFFSET: physical base of DRAM */
  unsigned long page_offset; /* PAGE_OFFSET: virtual base of direct map */
  unsigned long text_offset; /* TEXT_OFFSET: offset from PAGE_OFFSET to _text */
};

/* Shared analysis context passed to every inference plugin.
 * result_count is updated to num_results immediately before each on_exit call.
 * Fields are added only when a concrete plugin requires them. */
struct kasld_analysis_ctx {
  const struct result *results;
  size_t result_count;
  /* Constraint bounds — only tighten, never widen */
  unsigned long text_base_min;
  unsigned long text_base_max;
  unsigned long page_offset_min;
  unsigned long page_offset_max;
  const struct kasld_arch_params *arch;
};

/* Inference plugin descriptor. */
struct kasld_inference {
  const char *name;
  enum kasld_inference_phase phase;
  void (*run)(struct kasld_analysis_ctx *ctx);
};

/* Register a plugin in the kasld_inferences ELF linker section.
 * The orchestrator iterates __start_kasld_inferences..__stop_kasld_inferences
 * at each phase transition. No central registration file; adding a .c file
 * to src/inference/ is the only step required. */
#define KASLD_REGISTER_INFERENCE(inf)                                          \
  __attribute__((                                                              \
      used, section("kasld_inferences"))) static const struct kasld_inference  \
      *const __kasld_inf_ptr_##inf = &(inf)

#endif /* KASLD_INFERENCE_H */
