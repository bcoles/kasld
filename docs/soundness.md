# Soundness

The inference engine resolves each unknown to a window and reports it. This
document states what that window guarantees and what the system must hold true
to earn the guarantee. [architecture.md](architecture.md) describes how the
engine works; this states what its result means, in the engine's own lattice
vocabulary, so the property can be cited exactly rather than paraphrased.

Every obligation below is local: it is a property of one function, one rule, or
one architecture header, checkable without reference to the rest of the system.
The theorems compose them. Where an obligation is machine-checked, the check is
named; where it is not, that is said plainly.

## Contents

- [The quantities and their lattices](#the-quantities-and-their-lattices)
- [What a constraint admits](#what-a-constraint-admits)
- [Obligation A: the honest top contains the truth](#obligation-a-the-honest-top-contains-the-truth)
- [Obligation M: the meet narrows and does not drop](#obligation-m-the-meet-narrows-and-does-not-drop)
- [Obligation B: bottom means empty](#obligation-b-bottom-means-empty)
- [Obligation W: an observation states something true](#obligation-w-an-observation-states-something-true)
- [Obligation S: a rule never excludes the truth](#obligation-s-a-rule-never-excludes-the-truth)
- [Theorem T1: truth containment](#theorem-t1-truth-containment)
- [Corollary C1: a conflict is a witness](#corollary-c1-a-conflict-is-a-witness)
- [Theorem T2: containment survives the read](#theorem-t2-containment-survives-the-read)
- [Theorem T3: the floor separates the two windows](#theorem-t3-the-floor-separates-the-two-windows)
- [Theorem T4: termination](#theorem-t4-termination)
- [Theorem T5: saturation widens](#theorem-t5-saturation-widens)
- [Where each obligation is discharged](#where-each-obligation-is-discharged)
- [What the guarantee does not cover](#what-the-guarantee-does-not-cover)

## The quantities and their lattices

The engine solves for a fixed set of unknowns, the *quantities*. The set is a
closed enum in `src/include/kasld/quantity.h`, and each member's lattice and
starting value are declared once in the table in `src/quantities.c`. Write `Q`
for that set and `D_q` for the values quantity `q` can take — addresses for the
six placement quantities, a power-of-two alignment for the two granularity
quantities, a bit width for `Q_VA_BITS`.

The kernel the analysing process runs on has exactly one layout. Write

    T = (T_q) for q in Q

for that layout: the *true* value of every quantity, fixed for the duration of
the run. KASLR draws it once at boot and does not redraw it, so `T` is a
constant the engine is trying to locate, not a moving target.

Each quantity carries a lattice. An element `e` of it *denotes* a set of
still-possible values, through the concretisation `gamma`:

| lattice | element | `gamma(e)` |
|---|---|---|
| `LK_INTERVAL` | `lo`, `hi`, `stride`, `stride_offset` | `{ v : lo <= v <= hi, and v = stride_offset (mod stride) when stride is non-zero }` |
| `LK_MAXALIGN` | `lo`, `hi` | `{ a : lo divides a, and a divides hi when hi is non-zero }` |
| `LK_FINSET` | a bitmask over `candidates[]` | `{ candidates[i] : bit i is set }` |

Ordering is containment of the concretisation: `e` is at least as narrow as `e'`
when `gamma(e)` is a subset of `gamma(e')`. Lattice-bottom is the empty
concretisation.

`LK_MAXALIGN` looks unlike the other two and is not: on powers of two,
divisibility and ordering coincide, so `{ a : lo divides a and a divides hi }`
is the interval `[lo, hi]` taken along the chain `1 | 2 | 4 | ...`. That is why
its bottom test can compare `lo` against `hi` rather than test divisibility. The
correspondence needs every alignment reaching the lattice to be a power of two;
see obligation B for where that is enforced.

The reported window is the concretisation, never the representation. `gamma` is
not a function in the source — the accessors `quantity_window()`,
`quantity_admits()`, `quantity_pinned()` and `quantity_ranges()` are its
interface, and reading `.lo` / `.hi` of a quantity whose lattice is not an
interval reads something else entirely. `tests/check-lattice-seam` holds
consumers to the accessors.

## What a constraint admits

A constraint is one claim about one quantity: an operator from `enum
constraint_op`, one or two operands, a confidence, and a lineage. Write `adm(c)`
for the set of values it admits — the values that satisfy it.

`adm` is not a notation invented for this document. It exists in the source as
`constraint_admits()` in `src/estimate.c`, a total function over the operator
enum, and the finite-set lattice narrows by calling it on each live candidate.
The switch carries no `default:` arm deliberately, so an operator added without
a stated meaning is a `-Wswitch` diagnostic — an error under the `-Werror` CI
supplies — rather than an operator silently admitting everything.

| operator | `adm(c)` |
|---|---|
| `C_LOWER_BOUND` | `{ v : v >= value }` |
| `C_UPPER_BOUND` | `{ v : v <= value }` |
| `C_EQUALS` | `{ value }` |
| `C_AT_LEAST_ALIGN` | `{ v : value divides v }`, everything when `value` is zero |
| `C_EXCLUDE` | `{ v : v < value or v > value2 }`, the range inclusive at both ends |
| `C_STRIDE` | `{ v : v = value (mod value2) }`, everything when `value2` is zero |

## Obligation A: the honest top contains the truth

Each quantity starts at its *honest top*, built by the quantity table's
`init_top` from the architecture header's constants. The obligation:

> **A.** For every quantity `q`, `T_q` is in `gamma(top_q)`.

This is the induction base for everything below, and the reason the tops are
architectural constants rather than runtime-derived values. A top narrowed by a
configuration guess — a detected paging level, an assumed VMSPLIT — would make
every window downstream conditional on that guess being right. Runtime discovery
enters as a constraint, where it is subject to obligation S and carries a
confidence, and never as a smaller top.

## Obligation M: the meet narrows and does not drop

`estimate_meet()` narrows an estimate by one constraint. It must do two things,
and the second is the one prose usually omits:

> **M.** For every estimate `e` and constraint `c` on the same quantity:
>
>     gamma(e) intersect adm(c)  is a subset of  gamma(meet(e, c))
>     gamma(meet(e, c))          is a subset of  gamma(e)

The right inclusion is monotone narrowing: a meet can only ever remove values.
It is what makes rule order irrelevant and the fixpoint well-defined.

The left inclusion is the one that licenses an *approximate* meet. A single
interval cannot represent a hole in its middle, so `C_EXCLUDE` against the
interior of an interval leaves the interval alone: values the constraint rejects
stay in `gamma`, which M permits and the opposite inclusion would not. Every
lattice-and-operator pair is therefore exact or deliberately loose, never wrong:

| lattice | exact | over-approximating |
|---|---|---|
| `LK_INTERVAL` | both bounds, `C_EQUALS`, `C_STRIDE` within the folding range | `C_EXCLUDE` against the interior; `C_STRIDE` with a zero or out-of-range modulus; `C_AT_LEAST_ALIGN`, which the interval meet does not model |
| `LK_MAXALIGN` | `C_AT_LEAST_ALIGN` and `C_EQUALS` on power-of-two operands | every other operator, which it ignores; and a non-power-of-two alignment, where combining by the larger of the two is looser than their least common multiple |
| `LK_FINSET` | every operator | none — it tests each candidate against `adm` |

Two consequences worth stating rather than discovering. A `C_STRIDE` whose
modulus exceeds the range the residue folding can combine safely is dropped
rather than approximated, so an unusable modulus costs precision and not
soundness. And the interval meet's fallthrough arm means an operator it does not
model is silently ignored: sound by the left inclusion, but invisible, and
unlike `constraint_admits()` there is no diagnostic waiting for the next
operator to be added. Directing `C_AT_LEAST_ALIGN` at an interval quantity is
the reachable form of that today; no rule does. The switch on the lattice
around it has no such arm, so a new *lattice* cannot be added without every
operator being considered for it.

## Obligation B: bottom means empty

The resolver decides whether to accept a constraint by trial-meeting it and
asking `estimate_is_bottom()`. That test must not cry empty over a set that
still holds something:

> **B.** `estimate_is_bottom(e)` is 1 if and only if `gamma(e)` is empty.

Each direction is used for a different thing, and it is worth keeping them
apart. *Bottom implies empty* is what corollary C1 needs: a test that cried
empty over a set still holding values would discard a sound constraint. *Empty
implies bottom* is what stops an unsatisfiable estimate being reported as a
window. Neither direction is needed for truth containment itself — a wrongly
skipped constraint leaves the window wider, not wrong.

On `LK_INTERVAL` the test is `lo > hi`, plus the check that the residue class
meets the interval — exactly emptiness. On `LK_FINSET` it is the empty mask,
exactly emptiness. On `LK_MAXALIGN` it compares `lo` against a stated
granularity `hi`, which is emptiness exactly when both are powers of two; the
producers hold that side-condition — `base_align` is rejected at the wire seam
unless `is_pow2()` accepts it (`src/capture.c`), the alignment a rule reads from
the target's own configuration is range- and power-of-two-checked before
emission, and the rest are architecture constants.

## Obligation W: an observation states something true

The engine reasons about what components report. It cannot verify a report:

> **W.** An observation describes `T` correctly — an address said to lie in a
> region lies in it, a scalar fact holds of the running kernel.

This is the components' obligation, not the engine's, and it is discharged at a
different seam: a component parses one data source and states only what that
source says, `origin` is filled by the orchestrator rather than trusted from the
wire, and each component carries its own tests. W is the hypothesis under which
everything below holds, and naming it separately is the point — the engine's
guarantee is conditional on it, and the conditionality is not a weakness to hide
but the thing a reader needs in order to know what the result is worth.

Curation exists because W fails in practice. Verdict rules invalidate
observations that cannot be reconciled with the rest of the evidence, which
recovers a useful answer from a partly untruthful set. It is a robustness
mechanism; the guarantee below does not rest on it.

## Obligation S: a rule never excludes the truth

A rule is a pure function of the evidence set and the current estimates,
emitting constraints. Its obligation:

> **S.** For every layout `T`, every evidence set truthful for `T` under W, and
> **every** estimate vector `est` with `T_q` in `gamma(est_q)` for all `q`: each
> constraint `c` a rule emits satisfies `T_q` in `adm(c)`, where `q` is the
> quantity `c` names.

The three quantifiers carry the whole content, and each answers a way the
obligation is commonly misread.

**Over `T` and every configuration.** The constraint must hold for every layout
the architecture admits — every paging level, every endianness, every Kconfig
value the analysing binary has not learned. A bound that holds for the common
build and fails for a legitimate rarer one is a violation, not an optimization.
This is the cross-architecture axis, and `make test-cross` is what settles it by
exit status.

**Over truthful evidence sets, not complete ones.** A rule may assume an
observation says something true (obligation W). It may not assume the evidence
is complete: absence of an observation is not evidence of absence, and a rule
that narrows because it found nothing has assumed a completeness nobody
promised.

**Over every estimate vector containing the truth.** A rule reads `est`, and
what it reads there has already been narrowed by other rules — possibly to a
window far tighter than the rule's author imagined, and in a run where some
other rule is misbehaving, tighter than the truth. The quantifier demands the
emitted constraint hold anyway.

That last quantifier is why a rule reading its own quantity's estimate and
emitting a constraint on that same quantity is treated as a special hazard. If
the value it emits is *computed from* the estimate it read, a narrowing already
applied can be amplified into a narrowing past the truth.
`tests/check-self-edges` finds every such rule and requires each to be on a
reviewed list, so a new one cannot arrive unexamined.

Violating S can only *over-narrow*. An unsound rule risks excluding the truth
from the window; it cannot make the engine oscillate or hang, because
termination does not depend on any rule being well-behaved (theorem T4).

## Theorem T1: truth containment

> **T1.** Under A, M, W and S, every estimate the engine resolves contains the
> truth: at every pass, `T_q` is in `gamma(est_q)` for every quantity `q`.

*Proof.* Induction over the constraints the resolver accepts for a quantity.
The resolver starts from the honest top, which contains `T_q` by A. Suppose the
estimate `e` before some accepted constraint `c` contains `T_q`. By S, `T_q` is
in `adm(c)`, so `T_q` is in `gamma(e)` intersect `adm(c)`, which by the left
inclusion of M is a subset of `gamma(meet(e, c))`. The accepted estimate
therefore still contains `T_q`. Resolution is otherwise a fold over accepted
constraints, and each pass re-resolves from the constraint set rather than from
the previous estimate, so the property holds at every pass rather than only at
the fixpoint.

Obligation B is deliberately absent from the hypotheses. A constraint the
resolver skips is simply not applied, and by the right inclusion of M an
unapplied constraint leaves the estimate wider — so even a bottom test that
refused sound constraints could not push the truth out. B earns its place in
the next result, not this one.

The confidence floor does not appear in the proof. It does not have to: it
removes constraints from the fold, and by the right inclusion of M removing a
constraint can only widen the result. That is why a floored resolution is sound
whenever the unfloored one is, and — by theorem T3 — sound under a weaker
hypothesis besides.

## Corollary C1: a conflict is a witness

The resolver is greedy rather than a plain meet: it sorts the constraints on a
quantity strongest-first and *skips* any whose trial meet would reach bottom,
recording it as a conflict. That machinery is unreachable when the obligations
hold.

> **C1.** Under the hypotheses of T1, together with the *bottom implies empty*
> direction of B, no constraint is ever skipped, and the resolved estimate
> equals the meet of the whole constraint set.

*Proof.* By T1 the accepted estimate always contains `T_q`, and by S the next
constraint admits `T_q`, so the trial meet contains `T_q` by the left inclusion
of M. Its concretisation is therefore non-empty, and by B the bottom test
returns 0. The constraint is accepted.

Conflict resolution is therefore damage limitation, not part of the soundness
argument: it decides what to do once something has already gone wrong. The
contrapositive is the useful direction — **a conflict observed in a real run is
a witness that some rule violated S or some observation violated W**, and which
constraint was skipped names where to look. A run reports them per quantity
under `--verbose` in the default output mode.

One consequence for the resolver's own contract. Because skipping depends on
what else is present, resolution is *not* monotone in the constraint set once
a conflict does occur: adding a higher-priority contradictory constraint can
displace a lower-priority one that was narrowing an edge, and the resolved
window can widen. Under the obligations that cannot happen, and "estimates only
narrow" is exact. Where it does happen the evidence was already contradictory —
but termination must not, and does not, rest on it.

## Theorem T2: containment survives the read

What consumers read is not the stored estimate. Interior `C_EXCLUDE` holes are
not representable in a single interval, so they are carved at read time by
`quantity_ranges()`, which yields the valid sub-ranges of the estimate with the
holes removed; `quantity_slots()` counts the aligned candidates over them.

> **T2.** Under T1, the truth lies in the carved range set, and the reported
> slot count is an upper bound on the number of placements the evidence still
> admits.

*Proof.* Each carved hole is the complement of `adm(c)` for an excluding
constraint `c`. By S, `T_q` is in `adm(c)`, so `T_q` is not in the hole. `T_q`
is in `gamma(e)` by T1 and in none of the removed holes, hence in the carved
set.

The theorem has a side-condition the accessors state and callers must honour:
the carving floor must be the floor the estimate was resolved at. Carving with a
lower floor would remove candidates on the strength of evidence the estimate
itself was not allowed to use, which is how a below-floor signal would reach a
guaranteed number by the back door.

Residual entropy is reported from that count. Being an upper bound is the
honest direction: it can overstate what KASLR retains against this vantage and
cannot understate it. The slack is whatever the representation could not carry
— a stride whose modulus the folding declined, an operator a lattice's meet
does not model — and the grid the count steps along, which is a resolved
quantity in its own right: where the alignment is only bounded from below, the
count steps finer than the kernel did and reports more placements than exist.

## Theorem T3: the floor separates the two windows

Confidence is a trust ordering (`CONF_PARSED` strongest, `CONF_BRUTE` weakest).
A *floored* run puts a threshold on it. The engine resolves twice from one
evidence build: the **likely** window at `CONF_BRUTE`, which admits every
signal, and the **guaranteed** window at the sound floor `KASLD_SOUND_FLOOR`,
which admits only signals at or above `CONF_INFERRED`.

> **T3.** A run floored at `f` is a function of the observations and coverings
> whose confidence is at least `f`, together with the architecture's constants.

*Proof.* `resolve_evidence()` invalidates every observation and covering below
`f` before any rule runs, and re-applies the gate each time the effective view
is recomputed. A rule sees the gate by reading that effective view — an
observation's `valid` bit, and `covering_active()` for a map. Gating the input
rather than the output is what makes this independent of how a rule labels what
it emits, and it is the only mechanism available to a rule emitting verdicts,
which have no confidence to carry. `estimate_resolve()` independently filters
constraints below `f` out of the fold. Curation is re-derived within the run
rather than inherited: `engine_run_full_floored()` discards any standing
verdicts before resolving, so a verdict reached from evidence this run excludes
cannot invalidate an in-scope observation.

The proof rests on rules consulting the effective view, which is a discipline
rather than something the type system can impose. For coverings it is
machine-checked: `tests/check-covering-consumers` requires every rule reading
`ev->coverings[]` to ask `covering_active()` first, and to be on a reviewed
list. For observations it is held end-to-end instead, by the registry-wide
floor test below — a rule that forgot its `valid` guard would move the
guaranteed window under an injected sub-floor signal, and that is exactly what
the test refuses.

Three things follow, and they are worth separating because they are often run
together.

**A sub-floor signal cannot move the guaranteed window.** A wrong timing
estimate or a broken heuristic can pull *likely* toward the wrong slot and can
do nothing at all to *guaranteed*. This is structural — it holds whatever a rule
does with the inputs it is given, and does not depend on any rule labelling its
output carefully.

**The guaranteed window needs a weaker hypothesis than the likely one.** T1 at
`CONF_BRUTE` requires W of every observation. T1 at the sound floor requires it
only of the observations at or above the floor. That difference is what makes
the guaranteed window the number worth citing: a lying side-channel is outside
its hypothesis altogether.

**Likely is contained in guaranteed by construction.** The speculative window is
clamped into the sound one at the report boundary by
`kasld_clamp_likely_window()`, rather than being trusted to come out nested.

A rule's own confidence labelling is a separate obligation with separate
consequences. A constraint whose value is computed from its lineage should carry
no more confidence than the least confident of those inputs, or reported trust
and resolver priority overstate what the claim rests on. It is not what keeps
sub-floor evidence out of the guaranteed window — T3 does that at the input,
independently of every rule's diligence.

## Theorem T4: termination

> **T4.** `engine_run_full_floored()` terminates. The number of rule passes is
> at most the smaller of `ENGINE_MAX_PASSES` and one more than
> `ENGINE_MAX_CONSTRAINTS`; the number of curation rounds is at most the smaller
> of `ENGINE_MAX_CURATION_ROUNDS` and one more than `MAX_VERDICTS`.

*Proof.* Resolution is a pure function of the constraint set and the floor, and
the constraint store is append-only with duplicate claims dropped on arrival. A
pass that adds no new constraint therefore re-resolves the same set and produces
an estimate vector identical to the snapshot taken at the pass's start, and the
loop exits. Every non-final pass thus adds at least one constraint to a store
with a fixed capacity, which bounds the passes; the pass cap bounds them again.
For curation, `V_INVALID` is a latch and verdicts are deduplicated, so each
round either adds a verdict to a fixed-capacity store or is the last.

Two things this argument deliberately does not use. It does not use any rule
being well-behaved: an unsound rule cannot make the engine hang, only narrow
past the truth. And it does not use the estimates descending monotonically —
they do so under the obligations (corollary C1), but the bound above holds
without it, which is what makes termination structural rather than contingent.

## Theorem T5: saturation widens

Every store in the engine has a fixed capacity and can therefore fill: the
constraint store, a rule's emissions in one call, the per-quantity resolver
gather, the recorded conflicts, the verdict store, the curation rounds. Each
raises its own bit in the engine's saturation mask, reported under `--verbose`.
An observation that finds no room is dropped earlier still, at capture, and is
recorded in the discard ledger rather than in that mask.

> **T5.** With one exception, a cap that binds removes narrowing rather than
> adding it, so the reported window is wider than it would otherwise be and T1
> is unaffected.

Dropping an observation removes the constraints it would have produced.
Truncating a rule's emissions or the resolver's gather applies fewer
constraints. Overflowing the conflict list still skips the conflicting
constraint — only the record of which one is lost. Every one of these can only
widen.

The exception is the verdict store and the curation round cap. Curation
*removes* observations, so failing to complete it leaves an observation in scope
that the engine would have rejected, which can narrow rather than widen. That
matters only where W is already violated, which is outside T1's hypothesis; it
is a robustness limit, not a soundness hole, and it is why those two caps raise
their own saturation bits rather than sharing one.

## Where each obligation is discharged

| obligation | held by |
|---|---|
| A — honest tops contain the truth | the architecture headers and `src/quantities.c`; `test_honest_tops_admit_known_values` in `tests/test_estimate.c`, which asserts known real layouts for the host architecture lie inside the top; `tests/check-arch-axes` refuses a header that leaves a mandatory axis unanswered |
| M — the meet narrows and does not drop | `tests/test_estimate.c` over the lattice-and-operator pairs; `tests/check-lattice-seam` keeps consumers on the accessors, so what a test asserts about `gamma` is what a consumer reads |
| B — bottom means empty | `tests/test_estimate.c`; the power-of-two side-condition at the wire seam (`is_pow2()` in `src/capture.c`) and in the rules that read an alignment from the target |
| W — observations state something true | the components and their tests, and the orchestrator-filled `origin`. Not checkable inside the engine; a violation that reaches the result is caught, if at all, end-to-end by the corpus below |
| S — a rule never excludes the truth | one dedicated test per rule, with `tests/check-rule-registry` refusing a rule that has none; `tests/check-self-edges` for the self-referential case; `tests/check-confidence-floor` for collapsing constraints that would reach the guaranteed window |
| T1 — truth containment | `test_full_engine_property_<arch>` per architecture: over randomly drawn legal layouts and random subsets of faithful leaks, the resolved guaranteed window still contains the truth. `tests/check-property-arches` requires every supported architecture to have one and to run it; `make test-cross` settles it by exit status. On real captures rather than generated ones, `extra/validate-bundle` asserts the same containment against ground truth extracted from the capture, and `tests/validate-fixtures` runs it over every truth-bearing fixture |
| T3 — the floor separates the windows | `test_full_engine_property_<arch>_floor` per architecture, and `test_full_engine_floor_invariant`, which injects an adversarial pin at every sub-floor confidence and requires the whole guaranteed vector to be unchanged, with a positive control proving the injection is live. `test_full_engine_verdict_isolation` covers the inherited-verdict path, where a stale ruling would widen the window instead |

Two of those are worth reading as a pair. `check-rule-registry` proves a test
*exists* for every rule; obligation S is what that test must be testing. A test
that seeds one observation and asserts the estimate moved has shown the rule
works, not that it is sound. The pattern that discharges S adds an adversarial
observation — one that would push the estimate past the truth if the rule
believed it — and asserts the truth survives.

## What the guarantee does not cover

- **Completeness.** The engine is sound, not complete. A wide window means the
  evidence did not narrow it, and says nothing about whether a narrower one is
  derivable by other means. See [limitations.md](limitations.md).
- **The likely window.** Nothing above guarantees it. It admits signals below
  the sound floor precisely so that a good guess can refine the answer, and a
  bad guess can therefore point at the wrong slot. It is reported as
  speculative and is always contained in the guaranteed window.
- **Component truthfulness.** Obligation W is assumed, not proven. A component
  that misreports an address can move the guaranteed window, which is why the
  wire seam, per-component tests and the replay corpus sit where they do.
- **Confidence labelling.** A rule that labels a constraint above the trust of
  the inputs its value came from overstates reported provenance and can win a
  conflict it should have lost. Nothing in the store enforces the ordering: the
  lineage field records what a constraint was derived from without recording
  whether an entry supplied the value or merely gated the rule, and the two do
  not cap the result alike.
- **Interior holes in the stored estimate.** They live at the read seam only.
  Code that reads the stored interval directly, rather than through
  `quantity_ranges()`, sees the holes filled back in.
