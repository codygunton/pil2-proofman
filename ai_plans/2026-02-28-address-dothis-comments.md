# Address DOTHIS Comments Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Address all 10 `# DOTHIS:` comments left in the diff — adding explanatory comments where asked, and refactoring two helper functions to take `air_config` instead of `stark_info`.

**Architecture:** Mostly comment/documentation additions (Tasks 1–4, 6) plus one behaviour-equivalent refactor (Task 5). No protocol logic changes. All tasks are independent except Task 5, which must run after Tasks 1–4 so the file is in a clean state.

**Tech Stack:** Python, Sphinx Markdown (MyST), `executable-spec/protocol/prover.py`, `executable-spec/primitives/field.py`, `docs/sphinx/part-stark/glossary.md`

---

## Visual Dependency Tree

```
Task 1  (field.py comment)          ──┐
Task 2  (_commit_stage1 comments)   ──┤
Task 3  (_gen_proof_stage2 comments)──┤── all independent
Task 4  (gen_proof comments)        ──┤
Task 5  (air_config refactor)       ──┘── must follow 1-4 (same files)
Task 6  (glossary entries)          ── independent
```

---

## Task 1: Add comment explaining `ff3_from_interleaved_numpy` in `field.py`

**File:** `executable-spec/primitives/field.py`

**Context:** The line `# DOTHIS: explain here hwy this function neds to exist` sits directly above `ff3_from_interleaved_numpy`. Replace it with an explanatory comment.

**Step 1: Replace the DOTHIS comment**

In `field.py`, replace:
```python
# DOTHIS: explain here hwy this function neds to exist
def ff3_from_interleaved_numpy(arr: np.ndarray, n: int) -> FF3:
```
With:
```python
# C++ stores FF3 elements in flat numpy arrays as interleaved coefficients:
# [c0, c1, c2, c0, c1, c2, ...]. The galois FF3 type cannot reinterpret this
# layout directly because it uses descending-coefficient internal storage (c2, c1, c0).
# This function explicitly strides the buffer at positions 0, 1, 2 mod 3 to
# reconstruct the coefficient arrays, then builds a proper FF3 vector.
def ff3_from_interleaved_numpy(arr: np.ndarray, n: int) -> FF3:
```

**Step 2: Lint**
```bash
cd executable-spec && uv run ruff check primitives/field.py
```
Expected: All checks passed!

**Step 3: Commit**
```bash
git add executable-spec/primitives/field.py
git commit -m "docs: explain why ff3_from_interleaved_numpy exists"
```

---

## Task 2: Clarify `_commit_stage1` comments in `prover.py`

**File:** `executable-spec/protocol/prover.py`

Two `# DOTHIS:` comments inside `_commit_stage1`:
1. `# DOTHIS: clarify this, esp the conditional` — above the verkey conditional
2. `# DOTHIS: say what this is used for.` and `# DOTHIS: also make sure "constant polynomial tree" and "auxiliary trace" are in the glossary` — above `aux_trace`

**Step 1: Replace the verkey DOTHIS**

Replace:
```python
    # Build Merkle tree over constant polynomials (immutable AIR parameters)
    # verkey = Merkle root (4 field elements) serving as verification key
    # DOTHIS: clarify this, esp the conditional
    if const_pols_extended is not None and len(const_pols_extended) > 0:
        verkey = committer.build_const_tree(const_pols_extended)
    else:
        verkey = [0] * HASH_SIZE
```
With:
```python
    # Build the verification key from constant polynomial commitments.
    # The verkey is the Merkle root (4 field elements) of the constant polynomial tree.
    # AIRs without constant polynomials (e.g., purely trace-based AIRs) use a zero verkey.
    # This matches C++ proofman: both prover and verifier must agree on this default,
    # because verkey enters the global challenge hash.
    if const_pols_extended is not None and len(const_pols_extended) > 0:
        verkey = committer.build_const_tree(const_pols_extended)
    else:
        verkey = [0] * HASH_SIZE
```

**Step 2: Replace the aux_trace DOTHIS**

Replace:
```python
    # Auxiliary trace buffer: written by stages 2, Q, and FRI at different offsets
    # DOTHIS: say waht this is used for.
    # DOTHIS: also make sure "constant polynomial tree" and "axuiliary trace" are in the glossary
    aux_trace = np.zeros(stark_info.map_total_n, dtype=np.uint64)
```
With:
```python
    # Auxiliary trace buffer: a single flat array that holds all stage-dependent
    # polynomial evaluations beyond stage 1. Each stage writes to a fixed slice:
    #   Stage 2 (im_cluster, gsum, …)   at offsets defined by map_offsets[("cm2", …)]
    #   Quotient polynomial Q(x)          at offsets defined by map_offsets[("q",  True)]
    #   FRI polynomial f(x)               at offsets defined by map_offsets[("f",  True)]
    # stark_info.map_total_n is the total number of uint64 elements across all slices.
    # See glossary: "auxiliary trace".
    aux_trace = np.zeros(stark_info.map_total_n, dtype=np.uint64)
```

**Step 3: Lint**
```bash
uv run ruff check protocol/prover.py
```
Expected: All checks passed!

**Step 4: Commit**
```bash
git add executable-spec/protocol/prover.py
git commit -m "docs: clarify verkey conditional and aux_trace in _commit_stage1"
```

---

## Task 3: Clarify `_gen_proof_stage2_plus` comments in `prover.py`

**File:** `executable-spec/protocol/prover.py`

Two `# DOTHIS:` comments inside `_gen_proof_stage2_plus`:
1. `# DOTHIS: give examples because this is confusing...` — above `calculate_witness` call
2. `# DOTHIS: explain why this conditional` — above the `hash_commits` branch

**Step 1: Replace the calculate_witness DOTHIS**

Replace:
```python
    # Calculate AIR-specific witness polynomials using stage-2 challenges
    # DOTHIS: give examples because this is confusing--isn' tevery witness polynomial air-specific? if i'm wrong, then what isn't?
    # Dispatches to witness module for AIR (SimpleLeft, Lookup2_12, etc.)
    # Writes: im_cluster, gsum columns into aux_trace buffer
    # Returns: airgroup_values (cross-AIR boundary values for VADCOP)
```
With:
```python
    # Calculate stage-2 witness polynomials — the challenge-dependent part of the witness.
    # Stage-1 polynomials are the raw execution trace, fixed before any randomness.
    # Stage-2 polynomials can only be computed AFTER the stage-2 challenge is derived
    # from the stage-1 commitment, because they prove properties about stage-1 using
    # Fiat-Shamir randomness. Examples:
    #   im_cluster (lookup AIRs): multiplicity column — how many times each lookup table
    #     row is queried. Required to prove the lookup argument is balanced.
    #   gsum (bus AIRs): running bus accumulator — the sum of all bus messages sent and
    #     received, used to prove that senders and receivers agree.
    # Dispatches to the witness module registered for this AIR (SimpleLeft, Lookup2_12, …).
    # Writes computed columns into aux_trace; returns airgroup_values (cross-AIR VADCOP data).
```

**Step 2: Replace the hash_commits DOTHIS**

Replace:
```python
    # DOTHIS: explain why this conditional
    if not stark_info.stark_struct.hash_commits:
        transcript.put(evals)
    else:
        evals_as_ints = [int(v) for v in evals]
        evals_hash = list(linear_hash(evals_as_ints, width=POSEIDON2_LINEAR_HASH_WIDTH))
        transcript.put(evals_hash)
```
With:
```python
    # hash_commits controls how evaluations enter the Fiat-Shamir transcript.
    # False (default): absorb individual evaluation field elements directly.
    # True: first compress all evaluations with a Poseidon2 linear hash (16-element
    #   output), then absorb only the digest. This keeps transcript growth bounded
    #   when there are many openings (large ev_map), at the cost of one extra hash.
    # The setting is fixed per-AIR in stark_struct and must match between prover and verifier.
    if not stark_info.stark_struct.hash_commits:
        transcript.put(evals)
    else:
        evals_as_ints = [int(v) for v in evals]
        evals_hash = list(linear_hash(evals_as_ints, width=POSEIDON2_LINEAR_HASH_WIDTH))
        transcript.put(evals_hash)
```

**Step 3: Lint**
```bash
uv run ruff check protocol/prover.py
```
Expected: All checks passed!

**Step 4: Commit**
```bash
git add executable-spec/protocol/prover.py
git commit -m "docs: explain stage-2 witnesses and hash_commits conditional"
```

---

## Task 4: Clarify `gen_proof` comments in `prover.py`

**File:** `executable-spec/protocol/prover.py`

Four `# DOTHIS:` items in `gen_proof`:
1. `# DOTHIS: add a comment here saying what each of these outputs is...` — above `_commit_stage1` call
2. `# DOTHIS: add comments saying what this is` × 3 — on `air_values`, `air_values_stage1`, `proof_values_stage1`

**Step 1: Replace the `_commit_stage1` return-value DOTHIS**

Replace:
```python
    # DOTHIS: add a comment here saying what eact of thse outputs is. in particular why do we have roo1 and commitments -- aren't those the same, or one is included in the other?
    verkey, root1, aux_trace, commitments, committer = _commit_stage1(
```
With:
```python
    # _commit_stage1 returns five objects:
    #   verkey:      Merkle root of the constant polynomial tree (4 ints).
    #                Passed to derive_global_challenge to bind the AIR's constants.
    #   root1:       Merkle root of the stage-1 witness commitment (4 ints).
    #                Passed to derive_global_challenge to bind the stage-1 trace.
    #   aux_trace:   Zeroed flat buffer for stage 2+ polynomial data (see _commit_stage1).
    #   commitments: Mutable list starting as [root1]. Stages 2 and Q append their roots
    #                here; the final list becomes proof["roots"] read by the verifier.
    #   committer:   Stateful PolynomialCommitter that already holds the const_tree and
    #                stage_trees[1]; needed to commit stages 2 and Q, evaluate polys, etc.
    # root1 and commitments[0] are the same value — root1 is kept separately because
    # derive_global_challenge needs it as a standalone argument, while commitments grows.
    verkey, root1, aux_trace, commitments, committer = _commit_stage1(
```

**Step 2: Replace the three air_values/proof_values DOTHIS comments**

Replace:
```python
    # DOTHIS: add comments saying what this is
    air_values = np.zeros(stark_info.air_values_size, dtype=np.uint64)
    # DOTHIS: add comments saying what this is
    air_values_stage1 = _get_air_values_stage1(stark_info, air_values)
    # DOTHIS: add comments saying what this is
    proof_values_stage1 = _get_proof_values_stage1(stark_info)
```
With:
```python
    # air_values: per-AIR instance values — a buffer used by complex AIRs to pass
    # accumulator state between stages (e.g., bus totals in a VADCOP proof). For all
    # currently-supported Simple pilout AIRs, this buffer remains all zeros.
    air_values = np.zeros(stark_info.air_values_size, dtype=np.uint64)
    # air_values_stage1: the subset of air_values written during stage 1. These enter
    # the global challenge hash so verifiers can check cross-AIR state. Returns [] for
    # Simple pilout AIRs (no stage-1 air_values).
    air_values_stage1 = _get_air_values_stage1(stark_info, air_values)
    # proof_values_stage1: cross-AIR boundary values (e.g., bus message totals) at stage 1.
    # These also enter the global challenge hash. Returns [] for all currently-supported AIRs.
    proof_values_stage1 = _get_proof_values_stage1(stark_info)
```

**Step 3: Lint**
```bash
uv run ruff check protocol/prover.py
```
Expected: All checks passed!

**Step 4: Run E2E tests to confirm no behaviour change**
```bash
uv run pytest tests/test_stark_e2e.py -x -q 2>&1 | tail -5
```
Expected: `23 passed`

**Step 5: Commit**
```bash
git add executable-spec/protocol/prover.py
git commit -m "docs: clarify _commit_stage1 return values and air_values in gen_proof"
```

---

## Task 5: Refactor `_get_air_values_stage1` and `_get_proof_values_stage1` to take `air_config`

**File:** `executable-spec/protocol/prover.py`

**Context:** The DOTHIS comment says: "rather than extracting stark_info here and then passing that in in some places, let's just pass in air_config (so you'll have to change some function signatures)". The two helper functions `_get_air_values_stage1` and `_get_proof_values_stage1` currently take `stark_info: StarkInfo`. Change them to take `air_config: AirConfig` and extract `stark_info` internally. Then remove the `stark_info = air_config.stark_info` local from `gen_proof()`.

**Step 1: Update `_get_air_values_stage1` signature and body**

Replace:
```python
def _get_air_values_stage1(stark_info: StarkInfo, air_values: np.ndarray | None) -> list[int]:
    """Extract stage 1 air_values for global_challenge computation.

    C++ reference: proofman.rs:3472-3540 (get_contribution_air)
    Only stage 1 air_values go into global_challenge hash.
    For simple AIRs, this returns an empty list.
    """
    result = []
    if (
        hasattr(stark_info, "air_values_map")
        and stark_info.air_values_map
        and air_values is not None
    ):
        for i, av in enumerate(stark_info.air_values_map):
            if av.stage == 1:
                # Stage 1 air_values are single field elements
                result.append(int(air_values[i]))
    return result
```
With:
```python
def _get_air_values_stage1(air_config: AirConfig, air_values: np.ndarray | None) -> list[int]:
    """Extract stage 1 air_values for global_challenge computation.

    C++ reference: proofman.rs:3472-3540 (get_contribution_air)
    Only stage 1 air_values go into global_challenge hash.
    For simple AIRs, this returns an empty list.
    """
    stark_info = air_config.stark_info
    result = []
    if (
        hasattr(stark_info, "air_values_map")
        and stark_info.air_values_map
        and air_values is not None
    ):
        for i, av in enumerate(stark_info.air_values_map):
            if av.stage == 1:
                # Stage 1 air_values are single field elements
                result.append(int(air_values[i]))
    return result
```

**Step 2: Update `_get_proof_values_stage1` signature**

Replace:
```python
def _get_proof_values_stage1(stark_info: StarkInfo) -> list[int]:
    """Extract stage 1 proof_values for global_challenge computation.

    C++ reference: challenge_accumulation.rs:96-99
    proofValuesMap is empty for all currently-supported AIRs, so this
    always returns []. When non-empty AIRs are added, implement extraction here.
    """
    return []
```
With:
```python
def _get_proof_values_stage1(air_config: AirConfig) -> list[int]:
    """Extract stage 1 proof_values for global_challenge computation.

    C++ reference: challenge_accumulation.rs:96-99
    proofValuesMap is empty for all currently-supported AIRs, so this
    always returns []. When non-empty AIRs are added, implement extraction here.
    """
    return []
```

**Step 3: Update `gen_proof` to remove the `stark_info` local and fix call sites**

In `gen_proof`, remove `stark_info = air_config.stark_info` and update the three call sites:

Replace:
```python
    # DOTHIS: rather than extracting stark_info here and then passing that in in some places, le'ts just passin air_config (so you'll have to change some function signatures)
    stark_info = air_config.stark_info

    # [... _commit_stage1 call ...]

    # air_values: per-AIR instance values ...
    air_values = np.zeros(stark_info.air_values_size, dtype=np.uint64)
    # air_values_stage1: ...
    air_values_stage1 = _get_air_values_stage1(stark_info, air_values)
    # proof_values_stage1: ...
    proof_values_stage1 = _get_proof_values_stage1(stark_info)
    computed_challenge = derive_global_challenge(
        stark_info=stark_info,
```
With (remove the `stark_info` local; use `air_config.stark_info` where still needed):
```python
    # [... _commit_stage1 call unchanged ...]

    # air_values: per-AIR instance values ...
    air_values = np.zeros(air_config.stark_info.air_values_size, dtype=np.uint64)
    # air_values_stage1: ...
    air_values_stage1 = _get_air_values_stage1(air_config, air_values)
    # proof_values_stage1: ...
    proof_values_stage1 = _get_proof_values_stage1(air_config)
    computed_challenge = derive_global_challenge(
        stark_info=air_config.stark_info,
```

**Step 4: Remove `StarkInfo` from imports if no longer used directly in `gen_proof`**

Check if `StarkInfo` is still imported and used elsewhere in `prover.py` (it is — in `derive_challenges_for_stage`, `_compute_all_evals`, etc.). Leave the import unchanged.

**Step 5: Lint**
```bash
uv run ruff check protocol/prover.py
```
Expected: All checks passed!

**Step 6: Run E2E tests**
```bash
uv run pytest tests/test_stark_e2e.py -x -q 2>&1 | tail -5
```
Expected: `23 passed`

**Step 7: Commit**
```bash
git add executable-spec/protocol/prover.py
git commit -m "refactor: _get_air_values_stage1/_get_proof_values_stage1 take air_config"
```

---

## Task 6: Add glossary entries for "constant polynomial tree" and "auxiliary trace"

**File:** `docs/sphinx/part-stark/glossary.md`

**Context:** The DOTHIS comment asked to add these two terms. The glossary uses a notation table — add a separate "Defined Terms" section below it since these are prose concepts, not mathematical symbols.

**Step 1: Append new section to glossary**

At the end of `docs/sphinx/part-stark/glossary.md`, add:

```markdown

## Defined Terms

**Constant polynomial tree**
: Merkle tree built over the constant (precomputed) polynomials of an AIR. Its root is the
  *verification key* (`verkey`) — a 4-element base-field hash that uniquely identifies the
  AIR's fixed parameters. AIRs with no constant polynomials use a zero verkey by convention.
  Python: `committer.build_const_tree(const_pols_extended)` in `protocol/prover.py`.

**Auxiliary trace buffer** (`aux_trace`)
: A single pre-allocated flat `uint64` array that holds all stage-dependent polynomial
  evaluations beyond stage 1. It is partitioned into three non-overlapping slices by
  `stark_info.map_offsets`:
  - Stage 2 polynomials (im_cluster, gsum, …)
  - Quotient polynomial Q(x)
  - FRI polynomial f(x)
  Each stage writes its output into the appropriate slice; the committer reads from the
  relevant slice when building Merkle trees. Total size: `stark_info.map_total_n` uint64s.
```

**Step 2: Commit**
```bash
git add docs/sphinx/part-stark/glossary.md
git commit -m "docs: add 'constant polynomial tree' and 'auxiliary trace' to glossary"
```

---

## Verification Commands

```bash
# After all tasks
cd executable-spec
uv run ruff check .                             # no new lint errors
uv run pytest tests/test_stark_e2e.py -x -q    # 23 passed
./run-tests.sh e2e                              # 30 passed
```
