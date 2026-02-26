# Remove Global Challenge Modes 1 & 3 from gen_proof() Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove Modes 1 (external challenge) and 3 (standalone no-challenge) from `gen_proof()`, leaving Mode 2 (always compute internally) as the only code path. Multi-AIR coordination moves into `prove_simple_pilout()` which calls private prover internals directly.

**Architecture:** Extract Stage 1 commitment and Stage 2+ proving into separate private functions. `gen_proof()` becomes a thin wrapper that computes the challenge and calls them. `prove_simple_pilout()` uses those same private functions to orchestrate multi-AIR proving without going through the `gen_proof()` public API.

**Tech Stack:** Python, numpy, protocol/prover.py, protocol/simple_pilout.py, tests/test_stark_e2e.py

---

## Executive Summary

> **Problem**: `gen_proof()` has three modes controlled by `global_challenge` and `compute_global_challenge` parameters:
> - Mode 1: Accepts an externally-computed challenge (used by multi-AIR coordinator via `simple_pilout.py`)
> - Mode 2: Computes challenge internally via lattice expansion (correct single-AIR VADCOP)
> - Mode 3: No challenge at all, standalone non-VADCOP (dead code)
>
> Mode 1 exists because `prove_simple_pilout_stage1()` computes a multi-AIR challenge externally and needs to pass it into each per-AIR proof. This is the API surface we've been working to eliminate.
>
> **Solution**: Factor `gen_proof()` into two private functions: `_commit_stage1()` and `_gen_proof_stage2_plus()`. The public `gen_proof()` calls both and computes the challenge in between. `prove_simple_pilout()` calls `_commit_stage1()` for all AIRs, derives the shared challenge, then calls `_gen_proof_stage2_plus()` per AIR — never needing Mode 1 in the public API.

## Goals & Objectives

### Primary Goals
- `gen_proof()` takes zero mode-related parameters and always computes the global challenge
- `TestCppBinaryEquivalence` passes using `prove_simple_pilout()` instead of the two-step Mode 1 flow
- All 30 E2E tests continue to pass byte-identically

### Secondary Objectives
- Stage 1 is committed exactly once per AIR in the multi-AIR path (currently committed twice)
- Mode 3 dead code is fully deleted
- Public API of `gen_proof()` is simpler and unambiguous

## Solution Overview

### Approach

Factor `gen_proof()` into two private helpers that can be called independently by `prove_simple_pilout()`:

```
gen_proof()
  ├── _commit_stage1()          ← new private function
  ├── _compute_own_challenge()  ← Mode 2 logic extracted inline
  └── _gen_proof_stage2_plus()  ← new private function
```

```
prove_simple_pilout()
  ├── _commit_stage1()  × 5 AIRs  (Stage 1 only once per AIR)
  ├── derive_global_challenge_multi_air()
  └── _gen_proof_stage2_plus()  × 5 AIRs  (with shared challenge)
```

### Data Flow

```
Multi-AIR path (simple_pilout.py):
  air_data[5 AIRs]
    → _commit_stage1() × 5          → (verkey, root1, aux_trace, commitments) × 5
    → calculate_internal_contribution × 5 → contributions[5]
    → derive_global_challenge_multi_air()  → transcript_seed [3 ints]
    → _gen_proof_stage2_plus() × 5  → proof_dict × 5

Single-AIR path (gen_proof):
  (trace, const_pols, ...)
    → _commit_stage1()               → (verkey, root1, aux_trace, commitments)
    → derive_global_challenge()      → transcript_seed [3 ints]
    → _gen_proof_stage2_plus()       → proof_dict
```

### Expected Outcomes
- `gen_proof(air_config, trace, const_pols, const_pols_extended, public_inputs=...)` — no mode params
- `prove_simple_pilout(air_data)` returns `dict[str, dict]` (air_name → proof_dict) without `gen_proof()` ever receiving an external challenge
- `TestCppBinaryEquivalence` passes (byte-identical with C++) using `prove_simple_pilout()`
- `proof["global_challenge"]` is always a 3-element list, never None

---

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: Every implementation must be production-ready.
2. **MAKE BREAKING CHANGES**: Remove `global_challenge` and `compute_global_challenge` from `gen_proof()` signature.
3. **DO NOT duplicate Stage 1**: `prove_simple_pilout()` must commit Stage 1 exactly once per AIR.
4. **Tests must verify byte-identity**: `TestCppBinaryEquivalence` must still pass with `python_proof_bytes == cpp_proof_bytes`.

### Visual Dependency Tree

```
executable-spec/
├── protocol/
│   ├── prover.py          (Task #1: Factor out _commit_stage1 and _gen_proof_stage2_plus,
│   │                                remove Mode 1/3, simplify gen_proof signature)
│   └── simple_pilout.py   (Task #2: Add prove_simple_pilout() using private prover functions)
│
└── tests/
    └── test_stark_e2e.py  (Task #3: Update TestCppBinaryEquivalence to use prove_simple_pilout)
```

### Execution Plan

#### Group A: Refactor prover.py (independent foundation)

- [ ] **Task #1**: Refactor `protocol/prover.py` — extract private helpers, remove modes 1 & 3

  **File:** `executable-spec/protocol/prover.py`

  **Step 1: Extract `_commit_stage1()`**

  Add a new private function before `gen_proof()` with this signature and body:
  ```python
  def _commit_stage1(
      air_config: AirConfig,
      trace: np.ndarray,
      const_pols_extended: np.ndarray,
  ) -> tuple[list[int], list[int], np.ndarray, list[list[int]]]:
      """Commit Stage 1: build const tree and commit the witness trace.

      Returns:
          verkey: 4-element Merkle root of constant polynomial tree
          root1: 4-element Merkle root of Stage-1 witness commitment
          aux_trace: Zeroed auxiliary trace buffer (stages 2+) for continued proving
          commitments: list of committed roots so far (just [root1] at Stage 1)
      """
      stark_info = air_config.stark_info
      committer = PolynomialCommitter(air_config)
      verkey = list(committer.build_const_tree(const_pols_extended))
      aux_trace = np.zeros(stark_info.map_total_n, dtype=np.uint64)
      root1 = committer.commitStage(1, trace, aux_trace)
      return verkey, list(root1), aux_trace, [list(root1)]
  ```

  **Step 2: Extract `_gen_proof_stage2_plus()`**

  All code in `gen_proof()` AFTER the mode-selection block (i.e., after `transcript.put(transcript_seed)`) through to `return {...}` becomes this private function:
  ```python
  def _gen_proof_stage2_plus(
      air_config: AirConfig,
      const_pols: np.ndarray,
      const_pols_extended: np.ndarray,
      public_inputs: np.ndarray | None,
      verkey: list[int],
      root1: list[int],
      aux_trace: np.ndarray,
      commitments: list[list[int]],
      transcript_seed: list[int],
  ) -> dict:
      """Run Stages 2+ through FRI and return the proof dict.

      transcript_seed is the 3-element global challenge already committed to
      the transcript. Stage 1 must have been committed before calling this.
      """
      stark_info = air_config.stark_info
      transcript = Transcript(
          arity=stark_info.stark_struct.transcript_arity,
          custom=stark_info.stark_struct.merkle_tree_custom,
      )
      transcript.put(transcript_seed)
      # [all existing Stage 2+ code goes here verbatim]
      ...
      return {
          ...
          "global_challenge": transcript_seed,
      }
  ```

  The `Transcript` was previously initialized earlier in `gen_proof()`. Move the Transcript init inside `_gen_proof_stage2_plus()` since it only needs the seed at that point.

  **Step 3: Simplify `gen_proof()`**

  Replace the entire body of `gen_proof()` with:
  ```python
  def gen_proof(
      air_config: AirConfig,
      trace: np.ndarray,
      const_pols: np.ndarray,
      const_pols_extended: np.ndarray,
      public_inputs: np.ndarray | None = None,
  ) -> dict:
      """Generate a STARK proof, computing the global challenge via lattice expansion.

      Args:
          air_config: AIR configuration (stark_info, prover_helpers, etc.)
          trace: Stage-1 committed polynomial buffer (N * n_cm1_cols elements)
          const_pols: Constant polynomial buffer on base domain
          const_pols_extended: Constant polynomial buffer on extended domain
          public_inputs: Public input values (if any)

      Returns:
          Proof dict containing evals, fri_proof, roots, query_proofs, and
          global_challenge (the 3-element transcript seed used by stark_verify).
      """
      stark_info = air_config.stark_info

      verkey, root1, aux_trace, commitments = _commit_stage1(
          air_config, trace, const_pols_extended
      )

      air_values = np.zeros(stark_info.air_values_size, dtype=np.uint64)
      air_values_stage1 = _get_air_values_stage1(stark_info, air_values)
      proof_values_stage1 = _get_proof_values_stage1(stark_info)

      lattice_size = DEFAULT_LATTICE_SIZE
      if air_config.global_info is not None:
          lattice_size = air_config.global_info.lattice_size

      computed_challenge = derive_global_challenge(
          stark_info=stark_info,
          publics=public_inputs,
          root1=root1,
          verkey=verkey,
          air_values=air_values_stage1,
          proof_values_stage1=proof_values_stage1,
          lattice_size=lattice_size,
      )
      transcript_seed = list(computed_challenge[:3])

      return _gen_proof_stage2_plus(
          air_config, const_pols, const_pols_extended,
          public_inputs, verkey, root1, aux_trace, commitments, transcript_seed,
      )
  ```

  **Step 4: Delete Mode 1 and Mode 3 code**
  - Delete the `global_challenge: list[int] | None = None` parameter
  - Delete the `compute_global_challenge: bool = True` parameter
  - Delete the Mode 1 branch: `if global_challenge is not None: ...`
  - Delete the Mode 3 branch: `else: ... transcript_seed = None ...`
  - Delete the `elif compute_global_challenge:` guard (Mode 2 is now unconditional)

  **Step 5: Run linter and tests**
  ```bash
  cd executable-spec
  uv run ruff check protocol/prover.py
  uv run pytest tests/test_stark_e2e.py::TestStarkE2EComplete -x -q
  ```
  Expected: 23 prover E2E tests pass. `TestCppBinaryEquivalence` will fail (fixed in Task #3).

#### Group B: Add `prove_simple_pilout()` to simple_pilout.py (depends on Task #1)

- [ ] **Task #2**: Add `prove_simple_pilout()` to `protocol/simple_pilout.py`

  **File:** `executable-spec/protocol/simple_pilout.py`

  **Step 1: Update imports**

  Add imports for the new private prover functions:
  ```python
  from protocol.prover import _commit_stage1, _gen_proof_stage2_plus, _get_air_values_stage1, _get_proof_values_stage1
  ```
  Also import:
  ```python
  from protocol.utils.challenge_utils import (
      accumulate_contributions,
      calculate_internal_contribution,
      derive_global_challenge_multi_air,
  )
  import numpy as np
  ```

  **Step 2: Add `AIRProveData` dataclass** (extends AIRStage1Data with public_inputs)
  ```python
  @dataclass
  class AIRProveData:
      """All data needed to fully prove one AIR in the Simple pilout."""
      air_config: AirConfig
      trace: np.ndarray
      const_pols: np.ndarray
      const_pols_extended: np.ndarray
      public_inputs: np.ndarray | None = None
  ```

  **Step 3: Add `prove_simple_pilout()` function**

  ```python
  def prove_simple_pilout(
      air_data: dict[str, AIRProveData],
  ) -> dict[str, dict]:
      """Prove all Simple pilout AIRs with the shared multi-AIR global challenge.

      Implements the full C++ proofman VADCOP protocol:
        1. Commit Stage 1 for all AIRs (exactly once per AIR).
        2. Compute each AIR's Poseidon2 lattice contribution from (verkey, root1).
        3. Accumulate contributions element-wise → shared global challenge.
        4. Run Stage 2+ for each AIR using the shared challenge.

      Args:
          air_data: Dict mapping starkinfo AIR name → AIRProveData for all five AIRs.

      Returns:
          Dict mapping AIR name → proof_dict (same structure as gen_proof() returns).
      """
      # Stage 1: commit all AIRs and gather contributions
      stage1_cache: dict[str, tuple] = {}  # air_name → (verkey, root1, aux_trace, commitments)
      contributions: list[list[int]] = []

      for air_name, data in air_data.items():
          verkey, root1, aux_trace, commitments = _commit_stage1(
              data.air_config, data.trace, data.const_pols_extended
          )
          stage1_cache[air_name] = (verkey, root1, aux_trace, commitments)

          contribution = calculate_internal_contribution(
              stark_info=data.air_config.stark_info,
              verkey=verkey,
              root1=root1,
              air_values=[],  # All Simple AIRs have no air_values
              lattice_size=LATTICE_SIZE,
          )
          contributions.append(contribution)

      # Derive shared global challenge from all AIR contributions
      global_challenge = derive_global_challenge_multi_air(
          publics=[],
          n_publics=0,
          proof_values_stage1=[],
          contributions=contributions,
          transcript_arity=TRANSCRIPT_ARITY,
          merkle_tree_custom=False,
          lattice_size=LATTICE_SIZE,
      )
      transcript_seed = list(global_challenge[:3])

      # Stage 2+: prove each AIR using the shared challenge
      proofs: dict[str, dict] = {}
      for air_name, data in air_data.items():
          verkey, root1, aux_trace, commitments = stage1_cache[air_name]
          proof = _gen_proof_stage2_plus(
              data.air_config,
              data.const_pols,
              data.const_pols_extended,
              data.public_inputs,
              verkey,
              root1,
              aux_trace,
              commitments,
              transcript_seed,
          )
          proofs[air_name] = proof

      return proofs
  ```

  **Step 4: Verify linter**
  ```bash
  uv run ruff check protocol/simple_pilout.py
  ```

#### Group C: Update tests (depends on Task #2)

- [ ] **Task #3**: Update `tests/test_stark_e2e.py` — replace Mode 1 flow with `prove_simple_pilout()`

  **File:** `executable-spec/tests/test_stark_e2e.py`

  **Step 1: Update imports at top of file**

  Replace:
  ```python
  from protocol.simple_pilout import AIRStage1Data, prove_simple_pilout_stage1
  ```
  With:
  ```python
  from protocol.simple_pilout import AIRProveData, AIRStage1Data, prove_simple_pilout, prove_simple_pilout_stage1
  ```

  **Step 2: Update `test_full_binary_proof_match()`**

  The current test does:
  1. `_load_all_simple_air_data()` for all 5 AIRs
  2. Build `AIRStage1Data` for each
  3. Call `prove_simple_pilout_stage1()` to get `result.global_challenge`
  4. Call `gen_proof(..., global_challenge=result.global_challenge)` for the target AIR

  Replace with:
  ```python
  @pytest.mark.parametrize("test_air_name", SIMPLE_PILOUT_AIR_NAMES,
                           ids=SIMPLE_PILOUT_AIR_NAMES)
  def test_full_binary_proof_match(self, test_air_name: str) -> None:
      """Prove all Simple AIRs with the shared multi-AIR global challenge and compare bytes with C++."""
      all_data = self._load_all_simple_air_data()

      # Build AIRProveData for all five AIRs
      air_prove_data = {
          name: AIRProveData(
              air_config=data[0],
              trace=data[1],
              const_pols=data[2],
              const_pols_extended=data[3],
              public_inputs=data[4],
          )
          for name, data in all_data.items()
      }

      # Prove all five AIRs with shared global challenge (no Mode 1 needed)
      all_proofs = prove_simple_pilout(air_prove_data)

      # Compare the target AIR's proof bytes with C++
      starkinfo_name = SIMPLE_PILOUT_STARKINFO_AIR_NAMES[test_air_name]
      air_config = all_data[starkinfo_name][0]
      proof_dict = all_proofs[starkinfo_name]

      python_proof_bytes = to_bytes_full_from_dict(proof_dict, air_config.stark_info)

      config = AIR_CONFIGS[test_air_name]
      bin_path = TEST_DATA_DIR / config['test_vector'].replace('.json', '.proof.bin')
      with open(bin_path, 'rb') as f:
          cpp_proof_bytes = f.read()

      py_bin_path = TEST_DATA_DIR / config['test_vector'].replace('.json', '.proof.py.bin')
      with open(py_bin_path, 'wb') as f:
          f.write(python_proof_bytes)

      assert len(python_proof_bytes) == len(cpp_proof_bytes), (
          f"{test_air_name}: proof size mismatch "
          f"(Python {len(python_proof_bytes)}, C++ {len(cpp_proof_bytes)})"
      )
      assert python_proof_bytes == cpp_proof_bytes, (
          f"{test_air_name}: byte mismatch. Diff: cmp -l {bin_path} {py_bin_path}"
      )
  ```

  **Step 3: Update class docstring for `TestCppBinaryEquivalence`**

  Update the docstring to say:
  ```
  Protocol:
    1. Load Stage-1 traces for all five Simple pilout AIRs from C++ test vectors.
    2. Call prove_simple_pilout() which commits all Stage-1 witnesses, derives the
       shared multi-AIR global challenge, and proves Stage 2+ for each AIR.
    3. Compare each proof byte-for-byte with the C++ binary proof file.
  ```
  Remove references to "Mode 1 external VADCOP".

  **Step 4: Run verification**
  ```bash
  uv run pytest tests/test_stark_e2e.py -x -q
  ```
  Expected: ALL 30 E2E tests pass, including `TestCppBinaryEquivalence`.

#### Group D: Update verifier docstring (parallel with A)

- [ ] **Task #4**: Update `protocol/verifier.py` docstring for `stark_verify()` and `_reconstruct_transcript()`

  **File:** `executable-spec/protocol/verifier.py`

  **Step 1**: In `_reconstruct_transcript()`, update the `global_challenge=None` branch comment:

  Replace:
  ```python
  else:
      # VadcopFinal or Standalone: WE reconstruct from components
  ```
  With:
  ```python
  else:
      # VadcopFinal: this verifier IS the outer coordinator layer.
      # (Standalone non-VADCOP mode has been removed from the prover.)
  ```

  **Step 2**: In `stark_verify()` docstring, update the `global_challenge` parameter description:

  Change from:
  ```
  global_challenge: The 3-element transcript seed from proof['global_challenge'].
                    None for standalone (non-VADCOP) or VadcopFinal proofs.
  ```
  To:
  ```
  global_challenge: The 3-element transcript seed from proof['global_challenge'].
                    Always provided for per-AIR VADCOP proofs.
                    None only for VadcopFinal (outer coordinator verifier).
  ```

  **Step 3**: Run linter
  ```bash
  uv run ruff check protocol/verifier.py
  ```

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create TodoWrite tasks matching the checkboxes
3. **Execute & Update**: For each task:
   - Mark TodoWrite as `in_progress` when starting
   - Update checkbox `[ ]` to `[x]` when completing
   - Mark TodoWrite as `completed` when done
4. **Maintain Sync**: Keep this file and TodoWrite synchronized throughout

### Critical Rules
- Task #1 (prover.py) must complete before Task #2 (simple_pilout.py)
- Task #2 must complete before Task #3 (tests)
- Task #4 (verifier docstring) is independent and can run in parallel with Task #1
- After Task #3: run `uv run pytest tests/test_stark_e2e.py -x -q` — all 30 must pass
- After all tasks: run `./run-tests.sh e2e` — all 19 E2E tests must pass
- Tasks should be run in parallel where possible using subtasks

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

### Verification Commands
```bash
# After Task #1
uv run ruff check protocol/prover.py
uv run pytest tests/test_stark_e2e.py::TestStarkE2EComplete -x -q  # 23 pass

# After Task #2
uv run ruff check protocol/simple_pilout.py

# After Task #3
uv run pytest tests/test_stark_e2e.py -x -q  # All 30 pass

# Final
./run-tests.sh e2e  # All 19 E2E tests pass
uv run ruff check .  # No lint errors
```
