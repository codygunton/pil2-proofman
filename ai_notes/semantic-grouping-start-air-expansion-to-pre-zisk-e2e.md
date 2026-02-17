# Semantic Grouping: `start-air-expansion` to `pre-zisk-e2e`

## Overview

This diff covers 20 commits that extend the Python executable STARK spec from supporting 3 test AIRs (SimpleLeft, Lookup2_12, Permutation1_6) to verifying 12 production Zisk zkVM AIR proofs plus a VADCOP aggregated final proof. The work falls into 9 semantic groups, ordered from most architectural to most peripheral.

---

## Group 1: Bytecode Interpreter Recovery and Isolation

**Files affected:**
- `executable-spec/primitives/expression_bytecode/__init__.py` (new)
- `executable-spec/primitives/expression_bytecode/expressions_bin.py` (new, 869 lines)
- `executable-spec/primitives/expression_bytecode/expression_evaluator.py` (new, 767 lines)
- `executable-spec/primitives/expression_bytecode/witness_generation.py` (new, 426 lines)

**Summary:**
Three modules were recovered from git history (commit `731d33f4~1`) where a prior bytecode interpreter had been deleted in favor of hand-written constraint modules. These were placed into a new `primitives/expression_bytecode/` package, isolated from the protocol layer.

**What changed:**
- `expressions_bin.py`: A complete binary parser for compiled PIL expression bytecode (`.bin` files). Parses the three-section format (expressions, constraints, hints) matching C++ `ExpressionsBin` in `expressions_bin.hpp`. Includes `BinFileReader` for little-endian decoding, `ParserParams`/`ParserArgs` data structures, `Hint`/`HintField`/`HintFieldValue` for witness generation hints, and `OpType` enum mapping all 17 operand types.
- `expression_evaluator.py`: The bytecode evaluation engine. `ExpressionsPack` interprets compiled constraint expressions by iterating over rows, loading operands from flat buffers, and applying arithmetic operations (add/sub/mul/sub_swap) in base field (`FF`) or cubic extension (`FF3`). Includes `BufferSet` (flat buffer container replacing the deleted `ProofContext`), `ExpressionsCtx` (memory layout and stride mappings), and `Dest`/`Params` (evaluation parameters).
- `witness_generation.py`: Hint-driven witness computation for lookup and permutation arguments. Implements `calculate_witness_std()` which processes `gsum_col`/`gprod_col` hints to compute running sums/products, plus helper functions for intermediate column computation (`im_col`, `im_airval` hints).

**Key design decisions:**
- The recovered code is isolated in `primitives/expression_bytecode/` with no imports from `protocol/` — only the adapters (Group 2) bridge the two worlds.
- Named buffer type offset constants (`PUBLIC_INPUTS_OFFSET` through `EVALS_OFFSET`) replace magic numbers from the C++ codebase.
- Hint parsing extracted into named helper functions (`_parse_hint`, `_parse_hint_field`, `_parse_hint_field_value`) for readability.
- Mathematical variable citations added to docstrings (N, N_ext, xi, Z_H, zi, o).

---

## Group 2: Bytecode Adapter Wrappers and Registry Toggle

**Files affected:**
- `executable-spec/constraints/bytecode_adapter.py` (new, 507 lines)
- `executable-spec/witness/bytecode_adapter.py` (new, 420 lines)
- `executable-spec/constraints/__init__.py` (modified)
- `executable-spec/witness/__init__.py` (modified)
- `executable-spec/bytecode_utils.py` (new, 34 lines)

**Summary:**
Two adapter modules wrap the bytecode interpreter behind the existing `ConstraintModule` and `WitnessModule` ABCs, plus a registry toggle mechanism that selects between hand-written and bytecode backends per AIR.

**What changed:**
- `constraints/bytecode_adapter.py`: `BytecodeConstraintModule` implements `constraint_polynomial()` for both prover mode (array output over extended domain) and verifier mode (scalar output at single point xi). The critical design insight: the C++ compiled expression `cExpId` computes `Q(x) = C(x)/Z_H(x)` (zerofier division baked in), while the `ConstraintModule` interface expects `C(x)`. The adapter multiplies by `Z_H` to recover `C(x)`: prover path uses `batch_inverse(zi)`, verifier path computes `xi^N - 1` directly.
- `witness/bytecode_adapter.py`: `BytecodeWitnessModule` implements `compute_intermediates()` and `compute_grand_sums()` by running `calculate_witness_std()` from the recovered interpreter. Uses buffer caching (`_ensure_buffers`) so the witness computation runs once but results can be extracted in two calls.
- `constraints/__init__.py`: Added `BYTECODE_AIRS` dict, `_discover_zisk_airs()` auto-discovery function, and `_discover_vadcop_final()` for VadcopFinal. `get_constraint_module()` now checks `BYTECODE_AIRS` first, then `CONSTRAINT_REGISTRY`.
- `witness/__init__.py`: Parallel changes — added `BYTECODE_AIRS` dict (shared discovery via `_discover_zisk_airs()`), updated `get_witness_module()` with same priority order.
- `bytecode_utils.py`: Shared `compute_column_index()` helper for both adapters, extracted to avoid duplication.

**Key design decisions:**
- Buffer reconstruction functions are split into named phases: `_determine_domain_size`, `_reconstruct_aux_trace`, `_reconstruct_const_pols_extended`, `_build_challenges_and_airgroup_values` (constraint adapter) and `_reconstruct_trace_and_aux_trace`, `_reconstruct_const_pols`, `_build_challenges` (witness adapter).
- Z_H correction extracted into `_recover_constraint_from_quotient_prover` and `_recover_constraint_from_quotient_verifier` with clear docstrings explaining the conceptual round-trip.
- The constraint adapter distinguishes base-domain vs extended-domain buffers; the witness adapter only uses base-domain.
- `ZISK_PROVING_KEY_DIR` is hardcoded to `/home/cody/zisk-for-spec/provingKey`.

---

## Group 3: Verifier Custom Commit and Protocol Extensions

**Files affected:**
- `executable-spec/protocol/verifier.py` (major changes, +130/-30 lines)
- `executable-spec/protocol/proof.py` (+98/-6 lines)
- `executable-spec/protocol/stages.py` (+13 lines)
- `executable-spec/protocol/data.py` (+6 lines)
- `executable-spec/protocol/stark_info.py` (+24/-19 lines)
- `executable-spec/protocol/air_config.py` (1-line fix)
- `executable-spec/primitives/merkle_verifier.py` (+37 lines plus formatting)
- `executable-spec/primitives/pol_map.py` (doc update)

**Summary:**
The verifier and proof deserialization code was extended to support custom commits (used by Zisk's Rom AIR), correct constant polynomial indexing for multi-instance names, VADCOP final proof format, and several bug fixes.

**What changed in `verifier.py`:**
- `_parse_polynomial_values()`: Added parsing of custom commit polynomial query values from proof trees. Constants now track per-name indices (e.g., Zisk SpecifiedRanges has 33 entries named "RANGE").
- `_build_ev_id_to_poly_id_map()`: Added custom commit polynomial ID mapping using `(commit_id, pol_id)` tuple keys. Constants use incrementing indices for same-name entries.
- `_build_verifier_data()`: Added `publics`, `air_values`, `proof_values` parameters, passed through to `VerifierData` as flat numpy arrays for the bytecode adapter. Fixed `ev_type` comparison to use `EvMap.Type.cm` / `EvMap.Type.const_` instead of string `.name` comparison. Added `EvMap.Type.custom` handling.
- `_reconstruct_transcript()`: Now accepts `global_challenge=None` for VadcopFinal proofs, with alternative transcript seeding: `verkey + hashed_publics + root1`. Replaced `stark_info.air_values_map.index(air_value)` with enumerate-based indexing.
- `_verify_evaluations()`: Now passes `publics`, `air_values`, `proof_values` through to `_build_verifier_data`.
- `_verify_custom_commit_merkle()`: Fully implemented (was stub returning `True`). Creates `MerkleVerifier.for_custom_commit()` and verifies all queries.
- `_evaluate_constraint_with_module()`: Uses `_compute_xi_to_trace_size()` with O(log N) exponentiation instead of O(N) loop.
- Residual check simplified to single boolean expression.

**What changed in `proof.py`:**
- `from_bytes_full()`: Custom commit tree parsing added (Section 8). `pol_queries` and `last_levels` now include `n_custom` additional tree slots (`n_trees = n_stages + 2 + n_custom`). Air values parsing fixed: always reads `FIELD_EXTENSION_DEGREE` uint64s per entry (matching C++ binary format).
- `to_bytes_full_from_dict()`: Custom commit serialization added.
- `from_vadcop_final_bytes()`: New function parsing VadcopFinal proof binary with embedded publics header `[n_publics: u64][publics: n_publics * u64][standard_proof]`.

**What changed in `stark_info.py`:**
- Added `c_exp_id` and `fri_exp_id` fields (expression IDs for bytecode interpreter).
- `_parse_stark_struct()`: Replaced conditional BN128 vs other hash-type logic with `.get()` defaults. `pow_bits` now defaults to 0.

**What changed in `merkle_verifier.py`:**
- Added `for_custom_commit()` class method that constructs a MerkleVerifier for custom commit trees using `tree_idx = n_stages + 2 + commit_idx`.

**What changed in `data.py`:**
- `VerifierData` gained `publics_flat`, `air_values_flat`, `proof_values_flat` numpy array fields for bytecode adapter passthrough.

**What changed in `air_config.py`:**
- `ProverHelpers.from_challenge()`: Fixed `x_n` storage to use `ff3_to_numpy_coeffs(x_n_ff3)` instead of raw `z` array. This was a bug where `x_n` stored the challenge point `z` instead of `z^N`.

**What changed in `stages.py`:**
- Custom commit eval map handling: now raises descriptive `NotImplementedError` with guidance rather than a generic error. Added placeholder for `custom_commits_extended` buffer lookup.

**Key design decisions:**
- The verifier signature changed: `global_challenge` is now `Optional` (defaults to `None`), enabling VadcopFinal verification without a global challenge.
- Constant polynomial indices are no longer hardcoded to 0 — they use incrementing counters for same-name entries.
- Custom commit root comes from `publics[custom_commit.public_values[j]]` rather than from the proof itself.

---

## Group 4: Global Challenge Derivation

**Files affected:**
- `executable-spec/protocol/utils/challenge_utils.py` (new, 66 lines)

**Summary:**
Added multi-AIR global challenge derivation that computes the VADCOP global challenge from per-AIR proof data at test time, eliminating the need for a `global_challenge.json` fixture file.

**What changed:**
- `accumulate_contributions()`: Element-wise sum of per-AIR contribution vectors (mod Goldilocks prime), matching C++ `add_contributions()` for `CurveType::None`.
- `derive_global_challenge_multi_air()`: Full pipeline: accumulate contributions, then hash `[publics, proof_values_stage1, accumulated]` via Poseidon2 transcript to extract a 3-element cubic extension challenge. Takes `lattice_size` parameter (from `globalInfo.latticeSize`).

**Key design decisions:**
- The challenge is derived from data already present in per-AIR proof fixtures, making the test suite self-contained.
- Imports `GOLDILOCKS_PRIME` from `primitives.field` for modular accumulation.

---

## Group 5: Performance Fix (O(N) to O(log N) Exponentiation)

**Files affected:**
- `executable-spec/protocol/verifier.py` (2 locations)
- `executable-spec/constraints/bytecode_adapter.py` (1 location)

**Summary:**
Three locations had naive O(N) loops computing `xi^N` where N = 2^20 (~1 million iterations of FF3 multiplication). Replaced with `xi ** N` which uses galois library's built-in repeated squaring (O(log N)).

**What changed:**
- `_compute_xi_to_trace_size()`: Changed from `for _ in range(trace_size): x_power = x_power * xi` to `return xi ** trace_size`.
- `_evaluate_constraint_with_module()`: Uses the updated `_compute_xi_to_trace_size()`.
- `_recover_constraint_from_quotient_verifier()`: Uses `xi ** N` instead of a loop.

---

## Group 6: Zisk Verifier E2E Tests and Fixtures

**Files affected:**
- `executable-spec/tests/test_zisk_verifier_e2e.py` (new, 195 lines)
- `executable-spec/tests/test_zisk_vadcop_final_e2e.py` (new, 78 lines)
- `executable-spec/tests/test_stark_info.py` (+77 lines)
- `executable-spec/tests/test_bytecode_equivalence.py` (new, 116 lines)
- `executable-spec/tests/test_expressions_bin.py` (new, 382 lines)
- `executable-spec/tests/conftest.py` (+3 lines)
- `executable-spec/tests/json-proof-to-bin.py` (new, 431 lines)
- `executable-spec/tests/test-data/zisk/` (proof fixtures: 12 `.proof.bin` + `.json` files, `publics.json`, `proof_values.json`, `vadcop_final.proof.bin`)

**Summary:**
Complete test infrastructure for Zisk zkVM verification: 12 per-AIR E2E tests, 1 VADCOP final test, bytecode equivalence tests, expression binary parser tests, Zisk StarkInfo parsing tests, and all supporting fixtures.

**What changed:**
- `test_zisk_verifier_e2e.py`: `TestZiskVerifierE2E` with 12 parametrized test cases (Main, Rom, Mem, RomData, InputData, MemAlign, BinaryExtension, BinaryAdd, Binary, SpecifiedRanges, VirtualTable0, VirtualTable1). Global challenge derived at test time via `_derive_global_challenge()` using `@functools.lru_cache`. All 12 pass.
- `test_zisk_vadcop_final_e2e.py`: `TestZiskVadcopFinalE2E` verifies the aggregated VADCOP final proof. Uses `from_vadcop_final_bytes()` and passes `global_challenge=None` to trigger VadcopFinal transcript seeding.
- `test_bytecode_equivalence.py`: `TestVerifierConstraintEquivalence` parametrized over all 3 test AIRs, comparing hand-written vs bytecode constraint evaluation at the same verifier point xi. Validates the adapter produces identical `C(xi)` values.
- `test_expressions_bin.py`: 15+ tests covering BinFileReader header parsing, ExpressionsBin loading (expressions, constraints, hints), ParserParams validation, bytecode offset access, deterministic loading, verifier binary loading. Plus `TestExpressionsBinZisk` auto-discovered tests for all Zisk AIR `.bin` files.
- `test_stark_info.py`: `TestStarkInfoZisk` with auto-discovered parametrized tests: loads_successfully, common_params (nStages=2, qDim=3, nPublics=68), Rom custom commit assertions, non-Rom qDeg=2 assertions, Rom ev_map custom entries, Rom map_sections_n.
- `conftest.py`: Added `ZISK_PROVING_KEY = Path("/home/cody/zisk-for-spec/provingKey")`.
- `json-proof-to-bin.py`: CLI tool converting C++ JSON proofs to binary format. Handles all 13 sections (airgroup values, air values, roots, evals, const tree queries, custom commit trees, stage trees, FRI step roots, FRI step queries, finalPol, nonce). Includes round-trip verification against `from_bytes_full()`.

**Key design decisions:**
- No `pytest.skip()` inside test bodies per project policy. Module-level `pytestmark = pytest.mark.skipif` gates on fixture existence.
- Global challenge is computed once and cached via `lru_cache`.
- Test fixtures generated by GPU prover (byte-identical to CPU).
- No Arith AIR test because Fibonacci(10) guest doesn't exercise it.

---

## Group 7: Zisk Fixture Generation Script

**Files affected:**
- `generate-zisk-test-vectors.sh` (new, 258 lines)

**Summary:**
End-to-end shell script automating Zisk test fixture generation: ROM setup, GPU proof generation, JSON-to-binary conversion, and fixture installation.

**What changed:**
- 6-step pipeline: (1) ROM setup via `cargo-zisk rom-setup`, (2) proof generation via `cargo-zisk prove --save-proofs --emulator`, (3) JSON-to-binary conversion via `json-proof-to-bin.py`, (4) copy fixtures to `test-data/zisk/`, (5) optional VADCOP final proof via `cargo-zisk prove --aggregation`, (6) verification summary.
- Configurable via CLI flags (`--zisk-dir`, `--proving-key`, `--elf`, `--vadcop`) and environment variables.
- Handles known `cargo-zisk` SIGSEGV at cleanup (swallows exit code, verifies proofs in step 3).
- Sets up `LD_LIBRARY_PATH` for Rust stdlib and Intel OneAPI runtime.
- Skips ROM setup if `Rom.const` already exists.

---

## Group 8: GPU Proof ABI Fix

**Files affected:**
- `pil2-stark/src/api/starks_api.cu` (1 line changed)

**Summary:**
Added the missing `proofBinFile` parameter to the `gen_proof()` function signature in the CUDA API, aligning it with the C++ header and Rust FFI bindings.

**What changed:**
- Function signature changed from `..., char *proofFile, void *d_buffers_, ...` to `..., char *proofFile, char *proofBinFile, void *d_buffers_, ...`.

**Key design decision:**
- This is a binary ABI fix. Without it, the GPU prover would misinterpret the parameter positions, causing corrupted output or crashes.

---

## Group 9: Test Infrastructure and Documentation

**Files affected:**
- `executable-spec/run-tests.sh` (+47 lines modified)
- `executable-spec/pyproject.toml` (+1 line)
- `executable-spec/primitives/field.py` (+5 lines)
- `CLAUDE.md` (+70 lines modified)

**Summary:**
Test runner improvements, dependency additions, field utility function, and documentation updates.

**What changed in `run-tests.sh`:**
- Added parallel execution via `pytest-xdist` (default 32 workers, configurable via `PYTEST_WORKERS`).
- Added `zisk` and `vadcop-final` test filter options.
- All test invocations now pass `$PARALLEL_ARGS`.
- `unit` filter now excludes `test_zisk_verifier_e2e.py` and `test_zisk_vadcop_final_e2e.py`.

**What changed in `pyproject.toml`:**
- Added `pytest-xdist>=3.0.0` dependency for parallel test execution.

**What changed in `field.py`:**
- Added `ff3(coeffs)` convenience constructor: creates an FF3 scalar from ascending-order coefficients `[c0, c1, c2]`, handling galois's internal descending order.

**What changed in `CLAUDE.md`:**
- Added Zisk test fixture generation documentation.
- Added `test_expressions_bin.py`, `test_bytecode_equivalence.py`, `test_zisk_verifier_e2e.py` to test suite table.
- Added `TestZiskVerifierE2E` to key test classes.
- Added Testing Rules section (no-skip policy, xfail usage, hardcoded paths).
- Added Code Review Agents section.
- Updated package structure to show `bytecode_adapter.py` and `expression_bytecode/` package.

---

## Commit-to-Group Cross-Reference

| Commit | Group | Description |
|--------|-------|-------------|
| `99450f1c` | 1 | Recover bytecode interpreter from git history |
| `a5b7f1e2` | 2 | Add bytecode adapter wrappers and registry toggle |
| `71cf7158` | 3 | Fix: store z^N in x_n, not raw z |
| `ef8dd021` | 6 | Add bytecode equivalence and parser tests |
| `099c74bd` | 9 | Add bytecode hybrid plan and code review agent instructions |
| `95319bf7` | 9 | Resolve TODOs and update CLAUDE.md |
| `e140112c` | 3 | Add custom commit support for Zisk Rom AIR |
| `cfc41be1` | 2 | Auto-discover Zisk AIRs from v0.15.0 proving key |
| `056c25bc` | 6 | Add Zisk verifier E2E tests (12/13 AIRs pass) |
| `2a711d74` | 9 | Parallel execution, no-skip policy, Zisk starkinfo/bytecode tests |
| `454b96d4` | 9 | Update CLAUDE.md with Zisk tests and no-skip rules |
| `2728297d` | 8 | Fix GPU: add missing proofBinFile parameter |
| `aa4cf5d7` | 1 | Add debug tracing for expression evaluation |
| `8808bc99` | 6 | Regenerate Zisk E2E fixtures with CPU prover |
| `0f24680d` | 2 | Handle custom commit polynomials in verifier buffers |
| `742f49eb` | 5 | Fix O(N) -> O(log N) exponentiation |
| `776ff20d` | 9 | Update hybrid bytecode plan |
| `411ca750` | 9 | Update readme on testing and GPU fixture generation |
| `170b1187` | 6 | Regenerate Zisk E2E fixtures with GPU prover |
| `2c4e9040` | 3, 4 | Add VADCOP final proof verification support |
| `5991622a` | 4 | Derive VADCOP global challenge from per-AIR proofs |
| `c8842175` | 7 | Update generate-zisk-test-vectors.sh for VADCOP |

---

## Statistics

- **20 commits** spanning the range
- **~5,900 lines of diff** (excluding JSON/binary test data)
- **~3,100 lines of new Python code** across 10 new files
- **~350 lines of modified Python code** across 12 existing files
- **12 Zisk AIR proofs** verified end-to-end
- **1 VADCOP final proof** verified end-to-end
- **0 protocol-layer files created** for bytecode support (all adapter code)
