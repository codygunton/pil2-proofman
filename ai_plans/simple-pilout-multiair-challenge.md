# Simple Pilout Multi-AIR Global Challenge Implementation Plan

## Executive Summary

The simple pilout comprises five AIRs: **SimpleLeft, SimpleRight, U8Air, U16Air, SpecifiedRanges**.
The C++ proofman proves all five simultaneously and derives `global_challenge` by element-wise
accumulating each AIR's Poseidon2 lattice contribution before any AIR advances to Stage 2.

Python currently only proves **SimpleLeft** and uses its single-AIR contribution as the
global challenge (Mode 2 single-AIR). This produces a different challenge than C++ (which
accumulates all five), so no byte-identical comparison is possible against C++ proofs.

**Proposed solution:**

1. Add Python witness generators for the four missing AIRs — they derive their Stage-1
   traces from SimpleLeft's witness (permutation provers, range multiplicity tables).
2. Extend `generate-test-vectors.sh` to extract test vectors (trace + const_pols + binary proof)
   for all five AIRs from the existing C++ simple pilout run.
3. Add a `prove_simple_pilout_stage1()` helper that commits Stage 1 for all five AIRs,
   collects contributions, and calls `derive_global_challenge_multi_air()`.
4. Reinstate byte-identical C++ comparison tests, now using the Python-computed multi-AIR
   global challenge instead of reading it from the test vector JSON.

```
Data flow (multi-AIR challenge):

SimpleLeft witness ──────┐
SimpleRight witness ─────┤
U8Air witness ───────────┼─ commitStage(1) for each ──► stage1_commitments[5]
U16Air witness ──────────┤                              + verkeys[5]
SpecifiedRanges witness ─┘
                              ↓
              calculate_internal_contribution(verkey_i, root1_i) for each i
                              ↓
              accumulate_contributions([c_0, c_1, c_2, c_3, c_4])
                              ↓
              derive_global_challenge_multi_air(publics=[], contributions)
                              ↓
              global_challenge  ──►  gen_proof(each AIR, global_challenge=gc, Mode 1)
                              ↓
              SimpleLeft proof ──►  assert == simple-left.proof.bin  ✓
```

## Goals & Objectives

### Primary Goals
- Python computes the correct five-AIR global challenge, matching C++ to within hash equivalence.
- All five simple pilout AIRs are provable end-to-end in Python.
- Byte-identical comparison tests for SimpleLeft are reinstated using this challenge.

### Secondary Objectives
- Round-trip (prove + Python verify) tests for all five AIRs individually.
- AIR_CONFIGS extended so all five AIRs appear in parametrised test runs.
- `generate-test-vectors.sh` extended so a single run captures all five simple AIR test vectors.

## Solution Overview

### Approach

The Stage-1 witnesses for SimpleRight, U8Air, U16Air, and SpecifiedRanges are entirely derived
from SimpleLeft's witness:

| AIR | Witness derivation |
|-----|--------------------|
| **SimpleRight** | permutation proves of SimpleLeft's bus-2 columns [e,f]; lookup proves of SimpleLeft's bus-3 columns [g,h] with counted multiplicities |
| **U8Air** | multiplicity counts of each U8 value (0–255) across SimpleLeft's k[0], k[2], k[3] columns; table has 128 rows × 2 multiplicity columns |
| **U16Air** | multiplicity counts of each U16 value (0–65535) across SimpleLeft's k[1]; 16384 rows × 4 columns |
| **SpecifiedRanges** | multiplicity counts for custom ranges (k[4]: 0–255, k[5]: −128 to −1, k[6]: −128 to 127); 64 rows × 11 columns |

Stage-2 witnesses (im_cluster, gsum) are already handled by the bytecode fallback adapters;
no new constraint modules are required.

### Key Components

1. **`witness/simple_right.py`** — derives SimpleRight's Stage-1 trace from SimpleLeft's columns
2. **`witness/u8_air.py`** — computes U8 range multiplicity table from SimpleLeft k columns
3. **`witness/u16_air.py`** — computes U16 range multiplicity table
4. **`witness/specified_ranges.py`** — computes custom-range multiplicity table
5. **`generate-test-vectors.sh`** — extended to extract test vectors for all 5 Simple AIRs
6. **`protocol/simple_pilout.py`** — `prove_simple_pilout_stage1()` multi-AIR Stage-1 helper
7. **`tests/test_stark_e2e.py`** — extended AIR_CONFIGS + new `TestCppBinaryEquivalence` class

### Architecture Diagram

```
executable-spec/
├── witness/
│   ├── base.py                   (unchanged)
│   ├── simple_left.py            (unchanged)
│   ├── simple_right.py           (NEW: Task A2)
│   ├── u8_air.py                 (NEW: Task A3)
│   ├── u16_air.py                (NEW: Task A4)
│   ├── specified_ranges.py       (NEW: Task A5)
│   └── __init__.py               (Task B1: register 4 new modules)
│
├── protocol/
│   ├── simple_pilout.py          (NEW: Task B2 – multi-AIR Stage-1 helper)
│   └── utils/
│       └── challenge_utils.py    (unchanged – derive_global_challenge_multi_air already exists)
│
├── tests/
│   ├── test_stark_e2e.py         (Task C1: extend AIR_CONFIGS + TestCppBinaryEquivalence)
│   └── test-data/                (Task A1: 4 new JSON + 4 new .proof.bin files)
│       ├── simple-right.json     (NEW)
│       ├── u8-air.json           (NEW)
│       ├── u16-air.json          (NEW)
│       ├── specified-ranges.json (NEW)
│       ├── simple-right.proof.bin (NEW)
│       ├── u8-air.proof.bin      (NEW)
│       ├── u16-air.proof.bin     (NEW)
│       └── specified-ranges.proof.bin (NEW)
│
└── generate-test-vectors.sh      (Task A1: extend simple case)
```

### Expected Outcomes

- `pytest tests/test_stark_e2e.py::TestCppBinaryEquivalence` passes, comparing
  `simple-left.proof.bin` byte-for-byte using a Python-computed multi-AIR global challenge.
- `pytest tests/test_stark_e2e.py` runs all existing Mode-2 round-trip tests unchanged (no regression).
- `pytest tests/test_stark_e2e.py -k simple` parametrises over all five Simple AIRs for
  round-trip verification.
- `./generate-test-vectors.sh simple` generates test vectors for all five Simple AIRs
  in a single run.

---

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES

1. **No placeholder code** — every function must be complete and production-ready.
2. **Breaking changes are acceptable** — if a cleaner API requires changing callers, do so.
3. **Bytecode for Stage 2** — do not write constraint modules for the four new AIRs; the
   existing bytecode adapter (`BytecodeConstraintModule`, `BytecodeWitnessModule`) handles
   Stage-2 evaluation automatically once the `.bin` bytecode files are discovered via `starkinfo`.
4. **Witness consistency** — for byte-identical C++ comparison, Stage-1 traces extracted from
   test vectors (C++ output) must be used. Python-generated witnesses are for round-trip tests only.
5. **Module registration** — all new witness modules must be registered in `witness/__init__.py`
   using the exact AIR name strings that appear in starkinfo: `"SimpleRight"`, `"U8Air"`,
   `"U16Air"`, `"SpecifiedRanges"`.

---

### Visual Dependency Tree

```
generate-test-vectors.sh    (Task A1 – test vector extraction)
├── tests/test-data/simple-right.json
├── tests/test-data/u8-air.json
├── tests/test-data/u16-air.json
└── tests/test-data/specified-ranges.json

witness/simple_right.py     (Task A2)
witness/u8_air.py           (Task A3)
witness/u16_air.py          (Task A4)
witness/specified_ranges.py (Task A5)
      │
      └── witness/__init__.py  (Task B1 – register all 4)
                │
                └── protocol/simple_pilout.py  (Task B2 – multi-AIR helper)
                              │
                              └── tests/test_stark_e2e.py  (Task C1 – tests)
```

---

### Execution Plan

#### Group A: Foundation (all tasks independent, run in parallel)

- [ ] **Task A1**: Extend `generate-test-vectors.sh` to extract test vectors for all five Simple AIRs

  **File:** `generate-test-vectors.sh`

  **What changes:** The existing `simple)` case calls `generate_vectors` once for `SimpleLeft_0`.
  Add four more `generate_vectors` calls within the same `simple)` block, one for each remaining AIR.
  The C++ proofman already proves all five AIRs in a single run and writes their proof JSON files to
  `$OUTPUT_DIR/proofs/`. Only the Python extraction step is missing.

  **Specific additions to the `simple)` case:**
  ```bash
  generate_vectors "simple" "SimpleRight" \
      "$ROOT_DIR/pil2-components/test/simple/build" \
      "libsimple.so" "SimpleRight_0" "simple-right.json" \
      "build/Simple/airs/SimpleRight/air/SimpleRight.starkinfo.json"

  generate_vectors "simple" "U8Air" \
      "$ROOT_DIR/pil2-components/test/simple/build" \
      "libsimple.so" "U8Air_0" "u8-air.json" \
      "build/Simple/airs/U8Air/air/U8Air.starkinfo.json"

  generate_vectors "simple" "U16Air" \
      "$ROOT_DIR/pil2-components/test/simple/build" \
      "libsimple.so" "U16Air_0" "u16-air.json" \
      "build/Simple/airs/U16Air/air/U16Air.starkinfo.json"

  generate_vectors "simple" "SpecifiedRanges" \
      "$ROOT_DIR/pil2-components/test/simple/build" \
      "libsimple.so" "SpecifiedRanges_0" "specified-ranges.json" \
      "build/Simple/airs/SpecifiedRanges/air/SpecifiedRanges.starkinfo.json"
  ```

  **Note:** The C++ build and proof generation steps are **shared** across all five calls (they run
  once during `SimpleLeft` processing). The four new calls only execute the Python parsing step,
  which is fast. The `generate_vectors` function must be checked to ensure it does not re-run the
  C++ build if artifacts already exist in `$OUTPUT_DIR` from the SimpleLeft call. If it does
  re-run, add a guard: check for the existence of `$OUTPUT_DIR/proofs/SimpleLeft_0.json` and skip
  the build and proof-generation steps for subsequent calls.

  **Outputs:**
  - `executable-spec/tests/test-data/simple-right.json`
  - `executable-spec/tests/test-data/u8-air.json`
  - `executable-spec/tests/test-data/u16-air.json`
  - `executable-spec/tests/test-data/specified-ranges.json`
  - `executable-spec/tests/test-data/simple-right.proof.bin`
  - `executable-spec/tests/test-data/u8-air.proof.bin`
  - `executable-spec/tests/test-data/u16-air.proof.bin`
  - `executable-spec/tests/test-data/specified-ranges.proof.bin`

---

- [ ] **Task A2**: Write `executable-spec/witness/simple_right.py`

  **Context:** SimpleRight (8 rows, 5 witness columns: a, b, c, d, mul) proves two bus operations:
  - `permutation(2, [a, b])`: [a, b] must be a permutation of SimpleLeft's [e, f] columns
    (bus 2 that SimpleLeft `assumes`). SimpleRight proves bus 2 jointly (proves and assumes
    are the same bus, so SimpleRight IS the prover of whatever SimpleLeft assumed on bus 2).
  - `lookup_proves(3, [c, d], mul)`: [c, d] are the looked-up values; `mul` is the
    multiplicity (how many times SimpleLeft's [g, h] matches this row).

  **Starkinfo:** `n_bits=3` (8 rows), `cm1_n=5` (a, b, c, d, mul), `n_constants=1` (__L1__).

  **Class to implement:**
  ```python
  class SimpleRightWitness(WitnessModule):
      """Stage-1 witness generator for SimpleRight AIR.

      SimpleRight proves the permutation and lookup operations that SimpleLeft assumes.
      Given SimpleLeft's witness columns, derives consistent SimpleRight values.
      """

      @staticmethod
      def compute_trace(
          simple_left_trace: np.ndarray,
          simple_left_stark_info: StarkInfo,
          N: int = 8,
      ) -> np.ndarray:
          """Compute SimpleRight's cm1 trace from SimpleLeft's Stage-1 trace.

          Args:
              simple_left_trace: SimpleLeft's cm1 buffer (N * 15 field elements)
              simple_left_stark_info: SimpleLeft's StarkInfo (for column name lookup)
              N: Trace size (8 rows)

          Returns:
              SimpleRight cm1 buffer (N * 5 field elements): [a, b, c, d, mul]
          """
          # Extract SimpleLeft's e, f columns (bus 2 assumes → SimpleRight proves as permutation)
          # Extract SimpleLeft's g, h columns (bus 3 lookup with mul=-1 → SimpleRight proves)
          # a, b = sorted pairs from SimpleLeft's e, f (permutation prover)
          # c, d, mul = distinct [g,h] pairs from SimpleLeft with their multiplicity counts
          ...

      def compute_intermediates(self, ctx: ConstraintContext) -> dict[str, dict[int, FF3Poly]]:
          # Delegated to bytecode adapter via registry; SimpleRightWitness only computes Stage 1.
          return {}

      def compute_grand_sums(self, ctx: ConstraintContext) -> dict[str, FF3Poly]:
          # Delegated to bytecode adapter.
          return {}
  ```

  **Imports needed:**
  ```python
  import numpy as np
  from primitives.field import FF
  from protocol.stark_info import StarkInfo
  from witness.base import WitnessModule, ConstraintContext, FF3Poly
  ```

  **Implementation notes for `compute_trace`:**
  - Extract SimpleLeft's column layout from `simple_left_stark_info.pol_map` to find
    the byte offsets of columns e, f, g, h within the trace buffer.
  - Or, more practically, accept SimpleLeft's columns as named FF arrays directly
    (simpler API, avoids pointer arithmetic into the raw buffer).
  - For the permutation [a, b] = sorted rows of SimpleLeft's [e, f] (lexicographic).
  - For the lookup: collect all (g, h) pairs from SimpleLeft, count occurrences for `mul`,
    deduplicate for (c, d). Pad to N rows with zeros if fewer distinct pairs than N.
  - Return packed cm1 buffer in the interleaved format matching `map_sections_n['cm1']`.

---

- [ ] **Task A3**: Write `executable-spec/witness/u8_air.py`

  **Context:** U8Air (128 rows, 2 witness columns: mul[0], mul[1]) proves the U8 range
  lookups that SimpleLeft uses. The table covers U8 values in two packs per row (128 × 2 = 256
  values). SimpleLeft's columns that use U8 range checks are:
  - k[0]: `range_check(k[0], 0, 2^8-1, predefined: 1)` → U8 (0..255)
  - k[2]: `range_check(k[2], 1, 2^8-1, predefined: 1)` → U8 nonzero (1..255)
  - k[3]: `range_check(k[3], 0, 2^8, predefined: 1)` → (0..256)

  **Starkinfo:** `n_bits=7` (128 rows), `cm1_n=2` (mul[0], mul[1]), `n_constants=3`
  (RANGE[0], RANGE[1], __L1__). The RANGE constants pre-define what values each row covers.

  **Class to implement:**
  ```python
  class U8AirWitness(WitnessModule):
      """Stage-1 witness generator for U8Air AIR.

      Computes multiplicity columns mul[0], mul[1]: for each of the 256 U8 values,
      counts how many times it appears across SimpleLeft's U8 range-check columns.
      """

      @staticmethod
      def compute_trace(
          simple_left_k: np.ndarray,
          columns_using_u8: list[int],
          N: int = 128,
      ) -> np.ndarray:
          """Compute U8Air's cm1 trace.

          Args:
              simple_left_k: Array of shape (8, 7) with SimpleLeft's k[0..6] column values
              columns_using_u8: Indices into k of columns subject to U8 range checks
                  (k[0]=0, k[2]=2, k[3]=3 for predefined U8 range checks)
              N: Trace size = 128 rows

          Returns:
              cm1 buffer (128 * 2 field elements): [mul0_row0, mul1_row0, mul0_row1, ...]
              mul[i][row] = number of occurrences of value (row * 2 + i) across all
              SimpleLeft k rows subject to U8 range checks.
          """
          ...

      def compute_intermediates(self, ctx): return {}
      def compute_grand_sums(self, ctx): return {}
  ```

  **Implementation note:** The RANGE constant columns define which values each row covers.
  Check the U8Air starkinfo or const tree to confirm the exact packing (value = row * 2 + col_index
  or similar). Match exactly how the C++ witness library packs them.

---

- [ ] **Task A4**: Write `executable-spec/witness/u16_air.py`

  **Context:** U16Air (16384 rows, 4 witness columns: mul[0..3]) proves U16 range lookups.
  SimpleLeft's column k[1] uses `range_check(k[1], 0, 2^16-1, predefined: 1)`.
  16384 rows × 4 columns = 65536 values covering the full U16 range.

  **Starkinfo:** `n_bits=14` (16384 rows), `cm1_n=4`, `n_constants=5` (4 RANGE + __L1__).

  **Class to implement:**
  ```python
  class U16AirWitness(WitnessModule):
      """Stage-1 witness generator for U16Air AIR.

      Computes multiplicity columns mul[0..3]: for each of the 65536 U16 values,
      counts how many times it appears in SimpleLeft's k[1] column.
      """

      @staticmethod
      def compute_trace(
          simple_left_k1: np.ndarray,
          N: int = 16384,
      ) -> np.ndarray:
          """Compute U16Air's cm1 trace.

          Args:
              simple_left_k1: Array of 8 field elements (SimpleLeft's k[1] column)
              N: Trace size = 16384 rows

          Returns:
              cm1 buffer (16384 * 4 field elements)
              mul[j][row] = number of occurrences of value (row * 4 + j) in simple_left_k1
          """
          ...

      def compute_intermediates(self, ctx): return {}
      def compute_grand_sums(self, ctx): return {}
  ```

---

- [ ] **Task A5**: Write `executable-spec/witness/specified_ranges.py`

  **Context:** SpecifiedRanges (64 rows, 11 witness columns: mul[0..10]) proves custom
  (non-predefined) range lookups. SimpleLeft uses:
  - k[4]: `range_check(k[4], 0, 2^8-1, predefined: 0)` → custom 0..255
  - k[5]: `range_check(k[5], -2^7, -1, predefined: 0)` → custom −128..−1
  - k[6]: `range_check(k[6], -2^7-1, 2^7-1, predefined: 0)` → custom −129..127

  **Starkinfo:** `n_bits=6` (64 rows), `cm1_n=11`, `n_constants=12` (11 RANGE + __L1__).

  **Class to implement:**
  ```python
  class SpecifiedRangesWitness(WitnessModule):
      """Stage-1 witness generator for SpecifiedRanges AIR.

      Computes multiplicity columns for three custom range-check buses derived
      from SimpleLeft's k[4], k[5], k[6] columns.
      """

      @staticmethod
      def compute_trace(
          simple_left_k456: np.ndarray,
          const_pols: np.ndarray,
          N: int = 64,
      ) -> np.ndarray:
          """Compute SpecifiedRanges cm1 trace.

          The const_pols RANGE columns define what value each (row, mul_idx) cell covers.
          Multiplicity for each cell = number of occurrences of that value in the
          corresponding k column of SimpleLeft.

          Args:
              simple_left_k456: Array of shape (8, 3) — SimpleLeft's k[4], k[5], k[6]
              const_pols: SpecifiedRanges constant polynomials (N * 12 elements)
                  The first 11 columns are RANGE values defining coverage.
              N: Trace size = 64 rows

          Returns:
              cm1 buffer (64 * 11 field elements)
          """
          ...

      def compute_intermediates(self, ctx): return {}
      def compute_grand_sums(self, ctx): return {}
  ```

  **Implementation note:** Use the `const_pols` RANGE columns to determine which value
  each `mul[j]` cell represents per row, then count occurrences in SimpleLeft's k columns.
  This avoids hardcoding the range layout and matches C++ exactly.

---

#### Group B: Integration (run after Group A completes; B1 and B2 are independent)

- [ ] **Task B1**: Register new witness modules in `executable-spec/witness/__init__.py`

  **Current state:**
  ```python
  WITNESS_REGISTRY: dict[str, type[WitnessModule]] = {
      'SimpleLeft': SimpleLeftWitness,
      'Lookup2_12': Lookup2_12Witness,
      'Permutation1_6': Permutation1_6Witness,
  }
  ```

  **Required state:**
  ```python
  from witness.simple_right import SimpleRightWitness
  from witness.u8_air import U8AirWitness
  from witness.u16_air import U16AirWitness
  from witness.specified_ranges import SpecifiedRangesWitness

  WITNESS_REGISTRY: dict[str, type[WitnessModule]] = {
      'SimpleLeft': SimpleLeftWitness,
      'SimpleRight': SimpleRightWitness,
      'U8Air': U8AirWitness,
      'U16Air': U16AirWitness,
      'SpecifiedRanges': SpecifiedRangesWitness,
      'Lookup2_12': Lookup2_12Witness,
      'Permutation1_6': Permutation1_6Witness,
  }
  ```

  **Note:** The bytecode fallback (`BYTECODE_AIRS`) continues to handle Stage-2 evaluation
  (im_cluster, gsum) for the four new AIRs. The `WITNESS_REGISTRY` entries override the
  bytecode for Stage-1 only (since `compute_intermediates` and `compute_grand_sums` return
  `{}`, the caller falls through to the bytecode path for those). Verify that the
  `calculate_witness` call site in `prover.py` correctly handles empty returns from
  `compute_intermediates`/`compute_grand_sums` before falling back.

---

- [ ] **Task B2**: Write `executable-spec/protocol/simple_pilout.py`

  **Purpose:** Coordinates multi-AIR Stage-1 commitment across all five Simple AIRs to produce
  the correct global challenge. This is the core new protocol-level function.

  **Imports:**
  ```python
  import numpy as np
  from dataclasses import dataclass
  from protocol.air_config import AirConfig
  from protocol.stages import PolynomialCommitter
  from protocol.utils.challenge_utils import calculate_internal_contribution, derive_global_challenge_multi_air
  from primitives.merkle_tree import MerkleRoot
  ```

  **Functions to implement:**

  ```python
  @dataclass
  class AIRStage1Data:
      """All data needed to prove an AIR in the Simple pilout."""
      air_config: AirConfig
      trace: np.ndarray           # Stage-1 cm1 buffer (N * cm1_cols)
      const_pols: np.ndarray      # Constant polynomials on base domain
      const_pols_extended: np.ndarray  # Constant polynomials on extended domain


  @dataclass
  class SimplePiloutStage1Result:
      """Stage-1 results for all five Simple AIRs."""
      verkeys: dict[str, MerkleRoot]               # air_name → verkey (4 ints)
      stage1_commitments: dict[str, MerkleRoot]    # air_name → root1 (4 ints)
      global_challenge: list[int]                  # 3-element cubic extension challenge


  def prove_simple_pilout_stage1(air_data: dict[str, AIRStage1Data]) -> SimplePiloutStage1Result:
      """Commit Stage 1 for all Simple pilout AIRs and derive the multi-AIR global challenge.

      Implements the C++ proofman pattern:
        1. For each AIR: build const tree (verkey) and commit Stage-1 witness (root1)
        2. For each AIR: compute Poseidon2 lattice contribution from (verkey, root1)
        3. Accumulate all contributions element-wise (mod Goldilocks prime)
        4. Hash accumulated contribution with publics → global_challenge

      Args:
          air_data: Dict mapping air_name → AIRStage1Data for all five Simple AIRs.
              Keys must be: 'SimpleLeft', 'SimpleRight', 'U8Air', 'U16Air', 'SpecifiedRanges'

      Returns:
          SimplePiloutStage1Result with verkeys, stage1_commitments, and global_challenge.

      Notes:
          - The pilout has n_publics=0, so publics are not included in the challenge hash.
          - lattice_size=368 from pilout.globalInfo.json.
          - All five AIRs use the same transcript_arity=4 (from globalInfo).
      """
      LATTICE_SIZE = 368

      verkeys: dict[str, MerkleRoot] = {}
      stage1_commitments: dict[str, MerkleRoot] = {}
      contributions: list[list[int]] = []

      for air_name, data in air_data.items():
          committer = PolynomialCommitter(data.air_config)

          # Build verkey from constant polynomials
          verkey = committer.build_const_tree(data.const_pols_extended)
          verkeys[air_name] = list(verkey)

          # Commit Stage-1 witness
          aux_trace = np.zeros(data.air_config.stark_info.map_total_n, dtype=np.uint64)
          root1 = committer.commitStage(1, data.trace, aux_trace)
          stage1_commitments[air_name] = list(root1)

          # Compute this AIR's lattice contribution
          contribution = calculate_internal_contribution(
              stark_info=data.air_config.stark_info,
              verkey=list(verkey),
              root1=list(root1),
              air_values=[],  # All Simple AIRs have empty air_values
              lattice_size=LATTICE_SIZE,
          )
          contributions.append(contribution)

      # Derive global challenge from all five contributions
      # The Simple pilout has n_publics=0, so the publics list is empty
      global_challenge = derive_global_challenge_multi_air(
          publics=[],
          n_publics=0,
          proof_values_stage1=[],
          contributions=contributions,
          transcript_arity=4,
          merkle_tree_custom=False,
          lattice_size=LATTICE_SIZE,
      )

      return SimplePiloutStage1Result(
          verkeys=verkeys,
          stage1_commitments=stage1_commitments,
          global_challenge=global_challenge,
      )
  ```

---

#### Group C: Tests (run after Group B; C1 is the only task)

- [ ] **Task C1**: Extend `executable-spec/tests/test_stark_e2e.py`

  **Part 1: Extend AIR_CONFIGS**

  Add entries for all four new Simple AIRs:
  ```python
  AIR_CONFIGS = {
      'simple': {...},  # existing
      'simple_right': {
          'test_vector': 'simple-right.json',
          'starkinfo': '../../pil2-components/test/simple/build/provingKey/build/Simple/airs/SimpleRight/air/SimpleRight.starkinfo.json',
          'expressions_bin': '../../pil2-components/test/simple/build/provingKey/build/Simple/airs/SimpleRight/air/SimpleRight.bin',
          'global_info': '../../pil2-components/test/simple/build/provingKey/pilout.globalInfo.json',
      },
      'u8_air': {
          'test_vector': 'u8-air.json',
          'starkinfo': '../../pil2-components/test/simple/build/provingKey/build/Simple/airs/U8Air/air/U8Air.starkinfo.json',
          'expressions_bin': '../../pil2-components/test/simple/build/provingKey/build/Simple/airs/U8Air/air/U8Air.bin',
          'global_info': '../../pil2-components/test/simple/build/provingKey/pilout.globalInfo.json',
      },
      'u16_air': {
          'test_vector': 'u16-air.json',
          'starkinfo': '../../pil2-components/test/simple/build/provingKey/build/Simple/airs/U16Air/air/U16Air.starkinfo.json',
          'expressions_bin': '../../pil2-components/test/simple/build/provingKey/build/Simple/airs/U16Air/air/U16Air.bin',
          'global_info': '../../pil2-components/test/simple/build/provingKey/pilout.globalInfo.json',
      },
      'specified_ranges': {
          'test_vector': 'specified-ranges.json',
          'starkinfo': '../../pil2-components/test/simple/build/provingKey/build/Simple/airs/SpecifiedRanges/air/SpecifiedRanges.starkinfo.json',
          'expressions_bin': '../../pil2-components/test/simple/build/provingKey/build/Simple/airs/SpecifiedRanges/air/SpecifiedRanges.bin',
          'global_info': '../../pil2-components/test/simple/build/provingKey/pilout.globalInfo.json',
      },
      'lookup': {...},      # existing
      'permutation': {...}, # existing
  }
  ```

  The AIR name key in AIR_CONFIGS (e.g., `'simple_right'`) is the test-level identifier;
  the starkinfo AIR name (e.g., `'SimpleRight'`) is what the witness/constraint registry uses.
  Add a `'air_name'` field to each config entry to map between the two where they differ.

  **Part 2: Add a constant mapping Simple AIR names for the pilout tests**

  ```python
  # All five Simple pilout AIRs (for multi-AIR global challenge tests)
  SIMPLE_PILOUT_AIR_NAMES = ['simple', 'simple_right', 'u8_air', 'u16_air', 'specified_ranges']
  SIMPLE_PILOUT_STARKINFO_AIR_NAMES = {
      'simple': 'SimpleLeft',
      'simple_right': 'SimpleRight',
      'u8_air': 'U8Air',
      'u16_air': 'U16Air',
      'specified_ranges': 'SpecifiedRanges',
  }
  ```

  **Part 3: Add `TestCppBinaryEquivalence` class**

  ```python
  class TestCppBinaryEquivalence:
      """Byte-identical comparison between Python and C++ proofs using multi-AIR challenge.

      Protocol:
        1. Load Stage-1 trace for all five Simple AIRs from C++ test vectors.
        2. Commit Stage 1 for all five AIRs to get their stage1_commitments.
        3. Compute global_challenge via five-AIR lattice accumulation.
        4. Prove each AIR fully with this global_challenge (Mode 1).
        5. Compare each AIR's serialized proof byte-for-byte with C++ binary.

      This validates that Python's multi-AIR global challenge computation matches C++
      and that the full proof pipeline (witness → commitment → FRI) is byte-identical.
      """

      pytestmark = pytest.mark.skipif(
          not all(
              (Path(__file__).parent / "test-data" / AIR_CONFIGS[n]['test_vector']).exists()
              for n in SIMPLE_PILOUT_AIR_NAMES
          ),
          reason="Simple pilout test vectors not generated (run generate-test-vectors.sh simple)"
      )

      def _load_all_simple_air_data(self) -> dict[str, tuple]:
          """Load (air_config, trace, const_pols, const_pols_extended, public_inputs) for all five."""
          result = {}
          for test_name in SIMPLE_PILOUT_AIR_NAMES:
              air_config = load_air_config(test_name)
              vectors = load_test_vectors(test_name)
              if air_config is None or vectors is None:
                  pytest.fail(f"Missing test data for {test_name}")
              trace, const_pols, const_pols_extended, public_inputs = \
                  create_buffers_from_vectors(air_config.stark_info, vectors)
              result[SIMPLE_PILOUT_STARKINFO_AIR_NAMES[test_name]] = (
                  air_config, trace, const_pols, const_pols_extended, public_inputs
              )
          return result

      def test_global_challenge_matches_cpp(self) -> None:
          """Verify that the Python multi-AIR global challenge equals C++'s value.

          C++ proofman stores global_challenge in each AIR's test vector JSON
          (under inputs.global_challenge). All five should contain the same value.
          """
          from protocol.simple_pilout import AIRStage1Data, prove_simple_pilout_stage1

          all_data = self._load_all_simple_air_data()
          air_stage1 = {
              name: AIRStage1Data(
                  air_config=data[0],
                  trace=data[1],
                  const_pols=data[2],
                  const_pols_extended=data[3],
              )
              for name, data in all_data.items()
          }

          result = prove_simple_pilout_stage1(air_stage1)

          # Read C++ global_challenge from SimpleLeft test vector (same for all 5 AIRs)
          simple_vectors = load_test_vectors('simple')
          cpp_global_challenge = simple_vectors['inputs']['global_challenge']

          assert list(result.global_challenge) == list(cpp_global_challenge), (
              f"Python multi-AIR global challenge does not match C++.\n"
              f"  Python: {result.global_challenge}\n"
              f"  C++:    {cpp_global_challenge}"
          )

      @pytest.mark.parametrize("test_air_name", SIMPLE_PILOUT_AIR_NAMES)
      def test_full_binary_proof_match(self, test_air_name: str) -> None:
          """Prove each Simple AIR with the multi-AIR global challenge and compare bytes with C++."""
          from protocol.simple_pilout import AIRStage1Data, prove_simple_pilout_stage1

          all_data = self._load_all_simple_air_data()
          air_stage1 = {
              name: AIRStage1Data(
                  air_config=data[0],
                  trace=data[1],
                  const_pols=data[2],
                  const_pols_extended=data[3],
              )
              for name, data in all_data.items()
          }

          # Compute global challenge from all five AIRs
          result = prove_simple_pilout_stage1(air_stage1)
          global_challenge = result.global_challenge

          # Prove the target AIR fully with the multi-AIR global challenge (Mode 1)
          starkinfo_name = SIMPLE_PILOUT_STARKINFO_AIR_NAMES[test_air_name]
          air_config, trace, const_pols, const_pols_extended, public_inputs = \
              all_data[starkinfo_name]

          proof_dict = gen_proof(
              air_config, trace, const_pols, const_pols_extended,
              public_inputs=public_inputs,
              global_challenge=global_challenge,
          )

          # Serialize Python proof
          python_proof_bytes = to_bytes_full_from_dict(proof_dict, air_config.stark_info)

          # Load C++ binary proof
          config = AIR_CONFIGS[test_air_name]
          bin_path = TEST_DATA_DIR / config['test_vector'].replace('.json', '.proof.bin')
          with open(bin_path, 'rb') as f:
              cpp_proof_bytes = f.read()

          # Write Python proof for manual diff if test fails
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

  **Part 4: Extend `TestStarkE2EComplete` to include all five Simple AIRs**

  Modify the existing `TestStarkE2EComplete.test_full_proof_verifies` parametrize decorator
  to include all five Simple AIR names:

  ```python
  @pytest.mark.parametrize("air_name", list(AIR_CONFIGS.keys()))
  def test_full_proof_verifies(self, air_name: str) -> None:
      # unchanged — mode 2 round-trip; will now also run for simple_right, u8_air, etc.
  ```

  Since Mode-2 tests compute their own single-AIR global challenge internally, they do not
  need multi-AIR coordination and will work for each AIR independently.

---

## Implementation Workflow

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create TodoWrite tasks matching the checkboxes in Group A, B, C
3. **Execute & Update**: For each task:
   - Mark as `in_progress` when starting
   - Check off `[x]` when complete
   - Mark `completed` when done
4. **Run Group A tasks in parallel** — they have no inter-dependencies
5. **Run Group B tasks after Group A** — B1 and B2 can run in parallel
6. **Run Group C after Group B**

### Critical Verification Steps (after each group)

**After Group A:**
- Confirm each witness module can be instantiated without error
- Run: `uv run python -c "from witness.simple_right import SimpleRightWitness; print('ok')"` etc.
- Run: `./generate-test-vectors.sh simple` and verify 8 new files in `tests/test-data/`

**After Group B:**
- Confirm `witness/__init__.py` resolves all four new AIR names:
  `uv run python -c "from witness import get_witness_module; get_witness_module('SimpleRight')"`
- Confirm `simple_pilout.py` imports without error

**After Group C:**
- Run: `uv run pytest tests/test_stark_e2e.py::TestCppBinaryEquivalence::test_global_challenge_matches_cpp -v`
- Run: `uv run pytest tests/test_stark_e2e.py::TestCppBinaryEquivalence -v`
- Run: `uv run pytest tests/test_stark_e2e.py -v` (all E2E tests, no regressions)

### Progress Tracking
Keep the `[ ]` checkboxes above updated as each task is completed.
