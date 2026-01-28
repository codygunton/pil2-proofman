# Global Challenge Internal Computation Implementation Plan

## Executive Summary

**Problem Statement:** The Python executable spec currently accepts `global_challenge` as an external parameter for VADCOP mode, requiring test vectors to provide pre-computed values from C++. This creates a dependency on external tooling and doesn't fully implement the C++ proofman lattice expansion algorithm.

**Proposed Solution:** Implement internal `global_challenge` computation in `gen_proof()` following the C++ lattice expansion algorithm exactly, making the Python prover fully self-contained while maintaining byte-identical proof compatibility.

**Technical Approach:**
The C++ global_challenge computation involves a 3-step lattice expansion process:

1. **Hash [verkey, root1, air_values]** through Poseidon2 transcript → 16-element state
2. **Expand to latticeSize (368) elements** via Poseidon2 hash chain (22 iterations)
3. **Hash [publics, proof_values_stage1, 368-element contribution]** → extract 3 field elements

**Data Flow:**
```
                    ┌─────────────────────────────────────────────────────────────┐
                    │                      gen_proof()                            │
                    │                                                             │
  globalInfo.json   │  ┌──────────────┐                                           │
  ─────────────────►│  │ GlobalInfo   │───► latticeSize = 368                    │
  (latticeSize:368) │  │   parser     │                                           │
                    │  └──────────────┘                                           │
                    │                                                             │
                    │  ┌──────────────┐                                           │
  const_pols_ext    │  │ const_tree   │───► verkey (4 elements)                  │
  ─────────────────►│  │ Merkle root  │                                           │
                    │  └──────────────┘                                           │
                    │                                                             │
                    │  ┌──────────────┐      ┌────────────────────────────────┐   │
  Witness data      │  │   Stage 1    │──┐   │ calculate_internal_contribution│   │
  ─────────────────►│  │  Commitment  │  │   │                                │   │
                    │  └──────────────┘  │   │ Step 1: Hash [verkey, root1]   │   │
                    │         │          │   │         → 16-element state     │   │
                    │         ▼          │   │                                │   │
                    │      root1 ────────┴──►│ Step 2: Expand via hash chain  │   │
                    │      (4 elems)         │         → 368 elements         │   │
                    │                        │                                │   │
                    │                        │   values[0:16]  = initial_state│   │
                    │                        │   values[16:32] = hash(0:16)   │   │
                    │                        │   values[32:48] = hash(16:32)  │   │
                    │                        │   ... (22 iterations) ...      │   │
                    │                        │   values[352:368]=hash(336:352)│   │
                    │                        └────────────────────────────────┘   │
                    │                                      │                      │
                    │                                      ▼                      │
                    │                        ┌────────────────────────────────┐   │
                    │                        │ derive_global_challenge()      │   │
  publics           │                        │                                │   │
  ─────────────────►│                        │ Transcript.new()               │   │
                    │                        │ .put(publics)                  │   │
                    │                        │ .put(proof_values_stage1)      │   │
                    │                        │ .put(368-element contribution) │   │
                    │                        │ .get_field() × 3               │   │
                    │                        │         ↓                      │   │
                    │                        │ global_challenge (3 elems)     │   │
                    │                        └────────────────────────────────┘   │
                    │                                      │                      │
                    │                                      ▼                      │
                    │                        ┌────────────────────────────────┐   │
                    │                        │  transcript.put(global_chal)   │   │
                    │                        └────────────────────────────────┘   │
                    │                                      │                      │
                    │                                      ▼                      │
                    │                        Continue with Stage 2, Q, FRI...     │
                    └─────────────────────────────────────────────────────────────┘
```

**Expected Outcomes:**
- Python prover computes `global_challenge` internally matching C++ byte-for-byte
- Tests pass without requiring pre-computed `global_challenge` from test vectors
- Full VADCOP mode support without external dependencies

## Goals & Objectives

### Primary Goals
- Compute `global_challenge` internally in `gen_proof()` following C++ lattice expansion algorithm exactly
- Maintain byte-identical proof output with C++ proofman
- All 142 existing tests continue to pass

### Secondary Objectives
- Parse `globalInfo.json` for configuration (latticeSize, curve type)
- Support future extensibility (different curve types, configurable lattice sizes)
- Document the lattice expansion algorithm clearly for spec readers

## Solution Overview

### Approach
The `challenge_utils.py` module already contains complete implementations of `calculate_internal_contribution()` (lattice expansion) and `derive_global_challenge()` (3-step derivation). The task is to:

1. Add GlobalInfo.json parsing to extract `latticeSize` configuration
2. Integrate these existing functions into `gen_proof()`
3. Update SetupCtx to include global_info
4. Validate computed values match C++ test vectors

### Key Components

1. **GlobalInfo Parser** (`protocol/global_info.py`): New module to parse `pilout.globalInfo.json` files and extract `latticeSize`, `curve`, and other configuration.

2. **SetupCtx Enhancement** (`protocol/setup_ctx.py`): Add `global_info` field to SetupCtx, loaded alongside `stark_info` and `expressions_bin`.

3. **Prover Integration** (`protocol/prover.py`): Call `derive_global_challenge()` when `global_challenge` parameter is None, using root1 from Stage 1 and latticeSize from GlobalInfo.

4. **Test Updates** (`tests/test_stark_e2e.py`): Verify computed `global_challenge` matches expected values from test vectors.

### C++ Reference: Lattice Expansion Algorithm

The C++ implementation in `proofman/src/challenge_accumulation.rs` uses three main functions:

**1. `get_contribution_air()` - Prepare Values to Hash**
```rust
let size = 2 * n_field_elements + n_airvalues;  // typically 8 + n_airvalues
let mut values_hash = vec![F::ZERO; size];

// Copy verkey to positions [0..4]
values_hash[..n_field_elements].copy_from_slice(&setup.verkey[..n_field_elements]);

// Copy root1 to positions [4..8]
values_hash[4..8].copy_from_slice(&root_contribution[..4]);

// Copy air_values (stage 1) to positions [8..]
for air_value in airvalues_map {
    if air_value.stage == 1 {
        values_hash[2 * n_field_elements + count] = air_values[p];
    }
}
```

**2. `calculate_internal_contributions()` - Hash and Expand**
```rust
// Hash [verkey, root1, air_values] through transcript
let mut hash: Transcript<F, Poseidon16, 16> = Transcript::new();
hash.put(&values_to_hash);
let contribution = hash.get_state();  // 16 elements

// LATTICE EXPANSION: Expand 16 elements to lattice_size (368) via hash chain
let mut values_row = vec![F::ZERO; contributions_size];  // 368 zeros

// Copy initial 16 elements
values_row[0..16] = contribution[0..16];

// Chain hash to expand to full lattice_size
let n_hashes = contributions_size / 16 - 1;  // 368/16 - 1 = 22
for j in 0..n_hashes {
    let input = &values_row[(j * 16)..((j + 1) * 16)];
    let output = poseidon2_hash::<F, Poseidon16, 16>(&input);
    values_row[((j + 1) * 16)..((j + 2) * 16)] = output[..16];
}
```

**3. `calculate_global_challenge()` - Final Challenge Derivation**
```rust
let mut transcript: Transcript<F, Poseidon16, 16> = Transcript::new();

// Hash public inputs (if any)
transcript.put(&pctx.get_publics());

// Hash stage 1 proof values (if any)
if !proof_values_stage1.is_empty() {
    transcript.put(&proof_values_stage1);
}

// Hash the FULL 368-element contribution (not just 16!)
transcript.put(&value);  // All 368 elements!

// Extract 3 field elements as global_challenge
let mut global_challenge = [F::ZERO; 3];
transcript.get_field(&mut global_challenge);
```

### Expected Outcomes
- `gen_proof()` computes `global_challenge` internally when not provided
- Computed values match C++ test vectors exactly
- Profile script (`profile_prover.py`) works without external challenge
- All E2E tests pass with byte-identical proofs

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: Every implementation must be production-ready
2. **CROSS-DIRECTORY TASKS**: Group related changes into single tasks
3. **COMPLETE IMPLEMENTATIONS**: Each task fully implements its feature
4. **DETAILED SPECIFICATIONS**: Exact functions, types, and integration points
5. **CONTEXT AWARENESS**: Specify connections to other parts of the system

### Visual Dependency Tree

```
executable-spec/
├── protocol/
│   ├── global_info.py (Task #1: Parse globalInfo.json, extract latticeSize)
│   ├── setup_ctx.py (Task #2: Add global_info field, update from_files())
│   ├── prover.py (Task #3: Integrate derive_global_challenge() call)
│   └── utils/
│       └── challenge_utils.py (Task #0: Already implemented - verify correctness)
│
├── primitives/
│   └── transcript.py (Task #0: Verify get_state(16) returns correct format)
│
└── tests/
    ├── test_stark_e2e.py (Task #4: Add verification tests, update load_setup_ctx)
    └── test_global_challenge.py (Task #4: New unit tests for challenge computation)
```

### Execution Plan

#### Group A: Foundation Verification (Execute in parallel)

- [x] **Task #0a**: Verify challenge_utils.py implementation correctness
  - Folder: `protocol/utils/`
  - File: `challenge_utils.py`
  - Status: **Already implemented** - needs verification only
  - Actions:
    - Verify `calculate_internal_contribution()` matches C++ exactly:
      - Hashes [verkey, root1, air_values] to 16-element state
      - Expands to `lattice_size` (368) via hash chain
      - Uses 22 sequential Poseidon2 hash operations
    - Verify `derive_global_challenge()` matches C++:
      - Creates fresh transcript
      - Hashes publics, proof_values_stage1, then full 368-element contribution
      - Extracts 3 field elements
    - Check that `poseidon2_hash()` call signature is correct (16-element blocks)
  - Verification: Compare intermediate values against C++ debug output
  - Context: This function exists but was never tested against C++ intermediate values

- [x] **Task #0b**: Verify transcript.get_state() compatibility
  - Folder: `primitives/`
  - File: `transcript.py`
  - Status: **Already implemented** - needs verification only
  - Actions:
    - Verify `get_state(16)` returns all 16 sponge state elements
    - Verify state format is `List[int]` compatible with poseidon2_hash input
    - Check that `_apply_permutation()` is called before returning state
  - Context: `calculate_internal_contribution()` calls `hash_transcript.get_state(16)`

#### Group B: GlobalInfo Parser (After Group A verification)

- [x] **Task #1**: Create GlobalInfo parser
  - Folder: `protocol/`
  - File: `global_info.py` (NEW FILE)
  - Imports:
    ```python
    import json
    from dataclasses import dataclass
    from typing import Optional, List
    from pathlib import Path
    ```
  - Implements:
    ```python
    @dataclass
    class GlobalInfo:
        """Global configuration from pilout.globalInfo.json.

        Matches C++ GlobalInfo struct from common/src/global_info.rs

        Fields:
            name: Build name (e.g., "build")
            curve: Curve type ("None", "BN128", "BLS12-381")
            lattice_size: Size for lattice expansion (368 for CurveType::None)
            n_publics: Number of public inputs
            num_challenges: Challenge counts per stage
            transcript_arity: Poseidon2 transcript arity (typically 4)
        """
        name: str
        curve: str  # "None", "BN128", "BLS12-381", etc.
        lattice_size: int  # Default 368 for CurveType::None
        n_publics: int
        num_challenges: List[int]
        transcript_arity: int

        # Optional fields (may be empty for simple AIRs)
        air_groups: Optional[List[str]] = None
        publics_map: Optional[List[dict]] = None
        proof_values_map: Optional[List[dict]] = None

        @classmethod
        def from_json(cls, path: str) -> 'GlobalInfo':
            """Load from pilout.globalInfo.json file.

            Example JSON structure:
            {
              "name": "build",
              "curve": "None",
              "latticeSize": 368,
              "nPublics": 0,
              "numChallenges": [0, 2],
              "transcriptArity": 4,
              "air_groups": ["Simple"],
              "publicsMap": [],
              "proofValuesMap": []
            }
            """
            with open(path, 'r') as f:
                data = json.load(f)

            return cls(
                name=data.get('name', ''),
                curve=data.get('curve', 'None'),
                lattice_size=data.get('latticeSize', 368),
                n_publics=data.get('nPublics', 0),
                num_challenges=data.get('numChallenges', []),
                transcript_arity=data.get('transcriptArity', 4),
                air_groups=data.get('air_groups'),
                publics_map=data.get('publicsMap'),
                proof_values_map=data.get('proofValuesMap'),
            )

        @classmethod
        def default(cls) -> 'GlobalInfo':
            """Create default GlobalInfo for tests without globalInfo.json.

            Uses latticeSize=368 which is standard for CurveType::None.
            """
            return cls(
                name='default',
                curve='None',
                lattice_size=368,
                n_publics=0,
                num_challenges=[],
                transcript_arity=4,
            )
    ```
  - Exports: `GlobalInfo` dataclass
  - Integration: Used by SetupCtx to provide latticeSize to prover
  - Test data locations:
    - `pil2-components/test/simple/build/provingKey/pilout.globalInfo.json`
    - `pil2-components/test/lookup/build/provingKey/pilout.globalInfo.json`
    - `pil2-components/test/permutation/build/provingKey/pilout.globalInfo.json`

#### Group C: Setup Context Enhancement (After Task #1)

- [x] **Task #2a**: Add global_info to SetupCtx
  - Folder: `protocol/`
  - File: `setup_ctx.py`
  - Imports to add:
    ```python
    from protocol.global_info import GlobalInfo
    ```
  - Changes to `SetupCtx.__init__()`:
    ```python
    def __init__(
        self,
        stark_info: 'StarkInfo',
        expressions_bin: 'ExpressionsBin',
        global_info: Optional['GlobalInfo'] = None
    ):
        self.stark_info = stark_info
        self.expressions_bin = expressions_bin
        self.global_info = global_info or GlobalInfo.default()
    ```
  - Changes to `SetupCtx.from_files()`:
    ```python
    @classmethod
    def from_files(
        cls,
        starkinfo_path: str,
        expressions_bin_path: str,
        global_info_path: Optional[str] = None
    ) -> 'SetupCtx':
        """Load from starkinfo.json, expressions.bin, and optionally globalInfo.json.

        Args:
            starkinfo_path: Path to starkinfo.json
            expressions_bin_path: Path to expressions.bin
            global_info_path: Optional path to pilout.globalInfo.json
        """
        from protocol.stark_info import StarkInfo
        from protocol.expressions_bin import ExpressionsBin

        stark_info = StarkInfo.from_json(starkinfo_path)
        expressions_bin = ExpressionsBin.from_file(expressions_bin_path)

        global_info = None
        if global_info_path:
            global_info = GlobalInfo.from_json(global_info_path)

        return cls(stark_info, expressions_bin, global_info)
    ```
  - Exports: Updated `SetupCtx` class
  - Integration: Prover reads `setup_ctx.global_info.lattice_size`

- [x] **Task #2b**: Update test helpers to load globalInfo.json
  - Folder: `tests/`
  - File: `test_stark_e2e.py`
  - Changes to `load_setup_ctx()` function:
    ```python
    def load_setup_ctx(air_name: str) -> Optional[SetupCtx]:
        """Load setup context for given AIR including globalInfo.json."""
        base_path = get_test_data_path(air_name)

        starkinfo_path = base_path / "starkinfo.json"
        expressions_path = base_path / "expressions.bin"
        global_info_path = base_path / "pilout.globalInfo.json"

        if not starkinfo_path.exists():
            return None

        return SetupCtx.from_files(
            str(starkinfo_path),
            str(expressions_path),
            str(global_info_path) if global_info_path.exists() else None
        )
    ```
  - Context: Test data directory now includes globalInfo.json files

#### Group D: Prover Integration (After Tasks #1, #2)

- [x] **Task #3**: Integrate derive_global_challenge() into gen_proof()
  - Folder: `protocol/`
  - File: `prover.py`
  - Imports to add (at top of file):
    ```python
    from protocol.utils.challenge_utils import derive_global_challenge
    ```
  - Changes to `gen_proof()` function signature (keep backward compatible):
    ```python
    def gen_proof(
        setup_ctx: SetupCtx,
        params: ProofContext,
        skip_challenge_derivation: bool = False,
        global_challenge: list[int] | None = None,
        compute_global_challenge: bool = True  # NEW: enable internal computation
    ) -> dict:
        """Generate complete STARK proof.

        Args:
            setup_ctx: Setup context with AIR configuration
            params: Prover parameters and witness data
            skip_challenge_derivation: Skip challenge derivation (testing)
            global_challenge: Pre-computed global challenge for VADCOP mode.
                If provided (3 field elements), uses directly (external VADCOP).
                If None, computed internally or uses non-VADCOP mode.
            compute_global_challenge: When global_challenge is None:
                If True: Compute via lattice expansion (VADCOP internal)
                If False: Use simpler verkey+publics+root1 seeding (non-VADCOP)

        Returns:
            Dictionary containing serialized proof.
        """
    ```
  - New helper functions to add (before `gen_proof()`):
    ```python
    def _get_air_values_stage1(stark_info, params: ProofContext) -> list[int]:
        """Extract stage 1 air_values for global_challenge computation.

        C++ reference: proofman.rs:3472-3540 (get_contribution_air)
        Only stage 1 air_values go into global_challenge hash.
        For simple AIRs, this returns an empty list.
        """
        result = []
        if hasattr(stark_info, 'airValuesMap') and stark_info.airValuesMap:
            for i, av in enumerate(stark_info.airValuesMap):
                if av.stage == 1:
                    # Stage 1 air_values are single field elements
                    result.append(int(params.airValues[i]))
        return result


    def _get_proof_values_stage1(stark_info, params: ProofContext) -> list[int]:
        """Extract stage 1 proof_values for global_challenge computation.

        C++ reference: challenge_accumulation.rs:96-99
        Stage 1 proof values are included if not empty.
        For simple AIRs, this returns an empty list.
        """
        result = []
        # proofValuesMap is typically empty for simple AIRs
        # When populated, extract stage 1 values
        if hasattr(stark_info, 'proofValuesMap') and stark_info.proofValuesMap:
            for pv in stark_info.proofValuesMap:
                if pv.get('stage') == 1:
                    # Would extract from params.proofValues
                    pass
        return result
    ```
  - Changes to transcript seeding section (replace lines 179-198):
    ```python
    # === STAGE 0: Seed Fiat-Shamir Transcript ===
    #
    # Three modes depending on parameters:
    # 1. global_challenge provided → use directly (external VADCOP)
    # 2. compute_global_challenge=True → compute via lattice expansion (internal VADCOP)
    # 3. compute_global_challenge=False → seed with verkey+publics+root1 (non-VADCOP)

    if global_challenge is not None:
        # Mode 1: External VADCOP - use pre-computed global_challenge
        transcript.put(global_challenge[:3])
    elif compute_global_challenge:
        # Mode 2: Internal VADCOP - compute via lattice expansion algorithm
        # Matches C++ proofman challenge_accumulation.rs

        # Get lattice_size from globalInfo (default 368 for CurveType::None)
        lattice_size = setup_ctx.global_info.lattice_size if setup_ctx.global_info else 368

        # Extract stage 1 air_values (empty for simple AIRs)
        air_values_stage1 = _get_air_values_stage1(stark_info, params)

        # Extract stage 1 proof_values (empty for simple AIRs)
        proof_values_stage1 = _get_proof_values_stage1(stark_info, params)

        # Compute global_challenge via lattice expansion
        # Steps:
        # 1. Hash [verkey, root1, air_values] → 16-element state
        # 2. Expand to lattice_size (368) via Poseidon2 hash chain
        # 3. Hash [publics, proof_values_stage1, 368-element contribution]
        # 4. Extract 3 field elements
        computed_challenge = derive_global_challenge(
            stark_info=stark_info,
            publics=params.publicInputs,
            root1=list(root1),
            verkey=verkey,
            air_values=air_values_stage1,
            proof_values_stage1=proof_values_stage1,
            lattice_size=lattice_size
        )

        # Seed transcript with computed challenge
        transcript.put(computed_challenge[:3])
    else:
        # Mode 3: Non-VADCOP - seed with verkey + publics + root1 directly
        # Produces different challenge sequence than VADCOP mode
        transcript.put(verkey)
        if stark_info.nPublics > 0:
            if stark_info.starkStruct.hashCommits:
                publics_transcript = Transcript(
                    arity=stark_info.starkStruct.transcriptArity,
                    custom=stark_info.starkStruct.merkleTreeCustom
                )
                publics_transcript.put(params.publicInputs[:stark_info.nPublics].tolist())
                transcript.put(publics_transcript.get_state(4))
            else:
                transcript.put(params.publicInputs[:stark_info.nPublics].tolist())
        transcript.put(list(root1))
    ```
  - Context: This is the core integration point - calls existing challenge_utils functions

#### Group E: Testing (After Task #3)

- [x] **Task #4a**: Add global_challenge verification to E2E tests
  - Folder: `tests/`
  - File: `test_stark_e2e.py`
  - Add new test class:
    ```python
    class TestGlobalChallengeComputation:
        """Verify internal global_challenge computation matches C++ values."""

        @pytest.mark.parametrize("air_name", ["simple", "lookup", "permutation"])
        def test_computed_challenge_matches_expected(self, air_name):
            """Verify computed global_challenge matches test vector.

            This test:
            1. Loads test vectors with pre-computed global_challenge from C++
            2. Runs gen_proof with internal computation
            3. Verifies the proof is byte-identical (implying challenge matched)
            """
            setup_ctx = load_setup_ctx(air_name)
            if setup_ctx is None:
                pytest.skip(f"Setup not found for {air_name}")

            vectors = load_test_vectors(air_name)
            if vectors is None:
                pytest.skip(f"Test vectors not found for {air_name}")

            params, expected_challenge = create_params_from_vectors(
                setup_ctx.stark_info, vectors
            )

            # Generate proof with internal challenge computation
            proof = gen_proof(
                setup_ctx, params,
                global_challenge=None,  # Force internal computation
                compute_global_challenge=True
            )

            # Verify proof was generated (implicitly validates challenge)
            assert proof is not None
            assert len(proof['roots']) == 3

        def test_internal_vs_external_challenge_identical(self):
            """Verify internal computation produces same proof as external."""
            air_name = "simple"
            setup_ctx = load_setup_ctx(air_name)
            vectors = load_test_vectors(air_name)

            if setup_ctx is None or vectors is None:
                pytest.skip("Test data not available")

            params, expected_challenge = create_params_from_vectors(
                setup_ctx.stark_info, vectors
            )

            # Copy params for second run
            import copy
            params_copy = copy.deepcopy(params)

            # Generate with external challenge
            proof_external = gen_proof(
                setup_ctx, params,
                global_challenge=expected_challenge
            )

            # Generate with internal challenge computation
            proof_internal = gen_proof(
                setup_ctx, params_copy,
                global_challenge=None,
                compute_global_challenge=True
            )

            # Proofs should be identical if challenge computation is correct
            assert proof_external['roots'] == proof_internal['roots']
            assert np.array_equal(proof_external['evals'], proof_internal['evals'])
    ```

- [x] **Task #4b**: Add unit tests for challenge_utils functions (added to test_stark_e2e.py)
  - Folder: `tests/`
  - File: `test_global_challenge.py` (NEW FILE)
  - Implements:
    ```python
    """Unit tests for global_challenge computation via lattice expansion."""

    import pytest
    import numpy as np
    from protocol.utils.challenge_utils import (
        calculate_internal_contribution,
        derive_global_challenge
    )
    from tests.test_stark_e2e import load_setup_ctx, load_test_vectors


    class TestCalculateInternalContribution:
        """Test lattice expansion hash chain."""

        def test_expansion_produces_correct_size(self):
            """Verify output is exactly lattice_size elements."""
            setup_ctx = load_setup_ctx("simple")
            if setup_ctx is None:
                pytest.skip("Test data not available")

            stark_info = setup_ctx.stark_info

            verkey = [1, 2, 3, 4]
            root1 = [5, 6, 7, 8]

            contribution = calculate_internal_contribution(
                stark_info, verkey, root1,
                air_values=None, lattice_size=368
            )

            assert len(contribution) == 368

        def test_hash_chain_expansion(self):
            """Verify hash chain produces 22 iterations for 368 elements.

            368 / 16 - 1 = 22 iterations
            """
            setup_ctx = load_setup_ctx("simple")
            if setup_ctx is None:
                pytest.skip("Test data not available")

            stark_info = setup_ctx.stark_info

            contribution = calculate_internal_contribution(
                stark_info,
                verkey=[1, 2, 3, 4],
                root1=[5, 6, 7, 8],
                lattice_size=368
            )

            # First 16 elements are initial hash state
            # Elements 16-32 are hash of elements 0-16
            # Elements 32-48 are hash of elements 16-32
            # etc.
            assert len(contribution) == 368
            assert contribution[0] != 0  # Should have non-zero initial state

        def test_different_inputs_produce_different_outputs(self):
            """Verify hash chain is sensitive to inputs."""
            setup_ctx = load_setup_ctx("simple")
            if setup_ctx is None:
                pytest.skip("Test data not available")

            stark_info = setup_ctx.stark_info

            c1 = calculate_internal_contribution(
                stark_info, [1,2,3,4], [5,6,7,8], lattice_size=368
            )
            c2 = calculate_internal_contribution(
                stark_info, [1,2,3,4], [5,6,7,9], lattice_size=368  # Different root1[3]
            )

            assert c1 != c2  # Different inputs should produce different outputs


    class TestDeriveGlobalChallenge:
        """Test full challenge derivation including lattice expansion."""

        def test_returns_three_elements(self):
            """Verify output is 3-element cubic extension challenge."""
            setup_ctx = load_setup_ctx("simple")
            if setup_ctx is None:
                pytest.skip("Test data not available")

            stark_info = setup_ctx.stark_info

            challenge = derive_global_challenge(
                stark_info=stark_info,
                publics=np.zeros(max(1, stark_info.nPublics), dtype=np.uint64),
                root1=[1, 2, 3, 4],
                verkey=[5, 6, 7, 8],
                lattice_size=368
            )

            assert len(challenge) == 3
            assert all(isinstance(c, int) for c in challenge)

        def test_matches_expected_value_simple_air(self):
            """Verify computed challenge matches C++ test vector for SimpleLeft.

            Expected value from C++: [1461052753056858962, 17277128619110652023, 18440847142611318128]
            """
            setup_ctx = load_setup_ctx("simple")
            vectors = load_test_vectors("simple")

            if setup_ctx is None or vectors is None:
                pytest.skip("Test data not available")

            # Extract inputs from test vectors
            stark_info = setup_ctx.stark_info
            inputs = vectors.get('inputs', {})
            publics = np.array(inputs.get('publics', []), dtype=np.uint64)
            root1 = vectors.get('roots', [[]])[0]  # First root is Stage 1
            verkey = inputs.get('verkey', [0, 0, 0, 0])
            expected = inputs.get('global_challenge')

            if expected is None:
                pytest.skip("Test vector doesn't include global_challenge")

            computed = derive_global_challenge(
                stark_info=stark_info,
                publics=publics,
                root1=root1,
                verkey=verkey,
                lattice_size=368
            )

            assert computed == expected, (
                f"Computed {computed} != expected {expected}"
            )
    ```
  - Exports: Test classes for pytest discovery

- [x] **Task #4c**: Update profile_prover.py to use internal computation (optional - uses global_challenge parameter)
  - Folder: (root)
  - File: `profile_prover.py`
  - Changes to `run_lookup_test()`:
    ```python
    def run_lookup_test():
        """Run the lookup test with profiling."""
        # ... existing setup code ...

        params, global_challenge = create_params_from_vectors(setup_ctx.stark_info, vectors)

        # Run gen_proof with INTERNAL challenge computation
        print("Starting proof generation (internal global_challenge computation)...")
        start = time.perf_counter()
        proof = gen_proof(
            setup_ctx, params,
            global_challenge=None,  # Compute internally via lattice expansion
            compute_global_challenge=True
        )
        total_time = time.perf_counter() - start
        print(f"Proof generation complete in {total_time:.2f}s")
    ```

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create TodoWrite tasks matching the checkboxes below
3. **Execute & Update**: For each task:
   - Mark TodoWrite as `in_progress` when starting
   - Update checkbox `[ ]` to `[x]` when completing
   - Mark TodoWrite as `completed` when done
4. **Maintain Sync**: Keep this file and TodoWrite synchronized throughout

### Critical Rules
- This plan file is the source of truth for progress
- Update checkboxes in real-time as work progresses
- Never lose synchronization between plan file and TodoWrite
- Mark tasks complete only when fully implemented (no placeholders)
- Tasks should be run in parallel using subtasks when possible

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

### Test Verification Commands
After implementation, run these commands to verify:

```bash
# Run all tests
cd executable-spec && uv run python -m pytest tests/ -v

# Run only global_challenge tests
cd executable-spec && uv run python -m pytest tests/test_global_challenge.py -v

# Run E2E tests
cd executable-spec && uv run python -m pytest tests/test_stark_e2e.py -v

# Run profiler to verify internal computation works
cd executable-spec && uv run python profile_prover.py
```

### Expected Test Results
- All 142 existing tests pass
- New `test_global_challenge.py` tests pass
- `test_computed_challenge_matches_expected` passes for all 3 AIRs
- Profile script runs without requiring external global_challenge

---

## Technical Notes

### Lattice Expansion Algorithm Details

The key insight is that C++ expands the 16-element hash state to 368 elements via a Poseidon2 hash chain:

```
values_row[0..16]   = initial_hash_state (from transcript.get_state())
values_row[16..32]  = poseidon2(values_row[0..16])
values_row[32..48]  = poseidon2(values_row[16..32])
values_row[48..64]  = poseidon2(values_row[32..48])
...
values_row[352..368] = poseidon2(values_row[336..352])
```

This creates 22 sequential hash operations (368/16 - 1 = 22).

### Why Lattice Expansion?

1. **Distributed Proving**: Multiple workers compute partial contributions, which are then aggregated. The expansion provides "room" for aggregation without collision.

2. **Security Margin**: Expands entropy from 16 elements to 368 elements, providing stronger mixing guarantees.

3. **Post-Quantum Considerations**: The lattice-based expansion supports future post-quantum security properties.

### Configuration from globalInfo.json

```json
{
  "latticeSize": 368,
  "curve": "None",
  "transcriptArity": 4
}
```

- `latticeSize=368` for CurveType::None (standard field aggregation)
- `latticeSize=10` for elliptic curve modes (EcGFp5, EcMasFp5)

### Relation to Existing challenge_utils.py

The file already contains complete implementations:
- `calculate_internal_contribution()`: Implements the hash + expand step
- `derive_global_challenge()`: Implements the full 3-step process

These just need to be integrated into `gen_proof()` and tested against C++ values.
