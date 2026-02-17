# ProofContext Refactoring Implementation Plan

## Executive Summary

**Problem**: `ProofContext` is an opaque god object that conflates 5+ distinct responsibilities:
1. Buffer storage with hidden layout (trace, auxTrace)
2. Challenge state with manual indexing
3. Polynomial evaluations
4. AIR values (airgroup, air, public inputs)
5. Verifier-specific precomputation (xDivXSub)

The `auxTrace` buffer is particularly problematic - it contains multiple logical sections (cm2, cm3, quotient, FRI polynomial) packed together with offsets computed from `stark_info.map_offsets`. To access any data, you must know:
- Which section name (cm1, cm2, cm3, q, f)
- Whether extended domain (True/False)
- The offset from `map_offsets[(section, extended)]`
- The column count from `map_sections_n[section]`

This knowledge is scattered across `stages.py`, `fri_polynomial.py`, `prover.py`, and `verifier.py`.

**Solution**: Split ProofContext into single-responsibility components:

```
┌─────────────────────────────────────────────────────────────────┐
│                      ProverContext (new)                        │
│  ┌──────────────────┐ ┌─────────────────┐ ┌──────────────────┐  │
│  │  BufferLayout    │ │  ChallengeStore │ │  EvaluationStore │  │
│  │  ─────────────   │ │  ────────────── │ │  ─────────────── │  │
│  │  trace (stage 1) │ │  get(name)->FF3 │ │  evals array     │  │
│  │  auxTrace        │ │  set(name, val) │ │  get_eval(idx)   │  │
│  │  constPols[Ext]  │ │  (named access) │ │                  │  │
│  │                  │ └─────────────────┘ └──────────────────┘  │
│  │  get_section()   │                                           │
│  │  get_polynomial()│ ┌─────────────────────────────────────┐   │
│  └──────────────────┘ │           ValueStore                │   │
│                       │  ────────────────────────────────   │   │
│                       │  public_inputs, air_values,         │   │
│                       │  airgroup_values, proof_values      │   │
│                       └─────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

**Key benefits**:
- `BufferLayout` encapsulates the opaque `auxTrace` layout
- `ChallengeStore` provides named access instead of index math
- Each component has single responsibility
- Clear separation enables future optimization (lazy views, memoization)

## Goals & Objectives

### Primary Goals
- Make buffer layout explicit and encapsulated within `BufferLayout`
- Provide named challenge access via `ChallengeStore`
- Separate prover-only and verifier-only concerns
- Reduce the cognitive load of understanding where data lives

### Secondary Objectives
- Eliminate scattered `map_offsets` lookups across multiple files
- Enable typed views into buffer sections (future: zero-copy access)
- Prepare for potential removal of ProverData/VerifierData bridge layer

## Solution Overview

### Approach

Create four new focused classes that replace the monolithic ProofContext:

1. **BufferLayout** - Encapsulates all polynomial buffer storage and the complex auxTrace layout
2. **ChallengeStore** - Named access to Fiat-Shamir challenges
3. **EvaluationStore** - Polynomial evaluations at opening points (plus xDivXSub for verifier)
4. **ValueStore** - AIR values, airgroup values, public inputs, proof values

Then create thin composite classes:
- **ProverContext** - Composes the above for prover use
- **VerifierContext** - Composes the above for verifier use (different initialization)

### Key Components

1. **BufferLayout**: Hides `map_offsets`/`map_sections_n` complexity
   - `get_section(name, extended) -> np.ndarray` - Returns a view into auxTrace for the section
   - `get_polynomial(pol_map_entry) -> np.ndarray` - Gets a specific polynomial by its PolMap metadata
   - Internally manages trace (stage 1) vs auxTrace (stages 2+) split

2. **ChallengeStore**: Named challenge access
   - `get(name) -> FF3` - Get challenge by name (e.g., "std_alpha")
   - `set(name, value: FF3)` - Set challenge by name
   - Initialized with `challenges_map` from StarkInfo

3. **EvaluationStore**: Evaluation state
   - `evals` array storage
   - `get_eval(ev_map_entry) -> FF3` - Get evaluation by ev_map metadata
   - `x_div_x_sub` (verifier-only precomputation)

4. **ValueStore**: AIR and public values
   - `public_inputs`, `air_values`, `airgroup_values`, `proof_values`
   - Named or indexed access

### Data Flow

**Before** (current):
```
ProofContext.auxTrace (opaque blob)
    ↓ manual offset calculation in stages.py
ProverData (dict copy)
    ↓ constraint evaluation
results
    ↓ manual offset calculation in stages.py
ProofContext.auxTrace (write back)
```

**After** (proposed):
```
BufferLayout.get_section("cm2", extended=True)
    ↓ returns typed view
ProverData (built from views, less copying)
    ↓ constraint evaluation
results
    ↓ BufferLayout.write_polynomial(pol_info, data)
BufferLayout internal storage (encapsulated write)
```

### Expected Outcomes

- All `map_offsets` lookups consolidated into `BufferLayout`
- Challenge access by name instead of `index * FIELD_EXTENSION_DEGREE + j`
- Clear which fields are prover-only vs verifier-only
- Single file to understand buffer layout (`buffer_layout.py`) instead of 4+ files

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **NO PLACEHOLDER CODE**: Every change must be complete and tested
2. **PRESERVE BINARY COMPATIBILITY**: Proof output must remain byte-identical to C++
3. **INCREMENTAL MIGRATION**: Add new classes alongside ProofContext, migrate consumers gradually, then remove ProofContext
4. **TESTS MUST PASS**: Run `./run-tests.sh` after each task group

### Visual Dependency Tree

```
executable-spec/
├── protocol/
│   ├── buffer_layout.py (Task #1: NEW - encapsulates auxTrace complexity)
│   │   └── class BufferLayout
│   │       ├── get_section(name, extended) -> np.ndarray view
│   │       ├── get_polynomial(pol_map) -> np.ndarray
│   │       ├── write_polynomial(pol_map, data)
│   │       └── get_stage1_trace() -> np.ndarray
│   │
│   ├── challenge_store.py (Task #2: NEW - named challenge access)
│   │   └── class ChallengeStore
│   │       ├── get(name) -> FF3
│   │       ├── set(name, value: FF3)
│   │       └── to_array() -> np.ndarray (for backward compat)
│   │
│   ├── evaluation_store.py (Task #3: NEW - evaluation state)
│   │   └── class EvaluationStore
│   │       ├── evals: np.ndarray
│   │       ├── get_eval(ev_map_entry) -> FF3
│   │       └── x_div_x_sub: np.ndarray | None (verifier-only)
│   │
│   ├── value_store.py (Task #4: NEW - AIR/public values)
│   │   └── class ValueStore
│   │       ├── public_inputs, air_values, airgroup_values
│   │       └── get_airgroup_value(index) -> FF3
│   │
│   ├── prover_context.py (Task #5: NEW - prover composite)
│   │   └── class ProverContext
│   │       ├── buffers: BufferLayout
│   │       ├── challenges: ChallengeStore
│   │       ├── evaluations: EvaluationStore
│   │       └── values: ValueStore
│   │
│   ├── verifier_context.py (Task #6: NEW - verifier composite)
│   │   └── class VerifierContext
│   │       ├── (similar structure, different initialization)
│   │       └── x_div_x_sub lives in evaluations
│   │
│   ├── stages.py (Task #7: Migrate to BufferLayout)
│   │   ├── _build_prover_data_extended() - use buffers.get_section()
│   │   ├── _build_prover_data_base() - use buffers.get_section()
│   │   ├── _write_witness_to_buffer() - use buffers.write_polynomial()
│   │   └── Starks methods - use BufferLayout
│   │
│   ├── prover.py (Task #8: Migrate to ProverContext)
│   │   ├── gen_proof() - accept ProverContext
│   │   ├── _derive_stage_challenges() - use ChallengeStore
│   │   └── challenge access via names
│   │
│   ├── verifier.py (Task #9: Migrate to VerifierContext)
│   │   ├── stark_verify() - create/use VerifierContext
│   │   └── _build_verifier_data() - use new stores
│   │
│   ├── fri_polynomial.py (Task #10: Migrate buffer access)
│   │   ├── _get_polynomial_on_domain() - use BufferLayout
│   │   └── compute_fri_polynomial*() - use ChallengeStore
│   │
│   ├── proof_context.py (Task #11: DEPRECATE)
│   │   └── Mark as deprecated, keep for reference
│   │
│   └── __init__.py (Task #12: Update exports)
│
└── tests/
    ├── test_buffer_layout.py (Task #1: Unit tests for BufferLayout)
    ├── test_challenge_store.py (Task #2: Unit tests for ChallengeStore)
    ├── test_stark_e2e.py (Task #13: Migrate test fixtures)
    └── test_verifier_e2e.py (Task #13: Migrate test fixtures)
```

### Execution Plan

#### Group A: Foundation Classes (Execute all in parallel)

- [x] **Task #1**: Create BufferLayout class
  - Folder: `executable-spec/protocol/`
  - File: `buffer_layout.py`
  - Imports:
    ```python
    from dataclasses import dataclass
    import numpy as np
    from primitives.field import FF, FF3, FIELD_EXTENSION_DEGREE
    from primitives.pol_map import PolMap
    from protocol.stark_info import StarkInfo
    ```
  - Implements:
    ```python
    @dataclass
    class BufferLayout:
        """Encapsulates polynomial buffer storage with explicit section access.

        Replaces the opaque auxTrace buffer with named section accessors.
        Knows the buffer layout internally via stark_info offsets.
        """
        stark_info: StarkInfo
        trace: np.ndarray | None = None  # Stage 1 base domain (N x cm1_cols)
        aux_trace: np.ndarray | None = None  # Stages 2+, quotient, FRI
        const_pols: np.ndarray | None = None  # Constants base domain
        const_pols_extended: np.ndarray | None = None  # Constants extended
        custom_commits: np.ndarray | None = None

        def get_section(self, section: str, extended: bool) -> np.ndarray:
            """Get a view into the buffer for a named section.

            Args:
                section: Section name ("cm1", "cm2", "cm3", "q", "f", "const")
                extended: True for extended domain, False for base domain

            Returns:
                np.ndarray view into the appropriate buffer
            """
            # Handle const separately
            if section == "const":
                return self.const_pols_extended if extended else self.const_pols

            # Handle cm1 stage 1 (uses trace buffer for base domain)
            if section == "cm1" and not extended:
                return self.trace

            # All other sections use aux_trace with offset lookup
            offset = self.stark_info.map_offsets.get((section, extended), 0)
            n_cols = self.stark_info.map_sections_n.get(section, 0)
            n_rows = self._get_domain_size(extended)
            size = n_rows * n_cols
            return self.aux_trace[offset:offset + size]

        def get_section_2d(self, section: str, extended: bool) -> np.ndarray:
            """Get section as 2D array (n_rows x n_cols)."""
            data = self.get_section(section, extended)
            n_cols = self.stark_info.map_sections_n.get(section, 0)
            if section == "const":
                n_cols = self.stark_info.n_constants
            n_rows = len(data) // n_cols if n_cols > 0 else 0
            return data.reshape(n_rows, n_cols) if n_cols > 0 else data

        def get_polynomial(self, pol: PolMap, extended: bool) -> np.ndarray:
            """Get a specific polynomial by its PolMap metadata.

            Args:
                pol: PolMap entry describing the polynomial
                extended: True for extended domain

            Returns:
                1D array of polynomial values (length N or N_ext, interleaved if FF3)
            """
            section = f"cm{pol.stage}"
            section_data = self.get_section_2d(section, extended)
            # Extract column(s) based on stage_pos and dim
            return section_data[:, pol.stage_pos:pol.stage_pos + pol.dim].flatten()

        def write_section(self, section: str, extended: bool, data: np.ndarray) -> None:
            """Write data to a section."""
            target = self.get_section(section, extended)
            target[:len(data)] = data

        def _get_domain_size(self, extended: bool) -> int:
            """Get N or N_ext based on extended flag."""
            n_bits = self.stark_info.stark_struct.n_bits_ext if extended else self.stark_info.stark_struct.n_bits
            return 1 << n_bits

        @classmethod
        def create_for_prover(cls, stark_info: StarkInfo, trace: np.ndarray,
                             const_pols: np.ndarray, const_pols_extended: np.ndarray) -> "BufferLayout":
            """Factory for prover - allocates aux_trace buffer."""
            aux_trace = np.zeros(stark_info.map_total_n, dtype=np.int64)
            return cls(
                stark_info=stark_info,
                trace=trace,
                aux_trace=aux_trace,
                const_pols=const_pols,
                const_pols_extended=const_pols_extended,
            )

        @classmethod
        def create_for_verifier(cls, stark_info: StarkInfo, trace: np.ndarray,
                               aux_trace: np.ndarray, const_pols: np.ndarray) -> "BufferLayout":
            """Factory for verifier - uses pre-populated buffers from proof."""
            return cls(
                stark_info=stark_info,
                trace=trace,
                aux_trace=aux_trace,
                const_pols=const_pols,
                const_pols_extended=None,  # Verifier doesn't need extended constants
            )
    ```
  - Exports: `BufferLayout`
  - Context: This is the core abstraction that hides auxTrace complexity. All buffer access will go through this class.
  - Tests: Create `tests/test_buffer_layout.py` with:
    - Test `get_section()` returns correct offsets for each section
    - Test `get_polynomial()` extracts correct column data
    - Test `create_for_prover()` allocates correct buffer sizes

- [x] **Task #2**: Create ChallengeStore class
  - Folder: `executable-spec/protocol/`
  - File: `challenge_store.py`
  - Imports:
    ```python
    from dataclasses import dataclass, field
    import numpy as np
    from primitives.field import FF3, FIELD_EXTENSION_DEGREE
    from primitives.pol_map import ChallengeMap
    ```
  - Implements:
    ```python
    @dataclass
    class ChallengeStore:
        """Named access to Fiat-Shamir challenges.

        Replaces manual index calculation with semantic name-based access.
        Internally stores challenges in interleaved FF3 format for C++ compatibility.
        """
        _challenges_map: list[ChallengeMap]
        _data: np.ndarray  # Interleaved [c0_0, c0_1, c0_2, c1_0, c1_1, c1_2, ...]
        _name_to_index: dict[str, int] = field(default_factory=dict)

        def __post_init__(self) -> None:
            """Build name -> index lookup."""
            self._name_to_index = {ch.name: i for i, ch in enumerate(self._challenges_map)}

        def get(self, name: str) -> FF3:
            """Get challenge by name as FF3 element."""
            if name not in self._name_to_index:
                raise KeyError(f"Unknown challenge: {name}")
            index = self._name_to_index[name]
            return self.get_by_index(index)

        def get_by_index(self, index: int) -> FF3:
            """Get challenge by index as FF3 element."""
            base = index * FIELD_EXTENSION_DEGREE
            coeffs = [int(self._data[base + j]) for j in range(FIELD_EXTENSION_DEGREE)]
            return FF3(coeffs)

        def set(self, name: str, value: FF3) -> None:
            """Set challenge by name."""
            if name not in self._name_to_index:
                raise KeyError(f"Unknown challenge: {name}")
            index = self._name_to_index[name]
            self.set_by_index(index, value)

        def set_by_index(self, index: int, value: FF3) -> None:
            """Set challenge by index."""
            base = index * FIELD_EXTENSION_DEGREE
            coeffs = list(value.coeffs) if hasattr(value, 'coeffs') else value
            for j in range(FIELD_EXTENSION_DEGREE):
                self._data[base + j] = int(coeffs[j])

        def to_array(self) -> np.ndarray:
            """Return underlying array for backward compatibility."""
            return self._data

        def has(self, name: str) -> bool:
            """Check if challenge exists."""
            return name in self._name_to_index

        @classmethod
        def create(cls, challenges_map: list[ChallengeMap],
                   initial_data: np.ndarray | None = None) -> "ChallengeStore":
            """Create a ChallengeStore.

            Args:
                challenges_map: Challenge metadata from StarkInfo
                initial_data: Pre-populated challenge array (optional)
            """
            n_challenges = len(challenges_map)
            if initial_data is None:
                data = np.zeros(n_challenges * FIELD_EXTENSION_DEGREE, dtype=np.int64)
            else:
                data = initial_data
            return cls(_challenges_map=challenges_map, _data=data)
    ```
  - Exports: `ChallengeStore`
  - Context: Provides `store.get("std_alpha")` instead of `params.challenges[index * 3:(index+1) * 3]`
  - Tests: Create `tests/test_challenge_store.py` with:
    - Test `get(name)` returns correct FF3 value
    - Test `set(name, value)` stores correctly
    - Test unknown name raises KeyError

- [x] **Task #3**: Create EvaluationStore class
  - Folder: `executable-spec/protocol/`
  - File: `evaluation_store.py`
  - Imports:
    ```python
    from dataclasses import dataclass
    import numpy as np
    from primitives.field import FF3, FIELD_EXTENSION_DEGREE
    from primitives.pol_map import EvMap
    ```
  - Implements:
    ```python
    @dataclass
    class EvaluationStore:
        """Polynomial evaluations at opening points.

        Stores evaluations of committed polynomials at xi * omega^offset
        for verification and FRI polynomial construction.
        """
        _ev_map: list[EvMap]
        _evals: np.ndarray  # Interleaved FF3 coefficients
        x_div_x_sub: np.ndarray | None = None  # Verifier-only: precomputed 1/(x - xi*w^k)

        def get_eval(self, index: int) -> FF3:
            """Get evaluation at index as FF3."""
            base = index * FIELD_EXTENSION_DEGREE
            coeffs = [int(self._evals[base + j]) for j in range(FIELD_EXTENSION_DEGREE)]
            return FF3(coeffs)

        def set_eval(self, index: int, value: FF3) -> None:
            """Set evaluation at index."""
            base = index * FIELD_EXTENSION_DEGREE
            coeffs = list(value.coeffs) if hasattr(value, 'coeffs') else value
            for j in range(FIELD_EXTENSION_DEGREE):
                self._evals[base + j] = int(coeffs[j])

        def to_array(self) -> np.ndarray:
            """Return underlying evals array for backward compatibility."""
            return self._evals

        @classmethod
        def create(cls, ev_map: list[EvMap], n_evals: int | None = None,
                   initial_evals: np.ndarray | None = None) -> "EvaluationStore":
            """Create an EvaluationStore."""
            if n_evals is None:
                n_evals = len(ev_map)
            if initial_evals is None:
                evals = np.zeros(n_evals * FIELD_EXTENSION_DEGREE, dtype=np.int64)
            else:
                evals = initial_evals
            return cls(_ev_map=ev_map, _evals=evals)
    ```
  - Exports: `EvaluationStore`
  - Context: Manages the `evals` array and verifier's `xDivXSub` precomputation

- [x] **Task #4**: Create ValueStore class
  - Folder: `executable-spec/protocol/`
  - File: `value_store.py`
  - Imports:
    ```python
    from dataclasses import dataclass
    import numpy as np
    from primitives.field import FF, FF3, FIELD_EXTENSION_DEGREE
    ```
  - Implements:
    ```python
    @dataclass
    class ValueStore:
        """AIR values, airgroup values, public inputs, and proof values.

        Consolidates the various "value" arrays that flow through the protocol.
        """
        public_inputs: np.ndarray | None = None
        proof_values: np.ndarray | None = None
        air_values: np.ndarray | None = None
        airgroup_values: np.ndarray | None = None

        def get_airgroup_value(self, index: int) -> FF3:
            """Get airgroup value at index as FF3."""
            if self.airgroup_values is None:
                raise ValueError("airgroup_values not initialized")
            base = index * FIELD_EXTENSION_DEGREE
            coeffs = [int(self.airgroup_values[base + j]) for j in range(FIELD_EXTENSION_DEGREE)]
            return FF3(coeffs)

        def set_airgroup_value(self, index: int, value: FF3) -> None:
            """Set airgroup value at index."""
            if self.airgroup_values is None:
                raise ValueError("airgroup_values not initialized")
            base = index * FIELD_EXTENSION_DEGREE
            coeffs = list(value.coeffs) if hasattr(value, 'coeffs') else value
            for j in range(FIELD_EXTENSION_DEGREE):
                self.airgroup_values[base + j] = int(coeffs[j])

        def get_air_value(self, index: int, dim: int = 1) -> FF | FF3:
            """Get air value at index."""
            if self.air_values is None:
                raise ValueError("air_values not initialized")
            if dim == 1:
                return FF(int(self.air_values[index]))
            else:
                base = index * FIELD_EXTENSION_DEGREE
                coeffs = [int(self.air_values[base + j]) for j in range(FIELD_EXTENSION_DEGREE)]
                return FF3(coeffs)

        @classmethod
        def create(cls, n_publics: int = 0, n_proof_values: int = 0,
                   air_values_size: int = 0, airgroup_values_size: int = 0) -> "ValueStore":
            """Create a ValueStore with allocated arrays."""
            return cls(
                public_inputs=np.zeros(n_publics, dtype=np.int64) if n_publics > 0 else None,
                proof_values=np.zeros(n_proof_values, dtype=np.int64) if n_proof_values > 0 else None,
                air_values=np.zeros(air_values_size, dtype=np.int64) if air_values_size > 0 else None,
                airgroup_values=np.zeros(airgroup_values_size, dtype=np.int64) if airgroup_values_size > 0 else None,
            )
    ```
  - Exports: `ValueStore`
  - Context: Consolidates public_inputs, proof_values, air_values, airgroup_values

#### Group B: Composite Context Classes (Execute after Group A)

- [x] **Task #5**: Create ProverContext class
  - Folder: `executable-spec/protocol/`
  - File: `prover_context.py`
  - Imports:
    ```python
    from dataclasses import dataclass
    import numpy as np
    from protocol.buffer_layout import BufferLayout
    from protocol.challenge_store import ChallengeStore
    from protocol.evaluation_store import EvaluationStore
    from protocol.value_store import ValueStore
    from protocol.stark_info import StarkInfo
    ```
  - Implements:
    ```python
    @dataclass
    class ProverContext:
        """Complete prover state composed of single-responsibility stores.

        This replaces the monolithic ProofContext for prover operations.
        Each sub-store handles one concern:
        - buffers: Polynomial storage with explicit section access
        - challenges: Named Fiat-Shamir challenge access
        - evaluations: Polynomial evaluations at opening points
        - values: AIR/airgroup/public values
        """
        buffers: BufferLayout
        challenges: ChallengeStore
        evaluations: EvaluationStore
        values: ValueStore

        # Backward compatibility properties
        @property
        def trace(self) -> np.ndarray | None:
            return self.buffers.trace

        @property
        def auxTrace(self) -> np.ndarray | None:
            return self.buffers.aux_trace

        @property
        def constPols(self) -> np.ndarray | None:
            return self.buffers.const_pols

        @property
        def constPolsExtended(self) -> np.ndarray | None:
            return self.buffers.const_pols_extended

        @property
        def evals(self) -> np.ndarray | None:
            return self.evaluations.to_array()

        @property
        def publicInputs(self) -> np.ndarray | None:
            return self.values.public_inputs

        @property
        def airgroupValues(self) -> np.ndarray | None:
            return self.values.airgroup_values

        @property
        def airValues(self) -> np.ndarray | None:
            return self.values.air_values

        # Legacy challenge methods for backward compatibility
        def get_challenge(self, index: int) -> list[int]:
            """Legacy method - prefer challenges.get(name) or challenges.get_by_index(index)."""
            return list(self.challenges.get_by_index(index).coeffs)

        def set_challenge(self, index: int, value: list[int]) -> None:
            """Legacy method - prefer challenges.set(name, value)."""
            from primitives.field import FF3
            self.challenges.set_by_index(index, FF3(value))

        @classmethod
        def create(cls, stark_info: StarkInfo, trace: np.ndarray,
                   const_pols: np.ndarray, const_pols_extended: np.ndarray) -> "ProverContext":
            """Factory to create a ProverContext for proof generation."""
            buffers = BufferLayout.create_for_prover(
                stark_info, trace, const_pols, const_pols_extended
            )
            challenges = ChallengeStore.create(stark_info.challenges_map)
            evaluations = EvaluationStore.create(stark_info.ev_map)
            values = ValueStore.create(
                n_publics=stark_info.n_publics,
                air_values_size=stark_info.air_values_size,
                airgroup_values_size=stark_info.airgroup_values_size,
            )
            return cls(buffers=buffers, challenges=challenges,
                      evaluations=evaluations, values=values)
    ```
  - Exports: `ProverContext`
  - Context: Composes the four stores into a unified prover interface with backward-compat properties

- [x] **Task #6**: Create VerifierContext class
  - Folder: `executable-spec/protocol/`
  - File: `verifier_context.py`
  - Imports:
    ```python
    from dataclasses import dataclass
    import numpy as np
    from protocol.buffer_layout import BufferLayout
    from protocol.challenge_store import ChallengeStore
    from protocol.evaluation_store import EvaluationStore
    from protocol.value_store import ValueStore
    from protocol.stark_info import StarkInfo
    ```
  - Implements:
    ```python
    @dataclass
    class VerifierContext:
        """Complete verifier state composed of single-responsibility stores.

        Similar to ProverContext but:
        - Buffers are query-sized (n_queries rows), not full domain
        - No constPolsExtended (verifier doesn't need extended constants)
        - Has xDivXSub precomputation in evaluations store
        """
        buffers: BufferLayout
        challenges: ChallengeStore
        evaluations: EvaluationStore
        values: ValueStore

        # Same backward compatibility properties as ProverContext
        @property
        def trace(self) -> np.ndarray | None:
            return self.buffers.trace

        @property
        def auxTrace(self) -> np.ndarray | None:
            return self.buffers.aux_trace

        @property
        def constPols(self) -> np.ndarray | None:
            return self.buffers.const_pols

        @property
        def evals(self) -> np.ndarray | None:
            return self.evaluations.to_array()

        @property
        def xDivXSub(self) -> np.ndarray | None:
            return self.evaluations.x_div_x_sub

        @property
        def publicInputs(self) -> np.ndarray | None:
            return self.values.public_inputs

        @property
        def airgroupValues(self) -> np.ndarray | None:
            return self.values.airgroup_values

        @property
        def airValues(self) -> np.ndarray | None:
            return self.values.air_values

        def get_challenge(self, index: int) -> list[int]:
            return list(self.challenges.get_by_index(index).coeffs)

        @classmethod
        def create(cls, stark_info: StarkInfo, trace: np.ndarray, aux_trace: np.ndarray,
                   const_pols: np.ndarray, challenges: np.ndarray, evals: np.ndarray,
                   x_div_x_sub: np.ndarray, air_values: np.ndarray,
                   airgroup_values: np.ndarray, public_inputs: np.ndarray,
                   proof_values: np.ndarray) -> "VerifierContext":
            """Factory to create a VerifierContext from parsed proof data."""
            buffers = BufferLayout.create_for_verifier(
                stark_info, trace, aux_trace, const_pols
            )
            challenge_store = ChallengeStore.create(
                stark_info.challenges_map, initial_data=challenges
            )
            evaluations = EvaluationStore.create(
                stark_info.ev_map, initial_evals=evals
            )
            evaluations.x_div_x_sub = x_div_x_sub
            values = ValueStore(
                public_inputs=public_inputs,
                proof_values=proof_values,
                air_values=air_values,
                airgroup_values=airgroup_values,
            )
            return cls(buffers=buffers, challenges=challenge_store,
                      evaluations=evaluations, values=values)
    ```
  - Exports: `VerifierContext`
  - Context: Verifier variant with different initialization and xDivXSub support

#### Group C: Migration (Execute sequentially after Group B)

- [x] **Task #7**: Migrate stages.py to use BufferLayout
  - File: `executable-spec/protocol/stages.py`
  - Changes:
    - Import `BufferLayout` from `protocol.buffer_layout`
    - `_build_prover_data_extended()`: Replace manual offset calculation with `params.buffers.get_section()`
    - `_build_prover_data_base()`: Replace manual offset calculation with `params.buffers.get_section()`
    - `_write_witness_to_buffer()`: Replace manual writes with `params.buffers.write_section()`
    - `Starks.extendAndMerkelize()`: Use `buffers.get_section()` and `buffers.write_section()`
    - `Starks.commitStage()`: Use `buffers.get_section()`
    - `Starks.computeFriPol()`: Use `buffers.get_section("q", True)` for quotient
    - `Starks.calculateQuotientPolynomial()`: Use `buffers.write_section()`
    - `Starks.calculateFRIPolynomial()`: Use `buffers.write_section("f", True, ...)`
    - `Starks._load_evmap_poly()`: Use `buffers.get_polynomial()`
  - Context: This is the largest migration - stages.py has the most buffer access code. Run tests after.

- [x] **Task #8**: Migrate prover.py to use ProverContext
  - File: `executable-spec/protocol/prover.py`
  - Changes:
    - Import `ProverContext` from `protocol.prover_context`
    - Update type hints: `params: ProofContext` -> `params: ProverContext`
    - `_derive_stage_challenges()`: Use `params.challenges.set(name, value)` where possible
    - `_derive_eval_challenges()`: Use named challenge access
    - `gen_proof()`: Optionally accept ProverContext or create from ProofContext for backward compat
    - Replace `params.get_challenge(index)` with `params.challenges.get_by_index(index)` (or named)
  - Context: Prover is the main consumer. Backward-compat properties ensure minimal changes needed.

- [x] **Task #9**: Migrate verifier.py to use VerifierContext
  - File: `executable-spec/protocol/verifier.py`
  - Changes:
    - Import `VerifierContext` from `protocol.verifier_context`
    - `stark_verify()`: Create VerifierContext instead of ProofContext
    - `_build_verifier_data()`: Use `params.challenges.get(name)` for named access
    - `_verify_fri_consistency()`: Pass VerifierContext to fri_polynomial functions
  - Context: Verifier creates the context from parsed proof data
  - Note: Also added `__getitem__` and `__len__` to ChallengeStore for backward compatibility with fri_polynomial.py array access

- [x] **Task #10**: Migrate fri_polynomial.py to use new stores
  - File: `executable-spec/protocol/fri_polynomial.py`
  - Changes:
    - Updated type hints to use `ProverContext` and `VerifierContext` instead of `ProofContext`
    - Added `ProofParams` type alias for functions that accept either context type
    - Updated imports to reference new context modules
    - Updated docstrings to reflect new types
    - Note: Buffer and challenge access uses backward-compat properties/methods which work with both new stores
  - Context: FRI polynomial has significant buffer access for polynomial batching

#### Group D: Cleanup (Execute after Group C)

- [x] **Task #11**: Deprecate ProofContext
  - File: `executable-spec/protocol/proof_context.py`
  - Changes:
    - Add deprecation warning to class docstring
    - Add `warnings.warn()` in `__init__` or `__post_init__`
    - Keep class for backward compatibility but mark as deprecated
  - Context: Don't delete yet - external code may depend on it

- [x] **Task #12**: Update protocol/__init__.py exports
  - File: `executable-spec/protocol/__init__.py`
  - Changes:
    - Add exports: `BufferLayout`, `ChallengeStore`, `EvaluationStore`, `ValueStore`
    - Add exports: `ProverContext`, `VerifierContext`
    - Keep `ProofContext` export but mark as deprecated in comment
  - Context: Public API should expose new classes

- [x] **Task #13**: Migrate test fixtures
  - Files: `tests/test_stark_e2e.py`, `tests/test_verifier_e2e.py`
  - Changes:
    - `create_params_from_vectors()`: Return ProverContext instead of ProofContext
    - Update any direct buffer access to use new methods
    - Verify all 155 tests still pass
  - Context: Tests validate the migration is complete and correct
  - Note: Also fixed uint64 dtype in BufferLayout, ChallengeStore, EvaluationStore, ValueStore for field element compatibility

#### Group E: Verification (Execute last)

- [x] **Task #14**: Run full test suite and verify binary compatibility
  - Commands:
    ```bash
    cd executable-spec
    ./run-tests.sh  # All tests must pass
    ```
  - Verification:
    - All E2E tests produce byte-identical proofs
    - No import errors
    - No runtime attribute errors
    - Deprecation warnings appear for ProofContext usage
  - Context: Final verification that refactoring is complete and correct

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
- Tasks in Group A can run in parallel
- Tasks in Group C should run sequentially (each builds on previous migration)
- **RUN TESTS FREQUENTLY**: After each task, run `./run-tests.sh` to catch regressions early

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

---

## Appendix: Migration Cheat Sheet

### Old Pattern → New Pattern

**Buffer access:**
```python
# OLD
offset = stark_info.map_offsets[("cm2", True)]
n_cols = stark_info.map_sections_n["cm2"]
data = params.auxTrace[offset:offset + N_ext * n_cols]

# NEW
data = params.buffers.get_section("cm2", extended=True)
```

**Challenge access:**
```python
# OLD
base = index * FIELD_EXTENSION_DEGREE
coeffs = [params.challenges[base + j] for j in range(3)]

# NEW (by index)
value = params.challenges.get_by_index(index)

# NEW (by name - preferred)
value = params.challenges.get("std_alpha")
```

**Writing to buffer:**
```python
# OLD
offset = stark_info.map_offsets[("f", True)]
params.auxTrace[offset:offset + N_ext * 3] = fri_poly.flatten()

# NEW
params.buffers.write_section("f", extended=True, data=fri_poly.flatten())
```
