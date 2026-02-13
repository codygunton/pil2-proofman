# Remove Expression Binaries Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace C++ expression binary bytecode interpretation with direct Python constraint code, making the executable spec self-contained and readable.

**Architecture:** Per-AIR constraint modules evaluate constraints (prover + verifier). Per-AIR witness modules generate intermediate polynomials (prover only). Clean `ProverData`/`VerifierData` replace buffer-style `ProofContext`. Names resolved from `stark_info.json` mappings.

**Tech Stack:** Python 3.11+, galois (finite fields), numpy, pytest

---

## Phase 1: Infrastructure

### Task 1.1: Create ProverData and VerifierData dataclasses

**Files:**
- Create: `executable-spec/protocol/data.py`
- Test: `executable-spec/tests/test_data.py`

**Step 1: Write failing test for ProverData**

```python
# tests/test_data.py
import pytest
from primitives.field import FF, FF3

def test_prover_data_stores_columns():
    from protocol.data import ProverData

    # Create simple test data
    columns = {'a': FF3.Random(8), 'b': FF3.Random(8)}
    challenges = {'std_alpha': FF3.Random(1)[0]}

    data = ProverData(columns=columns, challenges=challenges)

    assert 'a' in data.columns
    assert 'std_alpha' in data.challenges
```

**Step 2: Run test to verify it fails**

Run: `cd executable-spec && uv run pytest tests/test_data.py::test_prover_data_stores_columns -v`
Expected: FAIL with "No module named 'protocol.data'"

**Step 3: Write minimal implementation**

```python
# protocol/data.py
"""Clean data structures for prover and verifier."""

from dataclasses import dataclass, field
from typing import Optional

from primitives.field import FF, FF3

# Type aliases
FF3Poly = FF3  # Array of extension field elements
FFPoly = FF    # Array of base field elements


@dataclass
class ProverData:
    """All polynomial data for proving."""
    columns: dict[str, FF3Poly] = field(default_factory=dict)
    constants: dict[str, FFPoly] = field(default_factory=dict)
    challenges: dict[str, FF3] = field(default_factory=dict)
    public_inputs: dict[str, FF] = field(default_factory=dict)

    def update_columns(self, new_columns: dict[str, FF3Poly]) -> None:
        """Add new columns (e.g., intermediates from witness generation)."""
        self.columns.update(new_columns)


@dataclass
class VerifierData:
    """All evaluation data for verification."""
    evals: dict[tuple[str, int, int], FF3] = field(default_factory=dict)  # (name, index, offset) -> value
    challenges: dict[str, FF3] = field(default_factory=dict)
    public_inputs: dict[str, FF] = field(default_factory=dict)
```

**Step 4: Run test to verify it passes**

Run: `cd executable-spec && uv run pytest tests/test_data.py::test_prover_data_stores_columns -v`
Expected: PASS

**Step 5: Write test for VerifierData**

```python
# Add to tests/test_data.py
def test_verifier_data_stores_evals():
    from protocol.data import VerifierData

    evals = {('a', 0, 0): FF3.Random(1)[0], ('a', 0, 1): FF3.Random(1)[0]}
    challenges = {'std_alpha': FF3.Random(1)[0]}

    data = VerifierData(evals=evals, challenges=challenges)

    assert ('a', 0, 0) in data.evals
    assert 'std_alpha' in data.challenges
```

**Step 6: Run test to verify it passes**

Run: `cd executable-spec && uv run pytest tests/test_data.py -v`
Expected: PASS (both tests)

**Step 7: Commit**

```bash
git add executable-spec/protocol/data.py executable-spec/tests/test_data.py
git commit -m "feat: add ProverData and VerifierData dataclasses"
```

---

### Task 1.2: Create ConstraintContext ABC and implementations

**Files:**
- Create: `executable-spec/constraints/__init__.py`
- Create: `executable-spec/constraints/base.py`
- Test: `executable-spec/tests/test_constraint_context.py`

**Step 1: Write failing test for ProverConstraintContext**

```python
# tests/test_constraint_context.py
import pytest
import numpy as np
from primitives.field import FF, FF3


def test_prover_context_col_returns_array():
    from constraints.base import ProverConstraintContext
    from protocol.data import ProverData

    # Create test data with 8 rows
    a_values = FF3.Random(8)
    columns = {('a', 0): a_values}
    challenges = {'std_alpha': FF3.Random(1)[0]}

    data = ProverData(columns=columns, challenges=challenges)
    ctx = ProverConstraintContext(data)

    result = ctx.col('a')
    assert len(result) == 8
    assert np.array_equal(result, a_values)


def test_prover_context_next_col_shifts():
    from constraints.base import ProverConstraintContext
    from protocol.data import ProverData

    # Create sequential values for easy verification
    a_values = FF3([1, 2, 3, 4, 5, 6, 7, 8])
    columns = {('a', 0): a_values}

    data = ProverData(columns=columns, challenges={})
    ctx = ProverConstraintContext(data)

    result = ctx.next_col('a')
    # next_col shifts by -1, so [1,2,3,4,5,6,7,8] -> [2,3,4,5,6,7,8,1]
    expected = FF3([2, 3, 4, 5, 6, 7, 8, 1])
    assert np.array_equal(result, expected)


def test_prover_context_challenge_returns_scalar():
    from constraints.base import ProverConstraintContext
    from protocol.data import ProverData

    alpha = FF3.Random(1)[0]
    data = ProverData(columns={}, challenges={'std_alpha': alpha})
    ctx = ProverConstraintContext(data)

    result = ctx.challenge('std_alpha')
    assert result == alpha
```

**Step 2: Run test to verify it fails**

Run: `cd executable-spec && uv run pytest tests/test_constraint_context.py -v`
Expected: FAIL with "No module named 'constraints'"

**Step 3: Write implementation**

```python
# constraints/__init__.py
"""Constraint evaluation modules."""

from .base import (
    ConstraintContext,
    ProverConstraintContext,
    VerifierConstraintContext,
    ConstraintModule,
)

__all__ = [
    'ConstraintContext',
    'ProverConstraintContext',
    'VerifierConstraintContext',
    'ConstraintModule',
]
```

```python
# constraints/base.py
"""Base classes for constraint evaluation."""

from abc import ABC, abstractmethod
from typing import Union

import numpy as np

from primitives.field import FF, FF3
from protocol.data import ProverData, VerifierData

# Type aliases
FF3Poly = FF3
FFPoly = FF


class ConstraintContext(ABC):
    """Uniform interface for constraint evaluation - works for prover and verifier."""

    @abstractmethod
    def col(self, name: str, index: int = 0) -> Union[FF3Poly, FF3]:
        """Get column at current row. Returns array (prover) or scalar (verifier)."""
        pass

    @abstractmethod
    def next_col(self, name: str, index: int = 0) -> Union[FF3Poly, FF3]:
        """Get column at next row (offset +1)."""
        pass

    @abstractmethod
    def prev_col(self, name: str, index: int = 0) -> Union[FF3Poly, FF3]:
        """Get column at previous row (offset -1)."""
        pass

    @abstractmethod
    def const(self, name: str) -> Union[FFPoly, FF]:
        """Get constant polynomial."""
        pass

    @abstractmethod
    def challenge(self, name: str) -> FF3:
        """Get Fiat-Shamir challenge (always scalar)."""
        pass


class ProverConstraintContext(ConstraintContext):
    """Prover implementation - returns polynomial arrays."""

    def __init__(self, data: ProverData):
        self._data = data

    def col(self, name: str, index: int = 0) -> FF3Poly:
        key = (name, index)
        return self._data.columns[key]

    def next_col(self, name: str, index: int = 0) -> FF3Poly:
        return np.roll(self.col(name, index), -1)

    def prev_col(self, name: str, index: int = 0) -> FF3Poly:
        return np.roll(self.col(name, index), 1)

    def const(self, name: str) -> FFPoly:
        return self._data.constants[name]

    def challenge(self, name: str) -> FF3:
        return self._data.challenges[name]


class VerifierConstraintContext(ConstraintContext):
    """Verifier implementation - returns scalar evaluations."""

    def __init__(self, data: VerifierData):
        self._data = data

    def col(self, name: str, index: int = 0) -> FF3:
        return self._data.evals[(name, index, 0)]

    def next_col(self, name: str, index: int = 0) -> FF3:
        return self._data.evals[(name, index, 1)]

    def prev_col(self, name: str, index: int = 0) -> FF3:
        return self._data.evals[(name, index, -1)]

    def const(self, name: str) -> FF:
        return self._data.evals[(name, 0, 0)]  # Constants stored in evals too

    def challenge(self, name: str) -> FF3:
        return self._data.challenges[name]


class ConstraintModule(ABC):
    """Per-AIR constraint evaluation. Used by both prover and verifier."""

    @abstractmethod
    def constraint_polynomial(self, ctx: ConstraintContext) -> Union[FF3Poly, FF3]:
        """Evaluate all constraints combined into single polynomial.

        Returns:
            Prover: array of constraint evaluations at all domain points
            Verifier: single constraint evaluation at xi
        """
        pass
```

**Step 4: Run test to verify it passes**

Run: `cd executable-spec && uv run pytest tests/test_constraint_context.py -v`
Expected: PASS (all 3 tests)

**Step 5: Commit**

```bash
git add executable-spec/constraints/
git add executable-spec/tests/test_constraint_context.py
git commit -m "feat: add ConstraintContext ABC and Prover/Verifier implementations"
```

---

### Task 1.3: Create WitnessModule ABC

**Files:**
- Create: `executable-spec/witness/__init__.py`
- Create: `executable-spec/witness/base.py`
- Test: `executable-spec/tests/test_witness_base.py`

**Step 1: Write test for WitnessModule interface**

```python
# tests/test_witness_base.py
import pytest
from primitives.field import FF3


def test_witness_module_is_abstract():
    from witness.base import WitnessModule

    with pytest.raises(TypeError):
        WitnessModule()  # Can't instantiate abstract class


def test_witness_module_subclass_must_implement_methods():
    from witness.base import WitnessModule
    from constraints.base import ConstraintContext

    class IncompleteWitness(WitnessModule):
        pass

    with pytest.raises(TypeError):
        IncompleteWitness()
```

**Step 2: Run test to verify it fails**

Run: `cd executable-spec && uv run pytest tests/test_witness_base.py -v`
Expected: FAIL with "No module named 'witness'"

**Step 3: Write implementation**

```python
# witness/__init__.py
"""Witness generation modules."""

from .base import WitnessModule

__all__ = ['WitnessModule']
```

```python
# witness/base.py
"""Base class for witness generation."""

from abc import ABC, abstractmethod
from typing import Dict

from primitives.field import FF3
from constraints.base import ConstraintContext

# Type alias
FF3Poly = FF3


class WitnessModule(ABC):
    """Per-AIR witness generation. Used by prover only."""

    @abstractmethod
    def compute_intermediates(self, ctx: ConstraintContext) -> Dict[str, Dict[int, FF3Poly]]:
        """Compute im_cluster polynomials.

        Returns:
            {'im_cluster': {0: poly0, 1: poly1, ...}}
        """
        pass

    @abstractmethod
    def compute_grand_sums(self, ctx: ConstraintContext) -> Dict[str, FF3Poly]:
        """Compute gsum/gprod running sum polynomials.

        Returns:
            {'gsum': gsum_poly}
        """
        pass
```

**Step 4: Run test to verify it passes**

Run: `cd executable-spec && uv run pytest tests/test_witness_base.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add executable-spec/witness/
git add executable-spec/tests/test_witness_base.py
git commit -m "feat: add WitnessModule ABC for witness generation"
```

---

### Task 1.4: Add name mapping helpers to StarkInfo

**Files:**
- Modify: `executable-spec/protocol/stark_info.py`
- Test: `executable-spec/tests/test_stark_info.py` (add tests)

**Step 1: Write failing test for name mapping**

```python
# Add to tests/test_stark_info.py in TestStarkInfoSimple class

def test_get_column_key_by_name(self, stark_info):
    """Test resolving column name to (name, index) key."""
    # 'a' is the first committed polynomial
    key = stark_info.get_column_key('a')
    assert key == ('a', 0)

    # 'im_cluster' has multiple instances
    key = stark_info.get_column_key('im_cluster', index=3)
    assert key == ('im_cluster', 3)


def test_get_challenge_by_name(self, stark_info):
    """Test resolving challenge name."""
    # Should find std_alpha in challengesMap
    assert stark_info.has_challenge('std_alpha')
    assert stark_info.has_challenge('std_gamma')
    assert not stark_info.has_challenge('nonexistent')


def test_build_column_name_map(self, stark_info):
    """Test building complete name -> indices mapping."""
    name_map = stark_info.build_column_name_map()

    # Single columns
    assert 'a' in name_map
    assert name_map['a'] == [0]  # Just index 0

    # Array columns (im_cluster appears multiple times)
    assert 'im_cluster' in name_map
    assert len(name_map['im_cluster']) == 6  # 6 im_cluster columns
```

**Step 2: Run test to verify it fails**

Run: `cd executable-spec && uv run pytest tests/test_stark_info.py::TestStarkInfoSimple::test_get_column_key_by_name -v`
Expected: FAIL with "has no attribute 'get_column_key'"

**Step 3: Add methods to StarkInfo class**

Add these methods to the `StarkInfo` class in `protocol/stark_info.py`:

```python
def get_column_key(self, name: str, index: int = 0) -> tuple[str, int]:
    """Get the (name, index) key for a column.

    Args:
        name: Column name (e.g., 'a', 'im_cluster')
        index: Index for array columns (default 0)

    Returns:
        Tuple (name, index) for use as dict key
    """
    return (name, index)

def has_challenge(self, name: str) -> bool:
    """Check if a challenge with given name exists."""
    return any(cm.name == name for cm in self.challengesMap)

def get_challenge_index(self, name: str) -> int:
    """Get the index of a challenge by name."""
    for i, cm in enumerate(self.challengesMap):
        if cm.name == name:
            return i
    raise KeyError(f"Challenge '{name}' not found")

def build_column_name_map(self) -> dict[str, list[int]]:
    """Build mapping from column names to their polsMapId indices.

    Returns:
        Dict mapping name -> list of polsMapId values
        e.g., {'a': [0], 'im_cluster': [16, 17, 18, 19, 20, 21]}
    """
    name_map: dict[str, list[int]] = {}
    for cm in self.cmPolsMap:
        if cm.name not in name_map:
            name_map[cm.name] = []
        name_map[cm.name].append(cm.polsMapId)
    return name_map
```

**Step 4: Run test to verify it passes**

Run: `cd executable-spec && uv run pytest tests/test_stark_info.py::TestStarkInfoSimple::test_get_column_key_by_name tests/test_stark_info.py::TestStarkInfoSimple::test_get_challenge_by_name tests/test_stark_info.py::TestStarkInfoSimple::test_build_column_name_map -v`
Expected: PASS

**Step 5: Commit**

```bash
git add executable-spec/protocol/stark_info.py executable-spec/tests/test_stark_info.py
git commit -m "feat: add name mapping helpers to StarkInfo"
```

---

## Phase 2: SimpleLeft Implementation (can run in parallel with Phase 3, 4)

### Task 2.1: Implement SimpleLeft constraint module

**Files:**
- Create: `executable-spec/constraints/simple_left.py`
- Test: `executable-spec/tests/test_simple_left_constraints.py`

**Context:** SimpleLeft is the simplest AIR with 8 rows. Refer to `tests/test-data/simple-left.json` for expected values. The constraint polynomial combines logup recurrence checks and boundary constraints.

**Step 1: Write failing test**

```python
# tests/test_simple_left_constraints.py
import pytest
import json
from pathlib import Path
from primitives.field import FF, FF3


TEST_DATA = Path(__file__).parent / "test-data" / "simple-left.json"


@pytest.fixture
def test_vectors():
    with open(TEST_DATA) as f:
        return json.load(f)


def test_simple_left_constraint_polynomial_shape(test_vectors):
    """Constraint polynomial should have correct shape."""
    from constraints.simple_left import SimpleLeftConstraints
    from constraints.base import ProverConstraintContext
    from protocol.data import ProverData

    # This test will be filled in once we understand the data layout
    # For now, just verify the module loads
    module = SimpleLeftConstraints()
    assert hasattr(module, 'constraint_polynomial')
```

**Step 2: Run test to verify it fails**

Run: `cd executable-spec && uv run pytest tests/test_simple_left_constraints.py -v`
Expected: FAIL with "No module named 'constraints.simple_left'"

**Step 3: Write initial implementation (skeleton)**

```python
# constraints/simple_left.py
"""SimpleLeft AIR constraint evaluation."""

from typing import Union

from primitives.field import FF, FF3
from .base import ConstraintModule, ConstraintContext

FF3Poly = FF3


class SimpleLeftConstraints(ConstraintModule):
    """Constraint evaluation for SimpleLeft AIR.

    SimpleLeft has 8 rows and uses the logup protocol for lookups.
    Constraints:
    - Grand sum recurrence: gsum' = gsum + sum(im_cluster[i])
    - Boundary: gsum[0] = 0
    """

    def constraint_polynomial(self, ctx: ConstraintContext) -> Union[FF3Poly, FF3]:
        """Evaluate combined constraint polynomial.

        TODO: Implement actual constraints after studying expression binary output.
        """
        # Placeholder - will be implemented by studying the expression evaluator output
        raise NotImplementedError("SimpleLeft constraints not yet implemented")
```

**Step 4: Update test to check skeleton loads**

Run: `cd executable-spec && uv run pytest tests/test_simple_left_constraints.py -v`
Expected: PASS (skeleton test)

**Step 5: Commit skeleton**

```bash
git add executable-spec/constraints/simple_left.py executable-spec/tests/test_simple_left_constraints.py
git commit -m "feat: add SimpleLeft constraint module skeleton"
```

**Step 6: Study existing expression output and implement full constraints**

This step requires careful study of what the expression evaluator produces for SimpleLeft. Use the existing tests to capture expected intermediate values, then implement the constraint polynomial to match.

---

### Task 2.2: Implement SimpleLeft witness module

**Files:**
- Create: `executable-spec/witness/simple_left.py`
- Test: `executable-spec/tests/test_simple_left_witness.py`

**Step 1: Write failing test**

```python
# tests/test_simple_left_witness.py
import pytest
from primitives.field import FF3


def test_simple_left_witness_module_loads():
    from witness.simple_left import SimpleLeftWitness

    module = SimpleLeftWitness()
    assert hasattr(module, 'compute_intermediates')
    assert hasattr(module, 'compute_grand_sums')
```

**Step 2: Run test to verify it fails**

Run: `cd executable-spec && uv run pytest tests/test_simple_left_witness.py -v`
Expected: FAIL with "No module named 'witness.simple_left'"

**Step 3: Write skeleton implementation**

```python
# witness/simple_left.py
"""SimpleLeft AIR witness generation."""

from typing import Dict

from primitives.field import FF3
from constraints.base import ConstraintContext
from .base import WitnessModule

FF3Poly = FF3


class SimpleLeftWitness(WitnessModule):
    """Witness generation for SimpleLeft AIR."""

    def compute_intermediates(self, ctx: ConstraintContext) -> Dict[str, Dict[int, FF3Poly]]:
        """Compute im_cluster polynomials (batch inverses for logup)."""
        raise NotImplementedError("SimpleLeft intermediates not yet implemented")

    def compute_grand_sums(self, ctx: ConstraintContext) -> Dict[str, FF3Poly]:
        """Compute gsum running sum polynomial."""
        raise NotImplementedError("SimpleLeft grand sums not yet implemented")
```

**Step 4: Run test and commit**

Run: `cd executable-spec && uv run pytest tests/test_simple_left_witness.py -v`
Expected: PASS

```bash
git add executable-spec/witness/simple_left.py executable-spec/tests/test_simple_left_witness.py
git commit -m "feat: add SimpleLeft witness module skeleton"
```

---

## Phase 3: Lookup2_12 Implementation (parallel with Phase 2, 4)

### Task 3.1: Implement Lookup2_12 constraint module

**Files:**
- Create: `executable-spec/constraints/lookup2_12.py`
- Test: `executable-spec/tests/test_lookup2_12_constraints.py`

Follow same pattern as Task 2.1.

---

### Task 3.2: Implement Lookup2_12 witness module

**Files:**
- Create: `executable-spec/witness/lookup2_12.py`
- Test: `executable-spec/tests/test_lookup2_12_witness.py`

Follow same pattern as Task 2.2.

---

## Phase 4: Permutation1_6 Implementation (parallel with Phase 2, 3)

### Task 4.1: Implement Permutation1_6 constraint module

**Files:**
- Create: `executable-spec/constraints/permutation1_6.py`
- Test: `executable-spec/tests/test_permutation1_6_constraints.py`

Follow same pattern as Task 2.1.

---

### Task 4.2: Implement Permutation1_6 witness module

**Files:**
- Create: `executable-spec/witness/permutation1_6.py`
- Test: `executable-spec/tests/test_permutation1_6_witness.py`

Follow same pattern as Task 2.2.

---

## Phase 5: Prover Integration

### Task 5.1: Wire constraint modules into prover

**Files:**
- Modify: `executable-spec/protocol/prover.py`
- Create: `executable-spec/constraints/registry.py`

**Step 1: Create module registry**

```python
# constraints/registry.py
"""Registry for constraint and witness modules."""

from typing import Optional

from .base import ConstraintModule
from .simple_left import SimpleLeftConstraints
from .lookup2_12 import Lookup2_12Constraints
from .permutation1_6 import Permutation1_6Constraints

from witness.base import WitnessModule
from witness.simple_left import SimpleLeftWitness
from witness.lookup2_12 import Lookup2_12Witness
from witness.permutation1_6 import Permutation1_6Witness


_CONSTRAINT_MODULES = {
    'SimpleLeft': SimpleLeftConstraints,
    'Lookup2_12': Lookup2_12Constraints,
    'Permutation1_6': Permutation1_6Constraints,
}

_WITNESS_MODULES = {
    'SimpleLeft': SimpleLeftWitness,
    'Lookup2_12': Lookup2_12Witness,
    'Permutation1_6': Permutation1_6Witness,
}


def get_constraint_module(air_name: str) -> ConstraintModule:
    """Get constraint module for an AIR by name."""
    if air_name not in _CONSTRAINT_MODULES:
        raise KeyError(f"No constraint module for AIR '{air_name}'")
    return _CONSTRAINT_MODULES[air_name]()


def get_witness_module(air_name: str) -> WitnessModule:
    """Get witness module for an AIR by name."""
    if air_name not in _WITNESS_MODULES:
        raise KeyError(f"No witness module for AIR '{air_name}'")
    return _WITNESS_MODULES[air_name]()
```

**Step 2: Integrate into prover.py**

Modify `prover.py` to use the new modules alongside (not replacing yet) the expression evaluator. Add a feature flag to switch between old and new code paths for testing.

---

### Task 5.2: Verify byte-identical proofs with new code path

**Test:** Run full E2E tests with new constraint modules:

```bash
cd executable-spec && uv run pytest tests/test_stark_e2e.py -v
```

All tests must pass with byte-identical proofs.

---

## Phase 6: Verifier Integration

### Task 6.1: Wire constraint modules into verifier

**Files:**
- Modify: `executable-spec/protocol/verifier.py`

Update verifier to use `VerifierConstraintContext` and `ConstraintModule.constraint_polynomial()`.

---

## Phase 7: Cleanup

### Task 7.1: Delete expression binary machinery

**Files to delete:**
- `executable-spec/protocol/expressions_bin.py`

**Files to gut:**
- `executable-spec/protocol/expression_evaluator.py` - keep only minimal helpers if needed
- `executable-spec/protocol/witness_generation.py` - remove hint parsing

### Task 7.2: Remove ProofContext, migrate fully to ProverData/VerifierData

### Task 7.3: Final test verification

```bash
cd executable-spec && uv run pytest tests/ -v
```

All 146 tests must pass.

---

## Verification Checkpoints

After each task:
1. Run `uv run pytest tests/ -v --tb=short`
2. For AIR implementations, specifically run `test_stark_e2e.py` to verify byte-identical proofs
3. Commit working code frequently

## Notes for Implementer

- **Expression binary study:** Before implementing constraint modules, study the output of `expression_evaluator.py` for each AIR to understand the exact constraint formulas.
- **Test vectors:** The `tests/test-data/*.json` files contain expected intermediate values - use these to verify correctness.
- **Galois broadcasting:** Remember that the same constraint code works for arrays (prover) and scalars (verifier) thanks to numpy broadcasting.
- **Row offsets:** `next_col()` uses `np.roll(arr, -1)` for circular shift. The constraint polynomial evaluation accounts for boundary conditions.
