# Debug New Simple AIRs — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix `test_full_proof_verifies` for u8_air, u16_air, and specified_ranges by debugging in a structured, layered way — starting from the verifier (using C++ ground-truth proofs) rather than debugging full E2E blindly.

**Architecture:** Three-layer debugging strategy. Layer 1 (verifier): can the Python verifier accept a known-good C++ proof? Layer 2 (constraint zeros): does the bytecode constraint evaluate to zero on the C++ trace? Layer 3 (prover): fix whatever layer reveals the bug. Stop as soon as a layer diagnoses the root cause.

**Tech Stack:** Python, pytest, galois/numpy, existing bytecode adapter (`BytecodeConstraintModule`), `test_verifier_e2e.py`, `test_bytecode_equivalence.py`

---

## Background

Three AIRs fail `test_full_proof_verifies` with "ERROR: Invalid evaluations" (Q_proof ≠ Q_constraint):

| AIR | N | qDeg | im_pol? | Most likely cause |
|-----|---|------|---------|-------------------|
| u8_air | 128 | 1 | Yes (exp_id=11) | Witness: C(x) ≠ 0 on trace |
| u16_air | 16384 | 2 | No | Prover or verifier: qDeg=2 handling |
| specified_ranges | 64 | 2 | No | Prover or verifier: qDeg=2 handling |

C++ `.proof.bin` files exist for all three in `tests/test-data/`. These are ground-truth proofs.

Key files:
- `tests/test_verifier_e2e.py` — only covers simple/lookup/permutation (does NOT include new AIRs)
- `tests/test_bytecode_equivalence.py` — only covers SimpleLeft/Lookup2_12/Permutation1_6
- `protocol/stages.py:551` — `computeFriPol` (quotient polynomial splitting for qDeg≥2)
- `protocol/verifier.py:702` — `_reconstruct_quotient_at_xi` (verifier Q reconstruction)
- `primitives/expression_bytecode/witness_generation.py:428` — im_pol fix (after gsum)

---

## Task 1: Verify C++ proofs with Python verifier

**Goal:** Determine if the Python verifier accepts known-good C++ proofs for the three failing AIRs.
If this PASSES → verifier is correct, bug is prover-side. Skip to Task 3.
If this FAILS → verifier has a bug. Fix it in Task 2.

**File:** `executable-spec/tests/test_verifier_e2e.py`

**Step 1: Read test_verifier_e2e.py AIR_CONFIGS (lines 24-40) to understand format**

```python
AIR_CONFIGS = {
    'simple': {
        'starkinfo': '../../pil2-components/test/simple/.../SimpleLeft.starkinfo.json',
        'test_vector': 'simple-left.json',   # .replace('.json', '.proof.bin') = proof path
        'expressions_bin': '...',
    },
    ...
}
```

**Step 2: Add three new entries to AIR_CONFIGS**

```python
_SIMPLE_PK = '../../pil2-components/test/simple/build/provingKey'

'u8_air': {
    'test_vector': 'u8-air.json',
    'starkinfo': f'{_SIMPLE_PK}/build/Simple/airs/U8Air/air/U8Air.starkinfo.json',
    'expressions_bin': f'{_SIMPLE_PK}/build/Simple/airs/U8Air/air/U8Air.bin',
},
'specified_ranges': {
    'test_vector': 'specified-ranges.json',
    'starkinfo': f'{_SIMPLE_PK}/build/Simple/airs/SpecifiedRanges/air/SpecifiedRanges.starkinfo.json',
    'expressions_bin': f'{_SIMPLE_PK}/build/Simple/airs/SpecifiedRanges/air/SpecifiedRanges.bin',
},
'u16_air': {
    'test_vector': 'u16-air.json',
    'starkinfo': f'{_SIMPLE_PK}/build/Simple/airs/U16Air/air/U16Air.starkinfo.json',
    'expressions_bin': f'{_SIMPLE_PK}/build/Simple/airs/U16Air/air/U16Air.bin',
},
```

**Step 3: Check how test_vector → proof_bin works in the existing test**

In `test_verify_valid_proof` (line ~141):
```python
bin_filename = config['test_vector'].replace('.json', '.proof.bin')
```
Verify this maps correctly:
- `u8-air.json` → `u8-air.proof.bin` ✓
- `specified-ranges.json` → `specified-ranges.proof.bin` ✓
- `u16-air.json` → `u16-air.proof.bin` ✓

**Step 4: Check if test_verifier_e2e needs global_info for these AIRs**

The existing `load_air_config` in test_verifier_e2e.py calls `AirConfig.from_starkinfo(str(starkinfo_path))` with no global_info. Check if u8_air/u16_air/specified_ranges require global_info (they're in the Simple pilout so they do have shared airgroup values). If `AirConfig.from_starkinfo` fails without global_info, update `load_air_config` to optionally accept a global_info path, or add global_info to AIR_CONFIGS.

Global info path: `{_SIMPLE_PK}/pilout.globalInfo.json`

**Step 5: Extend parametrize list**

Find the line:
```python
@pytest.mark.parametrize("air_name", ['simple', 'lookup', 'permutation'])
def test_verify_valid_proof(self, air_name: str) -> None:
```

Add the new AIRs (note: skip u16_air last since it's slow, test u8_air and specified_ranges first):
```python
@pytest.mark.parametrize("air_name", ['simple', 'lookup', 'permutation',
                                       'u8_air', 'specified_ranges', 'u16_air'])
```

**Step 6: Run the new verifier tests** (fast first — u8_air and specified_ranges)

```bash
cd executable-spec
uv run pytest tests/test_verifier_e2e.py::TestVerifierE2E::test_verify_valid_proof -k "u8_air or specified_ranges" -v --no-header -s
```

Expected output: either PASS or FAIL with specific error.

**Step 7: If u8/specified pass, run u16 (slower — may take 1-2 min for merkle tree build)**

```bash
uv run pytest tests/test_verifier_e2e.py::TestVerifierE2E::test_verify_valid_proof -k "u16_air" -v --no-header -s
```

**Step 8: Record results**

| AIR | Result | Error (if any) |
|-----|--------|----------------|
| u8_air | ? | |
| specified_ranges | ? | |
| u16_air | ? | |

→ **If all PASS:** verifier is correct, bug is 100% prover-side. Go to Task 3.
→ **If any FAIL:** verifier has a bug. Go to Task 2.

---

## Task 2: (CONDITIONAL — only if Task 1 fails) Fix verifier

**Goal:** Fix the verifier for whichever AIR type failed.

**Likely cause for specified_ranges/u16_air failure (qDeg=2):**

Read `protocol/verifier.py:702` — `_reconstruct_quotient_at_xi`:
```python
reconstructed_quotient = FF3(0)
xi_power_accumulator = FF3(1)
for piece_idx in range(stark_info.q_deg):
    # find q_piece_eval
    reconstructed_quotient += xi_power_accumulator * q_piece_eval
    xi_power_accumulator *= xi_to_n  # xi^N accumulator
```

Verify the formula: Q(xi) = Q_0(xi) + xi^N * Q_1(xi).
Cross-check with C++ `stark_verify.hpp` — search for `q_deg` in the C++ verifier.

**Likely cause for u8_air failure:**

u8_air has qDeg=1 (same as SimpleLeft). The `_reconstruct_quotient_at_xi` should be identical to SimpleLeft. If it fails for u8_air but passes for simple, check if the ev_map layout differs (quotient_start_idx computation).

**Debugging command for verifier failures:**

Add temporary print to verifier.py in `_verify_evaluations`:
```python
print(f"Q_proof={ff3_coeffs(quotient_at_xi)}")
print(f"Q_constraint={constraint_at_xi_divided}")
```

Then re-run: `uv run pytest tests/test_verifier_e2e.py -k "u8_air" -v -s 2>&1 | grep "Q_proof\|Q_constraint"`

---

## Task 3: Diagnose prover issue (if verifier passes Task 1)

**Goal:** Find why `gen_proof` produces incorrect Q when given the C++ trace.

This is a two-sub-task diagnosis:

### Sub-task 3a: Check constraint zeros on C++ trace

The question: does the bytecode evaluator produce C(x) = 0 at all N trace rows when given the C++ trace?

**Why this matters:** If C(x) ≠ 0 on the trace, then Q = C/Z_H is not a polynomial — the prover commits "garbage" Q values that the verifier will correctly reject.

**Script to write** (`executable-spec/diagnose_constraint_zeros.py`):

```python
"""Diagnostic: check if bytecode constraint evaluates to zero on C++ trace."""
import json
import sys
from pathlib import Path
import numpy as np

sys.path.insert(0, str(Path(__file__).parent))

from protocol.air_config import AirConfig
from protocol.stark_info import StarkInfo
from primitives.field import FF
from primitives.ntt import NTT
from tests.test_stark_e2e import load_test_vectors, create_buffers_from_vectors, AIR_CONFIGS, load_air_config

def check_constraint_zeros(air_name: str) -> None:
    """Check if C(x) = 0 at all N trace rows for the given AIR."""
    vectors = load_test_vectors(air_name)
    air_config = load_air_config(air_name)
    stark_info = air_config.stark_info
    N = 1 << stark_info.stark_struct.n_bits
    N_ext = 1 << stark_info.stark_struct.n_bits_ext

    trace, const_pols, const_pols_extended, public_inputs = create_buffers_from_vectors(stark_info, vectors)

    # Run the prover up to quotient polynomial computation and capture it
    from protocol.stages import ProverStages
    from protocol.prover import _run_prover_stages  # may need to expose this

    # Instead: use the bytecode expression evaluator directly.
    # Load expressions_bin
    from primitives.expression_bytecode.expressions_bin import ExpressionsBin
    bin_path = Path(__file__).parent / 'tests' / '..' / AIR_CONFIGS[air_name]['expressions_bin']
    with open(str(bin_path).replace('tests/../', ''), 'rb') as f:
        eb = ExpressionsBin.from_bytes(f.read())

    print(f"{air_name}: N={N}, qDeg={stark_info.q_deg}, cExpId={stark_info.c_exp_id}")
    # Note: checking C(x)=0 requires running the prover up to quotient stage
    # For now: just run gen_proof and check if the proof verifies
    from protocol.prover import gen_proof
    from protocol.verifier import stark_verify
    from protocol.stages import PolynomialCommitter
    from protocol.proof import to_bytes_full_from_dict, from_bytes_full

    proof_dict = gen_proof(air_config, trace, const_pols, const_pols_extended, public_inputs=public_inputs)
    global_challenge = np.array(proof_dict['global_challenge'], dtype=np.uint64)
    proof_bytes = to_bytes_full_from_dict(proof_dict, stark_info)
    proof = from_bytes_full(proof_bytes, stark_info)
    committer = PolynomialCommitter(air_config)
    verkey = committer.build_const_tree(const_pols_extended)
    result = stark_verify(proof=proof, air_config=air_config, verkey=verkey,
                          global_challenge=global_challenge, publics=public_inputs)
    print(f"  Round-trip verify: {result}")

if __name__ == '__main__':
    for air in ['u8_air', 'specified_ranges']:  # skip u16_air (slow)
        check_constraint_zeros(air)
```

This is mainly a scaffold. The real diagnostic is inside `stark_verify`. Add prints there.

### Sub-task 3b: Targeted verifier diagnostics

Add temporary logging to `protocol/verifier.py` in `_verify_evaluations` to print the mismatch:

```python
def _verify_evaluations(stark_info, evals, xi, challenges, airgroup_values, constraint_module):
    ...
    # After computing both Q_proof and Q_constraint:
    residual = ff3_coeffs(quotient_at_xi - constraint_at_xi)
    if any(r != 0 for r in residual):
        print(f"MISMATCH: Q_proof={ff3_coeffs(quotient_at_xi)} Q_constraint={ff3_coeffs(constraint_at_xi)}")
        print(f"  xi={ff3_coeffs(xi)}")
        print(f"  zh_at_xi={ff3_coeffs(zh_at_xi)}")
        print(f"  constraint_at_xi_raw={ff3_coeffs(constraint_at_xi * zh_at_xi)}")
```

Run:
```bash
uv run pytest tests/test_stark_e2e.py::TestStarkE2EComplete::test_full_proof_verifies -k "u8_air" -v -s 2>&1 | grep "MISMATCH\|Q_proof\|Q_constraint\|zh_at_xi"
```

Analyze the output:
- If `zh_at_xi` is huge/wrong → issue with zerofier computation
- If `constraint_at_xi_raw` ≈ 0 → constraint is satisfied, issue is in committed Q (prover split bug)
- If `constraint_at_xi_raw` ≠ 0 → constraint not satisfied → witness bug

### Sub-task 3c: Check the im_pol fix for U8Air

For u8_air specifically, verify the im_pol fix is actually being invoked:

```python
# Add to witness_generation.py:calculate_witness_std temporarily:
for pol_info in stark_info.cm_pols_map:
    if pol_info.im_pol:
        print(f"  im_pol: {pol_info.name} exp_id={pol_info.exp_id}")
    if pol_info.im_pol and pol_info.exp_id:
        print(f"  → Computing im_pol {pol_info.name} via exp_id {pol_info.exp_id}")
```

Run:
```bash
uv run pytest tests/test_stark_e2e.py::TestStarkE2EComplete::test_full_proof_verifies -k "u8_air" -v -s 2>&1 | grep "im_pol"
```

If no "im_pol" output: the `pol_info.im_pol` field is not True for U8Air. Check StarkInfo parsing of `imPol` JSON field.

---

## Task 4: Fix the root cause

Based on Task 3 findings, fix the specific bug. Expected fixes:

### Fix A: im_pol field not parsed (if Sub-task 3c shows im_pol not triggered)

Check `protocol/stark_info.py` — find where `cm_pols_map` is parsed. Look for `imPol` → `im_pol` mapping:

```bash
grep -n "im_pol\|imPol" executable-spec/protocol/stark_info.py
```

If the JSON key `imPol` is not being mapped to `pol_info.im_pol`, add the mapping.

### Fix B: Witness wrong for U8Air (if constraint_at_xi_raw ≠ 0)

Compare Python witness vs C++ trace for U8Air column by column:
```python
# In diagnose script:
cpp_trace_flat = vectors['inputs']['witness_trace']  # from test vectors
# Compare against trace buffer after gen_proof witness computation
```

Identify which column diverges. The `U8Air.ImPol` column (stage_pos=6 in stage 2) is the most likely culprit.

If ImPol is wrong: look at expression 11 in the bytecode. Decode it:
```python
from primitives.expression_bytecode.expressions_bin import ExpressionsBin
eb = ExpressionsBin.from_bytes(open(bin_path, 'rb').read())
expr = eb.get_expression(11)  # use get_expression, not get_expression_by_id
print(expr)
```

### Fix C: qDeg=2 prover bug (if constraint_at_xi_raw ≈ 0 but Q_proof ≠ Q_constraint)

This means the witness is fine (C(x) = 0 on trace), but the committed Q is wrong. The prover computed Q incorrectly.

Look at `stages.py:computeFriPol` — specifically the shift factor:
```python
shiftIn = FF(SHIFT_INV) ** N  # = SHIFT^(-N)
S[p] = S[p-1] * shiftIn  # S[p] = SHIFT^(-N*p)
```

Then: `cmQ[i*qDeg+p] = qPol[p*N+i] * S[p]`

After INTT, `qPol[p*N+i]` = coeff (p*N+i) of Q(x) evaluated at coset = Q_coeff[p*N+i] * SHIFT^(p*N+i)

So: `cmQ[i*qDeg+p]` = Q_coeff[p*N+i] * SHIFT^(p*N+i) * SHIFT^(-N*p) = Q_coeff[p*N+i] * SHIFT^i ✓

This looks correct. If the formula is wrong, compare with C++ `starks.cpp` or `fri_proof.cpp` implementation.

---

## Task 5: Run tests and verify all pass

After fixes:

```bash
cd executable-spec
uv run pytest tests/test_verifier_e2e.py -v --no-header  # verify C++ proofs pass
uv run pytest tests/test_stark_e2e.py::TestStarkE2EComplete -v --no-header  # round-trip tests
uv run pytest tests/test_stark_e2e.py -v --no-header  # all E2E tests
./run-tests.sh e2e  # full E2E suite (should be ~2 min)
```

Expected: all tests pass, including the previously failing u8_air, u16_air, specified_ranges.

---

## Decision Tree

```
Task 1: Verify C++ proofs with Python verifier
├── PASS for all 3 AIRs → Go to Task 3 (prover bug)
└── FAIL for some AIR
    ├── FAIL only for qDeg=2 (u16/specified) → Fix _reconstruct_quotient_at_xi (Task 2)
    └── FAIL for u8_air (qDeg=1) → Unusual; check ev_map quotient_start_idx (Task 2)

Task 3: Prover bug diagnosis
├── im_pol not triggered (Sub-task 3c) → Fix StarkInfo parsing (Fix A)
├── constraint_at_xi_raw ≠ 0 → Witness wrong (Fix B: check im_pol column)
└── constraint_at_xi_raw ≈ 0, Q_proof ≠ Q_constraint → qDeg=2 prover split (Fix C)
```

---

## Commit Checkpoints

- After Task 1: `git add tests/test_verifier_e2e.py && git commit -m "test: extend verifier E2E for u8_air, u16_air, specified_ranges"`
- After each fix: commit with clear message identifying what was wrong
- After Task 5 green: `git add -u && git commit -m "fix: correct witness/prover for u8_air, u16_air, specified_ranges"`
