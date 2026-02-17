# Task #1 Findings: Evaluation Check Comparison (C++ vs Python)

## Summary

The evaluation check logic is **semantically equivalent** between C++ and Python
verifiers. Both implement the same mathematical operation. However, there is a
**critical difference** in how the bytecode evaluator's `x_n` is initialized in
verify mode:

- **C++**: `x_n = z` (the raw challenge point xi, 3 coefficients)
- **Python**: `x_n = z^N` (xi raised to the trace size)

This means the bytecode evaluator in Python receives `z^N` where C++ receives
`z`, causing the bytecode to compute a **different value**. This does NOT affect
the verifier's own Q reconstruction (which is correct), but it DOES affect the
bytecode evaluation result `buff`, making the comparison fail.

**This is a STRONG CANDIDATE for the root cause of the Rom xfail.**

---

## Detailed Comparison

### 1. C++ Evaluation Check (stark_verify.hpp, lines 305-341)

```
Step 1: Run bytecode evaluator to get Q_bytecode(xi)
    ExpressionsPack expressionsPack(setupCtx, &proverHelpers, 1);
    Dest dest(buff, 1, 0);
    dest.addParams(starkInfo.cExpId, ...destDim);
    expressionsPack.calculateExpressions(params, dest, 1, false, false);
    // buff now contains Q_bytecode(xi), an FF3 value

Step 2: Compute xi^N
    xN = 1;
    for i in 0..N:
        xN *= xiChallenge    // xN = xi^N

Step 3: Reconstruct Q(xi) from quotient polynomial evals
    xAcc = 1, q = 0
    for i in 0..qDeg:
        index = qIndex + i
        evId = find ev_map entry where type==cm && id==index
        q += evals[evId] * xAcc
        xAcc *= xN            // xAcc = xi^(i*N)

Step 4: Compare directly
    res = q - buff           // q_from_evals - q_bytecode
    if res != 0: FAIL
```

**Key observation:** C++ compares `q` (from evals) directly against `buff`
(from bytecode). The bytecode is expected to return Q(xi) directly. There is
NO Z_H multiplication or division in the evaluation check itself.

### 2. Python Evaluation Check (verifier.py, lines 704-735)

```
Step 1: Evaluate constraint polynomial using per-AIR constraint module
    verifier_data = _build_verifier_data(...)
    constraint_buffer = _evaluate_constraint_with_module(stark_info, verifier_data, xi)
    constraint_at_xi = FF3.from(constraint_buffer)
    // This calls through to the constraint module, which for bytecode AIRs:
    //   1. Runs bytecode -> gets Q_bytecode(xi)
    //   2. Multiplies by Z_H(xi) to get C_bytecode(xi) = Q * Z_H
    //   3. Returns C_bytecode(xi)
    // Then _evaluate_constraint_with_module divides by Z_H(xi):
    //   constraint_buffer = C_bytecode(xi) / Z_H(xi) = Q_bytecode(xi)
    // So constraint_at_xi should equal Q_bytecode(xi)

Step 2: Compute xi^N
    trace_size = 1 << n_bits
    xi_to_n = xi
    for _ in range(trace_size - 1):   // NOTE: trace_size - 1 iterations
        xi_to_n *= xi                  // xi_to_n = xi^N

Step 3: Reconstruct Q(xi) from quotient polynomial evals
    quotient_start_idx = find cm_pol with stage==quotient_stage, stage_id==0
    reconstructed_quotient = 0
    xi_power_accumulator = 1
    for piece_idx in 0..q_deg:
        eval_map_idx = find ev_map where type==cm && id==quotient_start_idx + piece_idx
        q_piece_eval = FF3 from evals[eval_map_idx]
        reconstructed_quotient += xi_power_accumulator * q_piece_eval
        xi_power_accumulator *= xi_to_n

Step 4: Compare
    residual = quotient_at_xi - constraint_at_xi
    return residual == 0
```

**Key observation:** The Python verifier does a round-trip:
1. Bytecode computes Q(xi)
2. Adapter multiplies by Z_H(xi) to get C(xi)
3. `_evaluate_constraint_with_module` divides by Z_H(xi) to get back Q(xi)
4. Compares Q_from_evals == Q_from_bytecode

If the bytecode produces the correct Q(xi), this round-trip is identity and
should work. The issue is whether the bytecode ITSELF produces the right Q(xi).

### 3. Q Reconstruction from Quotient Polynomial Pieces

Both implementations use the same formula:

```
Q(xi) = sum_{i=0}^{qDeg-1} evals[Q_i](xi) * (xi^N)^i
```

For **qDeg=1** (Rom), this simplifies to:
```
Q(xi) = evals[Q_0](xi) * 1 = evals[Q_0](xi)
```

The loop runs once, xAcc starts at 1, so Q = evals[Q_0] * 1.

**Both C++ and Python compute this identically.** No off-by-one or indexing
error for qDeg=1 -- the simplification is straightforward.

#### xi^N computation:

- **C++:** `xN = 1; for i in 0..N: xN *= xi` --> N multiplications, result = xi^N
- **Python:** `xi_to_n = xi; for _ in range(N-1): xi_to_n *= xi` --> N-1 multiplications, result = xi^N

Both produce xi^N. The C++ starts from 1 and multiplies N times. Python starts
from xi and multiplies N-1 times. Same result.

#### Quotient polynomial index lookup:

- **C++:** `qIndex = find_if(cmPolsMap, stage==nStages+1 && stageId==0)`, uses
  `qIndex + i` to index into cmPolsMap, then finds evMap entry with `id==index`.
- **Python:** `quotient_start_idx = next(i for i,p in cm_pols_map if stage==quotient_stage and stage_id==0)`,
  uses `quotient_start_idx + piece_idx` similarly.

Both do the same linear search. **Identical.**

### 4. The x_n Bug in Bytecode Verifier Mode

**THIS IS THE CRITICAL FINDING.**

#### C++ ProverHelpers verify-mode constructor (setup_ctx.hpp, lines 85-88):

```cpp
x_n = new Goldilocks::Element[FIELD_EXTENSION];
x_n[0] = z[0];
x_n[1] = z[1];
x_n[2] = z[2];
```

In C++ verify mode, `x_n` is set to the **raw challenge point z** (= xi), NOT
xi^N. The variable name is misleading. In prover mode, x_n is the powers of w
on the trace domain. In verify mode, it is the raw evaluation point.

#### Python ProverHelpers.from_challenge (air_config.py, line 161):

```python
helpers.x_n = ff3_to_numpy_coeffs(x_n_ff3)
```

Where `x_n_ff3` is computed as:
```python
x_n_ff3 = one_ff3
for _ in range(N):
    x_n_ff3 = x_n_ff3 * z_ff3
# x_n_ff3 = z^N
```

So Python stores `z^N` in x_n, while C++ stores `z` in x_n.

#### How x_n is consumed in the bytecode evaluator:

In `expressions_pack.hpp` (C++), the load function for type `nStages+2` with
boundary==0 in verify mode:
```cpp
if(boundary == 0) {
    for(uint64_t j = 0; j < nrowsPack; ++j) {
        for(uint64_t e = 0; e < FIELD_EXTENSION; ++e) {
            value[j + e*nrowsPack] = proverHelpers->x_n[e];
        }
    }
}
```

It loads `proverHelpers->x_n`, which in C++ verify mode is **z** (= xi).

In `expression_evaluator.py` (Python), the same path:
```python
if boundary == 0:
    c0 = int(self.prover_helpers.x_n[0])
    c1 = int(self.prover_helpers.x_n[1])
    c2 = int(self.prover_helpers.x_n[2])
    scalar = ff3([c0, c1, c2])
    return FF3([int(scalar)] * nrows_pack)
```

It loads `prover_helpers.x_n`, which in Python verify mode is **z^N** (= xi^N).

**The bytecode evaluator receives different values for x_n between C++ and Python.**

This matters because the bytecode uses x_n (boundary==0) in its computation.
In C++ verify mode, boundary==0 returns z (the evaluation point). In Python
verify mode, it returns z^N.

The compiled bytecode for cExpId likely uses boundary==0 to get the evaluation
point xi (the "x" variable in symbolic constraint expressions), not xi^N.
So the Python evaluator feeds the wrong value to the bytecode.

### 5. Why This May Not Be the Issue for Non-Custom-Commit AIRs

The 12 passing Zisk AIRs use the bytecode adapter with the same x_n bug.
However, their constraint expressions (cExpId) may not reference boundary==0
at all, or if they do, the constraint structure may cancel out the error.

Alternatively: the hand-written constraint modules (SimpleLeft, Lookup2_12,
Permutation1_6) do NOT use the bytecode adapter in verifier mode, so they
never hit this x_n discrepancy.

Wait -- the Zisk AIRs ALL use the bytecode adapter. 12 of them pass. So
either:
1. The boundary==0 (x_n) operand is not used by most Zisk cExpId bytecodes.
2. The Z_H round-trip cancels out the x_n error for qDeg=2 but not qDeg=1.
3. Some other interaction makes this cancel for most AIRs.

To determine if boundary==0 is actually used by the Rom cExpId bytecode,
one would need to check the bytecode itself (expression 73 for Rom).

### 6. The Z_H Round-Trip Analysis

The Python adapter does:
```
Q_raw = bytecode_eval(...)    # Using wrong x_n = z^N
C = Q_raw * Z_H(xi)           # Z_H(xi) = xi^N - 1
```

Then `_evaluate_constraint_with_module` does:
```
Q_final = C / Z_H(xi) = Q_raw
```

So the Z_H round-trip perfectly cancels. If Q_raw is wrong due to the x_n bug,
it stays wrong. The round-trip does NOT help or hurt.

The comparison is effectively:
```
Q_from_evals == Q_raw_from_bytecode_with_wrong_x_n
```

### 7. Summary of Findings

| Aspect | C++ | Python | Match? |
|--------|-----|--------|--------|
| Q reconstruction from evals | sum(Q_i * xi^(iN)) | same formula | YES |
| xi^N computation | N mults from 1 | N-1 mults from xi | YES (same result) |
| qDeg=1 special case | loop runs once, Q = evals[Q_0] | same | YES |
| Quotient index lookup | find_if on cmPolsMap + evMap | same with next() | YES |
| Final comparison | q == buff (direct) | residual == 0 (equivalent) | YES |
| **Bytecode x_n in verify mode** | **x_n = z (= xi)** | **x_n = z^N (= xi^N)** | **NO** |
| Z_H round-trip | N/A (no round-trip) | Q*Z_H/Z_H = Q (identity) | N/A |

### 8. Recommended Next Steps

1. **Verify boundary==0 usage in Rom cExpId:** Check whether expression 73
   actually loads boundary==0. If it does, this confirms the root cause.

2. **Fix candidate:** In `ProverHelpers.from_challenge()`, change line 161:
   ```python
   # Was: helpers.x_n = ff3_to_numpy_coeffs(x_n_ff3)  # x_n = z^N
   # Fix: helpers.x_n = np.array([int(z[0]), int(z[1]), int(z[2])], dtype=np.uint64)  # x_n = z
   ```
   This would match C++ behavior where verify-mode x_n stores the raw challenge
   point, not its N-th power.

3. **Risk assessment:** This change would affect ALL bytecode AIR verifications.
   If 12 Zisk AIRs currently pass with the wrong x_n, they either:
   - Don't use boundary==0 in their cExpId bytecode
   - Use it in a way that happens to be correct regardless

   The fix should be safe IF the 12 passing AIRs don't reference boundary==0.
   If they DO reference it, we need to investigate further.

4. **Alternative hypothesis:** The 12 passing AIRs might pass because their
   bytecode does not reference the "x" variable (boundary==0) in the constraint
   expression. The Rom AIR, being unique (custom commits, qDeg=1), may have a
   more complex constraint expression that does reference it.
