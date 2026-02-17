# Task #5: Q Reconstruction from Quotient Polynomial Pieces

## Summary

The Q reconstruction logic in C++ and Python is **functionally identical** for the
Q-from-evals path. Both implementations use the same formula, the same loop bounds,
the same index arithmetic, and the same accumulator pattern. For qDeg=1, the loop
runs exactly once in both, producing Q(xi) = q_0(xi) * 1 = q_0(xi). No bugs found
in this specific path.

However, this analysis uncovered a **critical bug** in the bytecode evaluator path
(not in Q reconstruction itself, but in how x_n is set up for the bytecode's
constraint evaluation). This is documented in the Bonus Finding section at the end.

## Side-by-Side Comparison

### C++ (stark_verify.hpp lines 314-335)

```cpp
// Step 1: Compute xi^N
Goldilocks::Element xN[3] = {Goldilocks::one(), Goldilocks::zero(), Goldilocks::zero()};
for(uint64_t i = 0; i < uint64_t(1 << starkInfo.starkStruct.nBits); ++i) {
    Goldilocks3::mul((Goldilocks3::Element *)xN, (Goldilocks3::Element *)xN, (Goldilocks3::Element *)xiChallenge);
}
// xN = xi^N (NOT Z_H = xi^N - 1)

// Step 2: Find quotient polynomial index
Goldilocks::Element xAcc[3] = { Goldilocks::one(), Goldilocks::zero(), Goldilocks::zero() };
Goldilocks::Element q[3] = { Goldilocks::zero(), Goldilocks::zero(), Goldilocks::zero() };
uint64_t qStage = starkInfo.nStages + 1;
uint64_t qIndex = std::find_if(starkInfo.cmPolsMap.begin(), starkInfo.cmPolsMap.end(),
    [qStage](const PolMap& p) {
        return p.stage == qStage && p.stageId == 0;
    }) - starkInfo.cmPolsMap.begin();
// qIndex = index into cmPolsMap of Q0

// Step 3: Accumulate quotient pieces
for(uint64_t i = 0; i < starkInfo.qDeg; ++i) {
    uint64_t index = qIndex + i;
    uint64_t evId = std::find_if(starkInfo.evMap.begin(), starkInfo.evMap.end(),
        [index](const EvMap& e) {
            return e.type == EvMap::eType::cm && e.id == index;
        }) - starkInfo.evMap.begin();
    Goldilocks::Element aux[3];
    Goldilocks3::mul(aux, xAcc, evals[evId * FIELD_EXTENSION]);
    Goldilocks3::add(q, q, aux);
    Goldilocks3::mul(xAcc, xAcc, xN);
}
// q = sum_{i=0}^{qDeg-1} evals[Q_i] * (xi^N)^i

// Step 4: Compare
Goldilocks::Element res[3] = { q[0] - buff[0], q[1] - buff[1], q[2] - buff[2]};
// buff = result of cExpId bytecode evaluation (= Q(xi) from bytecode)
```

### Python (verifier.py lines 655-735)

```python
# Step 1: Compute xi^N (in _compute_xi_to_trace_size, line 655)
def _compute_xi_to_trace_size(xi: FF3, trace_size: int) -> FF3:
    x_power = FF3(1)
    for _ in range(trace_size):
        x_power = x_power * xi
    return x_power
# Returns xi^N (NOT Z_H = xi^N - 1) -- matches C++

# Step 2: Find quotient polynomial index (in _reconstruct_quotient_at_xi, line 666)
quotient_stage = stark_info.n_stages + QUOTIENT_STAGE_OFFSET  # n_stages + 1
quotient_start_idx = next(
    i for i, p in enumerate(stark_info.cm_pols_map)
    if p.stage == quotient_stage and p.stage_id == 0
)
# Equivalent to C++ qIndex

# Step 3: Accumulate quotient pieces (line 680)
reconstructed_quotient = FF3(0)
xi_power_accumulator = FF3(1)                   # xAcc = 1
for piece_idx in range(stark_info.q_deg):       # i = 0..qDeg-1
    eval_map_idx = next(
        j for j, e in enumerate(stark_info.ev_map)
        if e.type == EvMap.Type.cm and e.id == quotient_start_idx + piece_idx
    )
    q_piece_eval = FF3.Vector([...])            # evals[evId]
    reconstructed_quotient += xi_power_accumulator * q_piece_eval
    xi_power_accumulator *= xi_to_n             # xAcc *= xN
# Same formula as C++

# Step 4: Compare (in _verify_evaluations, line 732)
# constraint_at_xi = C(xi)/Z_H(xi) from _evaluate_constraint_with_module
# quotient_at_xi = Q(xi) from _reconstruct_quotient_at_xi
residual = ff3_coeffs(quotient_at_xi - constraint_at_xi)
```

## Detailed Comparison

### 1. How xi^N (xN) is Computed

| Aspect | C++ | Python |
|--------|-----|--------|
| Initial value | `{1, 0, 0}` (FF3 one) | `FF3(1)` |
| Loop iterations | `1 << nBits` = N | `trace_size` = N |
| Operation | `xN = xN * xiChallenge` | `x_power = x_power * xi` |
| Result | xi^N | xi^N |
| **Verdict** | **Identical** | **Identical** |

### 2. How qIndex (quotient_start_idx) is Found

| Aspect | C++ | Python |
|--------|-----|--------|
| Stage searched | `nStages + 1` | `n_stages + QUOTIENT_STAGE_OFFSET` (= n_stages + 1) |
| Condition | `p.stage == qStage && p.stageId == 0` | `p.stage == quotient_stage and p.stage_id == 0` |
| Returns | Index into cmPolsMap | Index into cm_pols_map |
| **Verdict** | **Identical** | **Identical** |

For Rom: both find cmPolsMap[3] (Q0, stage=3, stageId=0).

### 3. Loop Bounds (qDeg iterations)

| Aspect | C++ | Python |
|--------|-----|--------|
| Loop | `i = 0; i < starkInfo.qDeg; ++i` | `piece_idx in range(stark_info.q_deg)` |
| For qDeg=1 | Runs once (i=0) | Runs once (piece_idx=0) |
| For qDeg=2 | Runs twice (i=0,1) | Runs twice (piece_idx=0,1) |
| **Verdict** | **Identical** | **Identical** |

No off-by-one possible. Both use `< qDeg` / `range(q_deg)`.

### 4. Accumulator Formula

| Aspect | C++ | Python |
|--------|-----|--------|
| xAcc init | `{1, 0, 0}` (FF3 one) | `FF3(1)` |
| q init | `{0, 0, 0}` (FF3 zero) | `FF3(0)` |
| Loop body | `q += evals[evId] * xAcc; xAcc *= xN` | `q += xi_power_accumulator * q_piece_eval; xi_power_accumulator *= xi_to_n` |
| **Verdict** | **Identical** | **Identical** |

For qDeg=1: q = evals[Q0] * 1 = evals[Q0]. The xAcc multiplication by xN happens
after the accumulation, so it doesn't affect the single-iteration result.

### 5. Eval Index Lookup

| Aspect | C++ | Python |
|--------|-----|--------|
| Search | `find_if(evMap, e.type==cm && e.id==index)` | `next(j for j,e in ev_map if e.type==cm and e.id==start_idx+piece_idx)` |
| Index | `qIndex + i` | `quotient_start_idx + piece_idx` |
| **Verdict** | **Identical** | **Identical** |

For Rom: both find evMap[16] (type=cm, id=3) for the single quotient piece Q0.

### 6. The Final Comparison

Here the implementations diverge:

**C++:**
```
q == buff
```
Where `buff` = output of `cExpId` bytecode evaluation. The C++ bytecode directly
outputs Q(xi) because the bytecode bakes in Z_H division internally.

**Python:**
```
quotient_at_xi == constraint_at_xi
```
Where:
- `quotient_at_xi` = Q(xi) reconstructed from evals (identical to C++ `q`)
- `constraint_at_xi` = output of constraint module, which for bytecode AIRs does:
  1. Run bytecode to get `q_raw` (= Q(xi), same as C++ `buff`)
  2. Multiply by Z_H(xi) to get C(xi)
  3. Then `_verify_evaluations` divides by Z_H(xi) to get back to Q(xi)

This Z_H round-trip (multiply then divide) is a no-op for exact arithmetic, so the
Q reconstruction comparison is **mathematically equivalent** to the C++ approach.

## Concrete Values for Rom (qDeg=1)

```
qDeg = 1
qStage = 3 (nStages=2, so 2+1=3)
qIndex = 3 (cmPolsMap[3] = Q0)

evMap[16]: type=cm, id=3, prime=0
  -> This is Q0's evaluation at xi

Loop runs once (i=0):
  index = 3 + 0 = 3
  evId = 16
  xAcc = [1, 0, 0]
  q = evals[16] * xAcc = evals[16] * 1 = evals[16]
  (xAcc *= xN occurs but is not used again)

Q_from_evals = evals[16] = direct copy of Q0(xi) from proof

Known values:
  xi^N (xN): [3313400389158385524, 15738177539288021218, 3726790801791612697]
  Q_from_evals: [4216457208035997298, 12842449364465107706, 8718687622782149476]
  Q_bytecode:   [8967852549743287977, 15341396557711420347, 1183051410211694445]
```

The Q_from_evals != Q_bytecode mismatch is NOT caused by Q reconstruction.
The reconstruction is correct (it's just `evals[16]` for qDeg=1).
The mismatch is in the bytecode evaluation path (cExpId).

## qDeg=1 vs qDeg=2 Code Paths

There are no special code paths for qDeg=1 vs qDeg=2. Both use the same loop
with `range(q_deg)`. The only difference is the number of iterations:

- **qDeg=1**: Loop runs once. Q(xi) = evals[Q0] * 1. Trivial.
- **qDeg=2**: Loop runs twice. Q(xi) = evals[Q0] * 1 + evals[Q1] * xi^N.

Both are correct. The Q reconstruction is not the source of the Rom failure.

## Bonus Finding: x_n Discrepancy in ProverHelpers Verify Mode

While comparing the Q reconstruction (which is correct), I discovered a significant
discrepancy in how `x_n` is set up for the bytecode evaluator in verify mode.

### C++ (setup_ctx.hpp, ProverHelpers verify-mode constructor, lines 85-88)

```cpp
x_n = new Goldilocks::Element[FIELD_EXTENSION];
x_n[0] = z[0];  // = xi_0
x_n[1] = z[1];  // = xi_1
x_n[2] = z[2];  // = xi_2
```

**x_n = z = xi** (the challenge point itself, NOT xi^N)

### Python (air_config.py, ProverHelpers.from_challenge, line 161)

```python
helpers.x_n = ff3_to_numpy_coeffs(x_n_ff3)
```

Where `x_n_ff3` was computed as xi^N at lines 116-118:
```python
x_n_ff3 = one_ff3
for _ in range(N):
    x_n_ff3 = x_n_ff3 * z_ff3
```

**x_n = xi^N** (the N-th power of the challenge point)

### Impact

This is used by the bytecode evaluator when loading type `nStages + 2`, boundary 0:

- **C++ (expressions_pack.hpp lines 100-105):** In verify mode, boundary 0 loads
  `proverHelpers->x_n` which is **xi** (the challenge point)
- **Python (expression_evaluator.py lines 609-614):** In verify mode, boundary 0 loads
  `self.prover_helpers.x_n` which is **xi^N**

For the non-verify (prover) path, boundary 0 loads `x` (evaluation point) or `x_n`
(PIL1 compatibility), which are different altogether. The verify-mode meaning of
boundary 0 is "give me the evaluation point" (= xi), not "give me xi^N".

### Connection to Rom Failure

If the Rom bytecode (cExpId=73) uses type `nStages+2, boundary=0` during evaluation,
it would get xi^N from Python instead of xi from C++. This would cause the bytecode
to compute a wrong Q(xi), which when multiplied by Z_H and divided by Z_H in the
adapter round-trip, would produce a wrong comparison value.

This is a strong candidate for the root cause of the Rom xfail. Other tasks should
verify whether the Rom bytecode actually uses this operand type.

Note: The 12 passing Zisk AIRs all have qDeg=2. Whether they also use type
`nStages+2, boundary=0` in their bytecode is unknown -- they might not, or they
might but the error cancels for some reason specific to qDeg=2.

## Conclusion

- **Q reconstruction from quotient polynomial pieces: CORRECT in both implementations.**
  No bugs. Identical formula, loop bounds, index arithmetic, and accumulator pattern.
- **No qDeg=1 specific code paths** that could cause issues.
- **The root cause of Q_from_evals != Q_bytecode is NOT in Q reconstruction** -- it's
  in the bytecode evaluation (cExpId) which is analyzed in Tasks #1 and #2.
- **Bonus finding: x_n is wrong in Python verify mode** (xi^N instead of xi).
  This could be the root cause of the Rom failure if the bytecode uses this operand.
  This finding was independently corroborated by Task #2 (see rom-investigation-v2-task2.md).

## Appendix: qDeg Uniqueness Across All AIRs

Rom is the ONLY AIR with qDeg=1. All others have qDeg=2:

**Test suite AIRs:**
- SimpleLeft: qDeg=2, Lookup2_12: qDeg=2, Permutation1_6: qDeg=2

**All 22 Zisk AIRs:**
- Rom: **qDeg=1** (UNIQUE)
- All other 21 AIRs: qDeg=2 (Add256, Arith, ArithEq, ArithEq384, Binary,
  BinaryAdd, BinaryExtension, InputData, Keccakf, Main, Mem, MemAlign,
  MemAlignByte, MemAlignReadByte, MemAlignWriteByte, RomData, Sha256f,
  SpecifiedRanges, U256Delegation, VirtualTable0, VirtualTable1)

This means the Q reconstruction loop always runs at least once (qDeg >= 1), and the
xN power accumulator is always used in the first iteration with value 1 (identity),
making the single-piece case trivially correct. The qDeg=1 uniqueness is therefore
NOT the cause of the evaluation check failure.
