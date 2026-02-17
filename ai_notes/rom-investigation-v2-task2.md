# Task #2: Bytecode Evaluator Verify-Mode Setup Comparison (C++ vs Python)

## Summary of Findings

**CRITICAL BUG FOUND**: The C++ verifier stores `x_n = z` (the raw challenge point xi),
NOT `x_n = z^N`. The Python verifier stores `x_n = z^N`. This means the bytecode
evaluator in C++ and Python receive different values for the `boundary == 0` operand
in verify mode. However, this may be intentional because the C++ verifier also computes
`xN = z^N` separately in `stark_verify.hpp` outside the bytecode evaluator -- the
bytecode in verify mode does NOT use x_n the same way it uses it in prover mode.

**IMPORTANT CAVEAT**: This `x_n` discrepancy does NOT appear to be the root cause of
the Rom failure, because the same bytecode evaluator code path runs for all 12 passing
Zisk AIRs. If x_n were wrong, they would all fail. The key question is whether any
bytecode expression for Rom specifically references `boundary == 0` in a way that
differs from the other AIRs.

---

## 1. C++ Verify-Mode x_n and zi Setup

### Source: `/home/cody/pil2-proofman/pil2-stark/src/starkpil/setup_ctx.hpp` lines 24-90

The C++ `ProverHelpers(StarkInfo& starkInfo, Goldilocks::Element* z)` constructor
(the verify-mode constructor, called from `stark_verify.hpp` line 228):

```cpp
ProverHelpers(StarkInfo& starkInfo, Goldilocks::Element* z) {
    zi = new Goldilocks::Element[starkInfo.boundaries.size() * FIELD_EXTENSION];

    Goldilocks::Element one[3] = {Goldilocks::one(), Goldilocks::zero(), Goldilocks::zero()};

    // Compute z^N by repeated multiplication
    Goldilocks::Element xN[3] = {Goldilocks::one(), Goldilocks::zero(), Goldilocks::zero()};
    for(uint64_t i = 0; i < uint64_t(1 << starkInfo.starkStruct.nBits); ++i) {
        Goldilocks3::mul((Goldilocks3::Element *)xN, (Goldilocks3::Element *)xN, (Goldilocks3::Element *)z);
    }
    // xN is now z^N (xi^N)

    // Z_H(z) = z^N - 1
    Goldilocks::Element zN[3] = { xN[0] - Goldilocks::one(), xN[1], xN[2]};
    Goldilocks::Element zNInv[3];
    Goldilocks3::inv((Goldilocks3::Element *)zNInv, (Goldilocks3::Element *)zN);
    // zi[0..2] = 1/(z^N - 1)   <-- CORRECT: this is 1/Z_H(xi)
    std::memcpy(&zi[0], zNInv, FIELD_EXTENSION * sizeof(Goldilocks::Element));

    // ... (other boundaries: firstRow, lastRow, everyRow -- same logic as Python)

    // *** CRITICAL: x_n is set to z (raw challenge), NOT z^N ***
    x_n = new Goldilocks::Element[FIELD_EXTENSION];
    x_n[0] = z[0];
    x_n[1] = z[1];
    x_n[2] = z[2];
};
```

**Key observation**: `x_n = z` (the raw challenge xi), NOT `z^N`.

### How x_n is Used in C++ Verify Mode

In `expressions_pack.hpp` lines 99-112:

```cpp
if(setupCtx.starkInfo.verify) {
    if(boundary == 0) {
        for(uint64_t j = 0; j < nrowsPack; ++j) {
            for(uint64_t e = 0; e < FIELD_EXTENSION; ++e) {
                value[j + e*nrowsPack] = proverHelpers->x_n[e];
                // This loads z (raw challenge xi), NOT z^N
            }
        }
    } else {
        for(uint64_t j = 0; j < nrowsPack; ++j) {
            for(uint64_t e = 0; e < FIELD_EXTENSION; ++e) {
                value[j + e*nrowsPack] = proverHelpers->zi[(boundary - 1)*FIELD_EXTENSION + e];
            }
        }
    }
    return value;
}
```

So in C++ verify mode, `type == nStages+2, boundary == 0` loads the **raw challenge xi**
(not xi^N). This makes sense because:
- In prover mode (non-verify), `boundary == 0` loads `proverHelpers->x` (the coset
  points `shift * w^i`) when on extended domain, or `proverHelpers->x_n` (the w^i
  trace-domain powers) when on base domain.
- In verify mode, there's only one evaluation point (xi), so `boundary == 0` loads xi
  itself. The bytecode uses this as the "evaluation point x" where x = xi.

### How zi is Used in C++ Verify Mode

For `boundary >= 1`: loads from `proverHelpers->zi[(boundary - 1)*FIELD_EXTENSION]`.

- boundary 1 (index 0): `1/(z^N - 1)` = `1/Z_H(xi)`
- boundary 2+ (various): firstRow/lastRow/everyRow zerofiers

These are all correctly set in the constructor.

---

## 2. Python Verify-Mode x_n and zi Setup

### Source: `/home/cody/pil2-proofman/executable-spec/protocol/air_config.py` lines 93-162

```python
@classmethod
def from_challenge(cls, stark_info, z):
    helpers = cls()
    n_bits = stark_info.stark_struct.n_bits
    boundaries = stark_info.boundaries
    N = 1 << n_bits

    helpers.zi = np.zeros(len(boundaries) * FIELD_EXTENSION_DEGREE, dtype=np.uint64)

    z_ff3 = FF3.Vector([int(z[2]), int(z[1]), int(z[0])])
    one_ff3 = FF3(1)

    # z^N
    x_n_ff3 = one_ff3
    for _ in range(N):
        x_n_ff3 = x_n_ff3 * z_ff3
    # x_n_ff3 is now z^N

    # Z_H(z) = z^N - 1
    z_n_minus_one = x_n_ff3 - one_ff3
    z_n_inv = z_n_minus_one ** -1
    helpers.zi[0:3] = ff3_to_numpy_coeffs(z_n_inv)  # 1/(z^N - 1) -- CORRECT

    # ... (other boundaries -- same logic as C++)

    # *** CRITICAL: x_n is set to z^N, NOT z (raw challenge) ***
    helpers.x_n = ff3_to_numpy_coeffs(x_n_ff3)
    return helpers
```

**Key observation**: `x_n = z^N` (xi raised to the trace-size power), NOT the raw
challenge `z`.

### How x_n is Used in Python Verify Mode

In `expression_evaluator.py` lines 606-621:

```python
if type_arg == self.stark_info.n_stages + 2:
    boundary = args[i_args + 1]
    if self.verify:
        if boundary == 0:
            c0 = int(self.prover_helpers.x_n[0])
            c1 = int(self.prover_helpers.x_n[1])
            c2 = int(self.prover_helpers.x_n[2])
            scalar = ff3([c0, c1, c2])
            return FF3([int(scalar)] * nrows_pack) if dim == FIELD_EXTENSION_DEGREE else FF([c0] * nrows_pack)
            # This loads z^N (xi^N), NOT raw z
        else:
            base = (boundary - 1) * FIELD_EXTENSION_DEGREE
            c0 = int(self.prover_helpers.zi[base])
            c1 = int(self.prover_helpers.zi[base + 1])
            c2 = int(self.prover_helpers.zi[base + 2])
            scalar = ff3([c0, c1, c2])
            return FF3([int(scalar)] * nrows_pack)
```

So in Python verify mode, `boundary == 0` loads **xi^N**, not the raw challenge xi.

---

## 3. DISCREPANCY ANALYSIS: x_n in Verify Mode

| Aspect              | C++                          | Python                        |
|---------------------|------------------------------|-------------------------------|
| x_n value (verify)  | `z` (raw challenge xi)       | `z^N` (xi raised to N-th)    |
| x_n value (prover)  | `w^i` (trace domain omega)   | `w^i` (trace domain omega)   |
| zi[0] value (verify)| `1/(z^N - 1)`                | `1/(z^N - 1)`                |
| zi[0] value (prover)| `1/(x^N - 1)` per row       | `1/(x^N - 1)` per row       |

**This is a real discrepancy.** In C++ verify mode, `boundary == 0` provides xi (the
evaluation point). In Python verify mode, `boundary == 0` provides xi^N.

### What does boundary==0 mean semantically?

In **prover mode** (non-verify):
- `boundary == 0` returns x (the evaluation point on the domain)
- When `domainExtended = true`: returns `proverHelpers->x[row]` = `shift * w_ext^row`
- When `domainExtended = false`: returns `proverHelpers->x_n[row]` = `w^row`

In **C++ verify mode**:
- `boundary == 0` returns `proverHelpers->x_n` = `z` = xi (the single evaluation point)
- This is the equivalent of "x" (the evaluation point) in the single-point verifier context
- This is consistent: prover has x = evaluation points on domain; verifier has x = xi

In **Python verify mode**:
- `boundary == 0` returns `proverHelpers->x_n` = `z^N` = xi^N
- This is NOT the evaluation point -- it's the N-th power of the evaluation point

**The Python implementation is wrong here.** In verify mode, `boundary == 0` should
return the raw evaluation point xi, not xi^N.

### Impact Assessment

The question is: **does any bytecode expression actually reference boundary==0?**

For the constraint expression (cExpId), the bytecode evaluates the full constraint
expression Q(x) = C(x)/Z_H(x). If the constraint uses `x` (the evaluation point)
anywhere, it would reference boundary==0 (type `nStages+2, boundary=0`).

If boundary==0 is only used by the FRI expression (friExpId) for DEEP-ALI evaluation
and not by cExpId, then this bug would NOT affect the evaluation check -- it would
only affect FRI consistency checks.

### Why 12 AIRs Still Pass

If none of the 12 passing Zisk AIR constraint expressions reference boundary==0
(they don't use `x` in their constraints), they would not be affected by this bug.
Rom's constraint expression (cExpId=73) might reference boundary==0 if its constraints
involve `x` directly.

---

## 4. zi (Inverse Zerofier) Comparison

### C++ zi Setup (verify mode)

```
zi[0..2] = 1/(z^N - 1)               // everyRow boundary (inverse zerofier)
zi[3..5] = (z - 1)^(-1) * (z^N - 1)  // firstRow boundary
zi[6..8] = (z - w^(N-1))^(-1) * (z^N - 1)  // lastRow boundary
```

For everyRow boundary: `zi = 1/Z_H(xi)` where `Z_H(x) = x^N - 1`.
For everyFrame boundary: `zi = product of (z - w^k)` for excluded rows (NOT inverted).

### Python zi Setup (verify mode)

```python
# boundary 0 (everyRow): zi[0:3] = 1/(z^N - 1) = 1/Z_H(xi)
helpers.zi[0:3] = ff3_to_numpy_coeffs(z_n_inv)

# boundary 1+ (firstRow): zi[3:6] = (z - 1)^(-1) * (z^N - 1)
zi_temp = (z_ff3 - one_ff3) ** -1 * z_n_minus_one

# boundary 1+ (lastRow): zi[6:9] = (z - w^(N-1))^(-1) * (z^N - 1)
root_ff3 = FF3(int(w ** (N - 1)))
zi_temp = (z_ff3 - root_ff3) ** -1 * z_n_minus_one

# boundary 1+ (everyRow): zi = product of (z - w^k) for excluded rows
```

**The zi values match between C++ and Python.** Both compute identical zerofier values.

---

## 5. Scalar Parameters (scalar_params) Comparison

### C++ Layout (stark_verify.hpp + expressions_pack.hpp)

In `stark_verify.hpp` lines 288-301, the verifier builds `StepsParams`:
```cpp
StepsParams params = {
    .trace = trace,
    .aux_trace = aux_trace,
    .publicInputs = publics,
    .proofValues = proofValues,
    .challenges = challenges,
    .airgroupValues = airgroupValues,
    .airValues = airValues,
    .evals = evals,
    .xDivXSub = xDivXSub,
    .pConstPolsAddress = constPolsVals,
    .pConstPolsExtendedTreeAddress = nullptr,
    .pCustomCommitsFixed = trace_custom_commits_fixed,
};
```

In `expressions_pack.hpp` lines 354-362, the eval loop sets up `expressions_params`:
```cpp
expressions_params[bufferCommitsSize + 2] = params.publicInputs;
expressions_params[bufferCommitsSize + 3] = parserArgs.numbers;
expressions_params[bufferCommitsSize + 4] = params.airValues;
expressions_params[bufferCommitsSize + 5] = params.proofValues;
expressions_params[bufferCommitsSize + 6] = params.airgroupValues;
expressions_params[bufferCommitsSize + 7] = params.challenges;
expressions_params[bufferCommitsSize + 8] = params.evals;
```

### Python Layout (expression_evaluator.py)

In `expression_evaluator.py` lines 317-325:
```python
scalar_params: dict[int, np.ndarray] = {
    self.buffer_commits_size + PUBLIC_INPUTS_OFFSET: buffers.public_inputs,     # +2
    self.buffer_commits_size + NUMBERS_OFFSET: parser_args.numbers,             # +3
    self.buffer_commits_size + AIR_VALUES_OFFSET: buffers.air_values,           # +4
    self.buffer_commits_size + PROOF_VALUES_OFFSET: buffers.proof_values,       # +5
    self.buffer_commits_size + AIRGROUP_VALUES_OFFSET: buffers.airgroup_values, # +6
    self.buffer_commits_size + CHALLENGES_OFFSET: buffers.challenges,           # +7
    self.buffer_commits_size + EVALS_OFFSET: buffers.evals,                     # +8
}
```

**These match exactly.** Both use the same offset indices:
- `bufferCommitsSize + 2` = publicInputs
- `bufferCommitsSize + 3` = numbers (from parser)
- `bufferCommitsSize + 4` = airValues
- `bufferCommitsSize + 5` = proofValues
- `bufferCommitsSize + 6` = airgroupValues
- `bufferCommitsSize + 7` = challenges
- `bufferCommitsSize + 8` = evals

### bufferCommitsSize Calculation

Both implementations:
```
bufferCommitsSize = 1 + nStages + 3 + customCommits.size()
```

- C++: `expressions_ctx.hpp` line 202
- Python: `expression_evaluator.py` line 211

**Identical.**

---

## 6. FF3 Coefficient Ordering in Scalar Params

### C++ Coefficient Ordering

C++ Goldilocks3 uses elements in order `[c0, c1, c2]` where c0 is the base field
component, c1 is the degree-1 component, and c2 is the degree-2 component.

In `stark_verify.hpp` lines 44-48 (evals loading):
```cpp
for(uint64_t i = 0; i < starkInfo.evMap.size(); ++i) {
    for(uint64_t j = 0; j < FIELD_EXTENSION; ++j) {
        evals[i*FIELD_EXTENSION + j] = Goldilocks::fromString(jproof["evals"][i][j]);
    }
}
```
This stores evals in interleaved format: `[e0_c0, e0_c1, e0_c2, e1_c0, e1_c1, e1_c2, ...]`

### Python Coefficient Ordering

In `bytecode_adapter.py` `_build_buffers_from_verifier_data()` lines 261-263:
```python
coeffs = ff3_to_numpy_coeffs(data.evals[key])
evals[base:base + FIELD_EXTENSION_DEGREE] = coeffs
```

Where `ff3_to_numpy_coeffs` calls `ff3_coeffs` which returns ascending order `[c0, c1, c2]`:
```python
def ff3_coeffs(elem: FF3) -> list[int]:
    """Extract ascending-order coefficients [a0, a1, a2] from FF3 element."""
    return [int(c) for c in elem.vector()[::-1]]
```

**galois FF3 stores internally in descending order** (`[c2, c1, c0]`), and
`ff3_coeffs` reverses to ascending `[c0, c1, c2]`. This matches the C++ layout.

For challenges, the same `ff3_to_numpy_coeffs` is used (line 271):
```python
coeffs = ff3_to_numpy_coeffs(data.challenges[ch_map.name])
challenges[idx:idx + FIELD_EXTENSION_DEGREE] = coeffs
```

**The coefficient ordering matches between C++ and Python.**

---

## 7. Evals Loading in Verify Mode

### C++ Verify-Mode Eval Loading

In `expressions_pack.hpp`, when `type <= nStages+1` (committed polynomials) or
`type == 0` (constants) in verify mode, there is **no special verify-mode handling
for loading polynomial values**. The C++ bytecode evaluator in verify mode just loads
from the trace/aux_trace buffers that were populated from the JSON proof in
`stark_verify.hpp` lines 255-286.

Wait -- but the C++ verifier uses `domainSize = 1` and `domainExtended = false` for
cExpId evaluation. Looking again at `stark_verify.hpp` line 312:
```cpp
expressionsPack.calculateExpressions(params, dest, 1, false, false);
```

With `domainSize = 1`, the bytecode loops from `row = 0` only. For polynomial loads
(type 0 and type 1..nStages+1), it accesses `constPolsVals[row * nCols + stagePos]`
and `trace/aux_trace[offset + row * nCols + stagePos]`.

BUT WAIT: the C++ verifier does NOT load evals through the bytecode. The C++ verifier
binary uses a DIFFERENT binary than the prover. Looking at `stark_verify.hpp` line 306:
```cpp
ExpressionsPack expressionsPack(setupCtx, &proverHelpers, 1);
```
And line 310:
```cpp
dest.addParams(starkInfo.cExpId, setupCtx.expressionsBin.expressionsInfo[starkInfo.cExpId].destDim);
```

The C++ verifier uses `setupCtx.expressionsBin` which is the **verifier binary**
(not the prover binary). The verifier binary's cExpId bytecode uses type 15 (evals)
to load polynomial evaluations directly, not type 0/1 (trace buffers).

Actually, re-reading the code more carefully: the `starkInfo.verify` flag in
`expressions_ctx.hpp` line 173 is set based on the starkInfo configuration. But
in `stark_verify.hpp`, the `ExpressionsPack` is constructed with the regular
`setupCtx`, which contains the `expressionsBin` loaded at construction time.

Actually, looking at `stark_verify.hpp` more carefully, the `starkInfo.verify` flag
is NOT explicitly set. It's a flag in the StarkInfo that would need to be set before
constructing the ExpressionsPack. Let me check what happens.

Looking at `expressions_pack.hpp` line 99:
```cpp
if(setupCtx.starkInfo.verify) {
```

This flag determines whether the boundary/zi operands are loaded as scalars (verify
mode) vs arrays (prover mode). If `starkInfo.verify` is true, the load function
returns the scalar proverHelpers->x_n for boundary==0.

The question is: does the C++ verifier in `stark_verify.hpp` set `starkInfo.verify = true`?

Looking at the stark_verify.hpp function, it creates:
```cpp
ProverHelpers proverHelpers(starkInfo, xiChallenge);
SetupCtx setupCtx(starkInfo, expressionsBin);
ExpressionsPack expressionsPack(setupCtx, &proverHelpers, 1);
```

It passes `nrowsPack = 1` (the third argument), but doesn't explicitly set
`starkInfo.verify`. The `verify` flag must be set in StarkInfo when the verifier
binary is loaded.

In any case, the verifier calls `calculateExpressions(params, dest, 1, false, false)`
with `domainSize = 1`. For polynomial types (0 and 1..nStages+1), even without
the verify flag, with nrowsPack=1 and row=0, it would just load the first element
from the trace/constPols buffers. But the trace buffers were populated from the
JSON proof query values, not from evals.

Wait -- I need to re-examine this. The verifier computes the bytecode expression at
a SINGLE POINT (not at query points). The `domainSize = 1` means only one iteration.
But the buffers (trace, aux_trace, constPols) contain per-QUERY values, not per-
evaluation-point values. So there must be a verify flag that switches to evals...

Let me re-check: with `starkInfo.verify = true`, the bytecode load for type 0
(const pols) and type 1..nStages+1 (committed pols) doesn't have special verify-mode
handling in `expressions_pack.hpp`. Only `type == nStages+2` (boundary) and
`type == nStages+3` (xDivXSub) have verify-mode branches.

This confirms that the C++ verifier binary uses DIFFERENT bytecode opcodes. The
verifier binary (cExpId) uses type `bufferCommitsSize + 8` (= evals) to load
polynomial evaluations as scalars, not type 0/1 as the prover does. The compiled
bytecode for the verifier is different from the prover bytecode.

### Python Verify-Mode Eval Loading

The Python bytecode evaluator `_load_operand()` HAS explicit verify-mode handling
for type 0 and type 1..nStages+1 (lines 511-566):

```python
# Verify mode: load from evals
if self.verify and domain_size == 1:
    pol_id = None
    for idx, pol in enumerate(self.stark_info.const_pols_map):
        if pol.stage_pos == stage_pos:
            pol_id = idx
            break
    if pol_id is not None:
        for idx, e in enumerate(self.stark_info.ev_map):
            if e.type == EvMap.Type.const_ and e.id == pol_id and e.opening_pos == opening_idx:
                base = idx * FIELD_EXTENSION_DEGREE
                ...
                return ff3([c0, c1, c2])
```

This is a LINEAR SEARCH through ev_map to find the matching evaluation. The C++
verifier binary doesn't need this because the bytecode itself references evals
directly (using type `bufferCommitsSize + 8`).

The Python code adds this verify-mode overlay on top of the PROVER bytecode,
intercepting type 0 and type 1 loads and redirecting them to evals. This should
produce the same result, as long as the ev_map search correctly matches the right
eval for each polynomial access.

---

## 8. Key Findings Summary

### Finding 1: x_n Discrepancy (SIGNIFICANT)

| | C++ | Python |
|---|---|---|
| `proverHelpers.x_n` (verify mode) | `z` (raw xi) | `z^N` (xi^N) |

The Python `from_challenge()` stores `x_n = z^N` while C++ stores `x_n = z`.

In the bytecode, `boundary == 0` in verify mode returns `proverHelpers.x_n`.
If any bytecode expression references `boundary == 0`, it will get **different values**
in C++ vs Python.

The semantics in prover mode: `boundary == 0` returns `x` (the evaluation point).
In verify mode, C++ correctly returns `xi` (the evaluation point). Python incorrectly
returns `xi^N` (which is NOT the evaluation point).

### Finding 2: zi Values Match

Both implementations compute identical zi values:
- `zi[0] = 1/(z^N - 1)` for everyRow boundary
- Other boundaries computed identically

### Finding 3: Scalar Params Layout Matches

Both implementations use identical buffer type indices:
- `bufferCommitsSize` formula identical
- Offsets +2 through +8 identical
- FF3 coefficient ordering matches (ascending `[c0, c1, c2]`)

### Finding 4: Eval Loading Approach Differs but Should Be Equivalent

C++ verifier binary has its own bytecode that loads evals directly (type=evals index).
Python uses prover bytecode with verify-mode intercepts in `_load_operand()` that
redirect polynomial loads to ev_map searches. The ev_map search should find the same
values, assuming the bytecode args (stage_pos, opening_idx) correctly map to ev_map
entries.

### Finding 5: Python Verifier Z_H Round-Trip

The Python verifier flow for the evaluation check is:

```
bytecode_adapter._constraint_polynomial_verifier():
  1. bytecode evaluates Q(xi) [using zi which bakes in 1/Z_H division]
  2. adapter multiplies Q(xi) * Z_H(xi) to get C(xi)

verifier._evaluate_constraint_with_module():
  3. receives C(xi) from constraint module
  4. divides C(xi) / Z_H(xi) to get Q(xi) back

verifier._verify_evaluations():
  5. compares Q(xi) [from step 4] with Q_from_evals(xi) [from proof]
```

The C++ verifier does:
```
1. bytecode evaluates Q(xi) into buff
2. computes Q_from_evals = sum of eval pieces * xi^(i*N)
3. compares buff == Q_from_evals
```

The Python Z_H round-trip (multiply then divide) should cancel perfectly because:
- `Z_H(xi)` is computed identically each time (xi^N - 1)
- Goldilocks field arithmetic is exact (no rounding)

However, if the bytecode evaluator produces the WRONG Q(xi) (because x_n is wrong),
then the round-trip faithfully propagates the error.

---

## 9. Root Cause Assessment

The x_n discrepancy is a real bug in the Python code. Whether it causes the Rom
failure depends on whether Rom's cExpId=73 bytecode references `boundary == 0`.

**Next step**: Dump Rom's bytecode expression 73 to check if any operand has
`type == nStages+2, boundary == 0`. If yes, this x_n bug is the root cause.
If no, the bug exists but doesn't affect Rom, and the investigation must continue
to Task #3 (custom commit operand loading) and Task #4 (Merkle verification).

**Note**: Even if boundary==0 is not referenced in Rom's cExpId, this x_n bug should
be fixed in the Python code: `from_challenge()` should set `x_n = z` (raw challenge),
not `x_n = z^N`. The verifier.py functions that need xi^N already compute it
separately (see `_compute_xi_to_trace_size` and `_verify_evaluations`).
