# Vectorize Expression Evaluator — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace galois-based scalar dispatch in the expression evaluator with
Numba JIT column arithmetic, then remove the galois fork dependency.

**Architecture:** The expression evaluator currently processes one row at a time
using galois FF3 operations in `python-calculate` mode (15 µs/element dispatch via
`np.frompyfunc`). We replace every galois call with raw-numpy + Numba JIT, working
on full column arrays (`np.ndarray[uint64]`) so Numba SIMD compiles the hot loops.

**Profiling baseline (u16_air gen_proof, 652 s total):**
| Bottleneck | Calls | Time | Root cause |
|---|---|---|---|
| FF3 `multiply.calculate` | 11.9M | 186 s | galois python-calculate per element |
| FF3 `**` / inversion | 53 K | 216 s | batch_inverse called once-per-row with 1 element |
| FF3 `__add__` | 852 K | 162 s | galois python-calculate per element |
| galois `vector()` | 2.27M | 154 s | store-result loop |

**Expected outcome:** E2E 30-test suite ≤ 60 s (from 448 s); gen_proof ≤ 30 s
(from 652 s).

---

## Tasks

### Task 1 — Create `primitives/goldilocks_jit.py`

**File:** `executable-spec/primitives/goldilocks_jit.py` (new)

This module provides Numba-compiled GF(p) and GF(p³) arithmetic that bypasses
galois. Copy `_gl_add`, `_gl_sub`, `_gl_mul` verbatim from the galois fork at
`/home/cody/galois-fork/src/galois/_domains/_calculate.py` lines 139-214.

**Step 1: Write the file**

Implement the following in order:

```python
"""Fast Goldilocks field arithmetic via Numba JIT.

GF(p):  Goldilocks prime p = 2^64 - 2^32 + 1
GF(p³): cubic extension with irreducible polynomial x³ - x - 1  (x³ = x + 1)

FF3 multiplication formula  (derived from x³ = x + 1):
    t  = a1*b2 + a2*b1
    c0 = a0*b0 + t
    c1 = a0*b1 + a1*b0 + t + a2*b2
    c2 = a0*b2 + a1*b1 + a2*b0 + a2*b2
"""
import numba
import numpy as np

# ── scalar GF(p) ──────────────────────────────────────────────────────────────
# Copy _gl_add, _gl_sub, _gl_mul exactly from the galois fork
# (they are @numba.jit(uint64(uint64,uint64), nopython=True, cache=True))

@numba.njit(cache=True)
def _gl_pow(a: np.uint64, exp: np.uint64) -> np.uint64:
    """a ** exp mod p via square-and-multiply."""
    result = np.uint64(1)
    base = a
    while exp > np.uint64(0):
        if exp & np.uint64(1):
            result = _gl_mul(result, base)
        base = _gl_mul(base, base)
        exp >>= np.uint64(1)
    return result

@numba.njit(cache=True)
def _gl_inv(a: np.uint64) -> np.uint64:
    """a^(p-2) mod p  (Fermat's little theorem)."""
    return _gl_pow(a, np.uint64(0xFFFFFFFEFFFFFFFF))  # p - 2

# ── vectorized GF(p) ufuncs ───────────────────────────────────────────────────
@numba.vectorize([numba.uint64(numba.uint64, numba.uint64)], cache=True)
def gl_add_vec(a, b):
    return _gl_add(a, b)

@numba.vectorize([numba.uint64(numba.uint64, numba.uint64)], cache=True)
def gl_sub_vec(a, b):
    return _gl_sub(a, b)

@numba.vectorize([numba.uint64(numba.uint64, numba.uint64)], cache=True)
def gl_mul_vec(a, b):
    return _gl_mul(a, b)

# ── scalar GF(p³) ─────────────────────────────────────────────────────────────
@numba.njit(cache=True)
def _ff3_add(a0, a1, a2, b0, b1, b2):
    return _gl_add(a0,b0), _gl_add(a1,b1), _gl_add(a2,b2)

@numba.njit(cache=True)
def _ff3_sub(a0, a1, a2, b0, b1, b2):
    return _gl_sub(a0,b0), _gl_sub(a1,b1), _gl_sub(a2,b2)

@numba.njit(cache=True)
def _ff3_mul(a0, a1, a2, b0, b1, b2):
    t  = _gl_add(_gl_mul(a1, b2), _gl_mul(a2, b1))
    c0 = _gl_add(_gl_mul(a0, b0), t)
    c1 = _gl_add(_gl_add(_gl_add(_gl_mul(a0, b1), _gl_mul(a1, b0)), t), _gl_mul(a2, b2))
    c2 = _gl_add(_gl_add(_gl_add(_gl_mul(a0, b2), _gl_mul(a1, b1)), _gl_mul(a2, b0)), _gl_mul(a2, b2))
    return c0, c1, c2

@numba.njit(cache=True)
def _ff3_inv(a0, a1, a2):
    """Invert a non-zero FF3 element via Fermat: a^(p³-2).

    p³ - 2 is a 192-bit integer; we evaluate it as a polynomial in p
    using Horner: p³-2 = ((1*p + 0)*p + 0)*p - 2, i.e.
       exp = p³ - 2  with p = 0xFFFFFFFF00000001.
    Decompose into bits and use square-and-multiply over FF3.
    """
    # Build the 192-bit exponent p³-2 as a sequence of bits (little-endian word).
    # p³ - 2 has known bit pattern; iterate square-and-multiply directly.
    # Represent exponent via three 64-bit limbs (little-endian).
    P = np.uint64(0xFFFFFFFF00000001)
    # p² mod 2^192:  compute p*p using 128-bit schoolbook (two 64-bit limbs)
    # ... use recurrence: for e = p³-2 iterate bit-by-bit square-and-multiply
    # Implementation note: p³-2 has 192 bits; use three uint64 limbs (lo,mid,hi)
    # Precomputed limbs of p³-2:
    #   p   = 0xFFFFFFFF00000001
    #   p²  = 0xFFFFFFFE00000003_00000000_FFFFFFFE (192-bit, but fits in 128 bits below p² < 2^128)
    #   p³-2 in 3 × 64-bit limbs (little-endian):
    #   Computed offline: see docstring.
    # Simplest correct implementation: use Itoh-Tsujii chain for p³-2.
    # a^(p³-2) = (a^(p-1))^(p²+p+1) * a^(-1 mod p)... complex.
    # Fallback: direct square-and-multiply with explicit bit extraction.
    e_lo  = np.uint64(0xFFFFFFFF00000001) - np.uint64(2)  # p-2 for p's last word? No—
    # Precomputed limbs of p³-2 (little-endian uint64 limbs).
    # Verified: p = 0xFFFFFFFF00000001; computed via Python `p**3 - 2`.
    e_lo  = np.uint64(0xFFFFFFFCFFFFFFFF)   # least significant 64 bits of p³-2
    e_mid = np.uint64(0xFFFFFFF900000005)   # middle 64 bits
    e_hi  = np.uint64(0xFFFFFFFD00000005)   # most significant 64 bits
    r0, r1, r2 = np.uint64(1), np.uint64(0), np.uint64(0)
    b0, b1, b2 = a0, a1, a2
    for limb in (e_lo, e_mid, e_hi):
        for _ in range(64):
            if limb & np.uint64(1):
                r0, r1, r2 = _ff3_mul(r0, r1, r2, b0, b1, b2)
            b0, b1, b2 = _ff3_mul(b0, b1, b2, b0, b1, b2)
            limb >>= np.uint64(1)
    return r0, r1, r2

# ── columnar GF(p³) — operate on (c0_arr, c1_arr, c2_arr) uint64 arrays ───────
@numba.njit(parallel=True, cache=True)
def ff3_add_columns(a0, a1, a2, b0, b1, b2):
    n = len(a0) if hasattr(a0, '__len__') else 1
    c0 = np.empty(n, np.uint64)
    c1 = np.empty(n, np.uint64)
    c2 = np.empty(n, np.uint64)
    for i in numba.prange(n):
        c0[i], c1[i], c2[i] = _ff3_add(a0[i], a1[i], a2[i], b0[i], b1[i], b2[i])
    return c0, c1, c2

@numba.njit(parallel=True, cache=True)
def ff3_sub_columns(a0, a1, a2, b0, b1, b2):
    n = len(a0) if hasattr(a0, '__len__') else 1
    c0 = np.empty(n, np.uint64)
    c1 = np.empty(n, np.uint64)
    c2 = np.empty(n, np.uint64)
    for i in numba.prange(n):
        c0[i], c1[i], c2[i] = _ff3_sub(a0[i], a1[i], a2[i], b0[i], b1[i], b2[i])
    return c0, c1, c2

@numba.njit(parallel=True, cache=True)
def ff3_mul_columns(a0, a1, a2, b0, b1, b2):
    n = len(a0) if hasattr(a0, '__len__') else 1
    c0 = np.empty(n, np.uint64)
    c1 = np.empty(n, np.uint64)
    c2 = np.empty(n, np.uint64)
    for i in numba.prange(n):
        c0[i], c1[i], c2[i] = _ff3_mul(a0[i], a1[i], a2[i], b0[i], b1[i], b2[i])
    return c0, c1, c2

@numba.njit(cache=True)
def ff3_batch_inverse(c0s, c1s, c2s):
    """Batch-invert N FF3 elements using Montgomery's trick.
    Requires 2N-2 multiplications + 1 inversion (vs N inversions).
    """
    n = len(c0s)
    # Forward pass: prefix products
    p0 = np.empty(n, np.uint64)
    p1 = np.empty(n, np.uint64)
    p2 = np.empty(n, np.uint64)
    p0[0], p1[0], p2[0] = c0s[0], c1s[0], c2s[0]
    for i in range(1, n):
        p0[i], p1[i], p2[i] = _ff3_mul(p0[i-1], p1[i-1], p2[i-1], c0s[i], c1s[i], c2s[i])
    # Single inversion of the final prefix product
    inv0, inv1, inv2 = _ff3_inv(p0[n-1], p1[n-1], p2[n-1])
    # Backward pass
    out0 = np.empty(n, np.uint64)
    out1 = np.empty(n, np.uint64)
    out2 = np.empty(n, np.uint64)
    for i in range(n-1, 0, -1):
        out0[i], out1[i], out2[i] = _ff3_mul(inv0, inv1, inv2, p0[i-1], p1[i-1], p2[i-1])
        inv0, inv1, inv2 = _ff3_mul(inv0, inv1, inv2, c0s[i], c1s[i], c2s[i])
    out0[0], out1[0], out2[0] = inv0, inv1, inv2
    return out0, out1, out2
```

**Step 2: Confirm `_ff3_inv` limb constants**

The limbs are pre-verified. Quick sanity-check to confirm they are correct:
```python
p = 0xFFFFFFFF00000001
e = p**3 - 2
assert (e & 0xFFFFFFFFFFFFFFFF)         == 0xFFFFFFFCFFFFFFFF
assert ((e >> 64)  & 0xFFFFFFFFFFFFFFFF) == 0xFFFFFFF900000005
assert ((e >> 128) & 0xFFFFFFFFFFFFFFFF) == 0xFFFFFFFD00000005
```
Run this inline; if any assertion fails, update the limbs in `_ff3_inv`.

**Step 3: Add unit tests**

Add to `tests/test_goldilocks_jit.py`:
```python
import numpy as np
from primitives.goldilocks_jit import (
    gl_add_vec, gl_sub_vec, gl_mul_vec,
    ff3_mul_columns, ff3_batch_inverse,
    _ff3_inv, _ff3_mul,
)

P = 0xFFFFFFFF00000001

def test_gl_add_vec():
    a = np.array([P-1, 0, 5], dtype=np.uint64)
    b = np.array([1, P-1, P-3], dtype=np.uint64)
    r = gl_add_vec(a, b)
    assert list(r) == [0, P-1, P-1+5-(P-3)+P-3]  # adjust expected
    # Specifically: (P-1)+1=0, 0+(P-1)=P-1, 5+(P-3)=P-2  wait: 5 + (P-3) = P+2 > P so = 2
    assert list(r) == [0, P-1, 2]

def test_ff3_mul_identity():
    # a * 1 == a
    a0, a1, a2 = np.uint64(12345), np.uint64(67890), np.uint64(11111)
    c0, c1, c2 = _ff3_mul(a0, a1, a2, np.uint64(1), np.uint64(0), np.uint64(0))
    assert (c0, c1, c2) == (a0, a1, a2)

def test_ff3_inv():
    a0, a1, a2 = np.uint64(12345), np.uint64(67890), np.uint64(11111)
    i0, i1, i2 = _ff3_inv(a0, a1, a2)
    # a * inv(a) == 1
    r0, r1, r2 = _ff3_mul(a0, a1, a2, i0, i1, i2)
    assert (int(r0), int(r1), int(r2)) == (1, 0, 0)

def test_ff3_batch_inverse():
    n = 100
    c0s = np.array([i+1 for i in range(n)], dtype=np.uint64)
    c1s = np.array([i+2 for i in range(n)], dtype=np.uint64)
    c2s = np.array([i+3 for i in range(n)], dtype=np.uint64)
    inv0, inv1, inv2 = ff3_batch_inverse(c0s, c1s, c2s)
    # Verify: a[i] * inv[i] == (1,0,0) for each i
    for i in range(n):
        r0, r1, r2 = _ff3_mul(c0s[i], c1s[i], c2s[i], inv0[i], inv1[i], inv2[i])
        assert (int(r0), int(r1), int(r2)) == (1, 0, 0), f"failed at i={i}"
```

Run: `cd executable-spec && uv run pytest tests/test_goldilocks_jit.py -v`
Expected: all pass.

**Step 4: Commit**

```bash
git add executable-spec/primitives/goldilocks_jit.py executable-spec/tests/test_goldilocks_jit.py
git commit -m "feat(perf): add Numba JIT GF(p) and GF(p³) arithmetic in goldilocks_jit.py"
```

---

### Task 2 — Refactor `expression_evaluator.py` to raw-numpy fast path

**File:** `executable-spec/primitives/expression_bytecode/expression_evaluator.py`

Replace all galois operations with the Numba JIT functions from Task 1.

**Key design:**
- `FF1Col = np.ndarray` — dtype=uint64, shape (nrows_pack,) — base field column
- `FF3Cols = tuple[np.ndarray, np.ndarray, np.ndarray]` — three uint64 arrays
- `FastValue = FF1Col | np.uint64 | FF3Cols | tuple[np.uint64, np.uint64, np.uint64]`
- `_is_ff3(val)` → `isinstance(val, tuple)`

**Step 1: Update imports**

Remove:
```python
from primitives.field import (
    FF, FF3, FIELD_EXTENSION_DEGREE, batch_inverse,
    ff3, ff3_coeffs, ff3_from_buffer_at,
)
```

Add:
```python
import numpy as np
from primitives.field import FIELD_EXTENSION_DEGREE
from primitives.goldilocks_jit import (
    gl_add_vec, gl_sub_vec, gl_mul_vec,
    ff3_add_columns, ff3_sub_columns, ff3_mul_columns,
    ff3_batch_inverse,
)
```

**Step 2: Update type aliases and helpers**

Replace:
```python
GaloisValue = FF | FF3
def _is_ff3(val: GaloisValue) -> bool:
    return type(val).order != FF.order
```

With:
```python
# FastValue: either a uint64 ndarray (FF column) or a 3-tuple of uint64 ndarrays (FF3 columns).
# Scalars are numpy scalar uint64 values; arrays are shape (nrows_pack,).
FastValue = np.ndarray | tuple  # FF1Col or FF3Cols

def _is_ff3(val: FastValue) -> bool:
    return isinstance(val, tuple)

def _promote_ff_to_ff3(val: np.ndarray | np.uint64) -> tuple:
    """Lift a base-field value to the extension field (c1=c2=0)."""
    if isinstance(val, np.ndarray):
        zeros = np.zeros(len(val), dtype=np.uint64)
        return (val, zeros.copy(), zeros.copy())
    return (val, np.uint64(0), np.uint64(0))  # scalar case
```

**Step 3: Update `calculate_expressions` temp dict types**

Replace:
```python
tmp1_g: dict[int, FF] = {}
tmp3_g: dict[int, FF3] = {}
param_results: list[GaloisValue] = [None, None]
```

With:
```python
tmp1_g: dict[int, np.ndarray | np.uint64] = {}
tmp3_g: dict[int, tuple] = {}
param_results: list[FastValue | None] = [None, None]
```

Also remove:
```python
if p.op == "number":
    param_results[k] = FF(p.value)
```
Replace with:
```python
if p.op == "number":
    param_results[k] = np.uint64(p.value)
```

And:
```python
if p.op == "airvalue":
    if p.dim == 1:
        param_results[k] = FF(int(buffers.air_values[p.pols_map_id]))
    else:
        c = [int(buffers.air_values[p.pols_map_id + i]) for i in range(FIELD_EXTENSION_DEGREE)]
        param_results[k] = ff3(c)
```
Replace with:
```python
if p.op == "airvalue":
    if p.dim == 1:
        param_results[k] = np.uint64(int(buffers.air_values[p.pols_map_id]))
    else:
        c0 = np.uint64(int(buffers.air_values[p.pols_map_id]))
        c1 = np.uint64(int(buffers.air_values[p.pols_map_id + 1]))
        c2 = np.uint64(int(buffers.air_values[p.pols_map_id + 2]))
        param_results[k] = (c0, c1, c2)
```

**Step 4: Rewrite `_load_direct_poly` (vectorized)**

Replace the Python `for r in range(nrows_pack)` loops with numpy fancy indexing:

```python
def _load_direct_poly(self, buffers: BufferSet, param: Params, row: int,
                      nrows_pack: int, domain_size: int, domain_extended: bool,
                      map_offsets_exps: np.ndarray, next_strides_exps: np.ndarray
                      ) -> np.ndarray:
    o = int(next_strides_exps[param.row_offset_index])

    if param.op == "const":
        n_cols = int(self.map_sections_n[0])
        buf = buffers.const_pols_extended if domain_extended else buffers.const_pols
        rows = (np.arange(nrows_pack, dtype=np.intp) + row + o) % domain_size
        return buf[rows * n_cols + param.stage_pos].astype(np.uint64)

    offset = int(map_offsets_exps[param.stage])
    n_cols = int(self.map_sections_n[param.stage])

    if param.stage == 1 and not domain_extended:
        rows = (np.arange(nrows_pack, dtype=np.intp) + row + o) % domain_size
        return buffers.trace[rows * n_cols + param.stage_pos].astype(np.uint64)

    rows = (np.arange(nrows_pack, dtype=np.intp) + row + o) % domain_size
    base_indices = offset + rows * n_cols + param.stage_pos

    if param.dim == 1:
        return buffers.aux_trace[base_indices].astype(np.uint64)

    # FF3: load interleaved (c0, c1, c2) at consecutive positions
    c0 = buffers.aux_trace[base_indices].astype(np.uint64)
    c1 = buffers.aux_trace[base_indices + 1].astype(np.uint64)
    c2 = buffers.aux_trace[base_indices + 2].astype(np.uint64)
    return (c0, c1, c2)
```

Note: `param.dim` check requires exposing it on `Params` — verify the dataclass has `dim` field (it does via `_load_direct_poly`'s parent `Params`). If not, determine dim from `param.op`.

**Step 5: Rewrite `_load_operand` (all paths, vectorized)**

This is the longest function. Replace every `for j in range(nrows_pack)` loop
pattern with numpy fancy indexing. The pattern is always:
```python
# OLD
rows = []
for j in range(nrows_pack):
    cyclic_row = (row + j + o) % domain_size
    rows.append(int(buf[offset + cyclic_row * n_cols + stage_pos]))
return FF(rows)
# NEW
row_indices = (np.arange(nrows_pack, dtype=np.intp) + row + o) % domain_size
return buf[offset + row_indices * n_cols + stage_pos].astype(np.uint64)
```

For every committed polynomial load returning `FF(vals)` → return `np.ndarray`.
For every load returning `ff3_from_buffer_at(buf, indices)` → return `(c0, c1, c2)` tuple:
```python
# OLD: ff3_from_buffer_at(buf, indices)  where indices is list of base positions
# NEW:
row_indices = (np.arange(nrows_pack, dtype=np.intp) + row + o) % domain_size
base_indices = offset + row_indices * n_cols + stage_pos
c0 = buf[base_indices].astype(np.uint64)
c1 = buf[base_indices + 1].astype(np.uint64)
c2 = buf[base_indices + 2].astype(np.uint64)
return (c0, c1, c2)
```

For scalar loads (`dim == 1` from scalar_params, or challenges, etc.):
```python
# OLD: return FF(int(arr[idx]))
# NEW: return np.uint64(int(arr[idx]))

# OLD: return ff3([c0, c1, c2])
# NEW: return (np.uint64(c0), np.uint64(c1), np.uint64(c2))
```

For the boundary (x, zi) path — the prover already returns numpy slices, so just
ensure the return type annotation is `np.ndarray` (no change needed for prover).
For verifier zi/x returns `FF3([...]×nrows_pack)` — replace:
```python
# OLD: return FF3([int(scalar)] * nrows_pack)
# NEW: return (
#     np.full(nrows_pack, c0, dtype=np.uint64),
#     np.full(nrows_pack, c1, dtype=np.uint64),
#     np.full(nrows_pack, c2, dtype=np.uint64),
# )
```

For xi (x_div_x_sub) **prover** path — the key bottleneck change:
```python
# OLD:
x_vals = self.prover_helpers.x[row:row + nrows_pack]
x_ff3 = FF3(np.asarray(x_vals, dtype=np.uint64).tolist())
diff = x_ff3 - xi_val
return batch_inverse(diff)

# NEW:
x_vals = np.asarray(self.prover_helpers.x[row:row + nrows_pack], dtype=np.uint64)
xi_c0, xi_c1, xi_c2 = np.uint64(xi_c0), np.uint64(xi_c1), np.uint64(xi_c2)
diff0 = gl_sub_vec(x_vals, xi_c0)             # x - xi_c0
diff1 = np.full(nrows_pack, xi_c1, dtype=np.uint64)  # -xi_c1 component
diff1 = np.full(nrows_pack, 0, dtype=np.uint64) - diff1  # Negate via gl_sub_vec
# Actually x is a base-field element embedded as FF3 (c1=c2=0), so:
# x as FF3 = (x_vals, zeros, zeros)
# xi as FF3 = (xi_c0, xi_c1, xi_c2)
# diff = x - xi
diff0 = gl_sub_vec(x_vals, np.full(nrows_pack, xi_c0, dtype=np.uint64))
diff1 = np.full(nrows_pack, xi_c1, dtype=np.uint64)
diff1 = np.frompyfunc(lambda v: (0 - int(v)) % P, 1, 1)(diff1).astype(np.uint64)  # negate
# Better: use gl_sub_vec(zeros, diff1)
zeros = np.zeros(nrows_pack, dtype=np.uint64)
diff1_neg = gl_sub_vec(zeros, np.full(nrows_pack, xi_c1, dtype=np.uint64))
diff2_neg = gl_sub_vec(zeros, np.full(nrows_pack, xi_c2, dtype=np.uint64))
# diff = (x - xi_c0, -xi_c1, -xi_c2)
return ff3_batch_inverse(gl_sub_vec(x_vals, np.full(nrows_pack, np.uint64(xi_c0))),
                         diff1_neg, diff2_neg)
```

Wait, simplify. `x` is a GF(p) value (base field), embedded as FF3 with c1=c2=0.
So `x - xi = (x - xi_c0, 0 - xi_c1, 0 - xi_c2)`. Code:
```python
# xi loading — prover path
x_col = np.asarray(self.prover_helpers.x[row:row + nrows_pack], dtype=np.uint64)
xi_c0 = np.uint64(int(self.xis[xi_base]))
xi_c1 = np.uint64(int(self.xis[xi_base + 1]))
xi_c2 = np.uint64(int(self.xis[xi_base + 2]))

z = np.uint64(0)
diff_c0 = gl_sub_vec(x_col,                              np.full(nrows_pack, xi_c0, np.uint64))
diff_c1 = gl_sub_vec(np.zeros(nrows_pack, np.uint64),    np.full(nrows_pack, xi_c1, np.uint64))
diff_c2 = gl_sub_vec(np.zeros(nrows_pack, np.uint64),    np.full(nrows_pack, xi_c2, np.uint64))
return ff3_batch_inverse(diff_c0, diff_c1, diff_c2)
```

**Step 6: Rewrite `_apply_op`**

```python
def _apply_op(self, op: int, a: FastValue, b: FastValue) -> FastValue:
    """Apply arithmetic operation, promoting to FF3 if types mismatch."""
    a_ext, b_ext = _is_ff3(a), _is_ff3(b)
    if a_ext and not b_ext:
        b = _promote_ff_to_ff3(b)
    elif b_ext and not a_ext:
        a = _promote_ff_to_ff3(a)

    if a_ext or b_ext:
        a0, a1, a2 = a
        b0, b1, b2 = b
        if op == 0: return ff3_add_columns(a0, a1, a2, b0, b1, b2)
        if op == 1: return ff3_sub_columns(a0, a1, a2, b0, b1, b2)
        if op == 2: return ff3_mul_columns(a0, a1, a2, b0, b1, b2)
        if op == 3: return ff3_sub_columns(b0, b1, b2, a0, a1, a2)
    else:
        if op == 0: return gl_add_vec(a, b)
        if op == 1: return gl_sub_vec(a, b)
        if op == 2: return gl_mul_vec(a, b)
        if op == 3: return gl_sub_vec(b, a)
    raise ValueError(f"Invalid operation: {op}")
```

**Step 7: Rewrite `_multiply_results`**

Same pattern as `_apply_op` with `op=2` (multiply). Can just call `_apply_op(2, a, b)`.

**Step 8: Rewrite `_store_result`**

```python
def _store_result(self, dest: Dest, result: FastValue, row: int, nrows_pack: int) -> None:
    """Store result to destination buffer."""
    is_ext = _is_ff3(result)
    offset = dest.offset if dest.offset != 0 else (FIELD_EXTENSION_DEGREE if is_ext else 1)

    if not is_ext:
        # FF: consecutive writes with stride `offset`
        start = row * offset
        if isinstance(result, np.ndarray):
            dest.dest[start : start + nrows_pack * offset : offset] = result
        else:
            dest.dest[start : start + nrows_pack * offset : offset] = np.uint64(result)
    else:
        # FF3: interleaved [c0, c1, c2, c0, c1, c2, ...]
        c0, c1, c2 = result
        start = row * offset  # offset == 3 for FF3
        dest.dest[start     : start + nrows_pack * 3 : 3] = c0 if isinstance(c0, np.ndarray) else np.full(nrows_pack, c0, np.uint64)
        dest.dest[start + 1 : start + 1 + nrows_pack * 3 : 3] = c1 if isinstance(c1, np.ndarray) else np.full(nrows_pack, c1, np.uint64)
        dest.dest[start + 2 : start + 2 + nrows_pack * 3 : 3] = c2 if isinstance(c2, np.ndarray) else np.full(nrows_pack, c2, np.uint64)
```

**Step 9: Update the `batch_inverse` call in direct poly load**

At line 345-346 (in `calculate_expressions`):
```python
# OLD:
if p.inverse:
    result = batch_inverse(result)
# NEW:
if p.inverse:
    if _is_ff3(result):
        result = ff3_batch_inverse(*result)
    else:
        # FF batch inverse: use gl_inv_vec (add to goldilocks_jit.py if needed)
        # Or: result = np.array([_gl_inv(v) for v in result], dtype=np.uint64)
        # For now, use the Numba vectorize:
        result = gl_inv_vec(result)
```

Add `gl_inv_vec` to `goldilocks_jit.py`:
```python
@numba.vectorize([numba.uint64(numba.uint64)], cache=True)
def gl_inv_vec(a):
    return _gl_inv(a)
```

Also update the `p.inverse` check at line 424 (inside the expression loop):
```python
if p.inverse:
    param_results[k] = ff3_batch_inverse(*param_results[k]) if _is_ff3(param_results[k]) \
                        else gl_inv_vec(param_results[k])
```

**Step 10: Update type hints throughout**

Change `GaloisValue` to `FastValue` in type annotations. Remove all remaining
`FF(...)`, `FF3(...)`, `ff3(...)`, `ff3_coeffs(...)`, `ff3_from_buffer_at(...)` calls.

**Step 11: Run unit tests (E2E verifier, not prover)**

```bash
cd executable-spec && uv run pytest tests/test_verifier_e2e.py -v -n auto
```

Expected: all 30 verifier tests pass. The verifier uses `domain_size=1` with nrows_pack=1
so this tests the scalar code paths.

**Step 12: Commit**

```bash
git add executable-spec/primitives/expression_bytecode/expression_evaluator.py \
        executable-spec/primitives/goldilocks_jit.py
git commit -m "perf: replace galois FF3 with Numba JIT in expression evaluator"
```

---

### Task 3 — Remove `nrows_pack=1` from both adapters

**Files:**
- `executable-spec/constraints/bytecode_adapter.py`
- `executable-spec/witness/bytecode_adapter.py`

**Step 1: `constraints/bytecode_adapter.py`**

Find the `ExpressionsPack(...)` constructor call with `nrows_pack=1`.
Remove the `nrows_pack=1` argument. The default `NROWS_PACK = 1<<16 = 65536`
will be used, clamped to `min(NROWS_PACK, domain_size)` inside `__init__`.

**Step 2: `witness/bytecode_adapter.py`**

Same: find and remove `nrows_pack=1` argument in the `ExpressionsPack(...)` call.

**Step 3: Run E2E tests**

```bash
cd executable-spec && uv run pytest tests/test_stark_e2e.py tests/test_verifier_e2e.py -v -n auto
```

Expected: all 30 tests pass. This validates that large nrows_pack doesn't break
correctness (cyclic boundary handling, etc.).

**Step 4: Commit**

```bash
git add executable-spec/constraints/bytecode_adapter.py \
        executable-spec/witness/bytecode_adapter.py
git commit -m "perf: remove nrows_pack=1 override, enable batched column evaluation"
```

---

### Task 4 — Performance validation and profiling

**Step 1: Profile gen_proof on u16_air**

```bash
cd executable-spec
uv run python -c "
import cProfile, pstats, io
import numpy as np
# ... (copy the profiling setup from the previous profiling run)
# Profile gen_proof on u16_air
pr = cProfile.Profile()
pr.enable()
# run gen_proof for u16_air
pr.disable()
s = io.StringIO()
ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
ps.print_stats(25)
print(s.getvalue())
" > /tmp/profile_after.txt 2>&1
cat /tmp/profile_after.txt
```

**Step 2: Run 30 E2E tests and measure wall time**

```bash
cd executable-spec
time uv run pytest tests/test_stark_e2e.py tests/test_verifier_e2e.py -n auto -v
```

Record the total time. **Target: ≤ 60 s** (baseline was 448 s).

If the time is not significantly better (< 2× improvement), diagnose before proceeding
to Task 5. Common issues:
- Numba JIT compilation cold-start adds ~30 s on first run; run twice and compare
- If `ff3_batch_inverse` or `ff3_mul_columns` show up in new profile at the top, the
  Numba functions may not be compiling correctly

**Step 3: Accept or diagnose**

If wall time ≤ 150 s (3× improvement or more), proceed to Task 5. Otherwise,
check profile output and fix bottlenecks before proceeding.

---

### Task 5 — Remove galois fork dependency

> **Prerequisite:** Task 4 must show ≥ 3× performance improvement before running this task.

**Step 1: Check `field.py` SHIFT_INV**

Read `executable-spec/primitives/field.py` and find the SHIFT_INV line.
If it reads `SHIFT_INV = FF(1) / SHIFT` (our workaround), revert it to:
```python
SHIFT_INV = SHIFT ** -1
```

This works with upstream galois which handles negative exponents for base fields.

**Step 2: Revert `pyproject.toml`**

Read `executable-spec/pyproject.toml`. Find the galois dependency line.
It currently reads something like:
```toml
galois = { path = "/home/cody/galois-fork", editable = true }
```
Replace with the original upstream galois pin. Check git history for the original:
```bash
git log --oneline -- executable-spec/pyproject.toml | head -10
git show <commit-before-galois-fork>:executable-spec/pyproject.toml | grep galois
```
Restore that version (e.g., `galois = "0.3.10"` or whatever the original was).

**Step 3: Reinstall dependencies**

```bash
cd executable-spec && uv sync
```

**Step 4: Run full test suite to confirm no regression**

```bash
cd executable-spec
time uv run pytest tests/test_stark_e2e.py tests/test_verifier_e2e.py -n auto -v
```

Expected: same pass rate and time as after Task 4. This confirms the galois fork
is no longer needed.

**Step 5: Run full non-Zisk suite**

```bash
cd executable-spec && ./run-tests.sh
```

Expected: 320+ tests pass.

**Step 6: Commit**

```bash
git add executable-spec/pyproject.toml executable-spec/primitives/field.py
git commit -m "refactor: revert galois fork, upstream galois sufficient after expression evaluator fix"
```

---

## Implementation Workflow

When implementing this plan:

1. **Load Plan**: Read this entire file before starting.
2. **Sync Tasks**: Create TodoWrite tasks matching the 5 tasks above.
3. **Execute sequentially**: Tasks 1→2→3→4→5 in order (each depends on the previous).
4. **Mark tasks complete**: Only when all steps in a task pass their verification.
5. **Stop on unexpected failures**: Do not brute-force. Diagnose and ask if stuck.

### Critical Notes

- **`_ff3_inv` limbs**: Must be verified with Python before using. If wrong, all tests fail.
- **Scalar vs array broadcasting**: numpy vectorize ufuncs broadcast scalars automatically.
  `gl_add_vec(np.array([1,2,3], np.uint64), np.uint64(5))` → `[6, 7, 8]`. Use this.
- **`ff3_mul_columns` with scalar tuples**: `(np.uint64(c0), np.uint64(c1), np.uint64(c2))`
  broadcast works because each scalar pairs with the corresponding array via numpy.
  But Numba `@njit(parallel=True)` needs `len(a0)` — add a scalar check:
  ```python
  if not hasattr(a0, '__len__'):  # scalar case — should not occur after Task 3 fix
      c0, c1, c2 = _ff3_mul(a0, a1, a2, b0, b1, b2)
      return c0, c1, c2
  ```
- **Verifier path (`domain_size=1`)**: After changes, `_load_operand` with `domain_size=1`
  still hits the `verify and domain_size == 1` branches that return scalar tuples.
  These work with the new `_apply_op` and `_store_result` because nrows_pack=1 with
  the scalar → array fallback.
- **`batch_inverse` in `calculate_expressions` for `p.inverse`**: This only appears in
  the direct-poly load path (cm/const). The old `batch_inverse` was for galois FF3 arrays;
  replace with `ff3_batch_inverse(*result)` or `gl_inv_vec(result)`.
- **Do not change `witness_generation.py`**: It uses galois for minor operations that
  are not bottlenecks; leave it for a separate cleanup.

### Progress Tracking

- [ ] Task 1: `primitives/goldilocks_jit.py` created, unit tests pass
- [ ] Task 2: `expression_evaluator.py` refactored, verifier E2E tests pass
- [ ] Task 3: Adapters updated, E2E tests pass
- [ ] Task 4: Performance validated (≥ 3× improvement)
- [ ] Task 5: Galois fork removed, tests still pass
