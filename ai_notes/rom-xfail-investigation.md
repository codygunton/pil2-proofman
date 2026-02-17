# Rom XFAIL Investigation — INCOMPLETE

## Status

**Preliminary conclusion: C++ prover nFieldElements bug** — but this has NOT been
verified by comparing the C++ verifier code against the Python verifier. The
investigation needs to rule out Python-side bugs before attributing the failure
to the C++ prover.

## OPEN QUESTION: Is the Python verifier correct?

The investigation so far only examined the Python side. Key gap:
- **Never read** `pil2-stark/src/starkpil/stark_verify.hpp` (C++ verifier)
- **Never read** `pil2-stark/src/starkpil/verify_constraints.hpp` (C++ constraint eval)
- **Never read** `pil2-stark/src/starkpil/expressions_pack.hpp` (C++ bytecode evaluator)
- **Never ran** the C++ verifier against the Rom proof binary

### Next Steps (Required)

1. **Compare evaluation check**: Read `stark_verify.hpp` and compare the
   evaluation check logic against `_verify_evaluations()` in `verifier.py`.
   Focus on how Q is reconstructed from quotient pieces and how C is computed.

2. **Compare constraint evaluation**: Read `verify_constraints.hpp` and compare
   against `_evaluate_constraint_with_module()` in `verifier.py`. Check if the
   C++ path divides by Z_H the same way.

3. **Compare bytecode evaluation (verify mode)**: Read `expressions_pack.hpp`
   and compare verify-mode dim handling against `expression_evaluator.py`.
   Specifically check: how custom commit evaluations are loaded, how op_type
   determines FF vs FF3 arithmetic, how tmp registers store/load values.

4. **Optionally**: Run the C++ verifier against the Rom proof to see if it
   passes (would definitively prove a Python-side bug if it does).

## Evidence So Far (Python-Side Only)

### 1. Python bytecode evaluator appears correct

- **12 Zisk AIRs pass** through the same bytecode adapter code path (verify mode).
  RomData uses the same flow and passes, confirming the evaluator works.
- **All 18 ev_map entries** for Rom are found and loaded correctly with values
  matching the raw proof binary (verified by byte-level comparison).
- **FF3 arithmetic verified** — op[0] (challenge × flags) produces the expected
  result per manual computation.
- **Z_H round-trip is exact** — multiplying by Z_H then dividing returns the
  original value (finite field arithmetic is exact).

### 2. The proof data appears inconsistent (from Python's perspective)

The bytecode evaluator computes `C_bytecode` from the proof's evaluation data:
```
C_bytecode  = [138433633529502505, 2781424785653123464, 12233729151327695542]
C_expected  = [17127098632160451166, 4039472536038977490, 767163996891082047]
              (= Q_proof × Z_H(xi), where Q_proof is the committed quotient)
```

These don't match. Since all inputs are verified correct against the proof binary,
either the proof binary itself contains inconsistent data, OR the Python
bytecode evaluator handles something differently than the C++ evaluator.

### 3. Three verification failures

| Error | Cause |
|-------|-------|
| Invalid evaluations | Q_computed(xi) ≠ Q_proof(xi) — either proof is wrong or Python eval differs from C++ |
| Merkle verification failed | Custom commit Merkle tree verification fails — could be nFieldElements bug or Python code issue |
| Final polynomial not zero | FRI check fails as consequence |

### 4. Hypothesis: C++ verifier masks the Merkle bug (UNVERIFIED)

The C++ JSON verifier may use `nFieldElements=1` instead of `4` for GL mode,
which could skip custom commit Merkle verification. This hypothesis has NOT been
verified by reading the C++ code.

## Key Data Points

```
xi:        [8716174680162637030, 16549417886102123827, 7687471445282417950]
xi^N:      [3313400389158385524, 15738177539288021218, 3726790801791612697]
Z_H(xi):   [3313400389158385523, 15738177539288021218, 3726790801791612697]
Q_proof:   [4216457208035997298, 12842449364465107706, 8718687622782149476]
Q_bytecode:[8967852549743287977, 15341396557711420347, 1183051410211694445]
```

## What Was Fixed (Previous Session)

**Root Cause #1 (FIXED)**: `_build_buffers_from_verifier_data()` skipped
`EvMap.Type.custom` entries, writing zeros for all 11 custom commit
evaluations. Fixed by adding a custom type case. This was necessary but
not sufficient — the proof itself is buggy.

## Rom AIR Specifics

- Only Zisk AIR with custom commits (`commit stage(0) public(rom_root) rom`)
- `qDeg=1` (all others have `qDeg=2`)
- 11 custom commit polynomials: line, a_offset_imm0, a_imm1, b_offset_imm0,
  b_imm1, ind_width, op, store_offset, jmp_offset1, jmp_offset2, flags
- cExpId = expression 73 (36 bytecode operations)
- ev_map: 18 entries (7 cm/const + 11 custom)
