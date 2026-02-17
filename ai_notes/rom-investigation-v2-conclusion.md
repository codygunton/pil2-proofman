# Rom XFAIL Investigation v2 — Definitive Conclusion

## Verdict: The Rom proof is INVALID (C++ prover bug)

The C++ prover generates a proof where the quotient polynomial Q does not
satisfy the constraint equation C(xi) = Q(xi) * Z_H(xi).

## Evidence

### Manual computation matches bytecode evaluator

Both the Python bytecode evaluator and an independent manual computation
(step-by-step arithmetic following the bytecode) produce the same Q(xi):

```
Q_bytecode = Q_manual = [8967852549743287977, 15341396557711420347, 1183051410211694445]
Q_from_evals (proof)  = [4216457208035997298, 12842449364465107706, 8718687622782149476]
```

These do NOT match. The constraint expression, evaluated with the proof's
own polynomial evaluations, produces a Q(xi) inconsistent with the quotient
polynomial committed in the proof.

### All inputs verified correct

1. **Evals**: Binary proof matches JSON proof exactly (all 18 entries)
2. **Challenges**: Transcript reconstruction produces correct xi
3. **Custom commit evals**: All 11 correctly loaded via ev_map (Task #3)
4. **zi (zerofier inverse)**: Correctly computed as 1/(z^N - 1) (matches C++)
5. **Coefficient ordering**: Ascending [c0,c1,c2] round-trip verified
6. **Both binaries agree**: Prover binary (Rom.bin) and verifier binary
   (Rom.verifier.bin) produce identical Q_bytecode results

### Refuted hypotheses

| Hypothesis | Status | Evidence |
|-----------|--------|----------|
| x_n bug (z^N vs z) | Real but NOT the cause | Rom bytecode only uses boundary==1 (zi), not boundary==0 (x_n) |
| Dim annotation mismatch | Not a problem | Python type promotion compensates; both binaries give same result |
| Custom commit loading wrong | Not a problem | ev_map search produces correct evals (all 11 match C++ verifier binary) |
| Merkle verification wrong | Not investigated in detail | Would also fail if proof is invalid |
| Coefficient ordering | Not a problem | Round-trip verified: ascending -> FF3 -> ascending -> FF3 = identity |
| nFieldElements mismatch | REFUTED | Both C++ and Python use 4 for GL mode |

### x_n bug (latent)

There is a real bug in `air_config.py:161`: Python stores `z^N` in x_n
for verify mode, while C++ stores raw `z` (the challenge point). However,
this does NOT affect Rom because the Rom cExpId=73 bytecode never uses
boundary==0 (x_n). It only uses boundary==1 (zi = 1/Z_H(xi)).

This bug is latent — it would affect any AIR whose constraint expression
references boundary==0 in verify mode. No known Zisk AIR triggers it.

### Binary format comparison

The prover binary (Rom.bin) and verifier binary (Rom.verifier.bin) encode
the same expression with different dimension annotations:

| Feature | Prover binary | Verifier binary |
|---------|--------------|-----------------|
| Custom commit ops | FF3*FF (dim_b=1) | FF3*FF3 (dim_b=3) |
| CM polynomial ops | FF3*FF (dim_b=1) | FF3*FF3 (dim_b=3) |
| Const polynomial ops | FF*FF or FF3*FF | FF3*FF or FF3*FF3 |
| zi (boundary) op | FF3*FF | FF3*FF3 |

16 of 36 operations have different dimension annotations. But the Python
evaluator compensates via automatic type promotion in `_apply_op()`, so
both binaries produce identical results.

## Root Cause

The C++ prover (`cargo-zisk prove`) generates an invalid quotient polynomial
for the Rom AIR. The `generate-zisk-test-vectors.sh` script does NOT run
verification after proving (uses `|| true` to swallow errors), so the invalid
proof was saved without being detected.

The Rom AIR is unique among Zisk AIRs:
- Only AIR with qDeg=1 (all others have qDeg=2)
- Only AIR with custom commits
- Has 11 custom commit polynomials

One or more of these properties may trigger a C++ prover bug that produces
an incorrect quotient polynomial.

## Recommendation

Keep the xfail on Rom. The bug is in the C++ prover, not the Python verifier.

```python
pytest.param("Rom_1", marks=pytest.mark.xfail(
    reason="C++ prover generates invalid proof: Q(xi) from constraint "
           "evaluation != Q(xi) from quotient polynomial evals. "
           "Verified by independent manual computation.",
    strict=True,
))
```

## Files Consulted

### C++ Sources (ground truth)
- `pil2-stark/src/starkpil/stark_verify.hpp` — C++ verifier evaluation check
- `pil2-stark/src/starkpil/setup_ctx.hpp` — ProverHelpers verify-mode constructor
- `pil2-stark/src/starkpil/expressions_pack.hpp` — Bytecode evaluator

### Python Sources
- `executable-spec/protocol/verifier.py` — Python verifier
- `executable-spec/protocol/air_config.py` — ProverHelpers.from_challenge
- `executable-spec/constraints/bytecode_adapter.py` — Bytecode constraint adapter
- `executable-spec/primitives/expression_bytecode/expression_evaluator.py` — Evaluator

### Investigation Notes
- `ai_notes/rom-investigation-v2-task1.md` — Evaluation check comparison
- `ai_notes/rom-investigation-v2-task2.md` — Bytecode verify-mode setup
- `ai_notes/rom-investigation-v2-task3.md` — Custom commit operand loading
- `ai_notes/rom-investigation-v2-task4.md` — Custom commit Merkle verification
- `ai_notes/rom-investigation-v2-task5.md` — Q reconstruction from pieces
