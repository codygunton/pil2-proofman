/-
  FFI bindings to C++ constraint bytecode evaluator.

  Translates: executable-spec/constraints/bytecode_adapter.py

  The constraint evaluator takes polynomial evaluations, challenges,
  and other inputs, then evaluates the constraint polynomial at
  the verification point using compiled bytecode.

  In the Python spec, `BytecodeConstraintModule._constraint_polynomial_verifier`
  loads a `.bin` bytecode file, populates BufferSet from VerifierData, creates
  an ExpressionsPack in verify mode, and calls `calculate_expressions` to get
  Q(xi) -- the constraint quotient at the evaluation point.

  The caller (_evaluate_constraint_with_module in verifier.py) then recovers
  C(xi) = Q(xi) * Z_H(xi) and divides by Z_H(xi) to obtain the final Q(xi)
  for comparison with the reconstructed quotient from split pieces.

  For the Lean verifier we call directly into a C wrapper around the C++
  ExpressionsPack::calculateExpressions, passing all buffer data as flat
  UInt64 arrays in interleaved FF3 format.
-/
namespace FFI.Constraints

/-- Evaluate constraint polynomial at the verifier evaluation point.

    This is the core FFI entry point for constraint checking. It wraps the C++
    bytecode expression evaluator (ExpressionsPack::calculateExpressions) to
    compute Q(xi) = C(xi) / Z_H(xi) from the proof's polynomial evaluations.

    All array parameters use flat interleaved FF3 layout where each extension
    field element occupies 3 consecutive UInt64 slots: [c0, c1, c2, c0, c1, c2, ...].
    Base field arrays (publics, air_values) use 1 UInt64 per element.

    Parameters:
    - `bytecode_path`: filesystem path to the `.bin` constraint bytecode file
    - `evals`: polynomial evaluations at xi, interleaved FF3.
      Length = n_evals * 3 where n_evals = |ev_map|.
      Translates: BufferSet.evals in bytecode_adapter.py
    - `challenges`: Fiat-Shamir challenge values, interleaved FF3.
      Length = n_challenges * 3.
      Translates: BufferSet.challenges in bytecode_adapter.py
    - `publics`: public inputs, base field (1 UInt64 each).
      Length = n_publics.
      Translates: BufferSet.public_inputs in bytecode_adapter.py
    - `airgroup_values`: accumulated airgroup values, interleaved FF3.
      Length = n_airgroup_values * 3.
      Translates: BufferSet.airgroup_values in bytecode_adapter.py
    - `air_values`: AIR-specific values, base field layout with mixed dims.
      Length = air_values_size (cumulative: dim=1 for stage-1, dim=3 for stage-2+).
      Translates: BufferSet.air_values in bytecode_adapter.py
    - `proof_values`: proof-specific values, base field.
      Translates: BufferSet.proof_values in bytecode_adapter.py

    Returns: Array of exactly 3 UInt64 values representing Q(xi) as an FF3
    element in ascending coefficient order [c0, c1, c2].

    Note: The bytecode internally computes Q(xi) = C(xi)/Z_H(xi) (zerofier
    division is baked into the compiled constraint expression). The Lean
    verifier must then multiply by Z_H(xi) to recover C(xi) if needed for
    the final verification equation, matching the pattern in
    `_recover_constraint_from_quotient_verifier`.

    Translates: BytecodeConstraintModule._constraint_polynomial_verifier()
    in executable-spec/constraints/bytecode_adapter.py (lines 460-507). -/
@[extern "lean_constraint_evaluate_verifier"]
opaque evaluateVerifier
    (bytecode_path : @& String)
    (evals : @& Array UInt64)
    (challenges : @& Array UInt64)
    (publics : @& Array UInt64)
    (airgroup_values : @& Array UInt64)
    (air_values : @& Array UInt64)
    (proof_values : @& Array UInt64)
    : Array UInt64  -- 3 elements: [c0, c1, c2]

end FFI.Constraints
