/-
  FFI bindings to constraint bytecode evaluator (Rust implementation).

  Translates: executable-spec/constraints/bytecode_adapter.py

  The constraint evaluator takes polynomial evaluations, challenges,
  and other inputs, then evaluates the constraint polynomial at
  the verification point using compiled bytecode.

  The Rust implementation parses the starkinfo.json and expressions .bin
  files, then runs the verifier-mode bytecode interpreter to compute
  Q(xi) = C(xi) / Z_H(xi).
-/
namespace FFI.Constraints

/-- Evaluate constraint polynomial at the verifier evaluation point.

    Parameters:
    - `starkinfo_path`: filesystem path to the starkinfo.json file
    - `bytecode_path`: filesystem path to the `.bin` constraint bytecode file
    - `evals`: polynomial evaluations at xi, interleaved FF3
    - `challenges`: Fiat-Shamir challenge values, interleaved FF3
    - `publics`: public inputs, base field (1 UInt64 each)
    - `airgroup_values`: accumulated airgroup values, interleaved FF3
    - `air_values`: AIR-specific values (mixed dim layout)
    - `proof_values`: proof-specific values, base field

    Returns: Array of exactly 3 UInt64 values representing Q(xi) as an FF3
    element in ascending coefficient order [c0, c1, c2].

    Translates: BytecodeConstraintModule._constraint_polynomial_verifier()
    in executable-spec/constraints/bytecode_adapter.py (lines 460-507). -/
@[extern "lean_constraint_evaluate_verifier"]
opaque evaluateVerifier
    (starkinfo_path : @& String)
    (bytecode_path : @& String)
    (evals : @& Array UInt64)
    (challenges : @& Array UInt64)
    (publics : @& Array UInt64)
    (airgroup_values : @& Array UInt64)
    (air_values : @& Array UInt64)
    (proof_values : @& Array UInt64)
    : Array UInt64  -- 3 elements: [c0, c1, c2]

end FFI.Constraints
