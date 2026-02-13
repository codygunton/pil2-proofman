/-
  Lean 4 STARK Verifier Specification.

  A faithful translation of the Python executable spec
  (executable-spec/protocol/verifier.py and dependencies).

  Module structure mirrors the Python package:
    Primitives/ → primitives/ (field, transcript, Merkle, polynomial)
    Protocol/   → protocol/  (verifier, FRI, proof, stark_info)
    FFI/        → FFI bindings (Poseidon2, constraint evaluator)
-/
