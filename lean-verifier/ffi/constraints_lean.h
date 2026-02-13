/*
 * C API for constraint bytecode evaluation (Lean FFI).
 *
 * Translates: executable-spec/constraints/bytecode_adapter.py
 *
 * The Rust implementation parses starkinfo.json and the expressions .bin file,
 * then evaluates the constraint expression in verifier mode (single point).
 */

#ifndef CONSTRAINTS_LEAN_H
#define CONSTRAINTS_LEAN_H

#include <lean/lean.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Evaluate constraint polynomial at the verifier evaluation point.
 *
 * Parameters (Lean object encoding):
 *   starkinfo_path - lean_string: path to starkinfo.json
 *   bytecode_path  - lean_string: path to .bin constraint bytecode file
 *   evals          - lean_array of UInt64: polynomial evaluations (interleaved FF3)
 *   challenges     - lean_array of UInt64: Fiat-Shamir challenges (interleaved FF3)
 *   publics        - lean_array of UInt64: public inputs (base field)
 *   airgroup_values- lean_array of UInt64: airgroup accumulated values (interleaved FF3)
 *   air_values     - lean_array of UInt64: AIR-specific values (mixed dim layout)
 *   proof_values   - lean_array of UInt64: proof-specific values (base field)
 *
 * Returns:
 *   lean_array of 3 UInt64: Q(xi) coefficients [c0, c1, c2]
 */
LEAN_EXPORT lean_obj_res lean_constraint_evaluate_verifier(
    b_lean_obj_arg starkinfo_path,  /* String: path to starkinfo.json      */
    b_lean_obj_arg bytecode_path,   /* String: path to .bin file           */
    b_lean_obj_arg evals,           /* Array UInt64: interleaved FF3 evals */
    b_lean_obj_arg challenges,      /* Array UInt64: interleaved FF3       */
    b_lean_obj_arg publics,         /* Array UInt64: base field            */
    b_lean_obj_arg airgroup_values, /* Array UInt64: interleaved FF3       */
    b_lean_obj_arg air_values,      /* Array UInt64: mixed dim layout      */
    b_lean_obj_arg proof_values     /* Array UInt64: base field            */
);

#ifdef __cplusplus
}
#endif

#endif /* CONSTRAINTS_LEAN_H */
