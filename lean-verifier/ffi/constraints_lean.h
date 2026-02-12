/*
 * C API for constraint bytecode evaluation (Lean FFI).
 *
 * Translates: executable-spec/constraints/bytecode_adapter.py
 *
 * This header declares the Lean FFI entry point for constraint polynomial
 * evaluation. The implementation (constraints_lean.cpp, to be created when
 * integrating with the pil2-stark build system) will wrap the C++
 * ExpressionsPack::calculateExpressions from pil2-stark/src/starkpil.
 *
 * Data flow (from bytecode_adapter.py _constraint_polynomial_verifier):
 *   1. Load bytecode from .bin file (ExpressionsBin)
 *   2. Load StarkInfo from adjacent .starkinfo.json
 *   3. Build BufferSet from verifier data (evals, challenges, etc.)
 *   4. Create ExpressionsPack in verify mode
 *   5. Call calculateExpressions -> Q(xi) as 3 Goldilocks field elements
 *
 * All FF3 (cubic extension) arrays use interleaved layout:
 *   [c0_0, c1_0, c2_0, c0_1, c1_1, c2_1, ...]
 * where c0 is the constant term and c2 is the x^2 coefficient.
 *
 * Base field arrays use 1 uint64_t per element.
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
 *
 * The bytecode evaluator computes Q(xi) = C(xi)/Z_H(xi) where the zerofier
 * division is baked into the compiled constraint expression (cExpId).
 *
 * All b_lean_obj_arg parameters are borrowed references (caller retains ownership).
 */
LEAN_EXPORT lean_obj_res lean_constraint_evaluate_verifier(
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
