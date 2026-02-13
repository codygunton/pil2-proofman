//! Constraint bytecode evaluator FFI for Lean verifier over Goldilocks field.
//!
//! Provides the `@[extern]` symbol expected by FFI/Constraints.lean:
//!   lean_constraint_evaluate_verifier
//!
//! Evaluates constraint polynomial Q(xi) = C(xi)/Z_H(xi) at the verification
//! point using compiled bytecode from the expressions .bin file.

mod evaluator;
mod expressions_bin;
mod field;
mod starkinfo;

// ============================================================================
// Lean Runtime FFI via C shim
// ============================================================================

pub type LeanObject = std::ffi::c_void;

extern "C" {
    fn cst_shim_alloc_array(size: usize, capacity: usize) -> *mut LeanObject;
    fn cst_shim_array_size(a: *const LeanObject) -> usize;
    fn cst_shim_array_uget_uint64(a: *const LeanObject, i: usize) -> u64;
    fn cst_shim_array_set_uint64(a: *mut LeanObject, i: usize, v: u64);
}

/// Read a Lean `Array UInt64` into a Vec<u64>.
#[inline]
unsafe fn read_lean_u64_array(arr: *const LeanObject) -> Vec<u64> {
    let len = cst_shim_array_size(arr);
    let mut result = Vec::with_capacity(len);
    for i in 0..len {
        result.push(cst_shim_array_uget_uint64(arr, i));
    }
    result
}

/// Create a Lean `Array UInt64` from a slice.
#[inline]
unsafe fn create_lean_u64_array(data: &[u64]) -> *mut LeanObject {
    let len = data.len();
    let arr = cst_shim_alloc_array(len, len);
    for i in 0..len {
        cst_shim_array_set_uint64(arr, i, data[i]);
    }
    arr
}

// ============================================================================
// Lean String FFI
// ============================================================================

extern "C" {
    fn cst_shim_string_cstr(s: *const LeanObject) -> *const std::ffi::c_char;
}

/// Read a Lean String as a Rust &str.
unsafe fn read_lean_string(s: *const LeanObject) -> &'static str {
    let cstr = std::ffi::CStr::from_ptr(cst_shim_string_cstr(s));
    cstr.to_str().unwrap_or("")
}

// ============================================================================
// Lean FFI Export
// ============================================================================

/// Evaluate constraint polynomial at the verifier evaluation point.
///
/// Lean signature:
///   evaluateVerifier (starkinfo_path : @& String) (bytecode_path : @& String)
///     (evals : @& Array UInt64) (challenges : @& Array UInt64)
///     (publics : @& Array UInt64) (airgroup_values : @& Array UInt64)
///     (air_values : @& Array UInt64) (proof_values : @& Array UInt64)
///     : Array UInt64
#[no_mangle]
pub unsafe extern "C" fn lean_constraint_evaluate_verifier(
    starkinfo_path: *const LeanObject,
    bytecode_path: *const LeanObject,
    evals: *const LeanObject,
    challenges: *const LeanObject,
    publics: *const LeanObject,
    airgroup_values: *const LeanObject,
    air_values: *const LeanObject,
    proof_values: *const LeanObject,
) -> *mut LeanObject {
    let si_path = read_lean_string(starkinfo_path);
    let bc_path = read_lean_string(bytecode_path);

    let evals_data = read_lean_u64_array(evals);
    let challenges_data = read_lean_u64_array(challenges);
    let publics_data = read_lean_u64_array(publics);
    let airgroup_values_data = read_lean_u64_array(airgroup_values);
    let air_values_data = read_lean_u64_array(air_values);
    let proof_values_data = read_lean_u64_array(proof_values);

    // Parse starkinfo and bytecode
    let si = starkinfo::StarkInfo::from_file(si_path)
        .unwrap_or_else(|e| panic!("Failed to parse starkinfo: {e}"));
    let expr_bin = expressions_bin::ExpressionsBin::from_file(bc_path)
        .unwrap_or_else(|e| panic!("Failed to parse bytecode: {e}"));

    // Evaluate constraint
    let result = evaluator::evaluate_constraint_verifier(
        &si,
        &expr_bin,
        &evals_data,
        &challenges_data,
        &publics_data,
        &airgroup_values_data,
        &air_values_data,
        &proof_values_data,
    );

    create_lean_u64_array(&[result.c0, result.c1, result.c2])
}
