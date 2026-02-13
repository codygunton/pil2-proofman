// C shim to expose Lean's static inline functions to Rust (constraints crate).
//
// Uses "cst_shim_" prefix to avoid symbol collisions with the poseidon2 crate.

#include "lean/lean.h"

// --- Array allocation and access ---

lean_obj_res cst_shim_alloc_array(size_t size, size_t capacity) {
    return lean_alloc_array(size, capacity);
}

size_t cst_shim_array_size(b_lean_obj_arg a) {
    return lean_array_size(a);
}

uint64_t cst_shim_array_uget_uint64(b_lean_obj_arg a, size_t i) {
    lean_object* elem = lean_array_get_core(a, i);
    return lean_unbox_uint64(elem);
}

void cst_shim_array_set_uint64(lean_object* a, size_t i, uint64_t v) {
    lean_object* boxed = lean_box_uint64(v);
    lean_array_set_core(a, i, boxed);
}

// --- String access ---

const char* cst_shim_string_cstr(b_lean_obj_arg s) {
    return lean_string_cstr(s);
}
