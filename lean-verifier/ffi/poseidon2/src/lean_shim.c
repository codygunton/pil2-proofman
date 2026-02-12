// C shim to expose Lean's static inline array functions to Rust.
//
// Array UInt64 in Lean is a lean_array_object (NOT a scalar array).
// Each element is a boxed UInt64 (lean_ctor with uint64 at scalar offset 0).
// We expose helpers that handle the boxing/unboxing.

#include "lean/lean.h"

// --- Array allocation and access ---

lean_obj_res lean_shim_alloc_array(size_t size, size_t capacity) {
    return lean_alloc_array(size, capacity);
}

size_t lean_shim_array_size(b_lean_obj_arg a) {
    return lean_array_size(a);
}

// Read element i as raw uint64_t (unbox from lean_object*)
uint64_t lean_shim_array_uget_uint64(b_lean_obj_arg a, size_t i) {
    lean_object* elem = lean_array_get_core(a, i);
    return lean_unbox_uint64(elem);
}

// Set element i from raw uint64_t (box into lean_object*)
void lean_shim_array_set_uint64(lean_object* a, size_t i, uint64_t v) {
    lean_object* boxed = lean_box_uint64(v);
    lean_array_set_core(a, i, boxed);
}

// --- Scalar array (sarray) for ByteArray if ever needed ---

lean_obj_res lean_shim_alloc_sarray(unsigned elem_size, size_t size, size_t capacity) {
    return lean_alloc_sarray(elem_size, size, capacity);
}

size_t lean_shim_sarray_size(b_lean_obj_arg o) {
    return lean_sarray_size(o);
}

uint8_t* lean_shim_sarray_cptr(lean_object* o) {
    return lean_sarray_cptr(o);
}
