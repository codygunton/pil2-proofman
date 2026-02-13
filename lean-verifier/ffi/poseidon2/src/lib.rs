//! Poseidon2 hash FFI for Lean verifier over Goldilocks field.
//!
//! Provides the 4 `@[extern]` symbols expected by FFI/Poseidon2.lean:
//!   lean_poseidon2_hash, lean_poseidon2_linear_hash,
//!   lean_poseidon2_hash_seq, lean_poseidon2_verify_grinding
//!
//! Core Poseidon2 logic copied from executable-spec/primitives/poseidon2-ffi/src/lib.rs.
//! C++ Reference: pil2-stark/src/goldilocks/src/poseidon2_goldilocks.cpp


// ============================================================================
// Lean Runtime FFI via C shim
// ============================================================================
//
// Array UInt64 in Lean is a lean_array_object (NOT a scalar array).
// Each element is a boxed UInt64 (lean_ctor containing a uint64_t).
// We use a small C shim (lean_shim.c, compiled by build.rs) that wraps
// Lean's static inline functions for array allocation, element access,
// and UInt64 boxing/unboxing.

/// Opaque Lean object pointer — we never inspect the layout directly.
pub type LeanObject = std::ffi::c_void;

extern "C" {
    fn lean_shim_alloc_array(size: usize, capacity: usize) -> *mut LeanObject;
    fn lean_shim_array_size(a: *const LeanObject) -> usize;
    fn lean_shim_array_uget_uint64(a: *const LeanObject, i: usize) -> u64;
    fn lean_shim_array_set_uint64(a: *mut LeanObject, i: usize, v: u64);
}

// ============================================================================
// Lean array helpers
// ============================================================================

/// Read a Lean `Array UInt64` into a Vec<u64>.
#[inline]
unsafe fn read_lean_u64_array(arr: *const LeanObject) -> Vec<u64> {
    let len = lean_shim_array_size(arr);
    let mut result = Vec::with_capacity(len);
    for i in 0..len {
        result.push(lean_shim_array_uget_uint64(arr, i));
    }
    result
}

/// Create a Lean `Array UInt64` from a slice.
#[inline]
unsafe fn create_lean_u64_array(data: &[u64]) -> *mut LeanObject {
    let len = data.len();
    let arr = lean_shim_alloc_array(len, len);
    for i in 0..len {
        lean_shim_array_set_uint64(arr, i, data[i]);
    }
    arr
}

// ============================================================================
// Goldilocks Field Arithmetic
// ============================================================================

const GOLDILOCKS_PRIME: u64 = 0xFFFFFFFF00000001;
const CAPACITY: usize = 4;
const ROUNDS_F: usize = 8;
const HALF_ROUNDS_F: usize = ROUNDS_F / 2;
const ROUNDS_P_4: usize = 21;
const ROUNDS_P_8: usize = 22;
const ROUNDS_P_12: usize = 22;
const ROUNDS_P_16: usize = 22;

#[inline]
fn reduce(x: u128) -> u64 {
    let rl = x as u64;
    let rh = (x >> 64) as u64;
    let rhh = rh >> 32;
    let rhl = rh & 0xFFFFFFFF;

    let (aux1, borrow) = rl.overflowing_sub(rhh);
    let aux1 = if borrow {
        aux1.wrapping_sub(0xFFFFFFFF)
    } else {
        aux1
    };

    let aux = 0xFFFFFFFF_u64.wrapping_mul(rhl);

    let (result, carry) = aux1.overflowing_add(aux);
    let result = if carry {
        result.wrapping_add(0xFFFFFFFF)
    } else {
        result
    };

    if result >= GOLDILOCKS_PRIME {
        result - GOLDILOCKS_PRIME
    } else {
        result
    }
}

#[inline]
fn add(a: u64, b: u64) -> u64 {
    let (sum, overflow) = a.overflowing_add(b);
    if overflow || sum >= GOLDILOCKS_PRIME {
        sum.wrapping_sub(GOLDILOCKS_PRIME)
    } else {
        sum
    }
}

#[inline]
fn mul(a: u64, b: u64) -> u64 {
    reduce((a as u128) * (b as u128))
}

#[inline]
fn pow7(x: u64) -> u64 {
    let x2 = mul(x, x);
    let x3 = mul(x, x2);
    let x4 = mul(x2, x2);
    mul(x3, x4)
}

// ============================================================================
// Matrix Operations
// ============================================================================

#[inline]
fn matmul_m4(x: &mut [u64; 4]) {
    let t0 = add(x[0], x[1]);
    let t1 = add(x[2], x[3]);
    let t2 = add(add(x[1], x[1]), t1);
    let t3 = add(add(x[3], x[3]), t0);
    let t1_2 = add(t1, t1);
    let t0_2 = add(t0, t0);
    let t4 = add(add(t1_2, t1_2), t3);
    let t5 = add(add(t0_2, t0_2), t2);
    let t6 = add(t3, t5);
    let t7 = add(t2, t4);

    x[0] = t6;
    x[1] = t5;
    x[2] = t7;
    x[3] = t4;
}

fn matmul_external(state: &mut [u64]) {
    let width = state.len();

    for i in (0..width).step_by(4) {
        let mut block = [state[i], state[i+1], state[i+2], state[i+3]];
        matmul_m4(&mut block);
        state[i] = block[0];
        state[i+1] = block[1];
        state[i+2] = block[2];
        state[i+3] = block[3];
    }

    if width > 4 {
        let mut stored = [0u64; 4];
        for i in (0..width).step_by(4) {
            stored[0] = add(stored[0], state[i]);
            stored[1] = add(stored[1], state[i+1]);
            stored[2] = add(stored[2], state[i+2]);
            stored[3] = add(stored[3], state[i+3]);
        }

        for i in 0..width {
            state[i] = add(state[i], stored[i % 4]);
        }
    }
}

fn pow7add(state: &mut [u64], constants: &[u64]) {
    for i in 0..state.len() {
        let xi = add(state[i], constants[i]);
        state[i] = pow7(xi);
    }
}

// ============================================================================
// Round Constants
// ============================================================================

mod constants;
use constants::*;

// ============================================================================
// Core Poseidon2 Permutation
// ============================================================================

fn poseidon2_permutation(input: &[u64], width: usize) -> Vec<u64> {
    let (rc, diag, n_partial_rounds) = match width {
        4 => (&C4[..], &D4[..], ROUNDS_P_4),
        8 => (&C8[..], &D8[..], ROUNDS_P_8),
        12 => (&C12[..], &D12[..], ROUNDS_P_12),
        16 => (&C16[..], &D16[..], ROUNDS_P_16),
        _ => panic!("Unsupported width: {}", width),
    };

    let mut state: Vec<u64> = input.iter()
        .map(|&x| if x >= GOLDILOCKS_PRIME { x % GOLDILOCKS_PRIME } else { x })
        .collect();

    matmul_external(&mut state);

    for r in 0..HALF_ROUNDS_F {
        let rc_offset = r * width;
        pow7add(&mut state, &rc[rc_offset..rc_offset + width]);
        matmul_external(&mut state);
    }

    let partial_rc_start = HALF_ROUNDS_F * width;
    for r in 0..n_partial_rounds {
        state[0] = add(state[0], rc[partial_rc_start + r]);
        state[0] = pow7(state[0]);

        let mut sum = 0u64;
        for &s in state.iter() {
            sum = add(sum, s);
        }

        for i in 0..width {
            state[i] = add(mul(state[i], diag[i]), sum);
        }
    }

    let second_half_rc_start = partial_rc_start + n_partial_rounds;
    for r in 0..HALF_ROUNDS_F {
        let rc_offset = second_half_rc_start + r * width;
        pow7add(&mut state, &rc[rc_offset..rc_offset + width]);
        matmul_external(&mut state);
    }

    state
}

// ============================================================================
// Lean FFI Exports
// ============================================================================

/// Full Poseidon2 permutation.
/// Lean signature: poseidon2Hash (input : @& Array UInt64) (width : UInt64) : Array UInt64
#[no_mangle]
pub unsafe extern "C" fn lean_poseidon2_hash(
    input: *const LeanObject,   // b_lean_obj_arg (borrowed)
    width: u64,
) -> *mut LeanObject {          // lean_obj_res (owned)
    let input_data = read_lean_u64_array(input);
    let w = width as usize;
    let result = poseidon2_permutation(&input_data, w);
    create_lean_u64_array(&result)
}

/// Sponge-based variable-length hash.
/// Lean signature: linearHash (input : @& Array UInt64) (width : UInt64) : Array UInt64
#[no_mangle]
pub unsafe extern "C" fn lean_poseidon2_linear_hash(
    input: *const LeanObject,
    width: u64,
) -> *mut LeanObject {
    let input_data = read_lean_u64_array(input);
    let w = width as usize;
    let rate = w - CAPACITY;
    let size = input_data.len();

    // If input fits in capacity, return padded input
    if size <= CAPACITY {
        let mut output = vec![0u64; CAPACITY];
        output[..size].copy_from_slice(&input_data);
        return create_lean_u64_array(&output);
    }

    let mut state = vec![0u64; w];
    let mut remaining = size;
    let mut offset = 0;

    while remaining > 0 {
        if offset > 0 {
            for i in 0..CAPACITY {
                state[rate + i] = state[i];
            }
        }

        for i in 0..rate {
            state[i] = 0;
        }

        let n = remaining.min(rate);
        for i in 0..n {
            state[i] = input_data[offset + i];
        }

        state = poseidon2_permutation(&state, w);

        offset += n;
        remaining -= n;
    }

    create_lean_u64_array(&state[..CAPACITY])
}

/// Permutation returning only capacity elements.
/// Lean signature: hashSeq (input : @& Array UInt64) (width : UInt64) : Array UInt64
#[no_mangle]
pub unsafe extern "C" fn lean_poseidon2_hash_seq(
    input: *const LeanObject,
    width: u64,
) -> *mut LeanObject {
    let input_data = read_lean_u64_array(input);
    let w = width as usize;
    let result = poseidon2_permutation(&input_data, w);
    create_lean_u64_array(&result[..CAPACITY])
}

/// Verify a proof-of-work nonce.
/// Lean signature: verifyGrinding (challenge : @& Array UInt64) (nonce : UInt64) (powBits : UInt32) : Bool
#[no_mangle]
pub unsafe extern "C" fn lean_poseidon2_verify_grinding(
    challenge: *const LeanObject,
    nonce: u64,
    pow_bits: u32,
) -> u8 {
    let challenge_data = read_lean_u64_array(challenge);
    if challenge_data.len() != 3 {
        return 0;
    }

    let level = 1u64 << (64 - pow_bits);
    let state = vec![challenge_data[0], challenge_data[1], challenge_data[2], nonce];
    let result = poseidon2_permutation(&state, 4);

    if result[0] < level { 1 } else { 0 }
}
