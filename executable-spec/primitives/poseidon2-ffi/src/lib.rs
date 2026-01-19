//! Poseidon2 hash implementation for Goldilocks field.
//!
//! This module implements the Poseidon2 permutation and related hash functions
//! matching the C++ implementation exactly.
//!
//! C++ Reference: pil2-stark/src/goldilocks/src/poseidon2_goldilocks.cpp

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

/// Goldilocks prime: 2^64 - 2^32 + 1
const GOLDILOCKS_PRIME: u64 = 0xFFFFFFFF00000001;

/// Hash output size (capacity)
const CAPACITY: usize = 4;

/// Number of full rounds (split: 4 before, 4 after partial rounds)
const ROUNDS_F: usize = 8;
const HALF_ROUNDS_F: usize = ROUNDS_F / 2;

/// Partial rounds per width
const ROUNDS_P_4: usize = 21;
const ROUNDS_P_8: usize = 22;
const ROUNDS_P_12: usize = 22;
const ROUNDS_P_16: usize = 22;

// ============================================================================
// Goldilocks Field Arithmetic
// ============================================================================

/// Reduce a u128 value modulo the Goldilocks prime
///
/// Algorithm from C++ Goldilocks implementation:
/// x = rh * 2^64 + rl
/// x mod p = rl - rh + rh * 2^32 (mod p)
///         = rl - rhh + rhl * (2^32 - 1) (mod p)
/// where rh = rhh * 2^32 + rhl
#[inline]
fn reduce(x: u128) -> u64 {
    let rl = x as u64;                    // Low 64 bits
    let rh = (x >> 64) as u64;            // High 64 bits
    let rhh = rh >> 32;                   // Upper 32 bits of rh
    let rhl = rh & 0xFFFFFFFF;            // Lower 32 bits of rh

    // aux1 = rl - rhh (with borrow handling)
    let (aux1, borrow) = rl.overflowing_sub(rhh);
    let aux1 = if borrow {
        // Subtract 0xFFFFFFFF (which is -1 mod p when p = 2^64 - 2^32 + 1)
        aux1.wrapping_sub(0xFFFFFFFF)
    } else {
        aux1
    };

    // aux = rhl * (2^32 - 1) = rhl * 0xFFFFFFFF
    // This fits in 64 bits since rhl < 2^32
    let aux = 0xFFFFFFFF_u64.wrapping_mul(rhl);

    // result = aux1 + aux (mod p)
    let (result, carry) = aux1.overflowing_add(aux);
    let result = if carry {
        // Add correction: when overflow occurs, we need to add 2^64 - p = 2^32 - 1 = 0xFFFFFFFF
        result.wrapping_add(0xFFFFFFFF)
    } else {
        result
    };

    // Final reduction if result >= p
    if result >= GOLDILOCKS_PRIME {
        result - GOLDILOCKS_PRIME
    } else {
        result
    }
}

/// Add two field elements
#[inline]
fn add(a: u64, b: u64) -> u64 {
    let (sum, overflow) = a.overflowing_add(b);
    if overflow || sum >= GOLDILOCKS_PRIME {
        sum.wrapping_sub(GOLDILOCKS_PRIME)
    } else {
        sum
    }
}

/// Multiply two field elements
#[inline]
fn mul(a: u64, b: u64) -> u64 {
    reduce((a as u128) * (b as u128))
}

/// Compute x^7 in the Goldilocks field
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

/// Apply the 4x4 matrix multiplication (external layer core)
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

/// Apply external matrix multiplication for any supported width
fn matmul_external(state: &mut [u64]) {
    let width = state.len();

    // Apply matmul_m4 to each 4-element block
    for i in (0..width).step_by(4) {
        let mut block = [state[i], state[i+1], state[i+2], state[i+3]];
        matmul_m4(&mut block);
        state[i] = block[0];
        state[i+1] = block[1];
        state[i+2] = block[2];
        state[i+3] = block[3];
    }

    // For width > 4, add column sums
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

/// Apply pow7 and add constants element-wise
fn pow7add(state: &mut [u64], constants: &[u64]) {
    for i in 0..state.len() {
        let xi = add(state[i], constants[i]);
        state[i] = pow7(xi);
    }
}

// ============================================================================
// Round Constants (from C++ poseidon2_goldilocks_constants.hpp)
// ============================================================================

mod constants;
use constants::*;

// ============================================================================
// Core Poseidon2 Permutation
// ============================================================================

/// Perform the full Poseidon2 permutation
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

    // Initial external matrix multiplication
    matmul_external(&mut state);

    // First half of full rounds
    for r in 0..HALF_ROUNDS_F {
        let rc_offset = r * width;
        pow7add(&mut state, &rc[rc_offset..rc_offset + width]);
        matmul_external(&mut state);
    }

    // Partial rounds
    let partial_rc_start = HALF_ROUNDS_F * width;
    for r in 0..n_partial_rounds {
        // Add round constant only to first element
        state[0] = add(state[0], rc[partial_rc_start + r]);
        // Apply S-box only to first element
        state[0] = pow7(state[0]);

        // Compute sum of all elements
        let mut sum = 0u64;
        for &s in state.iter() {
            sum = add(sum, s);
        }

        // Apply internal matrix: x[i] = x[i] * D[i] + sum
        for i in 0..width {
            state[i] = add(mul(state[i], diag[i]), sum);
        }
    }

    // Second half of full rounds
    let second_half_rc_start = partial_rc_start + n_partial_rounds;
    for r in 0..HALF_ROUNDS_F {
        let rc_offset = second_half_rc_start + r * width;
        pow7add(&mut state, &rc[rc_offset..rc_offset + width]);
        matmul_external(&mut state);
    }

    state
}

// ============================================================================
// Public API (PyO3 bindings)
// ============================================================================

/// Compute the full Poseidon2 permutation.
///
/// Args:
///     input_data: List of field elements (as integers) of length `width`
///     width: Sponge width (4, 8, 12, or 16)
///
/// Returns:
///     List of `width` field elements after the permutation
#[pyfunction]
#[pyo3(signature = (input_data, width=12))]
fn poseidon2_hash(input_data: Vec<u64>, width: usize) -> PyResult<Vec<u64>> {
    if ![4, 8, 12, 16].contains(&width) {
        return Err(PyValueError::new_err(
            format!("width must be 4, 8, 12, or 16, got {}", width)
        ));
    }

    if input_data.len() != width {
        return Err(PyValueError::new_err(
            format!("input_data must have {} elements, got {}", width, input_data.len())
        ));
    }

    Ok(poseidon2_permutation(&input_data, width))
}

/// Hash variable-length input using sponge construction.
///
/// Args:
///     input_data: List of field elements (as integers)
///     width: Sponge width (4, 8, 12, or 16), default 8
///
/// Returns:
///     List of CAPACITY (4) field elements
#[pyfunction]
#[pyo3(signature = (input_data, width=8))]
fn linear_hash(input_data: Vec<u64>, width: usize) -> PyResult<Vec<u64>> {
    if ![4, 8, 12, 16].contains(&width) {
        return Err(PyValueError::new_err(
            format!("width must be 4, 8, 12, or 16, got {}", width)
        ));
    }

    let rate = width - CAPACITY;
    let size = input_data.len();

    // If input fits in capacity, just return padded input
    if size <= CAPACITY {
        let mut output = input_data.clone();
        output.resize(CAPACITY, 0);
        return Ok(output);
    }

    let mut state = vec![0u64; width];
    let mut remaining = size;
    let mut offset = 0;

    while remaining > 0 {
        // Set up capacity portion
        if offset > 0 {
            // Copy previous output (first CAPACITY elements) to capacity position
            for i in 0..CAPACITY {
                state[rate + i] = state[i];
            }
        }

        // Zero-pad the rate portion
        for i in 0..rate {
            state[i] = 0;
        }

        // Copy input chunk
        let n = remaining.min(rate);
        for i in 0..n {
            state[i] = input_data[offset + i];
        }

        // Apply permutation
        state = poseidon2_permutation(&state, width);

        offset += n;
        remaining -= n;
    }

    // Return first CAPACITY elements
    Ok(state[..CAPACITY].to_vec())
}

/// Wrapper that returns only the first CAPACITY elements.
#[pyfunction]
#[pyo3(signature = (input_data, width=12))]
fn hash_seq(input_data: Vec<u64>, width: usize) -> PyResult<Vec<u64>> {
    let result = poseidon2_hash(input_data, width)?;
    Ok(result[..CAPACITY].to_vec())
}

/// Find a proof-of-work nonce.
///
/// Searches for a nonce such that when appended to the challenge and hashed,
/// the first element of the result is less than 2^(64 - pow_bits).
///
/// Args:
///     challenge: List of 3 field elements (width-1 for width=4)
///     pow_bits: Number of leading zero bits required
///
/// Returns:
///     Nonce value that satisfies the PoW requirement
#[pyfunction]
fn grinding(challenge: Vec<u64>, pow_bits: u32) -> PyResult<u64> {
    const WIDTH: usize = 4;

    if challenge.len() != WIDTH - 1 {
        return Err(PyValueError::new_err(
            format!("challenge must have {} elements, got {}", WIDTH - 1, challenge.len())
        ));
    }

    let level = 1u64 << (64 - pow_bits);
    let max_attempts = ((1u64 << pow_bits) as u64) * 512;

    for nonce in 0..max_attempts {
        // Construct state: challenge + nonce
        let state = vec![challenge[0], challenge[1], challenge[2], nonce];

        // Hash
        let result = poseidon2_permutation(&state, WIDTH);

        // Check if first element is below threshold
        if result[0] < level {
            return Ok(nonce);
        }
    }

    Err(PyValueError::new_err("grinding: could not find a valid nonce"))
}

/// Verify a proof-of-work nonce.
///
/// Checks that hash(challenge || nonce)[0] < 2^(64 - pow_bits).
///
/// Args:
///     challenge: List of 3 field elements
///     nonce: Nonce value to verify
///     pow_bits: Number of leading zero bits required
///
/// Returns:
///     True if the nonce is valid, False otherwise
#[pyfunction]
fn verify_grinding(challenge: Vec<u64>, nonce: u64, pow_bits: u32) -> PyResult<bool> {
    const WIDTH: usize = 4;

    if challenge.len() != WIDTH - 1 {
        return Ok(false);
    }

    let level = 1u64 << (64 - pow_bits);

    // Construct state: challenge + nonce
    let state = vec![challenge[0], challenge[1], challenge[2], nonce];

    // Hash
    let result = poseidon2_permutation(&state, WIDTH);

    // Check if first element is below threshold
    Ok(result[0] < level)
}

/// Python module definition
#[pymodule]
fn poseidon2_ffi(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(poseidon2_hash, m)?)?;
    m.add_function(wrap_pyfunction!(linear_hash, m)?)?;
    m.add_function(wrap_pyfunction!(hash_seq, m)?)?;
    m.add_function(wrap_pyfunction!(grinding, m)?)?;
    m.add_function(wrap_pyfunction!(verify_grinding, m)?)?;
    m.add("CAPACITY", CAPACITY)?;
    Ok(())
}
