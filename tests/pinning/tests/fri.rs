//! FRI pinning tests.
//!
//! These tests validate that FRI output matches expected golden values by
//! invoking the C++ fri-pinning-test binary.
//!
//! Run with:
//!   cargo test -p pinning fri           # all FRI tests
//!   cargo test -p pinning fri_simple    # simple test only
//!   cargo test -p pinning fri_lookup    # lookup test only

use pinning::{build_fri_test, require_fri_proof, run_fri_test};

#[test]
fn fri_simple() {
    let proof_path = require_fri_proof("simple", "SimpleLeft_0");
    build_fri_test();
    run_fri_test(&proof_path);
}

#[test]
fn fri_lookup() {
    let proof_path = require_fri_proof("lookup", "Lookup2_12_2");
    build_fri_test();
    run_fri_test(&proof_path);
}
