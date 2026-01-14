//! Proof pinning tests.
//!
//! These tests validate that proof generation produces deterministic output
//! by comparing SHA256 checksums of proof files against golden values.
//!
//! Run with:
//!   cargo test -p pinning proof           # all proof pinning tests
//!   cargo test -p pinning proof_simple    # simple test only
//!   cargo test -p pinning proof_lookup    # lookup test only

use pinning::{build_witness_lib, repo_root, require_setup, sha256_file};
use std::fs;
use std::process::Command;

// ============================================================================
// Golden values - SHA256 checksums of expected proof files
// ============================================================================

/// Simple test expected checksums (proof file name -> SHA256 hex)
const SIMPLE_CHECKSUMS: &[(&str, &str)] = &[
    (
        "SimpleLeft_0.json",
        "67f19b7e8b87ad5138edc0b61c1ab46f11dddb3cc98dce01ad5e6a62766cb62b",
    ),
    (
        "SimpleRight_1.json",
        "03dc94421c31af8614b3885d12a0367fe59ebe5af6da5f783b4281e5a5da0af1",
    ),
    (
        "SpecifiedRanges_4.json",
        "e19d09ac109eccf0d6cfc8f7668b2c7f2717cedee47def0febac4199091c9982",
    ),
    (
        "U16Air_3.json",
        "b1248e9304c2a27ceedeef0a05ee0d687f73f76202f76aacf70f0cc854ccbdec",
    ),
    (
        "U8Air_2.json",
        "d1d80ab182eaedced823bd7df17c8c24cce65c6337ae912f99cd00e48518f815",
    ),
];

/// Simple test expected global challenge
const SIMPLE_GLOBAL_CHALLENGE: &str = "[1461052753056858962, 17277128619110652023, 18440847142611318128]";

/// Lookup test expected checksums
const LOOKUP_CHECKSUMS: &[(&str, &str)] = &[
    (
        "Lookup0_0.json",
        "91a23330035cc576bac2b203a2140fa799633947afc81c39abfce4c410e168a6",
    ),
    (
        "Lookup1_1.json",
        "239719361db9ff50a22726dc7c01d654296cb0e3f31d7049ec6d980096ec6e56",
    ),
    (
        "Lookup2_12_2.json",
        "419ac85c0c97a0deeb1534543bebd1c32e24b6ff7bad47e6fed6cc7f0738dcd0",
    ),
    (
        "Lookup2_13_3.json",
        "4d2e9644f17eef6dde9dc72d5c585f0c4c791434036e01253be452c1897d40f5",
    ),
    (
        "Lookup2_15_4.json",
        "c34fcda32546e4027031d987d484f7eb59df2441b644c6e3cf02f2e4da5875a9",
    ),
    (
        "Lookup3_5.json",
        "69f5ebd4dad26be9297954aa8b96949666c5f1b5a8fee5dc035221d0b595767d",
    ),
];

/// Lookup test expected global challenge
const LOOKUP_GLOBAL_CHALLENGE: &str = "[8703044403523920118, 18374967019439620840, 17962188255440010291]";

// ============================================================================
// Test implementation
// ============================================================================

/// Runs a pinning test for the given test suite.
fn run_pinning_test(
    test_name: &str,
    lib_name: &str,
    expected_checksums: &[(&str, &str)],
    expected_challenge: &str,
) {
    let root = repo_root();
    let proving_key = require_setup(test_name);
    let build_dir = proving_key.parent().unwrap();
    let output_dir = build_dir.join("pinning_test_output");

    // Build witness library with debug feature for deterministic output
    build_witness_lib(test_name);

    // Clean output directory
    if output_dir.exists() {
        fs::remove_dir_all(&output_dir).expect("Failed to clean output directory");
    }
    fs::create_dir_all(&output_dir).expect("Failed to create output directory");

    // Run proof generation
    let witness_lib = root.join("target").join("debug").join(lib_name);
    let mut cmd = Command::new("cargo");
    cmd.args(["run", "--manifest-path"])
        .arg(root.join("Cargo.toml"))
        .args(["--bin", "proofman-cli", "prove"])
        .arg("--witness-lib")
        .arg(&witness_lib)
        .arg("--proving-key")
        .arg(&proving_key)
        .arg("--output-dir")
        .arg(&output_dir)
        .arg("--save-proofs")
        .arg("--verify-proofs");

    // Add Intel OneAPI library path if it exists
    let intel_lib = "/opt/intel/oneapi/compiler/2025.0/lib";
    if std::path::Path::new(intel_lib).exists() {
        let library_path = std::env::var("LIBRARY_PATH").unwrap_or_default();
        let new_path = if library_path.is_empty() {
            intel_lib.to_string()
        } else {
            format!("{}:{}", library_path, intel_lib)
        };
        cmd.env("LIBRARY_PATH", &new_path);
        cmd.env("LD_LIBRARY_PATH", &new_path);
    }

    let output = cmd.output().expect("Failed to run proofman-cli prove");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        eprintln!("=== proofman-cli STDOUT ===\n{}", stdout);
        eprintln!("=== proofman-cli STDERR ===\n{}", stderr);
        panic!("Proof generation failed for {}", test_name);
    }

    // Extract and validate global challenge from output
    let challenge_line = stderr
        .lines()
        .chain(stdout.lines())
        .find(|line| line.contains("Global challenge:"))
        .expect("Global challenge not found in output");

    let actual_challenge = challenge_line
        .split("Global challenge:")
        .nth(1)
        .map(|s| s.trim())
        .expect("Failed to parse global challenge");

    assert_eq!(
        actual_challenge, expected_challenge,
        "Global challenge mismatch for {}\nExpected: {}\nActual: {}",
        test_name, expected_challenge, actual_challenge
    );
    println!("Global challenge: OK");

    // Validate proof checksums
    let proofs_dir = output_dir.join("proofs");
    let mut failures = Vec::new();

    for (proof_file, expected_hash) in expected_checksums {
        let proof_path = proofs_dir.join(proof_file);

        if !proof_path.exists() {
            failures.push(format!("{}: NOT FOUND", proof_file));
            continue;
        }

        let actual_hash = sha256_file(&proof_path);

        if actual_hash == *expected_hash {
            println!("  {}: OK", proof_file);
        } else {
            failures.push(format!(
                "{}: MISMATCH\n    Expected: {}\n    Actual:   {}",
                proof_file, expected_hash, actual_hash
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "Proof checksum failures for {}:\n{}",
            test_name,
            failures.join("\n")
        );
    }

    // Clean up on success
    fs::remove_dir_all(&output_dir).ok();
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn pinning_simple() {
    run_pinning_test(
        "simple",
        "libsimple.so",
        SIMPLE_CHECKSUMS,
        SIMPLE_GLOBAL_CHALLENGE,
    );
}

#[test]
fn pinning_lookup() {
    run_pinning_test(
        "lookup",
        "liblookup.so",
        LOOKUP_CHECKSUMS,
        LOOKUP_GLOBAL_CHALLENGE,
    );
}
