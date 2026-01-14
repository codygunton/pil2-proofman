//! Integration test utilities for pil2-proofman.
//!
//! Provides helper functions for pinning tests and FRI validation tests.

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Root directory of the pil2-proofman repository.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Asserts that setup has been run for the given test suite.
///
/// Panics with a helpful message if the proving key doesn't exist.
pub fn require_setup(test_name: &str) -> PathBuf {
    let root = repo_root();
    let proving_key = root
        .join("pil2-components")
        .join("test")
        .join(test_name)
        .join("build")
        .join("provingKey");

    assert!(
        proving_key.exists(),
        "Setup required: run ./setup.sh {} first\nExpected: {}",
        test_name,
        proving_key.display()
    );

    proving_key
}

/// Returns the path to a FRI proof file, asserting it exists.
pub fn require_fri_proof(test_name: &str, air_name: &str) -> PathBuf {
    let root = repo_root();

    // Try fri_vectors_output first, then pinning_test_output
    let locations = [
        root.join("pil2-components")
            .join("test")
            .join(test_name)
            .join("build")
            .join("fri_vectors_output")
            .join("proofs")
            .join(format!("{}.json", air_name)),
        root.join("pil2-components")
            .join("test")
            .join(test_name)
            .join("build")
            .join("pinning_test_output")
            .join("proofs")
            .join(format!("{}.json", air_name)),
    ];

    for path in &locations {
        if path.exists() {
            return path.clone();
        }
    }

    panic!(
        "FRI proof file not found for {} / {}\nRun ./generate-fri-vectors.sh {} first\nTried: {:?}",
        test_name, air_name, test_name, locations
    );
}

/// Computes SHA256 hash of a file and returns it as a hex string.
pub fn sha256_file(path: &Path) -> String {
    let contents = fs::read(path).expect("Failed to read file for checksumming");
    let hash = Sha256::digest(&contents);
    hex::encode(hash)
}

/// Builds the witness library with debug feature for deterministic output.
pub fn build_witness_lib(test_name: &str) {
    let root = repo_root();
    let manifest = root
        .join("pil2-components")
        .join("test")
        .join(test_name)
        .join("rs")
        .join("Cargo.toml");

    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--manifest-path"])
        .arg(&manifest)
        .args(["--features", "debug"]);

    // Add Intel OneAPI library path if it exists
    let intel_lib = "/opt/intel/oneapi/compiler/2025.0/lib";
    if Path::new(intel_lib).exists() {
        let library_path = std::env::var("LIBRARY_PATH").unwrap_or_default();
        let new_path = if library_path.is_empty() {
            intel_lib.to_string()
        } else {
            format!("{}:{}", library_path, intel_lib)
        };
        cmd.env("LIBRARY_PATH", &new_path);
        cmd.env("LD_LIBRARY_PATH", &new_path);
    }

    let status = cmd.status().expect("Failed to run cargo build");

    assert!(
        status.success(),
        "Failed to build witness library for {}",
        test_name
    );
}

/// Builds the C++ FRI pinning test binary.
pub fn build_fri_test() {
    let root = repo_root();
    let tests_dir = root.join("pil2-stark").join("tests");

    let status = Command::new("make")
        .arg("-C")
        .arg(&tests_dir)
        .arg("fri-pinning-test")
        .status()
        .expect("Failed to run make");

    assert!(status.success(), "Failed to build fri-pinning-test");
}

/// Runs the FRI pinning test binary with the given proof file.
pub fn run_fri_test(proof_path: &Path) {
    let root = repo_root();
    let binary = root
        .join("pil2-stark")
        .join("tests")
        .join("build")
        .join("fri-pinning-test");

    let output = Command::new(&binary)
        .arg(format!("--proof-path={}", proof_path.display()))
        .output()
        .expect("Failed to run fri-pinning-test");

    if !output.status.success() {
        eprintln!("=== FRI Test STDOUT ===");
        eprintln!("{}", String::from_utf8_lossy(&output.stdout));
        eprintln!("=== FRI Test STDERR ===");
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        panic!("FRI pinning test failed for {}", proof_path.display());
    }
}

// Re-export hex for convenience
pub use hex;
