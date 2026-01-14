//! Python executable spec tests.
//!
//! These tests validate that the Python FRI implementation produces
//! byte-identical outputs to the C++ implementation.
//!
//! Run with:
//!   cargo test -p pinning spec

use pinning::repo_root;
use std::process::Command;

#[test]
fn spec() {
    let root = repo_root();
    let spec_dir = root.join("executable-spec");

    // Build Poseidon2 FFI if needed
    let ffi_check = Command::new("python")
        .args(["-c", "import poseidon2_ffi"])
        .current_dir(&spec_dir)
        .output()
        .expect("Failed to check poseidon2_ffi");

    if !ffi_check.status.success() {
        println!("Building Poseidon2 FFI...");
        let build = Command::new("maturin")
            .args(["develop", "--quiet"])
            .current_dir(spec_dir.join("poseidon2-ffi"))
            .status()
            .expect("Failed to build poseidon2_ffi");

        assert!(build.success(), "Failed to build poseidon2_ffi");
    }

    // Run pytest on all test files, inheriting stdout/stderr for live output
    let status = Command::new("python")
        .args(["-m", "pytest", "test_pinning.py", "test_prove_e2e.py", "-v"])
        .current_dir(&spec_dir)
        .status()
        .expect("Failed to run pytest");

    assert!(status.success(), "Python spec tests failed");
}
