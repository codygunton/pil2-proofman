use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let lean_sysroot = find_lean_sysroot();
    let lean_include = lean_sysroot.join("include");

    if !lean_include.join("lean").join("lean.h").exists() {
        panic!(
            "lean.h not found at {:?}. Set LEAN_SYSROOT or ensure elan is installed.",
            lean_include
        );
    }

    // Compile the C shim that wraps Lean's static inline sarray functions
    cc::Build::new()
        .file("src/lean_shim.c")
        .include(&lean_include)
        .opt_level(3)
        .compile("lean_shim");

    println!("cargo:rerun-if-changed=src/lean_shim.c");
    println!("cargo:rerun-if-changed=build.rs");
}

fn find_lean_sysroot() -> PathBuf {
    // Check LEAN_SYSROOT env var first
    if let Ok(sysroot) = env::var("LEAN_SYSROOT") {
        return PathBuf::from(sysroot);
    }

    // Try elan's lean --print-prefix
    let home = env::var("HOME").expect("HOME not set");
    let lean_bin = PathBuf::from(&home).join(".elan/bin/lean");
    if lean_bin.exists() {
        if let Ok(output) = Command::new(&lean_bin).arg("--print-prefix").output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                return PathBuf::from(path);
            }
        }
    }

    // Fall back to searching ~/.elan/toolchains/
    let toolchains = PathBuf::from(&home).join(".elan/toolchains");
    if let Ok(entries) = std::fs::read_dir(&toolchains) {
        for entry in entries.flatten() {
            let include = entry.path().join("include/lean/lean.h");
            if include.exists() {
                return entry.path();
            }
        }
    }

    panic!("Could not find Lean sysroot. Set LEAN_SYSROOT env var.");
}
