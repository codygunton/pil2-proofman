import Lake
open Lake DSL

package «LeanVerifier» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]
  -- Link the Poseidon2 Rust static library into all executables
  moreLinkArgs := #[
    s!"{__dir__}/ffi/poseidon2/target/release/libposeidon2_lean.a"
  ]

-- Core libraries mirroring Python package structure
@[default_target]
lean_lib «Primitives» where
  srcDir := "."

lean_lib «Protocol» where
  srcDir := "."

lean_lib «FFI» where
  srcDir := "."

-- LSpec dependency for testing
require LSpec from git
  "https://github.com/argumentcomputer/LSpec" @ "main"

-- Build Poseidon2 Rust FFI static library
extern_lib «poseidon2_lean» := Job.async do
  let crateDir := __dir__ / "ffi" / "poseidon2"
  let libFile := crateDir / "target" / "release" / nameToStaticLib "poseidon2_lean"
  -- Build the Rust crate
  proc {
    cmd := "cargo"
    args := #["build", "--release"]
    cwd := crateDir
  }
  -- Track the output binary for rebuild detection
  setTrace (← computeTrace libFile)
  return libFile

-- Test executables
lean_exe «test-field» where
  root := `Tests.TestField

lean_exe «test-transcript» where
  root := `Tests.TestTranscript

lean_exe «test-starkinfo» where
  root := `Tests.TestStarkInfo

lean_exe «test-data» where
  root := `Tests.TestData

lean_exe «test-proof» where
  root := `Tests.TestProof

lean_exe «test-merkle» where
  root := `Tests.TestMerkle

lean_exe «test-polynomial» where
  root := `Tests.TestPolynomial

lean_exe «test-fri» where
  root := `Tests.TestFRI

lean_exe «test-verifier» where
  root := `Tests.TestVerifier

lean_exe «test-poseidon2» where
  root := `Tests.TestPoseidon2

lean_exe «test-all» where
  root := `Tests.Main
