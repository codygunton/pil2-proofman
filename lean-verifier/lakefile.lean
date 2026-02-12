import Lake
open Lake DSL

package «LeanVerifier» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
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

lean_exe «test-all» where
  root := `Tests.Main
