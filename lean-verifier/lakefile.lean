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

lean_exe «test-all» where
  root := `Tests.Main
