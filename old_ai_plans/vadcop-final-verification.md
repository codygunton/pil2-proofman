# VADCOP Final Proof Verification — Implementation Plan

## Executive Summary

**Problem**: The Python executable spec verifies per-AIR STARK proofs but cannot yet verify
the aggregated VADCOP final proof — the outermost proof that binds all per-AIR recursive
proofs into a single cryptographic statement.

**Solution**: Extend the existing verifier to handle VadcopFinal proofs with two targeted
code changes (transcript initialization, proof binary format), plus infrastructure work
to obtain matching setup artifacts and proof fixtures.

**Critical finding from go/no-go investigation**: The `zisk-corruption` provingKey on disk
is from an **older, incompatible protocol version** (arity 3, no powBits/transcriptArity/
lastLevelVerification fields). It CANNOT be used — its per-AIR starkStruct differs from
`zisk-for-spec` on every parameter. The artifacts must come from the GCS 0.15.0 tarball
or a local recursive setup run.

## Go/No-Go: Infrastructure Verification (completed)

### What We Checked

| Source | Status | Why |
|--------|--------|-----|
| `zisk-corruption/provingKey/` | **NO-GO** | Different protocol version. arity=3 vs 4, missing powBits/transcriptArity/lastLevelVerification. Parser crashes: `KeyError: 'powBits'` |
| `zisk-for-spec/provingKey/` | **NO vadcop_final** | Built without `-r` flag. Only per-AIR artifacts |
| GCS `zisk-provingkey-0.15.0.tar.gz` | **Accessible** (2.16 GB, HTTP 200) | Same version tag as our tools. Likely has compatible vadcop_final. **Must download and verify** |
| GCS `zisk-provingkey-pre-0.15.0.tar.gz` | **Accessible** (2.14 GB, HTTP 200) | Pre-release; may or may not match |
| Local recursive setup | **Feasible** | pil2-proofman-js installed, Circom binary present at `pil2-proofman-js/src/setup/circom/circom`. Heavy computation |

### StarkInfo Parser Bug (affects all VadcopFinal versions)

`protocol/stark_info.py:141` does `ss["powBits"]` — hard KeyError before the GL/BN128 branch.
The GL branch (lines 149-152) also uses direct dict access for `merkleTreeArity`,
`transcriptArity`, `merkleTreeCustom`, `lastLevelVerification`.

The zisk-corruption starkinfo is missing `powBits`, `transcriptArity`, `lastLevelVerification`.
The 0.15.0 per-AIR starkinfos DO have all these fields — unknown whether 0.15.0 vadcop_final
does. Parser must be made robust regardless.

### Protocol Version Comparison

| Field | zisk-corruption (old) | zisk-for-spec v0.15.0 |
|-------|----------------------|----------------------|
| merkleTreeArity | 3 | 4 |
| transcriptArity | *missing* | 4 |
| lastLevelVerification | *missing* | 2 |
| powBits | *missing* | 16 |
| nQueries (Main) | 128 | 230 |
| VadcopFinal opening_points | [-1, 0, 1, 3] | unknown (need tarball) |

### Conclusion

**Must download GCS 0.15.0 tarball** and verify the vadcop_final starkinfo before writing
any verification code. If the 0.15.0 vadcop_final starkinfo includes all expected fields,
the parser fix is minimal. If it doesn't, we need more substantial parser changes.

## Goals & Objectives

### Primary Goals
- Verify a genuine VadcopFinal binary proof using the Python `stark_verify()` function
- Follow existing test patterns from `test_zisk_verifier_e2e.py` exactly
- Extend `generate-zisk-test-vectors.sh` to produce VADCOP fixtures

### Secondary Objectives
- Ensure `stark_verify()` API change is backwards-compatible (no regressions)
- Make StarkInfo parser robust to optional fields (prevent future KeyErrors)
- Keep the unit filter in `run-tests.sh` updated to exclude new E2E test

## Solution Overview

### Key Differences: VadcopFinal vs Per-AIR Proofs

| Aspect | Per-AIR (current) | VadcopFinal (new) |
|--------|-------------------|-------------------|
| Transcript seed | `global_challenge` (3 elements) | `verkey` (4) + `publics_hash` (4) + `root1` (4) |
| Binary format | `[airgroupValues, airValues, roots, evals, ...]` | `[n_publics, publics..., airgroupValues(empty), airValues(empty), roots, evals, ...]` |
| Merkle tree arity | 4 (Poseidon16) | TBD from tarball (2 or 3) — code supports both |
| Constraint bytecode | `provingKey/zisk/Zisk/airs/{AIR}/air/{AIR}.bin` | `provingKey/zisk/vadcop_final/vadcop_final.bin` |
| airgroup/airValues | Non-empty for some AIRs | Always empty |
| customCommits | Some AIRs (e.g., Rom) | None |

### Transcript Initialization Difference

For per-AIR proofs within VADCOP, an outer transcript has already absorbed `verkey + publics + root1`
and squeezed out a `global_challenge`. Each per-AIR verifier uses that challenge as its seed.

The VadcopFinal IS the outer layer — there's no higher transcript. It seeds with verkey,
absorbs hashed publics, absorbs root1, then proceeds identically to per-AIR verification.

```
Per-AIR transcript:                  VadcopFinal transcript:
┌─────────────────────────┐          ┌─────────────────────────┐
│ put(global_challenge)   │          │ put(verkey)             │  4 elements
│   (3 elements)          │          │ put(hash(publics))      │  4 elements
│                         │          │ put(root1)              │  4 elements
├─────────────────────────┤          ├─────────────────────────┤
│ derive stage-2 challs   │          │ derive stage-2 challs   │
│ put(root2)              │          │ put(root2)              │
│ derive stage-3 challs   │          │ derive stage-3 challs   │
│ put(root3)              │          │ put(root3)              │
│ derive xi challenges    │          │ derive xi challenges    │
│ put(evals)              │          │ put(evals)              │
│ derive FRI challenges   │          │ derive FRI challenges   │
│ FRI steps...            │          │ FRI steps...            │
└─────────────────────────┘          └─────────────────────────┘
         ↑ identical from here down ↑
```

### Data Flow

```
Proving Key (with recursive setup, -r flag):
  provingKey/zisk/vadcop_final/
    ├── vadcop_final.starkinfo.json  --> AirConfig   --> stark_info
    ├── vadcop_final.verkey.json     --> load_verkey  --> verkey (4 ints)
    └── vadcop_final.bin             --> BYTECODE_AIRS --> constraint eval

Test Fixtures:
  tests/test-data/zisk/
    └── vadcop_final.proof.bin       --> from_vadcop_final_bytes()
                                         --> (STARKProof, publics)

All fed into:
  stark_verify(proof, air_config, verkey, global_challenge=None, publics=publics)
                                              ↑ None triggers VadcopFinal transcript init
```

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. All changes must be backwards-compatible — existing 320+ tests MUST pass unchanged
2. Do NOT write verification code until Task #0 confirms the artifacts parse correctly
3. Run `./run-tests.sh e2e` and `./run-tests.sh zisk` after code changes to verify no regressions
4. Follow existing file naming conventions (hyphens, not underscores)

### Visual Dependency Tree

```
generate-zisk-test-vectors.sh  (Task #5: Extend for VADCOP proof generation)

executable-spec/
├── protocol/
│   ├── stark_info.py      (Task #1: Fix parser for optional starkStruct fields)
│   ├── verifier.py        (Task #2: VadcopFinal transcript init + optional global_challenge)
│   └── proof.py           (Task #3: from_vadcop_final_bytes() parser)
│
├── constraints/
│   └── __init__.py         (Task #4: Discover vadcop_final bytecode)
│
├── tests/
│   └── test_zisk_vadcop_final_e2e.py  (Task #6: New test file)
│
├── run-tests.sh            (Task #7: Add vadcop-final filter)
```

### Execution Plan

#### Task #0: Download GCS Tarball and Verify (BLOCKING — do this first)

This is the go/no-go gate. If it fails, the entire plan is blocked.

- [ ] Download GCS 0.15.0 tarball:
  ```bash
  cd /tmp
  wget https://storage.googleapis.com/zisk-setup/zisk-provingkey-0.15.0.tar.gz
  ```
- [ ] Check if vadcop_final is included:
  ```bash
  tar tzf zisk-provingkey-0.15.0.tar.gz | grep vadcop_final
  ```
- [ ] If present, extract ONLY vadcop_final into the existing provingKey:
  ```bash
  tar xzf zisk-provingkey-0.15.0.tar.gz -C /home/cody/zisk-for-spec/ \
      --include='provingKey/zisk/vadcop_final/*'
  ```
- [ ] Verify the starkinfo has all expected fields:
  ```bash
  cd /home/cody/pil2-proofman/executable-spec
  python3 -c "
  import json
  j = json.load(open('/home/cody/zisk-for-spec/provingKey/zisk/vadcop_final/vadcop_final.starkinfo.json'))
  ss = j['starkStruct']
  for field in ['powBits', 'transcriptArity', 'lastLevelVerification', 'merkleTreeArity', 'merkleTreeCustom', 'hashCommits']:
      print(f'{field}: {ss.get(field, \"MISSING\")}')
  print(f'openingPoints: {j.get(\"openingPoints\", \"MISSING\")}')
  "
  ```
- [ ] Try parsing with the existing StarkInfo parser (may need Task #1 fix first):
  ```bash
  cd /home/cody/pil2-proofman/executable-spec
  uv run python -c "
  from protocol.air_config import AirConfig
  c = AirConfig.from_starkinfo('/home/cody/zisk-for-spec/provingKey/zisk/vadcop_final/vadcop_final.starkinfo.json')
  print('SUCCESS:', c.stark_info.name, c.stark_info.stark_struct.merkle_tree_arity)
  "
  ```

**If the tarball has no vadcop_final**: Try `zisk-provingkey-pre-0.15.0.tar.gz` (2.14 GB).

**If neither tarball works**: Must run recursive setup locally:
```bash
cd /home/cody/zisk-for-spec
node --max-old-space-size=16384 --stack-size=8192 \
    /home/cody/pil2-proofman-js/src/main_setup.js \
    -a ./pil/zisk.pilout -b build \
    -u tmp/fixed \
    -t /home/cody/pil2-proofman/pil2-components/lib/std/pil \
    -r -s state-machines/starkstructs.json
```

**If all options fail**: Plan is blocked. Cannot proceed without vadcop_final setup artifacts.

#### Group A: Parser Robustness (no dependencies)

- [ ] **Task #1**: Make StarkInfo parser robust to optional starkStruct fields
  - File: `executable-spec/protocol/stark_info.py`
  - Change `_parse_stark_struct()` (lines 135-155) to use `.get()` with defaults for ALL fields:
    ```python
    def _parse_stark_struct(self, ss: dict) -> None:
        """Parse StarkStruct from JSON."""
        self.stark_struct.n_bits = ss["nBits"]
        self.stark_struct.n_bits_ext = ss["nBitsExt"]
        self.stark_struct.n_queries = ss["nQueries"]
        self.stark_struct.verification_hash_type = ss["verificationHashType"]
        self.stark_struct.pow_bits = ss.get("powBits", 0)
        self.stark_struct.merkle_tree_arity = ss.get("merkleTreeArity", 16)
        self.stark_struct.transcript_arity = ss.get("transcriptArity", 16)
        self.stark_struct.merkle_tree_custom = ss.get("merkleTreeCustom", False)
        self.stark_struct.last_level_verification = ss.get("lastLevelVerification", 0)
        self.stark_struct.hash_commits = ss.get("hashCommits", False)
        self.stark_struct.fri_fold_steps = [FriFoldStep(domain_bits=s["nBits"]) for s in ss["steps"]]
    ```
    This removes the BN128/GL branching entirely — `.get()` with sane defaults works for both.
    Defaults: `pow_bits=0` (no PoW), `merkle_tree_arity=16`, `transcript_arity=16`,
    `merkle_tree_custom=False`, `last_level_verification=0`, `hash_commits=False`.
  - **Regression safety**: All existing starkinfo JSONs include these fields explicitly, so
    `.get()` returns the same values as direct access. This is a pure robustness improvement.
  - **Verification**: Run `./run-tests.sh e2e` and `./run-tests.sh zisk` — all must pass unchanged.
  - After this fix, re-run the Task #0 parser verification to confirm vadcop_final parses.

#### Group B: Verifier Changes (depends on Task #0 verification, parallel with each other)

- [ ] **Task #2**: Support VadcopFinal transcript initialization in verifier.py
  - File: `executable-spec/protocol/verifier.py`
  - **Change 1** — Make `global_challenge` optional in `stark_verify()` (line 62):
    ```python
    global_challenge: InterleavedFF3 | None = None,  # None for VadcopFinal
    ```
    Backwards-compatible: all existing callers pass it positionally.
  - **Change 2** — Pass extra args to `_reconstruct_transcript()` (line ~85):
    ```python
    challenges = _reconstruct_transcript(proof, stark_info, global_challenge, verkey, publics)
    ```
  - **Change 3** — Modify `_reconstruct_transcript()` signature and initialization (line 382+):
    ```python
    def _reconstruct_transcript(
        proof: STARKProof,
        stark_info: StarkInfo,
        global_challenge: InterleavedFF3 | None,
        verkey: MerkleRoot | None = None,
        publics: FFArray | None = None,
    ) -> InterleavedFF3:
    ```
    Replace the single line `transcript.put(global_challenge[:3].tolist())` with:
    ```python
    if global_challenge is not None:
        # Per-AIR: outer VADCOP transcript already absorbed verkey + publics + root1
        transcript.put(global_challenge[:3].tolist())
    else:
        # VadcopFinal: WE ARE the outer layer
        transcript.put(list(verkey))
        if publics is not None and len(publics) > 0:
            if stark_struct.hash_commits:
                hash_transcript = Transcript(
                    arity=stark_struct.transcript_arity,
                    custom=stark_struct.merkle_tree_custom,
                )
                hash_transcript.put(publics.tolist())
                transcript.put(hash_transcript.get_state(HASH_SIZE))
            else:
                transcript.put(publics.tolist())
        transcript.put(proof.roots[0])  # root1
    ```
    Rest of function unchanged — stage roots, challenge derivation, evals, FRI identical.
  - **Source**: Rust `verifier.rs` lines 249-268 shows this exact flow.
  - **Verification**: Run `./run-tests.sh e2e` and `./run-tests.sh zisk` — all must pass.

- [ ] **Task #3**: Add VadcopFinal binary proof parser
  - File: `executable-spec/protocol/proof.py`
  - Add after `from_bytes_full()`:
    ```python
    def from_vadcop_final_bytes(data: bytes, stark_info: Any) -> tuple["STARKProof", np.ndarray]:
        """Parse a VadcopFinal proof binary with embedded publics header.

        VadcopFinal proofs prepend [n_publics: u64] [publics: n_publics * u64]
        before the standard proof body (ref: recursion.rs:622-627).
        """
        n_publics = struct.unpack('<Q', data[:8])[0]
        header_size = 8 + n_publics * 8
        publics = np.array(
            struct.unpack(f'<{n_publics}Q', data[8:header_size]),
            dtype=np.uint64,
        )
        proof = from_bytes_full(data[header_size:], stark_info)
        return proof, publics
    ```
  - Purely additive. Filename confirmed: `vadcop_final_proof.bin` from Rust source
    (`cli/src/commands/prove.rs:186`, `sdk/src/prover/backend.rs:205`).

- [ ] **Task #4**: Extend constraint bytecode discovery for vadcop_final
  - File: `executable-spec/constraints/__init__.py`
  - Add after `_discover_zisk_airs()`:
    ```python
    def _discover_vadcop_final() -> dict[str, str]:
        """Discover VadcopFinal constraint bytecode from the proving key."""
        vf_dir = ZISK_PROVING_KEY_DIR / "zisk" / "vadcop_final"
        bin_path = vf_dir / "vadcop_final.bin"
        si_path = vf_dir / "vadcop_final.starkinfo.json"
        if not bin_path.exists() or not si_path.exists():
            return {}
        import json
        with open(si_path) as f:
            name = json.load(f).get("name", "vadcop_final")
        return {name: str(bin_path)}
    ```
  - Update BYTECODE_AIRS: `{**_discover_zisk_airs(), **_discover_vadcop_final()}`
  - **Note**: `witness/__init__.py` has a parallel structure but is intentionally NOT updated.
    The verifier never calls witness modules. This is deliberate, not an oversight.
  - **Note**: `ZISK_PROVING_KEY` in conftest.py is always a `Path` (hardcoded, never None),
    so `ZISK_PROVING_KEY_DIR / "zisk" / "vadcop_final"` won't crash on None division.

#### Group C: Test Fixtures (depends on Task #0)

- [ ] **Task #5**: Extend generate-zisk-test-vectors.sh for VADCOP proof generation
  - File: `generate-zisk-test-vectors.sh`
  - Add `--vadcop` flag to argument parser
  - When set, add a new step after step 2:
    - Verify recursive setup exists (`vadcop_final.starkinfo.json` in provingKey)
    - Run `cargo-zisk prove --elf ... --aggregation --output-dir $VADCOP_DIR`
    - Copy `$VADCOP_DIR/vadcop_final_proof.bin` → `test-data/zisk/vadcop_final.proof.bin`
  - Existing per-AIR generation unchanged
  - **Risk**: `cargo-zisk prove -a` may also require `--verify-proofs` to validate the
    proof before saving. Include `-y` flag for inline verification.

#### Group D: Test & Integration (depends on Groups B and C)

- [ ] **Task #6**: Create VADCOP final verifier E2E test
  - File: `executable-spec/tests/test_zisk_vadcop_final_e2e.py` (new file)
  - Module-level `pytestmark` gate: skip if starkinfo or proof fixture missing
  - Single test: load starkinfo + verkey from provingKey, load proof from test-data,
    parse with `from_vadcop_final_bytes()`, verify with `stark_verify(..., global_challenge=None)`
  - Verkey format: flat 4-element JSON array of u64 (confirmed from Main.verkey.json)
  - **Note on `run-tests.sh zisk` filter**: The new test should NOT be included in the
    `zisk` filter since it has different prerequisites (vadcop_final setup vs per-AIR setup).
    It gets its own `vadcop-final` filter.

- [ ] **Task #7**: Update run-tests.sh
  - Add `vadcop-final` case running `test_zisk_vadcop_final_e2e.py`
  - Update `unit` case to add `--ignore=tests/test_zisk_vadcop_final_e2e.py`
  - Update header comment

---

## Risks and Mitigations

### Risk 1 (HIGH): GCS tarball missing vadcop_final or incompatible
The 0.15.0 tarball may not include vadcop_final, or its starkinfo may have a different
format than expected.

**Mitigation**: Task #0 verifies this before any code is written. Fallback: local recursive
setup (pil2-proofman-js is installed, Circom is available).

### Risk 2 (MEDIUM): Merkle arity untested
All current tests use arity 4. The VadcopFinal may use arity 2 or 3 (version-dependent).
Zero test coverage for non-4 arities.

**Mitigation**: The MerkleVerifier sponge_width mapping `{2: 8, 3: 12, 4: 16}` is correct,
and Poseidon2 FFI has round constants for all widths. Consider adding a targeted unit test
for the VadcopFinal's arity before the full E2E test.

### Risk 3 (MEDIUM): Transcript mismatch
The VadcopFinal transcript initialization is reverse-engineered from the Rust verifier.
If the challenges_map doesn't align with the Rust sequence, challenges will mismatch.

**Mitigation**: If verification fails, compare challenge values between Rust and Python
step-by-step. The Rust verifier source is available and the flow is deterministic.

### Risk 4 (LOW): Opening points
The plan assumed [-1, -2, 0, 1] from the committed Rust verifier, but the zisk-corruption
version has [-1, 0, 1, 3]. The actual values depend on which VadcopFinal circuit version
is in the 0.15.0 tarball. Our code handles arbitrary opening points generically.

**Mitigation**: None needed — `_compute_x_div_x_sub` handles any opening points. Just note
that the values can't be predicted until we see the actual starkinfo.

---

## Implementation Workflow

### Required Process
1. **Task #0 first**: Download tarball, verify artifacts, confirm parser works
2. **Task #1 next**: Fix parser (may be needed for Task #0 to succeed)
3. **Tasks #2-4 in parallel**: Verifier changes, proof parser, constraint discovery
4. **Regression check**: `./run-tests.sh e2e` and `./run-tests.sh zisk` (320+ tests)
5. **Task #5**: Generate VADCOP proof fixture
6. **Tasks #6-7**: Test file and run-tests.sh update
7. **Final check**: `./run-tests.sh` (all tests)

### Critical Rules
- NEVER use `pytest.skip()` inside test bodies
- Gate entire modules with `pytestmark = pytest.mark.skipif(...)`
- Missing fixtures when gate passes = error, not skip
- Run full test suite before considering work complete
