# Zisk E2E Integration — Current Blockers

## Goal

Generate Zisk proof fixtures (like we did for SimpleLeft/Lookup2_12/Permutation1_6) so the Python executable spec can verify real Zisk proofs.

## What We Need

1. **Binary proof files** (`.proof.bin` or JSON) for at least a few Zisk AIRs
2. **Public inputs** (68 values) and **global challenge** (3 values)
3. These must match the current proving key at `/home/cody/zisk/provingKey/`

## What We Have

| Asset | Path | Status |
|-------|------|--------|
| Proving keys (23 AIRs) | `/home/cody/zisk/provingKey/` | OK (24 GB, current) |
| proofman-cli (release) | `/home/cody/pil2-proofman/target/release/proofman-cli` | Builds and runs |
| proofman-cli (debug) | `/home/cody/pil2-proofman/target/debug/proofman-cli` | Built Jan 21 |
| Zisk witness lib | `/home/cody/zisk/target/release/libzisk_witness.so` | Exists, unknown build date |
| Test ELF | `/home/cody/zisk-for-spec/witness-computation/rom/zisk.elf` | 490 KB RISC-V |
| Test input | `/home/cody/zisk-for-spec/witness-computation/rom/input.bin` | 8 bytes |
| Stale JSON proofs | `/home/cody/zisk/tmp/proofs/*.json` | **STALE** — Jan 15, nQueries=128 vs current 230 |
| Stale publics | `/home/cody/zisk/tmp/publics.json` | **STALE** — matches stale proofs, not current PK |

## Blocker 1: Witness Library Segfaults on Load

**Command tried:**
```bash
RUST_LIB="/home/cody/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/lib"
INTEL_LIB="/opt/intel/oneapi/compiler/2025.0/lib"

LD_LIBRARY_PATH="$RUST_LIB:$INTEL_LIB" \
  proofman-cli prove \
    --witness-lib /home/cody/zisk/target/release/libzisk_witness.so \
    --elf /home/cody/zisk-for-spec/witness-computation/rom/zisk.elf \
    --proving-key /home/cody/zisk/provingKey \
    --output-dir /tmp/zisk-proof-test \
    --save-proofs -v
```

**Error:** Segfault in `init_library()` → `ucs_rcache_distribution_get_num_bins()` (UCX/MPI)

Both debug and release proofman-cli crash identically when loading the witness .so. The crash is in UCX (Unified Communication X, part of MPI infrastructure) during library initialization.

**Possible causes:**
- ABI mismatch between proofman-cli and libzisk_witness.so (built at different times?)
- UCX/MPI configuration issue on this system
- Missing MPI environment initialization

**Note:** `gen-custom-commits-fixed` also segfaults the same way (same code path loads the witness lib).

## Blocker 2: Cannot Rebuild Witness Library

**Command tried:**
```bash
cargo build --release -p cargo-zisk  # in /home/cody/zisk-for-spec/
```

**Error:**
```
error: couldn't read `core/src/../../lib-float/c/lib/ziskfloat.elf`: No such file or directory
  --> core/src/elf2rom.rs:17:35
```

The `zisk-core` crate expects `lib-float/c/lib/ziskfloat.elf` but only `libziskfloat.a` exists. The `zisk-witness` crate depends on `zisk-core`, so the entire witness library chain is blocked.

## Blocker 3: Stale JSON Proofs Don't Match Current Proving Key

The 16 JSON proofs in `/home/cody/zisk/tmp/proofs/` were generated Jan 15 with an older starkstruct:
- Proof has 128 queries, current starkinfo expects 230
- Column widths DO match (e.g., cm1=44 for Arith)
- No `nonce` field in JSON proofs (needed for PoW verification)
- No `publics.json` or `global_challenges.json` in that directory

## How SimpleLeft/Lookup/Permutation Fixtures Were Generated

The script `generate-test-vectors.sh` does:
1. Build pil2-stark C++ lib with `CAPTURE_TEST_VECTORS` flag
2. Build `proofman-cli` (Rust, links against pil2-stark)
3. Run `proofman-cli prove --witness-lib <test>.so --proving-key <pk> --save-proofs`
4. Run `tests/create-test-vectors.py` to package JSON + binary proof

For Zisk, the equivalent would be the same pipeline but with `libzisk_witness.so` instead of `libsimple.so`.

## Questions for User

1. **Have you run Zisk proving on this machine recently?** If so, what command did you use and where are the outputs?
2. **Is there a working libzisk_witness.so** that's compatible with the current proofman-cli? (The one at `/home/cody/zisk/target/release/` segfaults)
3. **Is there a way to build ziskfloat.elf** to unblock the witness lib rebuild?
4. **Would it work to use a Docker container** (the `zisk-for-spec/tools/test-env/Dockerfile` exists) to generate proofs in a clean environment?
