# Why the E2E Tests Are Meaningful

## Three independent checks, not one circular one

### 1. Byte-identical comparison against C++ prover output

`TestCppBinaryEquivalence.test_full_binary_proof_match` reads `.proof.bin` files written
by the C++ prover from disk and compares every byte:

```python
python_proof_bytes = to_bytes_full_from_dict(proof_dict, air_config.stark_info)

bin_path = TEST_DATA_DIR / config['test_vector'].replace('.json', '.proof.bin')
with open(bin_path, 'rb') as f:
    cpp_proof_bytes = f.read()

assert python_proof_bytes == cpp_proof_bytes
```

The C++ binary was generated once by a completely independent codebase. Python cannot
pass this test by being self-consistent — it has to match a fixed external ground truth
at every single byte.

`test_global_challenge_matches_cpp` independently checks that the Python multi-AIR
challenge derivation matches a value the C++ prover stored in the test vector JSON:

```python
result = prove_simple_pilout_stage1(air_stage1)
cpp_global_challenge = simple_vectors['inputs']['global_challenge']
assert list(result.global_challenge) == list(cpp_global_challenge)
```

### 2. Python verifier reads C++ proofs with no Python prover involved

`TestVerifierE2E.test_verify_valid_proof` loads `.proof.bin` directly and runs only the
verifier — `gen_proof()` is never called:

```python
with open(bin_path, 'rb') as f:
    proof_bytes = f.read()
proof = from_bytes_full(proof_bytes, stark_info)

result = stark_verify(proof=proof, air_config=air_config, verkey=verkey,
                      global_challenge=global_challenge, publics=public_inputs)
assert result is True
```

`test_verify_corrupted_root_fails` proves the verifier is not trivially returning True:

```python
proof.roots[0] = [0, 0, 0, 0]
result = stark_verify(...)
assert result is False
```

### 3. Zisk AIR tests — Python prover has never touched these

The 12 Zisk per-AIR tests are the purest non-circularity: the Python prover has no
Zisk witness modules and has never produced a Zisk proof. The proofs come from the GPU
prover in a completely separate codebase (`zisk-for-spec`), and the Python verifier
either accepts or rejects them:

```python
# test_zisk_main_verifier.py
proof = load_binary_proof("Main_0", air_config.stark_info)  # GPU-generated
result = stark_verify(proof=proof, air_config=air_config,
                      verkey=verkey, global_challenge=GLOBAL_CHALLENGE, ...)
assert result is True
```

## `TestStarkE2EComplete` is not meaningfully circular

This class runs Python prove → serialize/deserialize → Python verify, which looks
circular. But the verifier's only prover-derived input is `global_challenge`, used
solely to seed the Fiat-Shamir transcript:

```python
if global_challenge is not None:
    transcript.put(global_challenge[:3].tolist())
```

Everything after that is derived independently: the verifier absorbs the committed
Merkle roots from the proof to re-derive β/γ/query-point challenges, opens the Merkle
trees at independently-derived query indices, checks polynomial evaluations at those
points, and verifies the FRI proof. Passing `global_challenge` from prover to verifier
is how VADCOP works — the verifier always needs it as the transcript seed. The
subsequent checking is real.

## Which tests cover which AIRs

| Test file | AIRs covered | How |
|-----------|-------------|-----|
| `test_stark_e2e.py` | SimpleLeft, SimpleRight, U8Air, U16Air, SpecifiedRanges, Lookup2_12, Permutation1_6 | Python prover → Python verifier; byte-comparison vs C++ `.proof.bin` |
| `test_verifier_e2e.py` | SimpleLeft, U8Air, U16Air, SpecifiedRanges, Lookup2_12, Permutation1_6 | C++ `.proof.bin` → Python verifier only |
| `test_zisk_verifier_e2e.py` + `test_zisk_*_verifier.py` | 12 Zisk AIRs (Main, Rom, Mem, BinaryAdd, Binary, …) | GPU-generated `.proof.bin` from Fibonacci(10) → Python verifier only |
