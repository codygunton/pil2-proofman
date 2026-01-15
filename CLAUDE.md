pil2-proofman is a SNARK library used by the zisk zkvm.

## Conventions
Filenames use - (hyphen) for separators, not _ (underscore) whenever possible.

## Tests

### Setup

Before running tests, set up the proving keys:

```bash
./setup.sh              # set up all tests (simple + lookup + permutation)
./setup.sh simple       # set up only simple test
./setup.sh lookup       # set up only lookup test
./setup.sh permutation  # set up only permutation test
```

Requires `pil2-compiler` and `pil2-proofman-js` as sibling directories.

### Python Executable Spec

The Python FRI implementation in `executable-spec/` cross-validates against C++ golden values.

Supported AIRs:
- **SimpleLeft**: 8 rows, basic constraints (no FRI folding)
- **Lookup2_12**: 4096 rows, complex lookup operations (has FRI folding)
- **Permutation1_6**: 64 rows, permutation constraints (has FRI folding)

**Generate test vectors** (requires setup.sh first):
```bash
./generate-test-vectors.sh              # generate all test vectors
./generate-test-vectors.sh simple       # generate SimpleLeft only
./generate-test-vectors.sh lookup       # generate Lookup2_12 only
./generate-test-vectors.sh permutation  # generate Permutation1_6 only
```

**Run Python tests**:
```bash
cd executable-spec && uv run python -m pytest test_fri.py -v
```

Test vectors are stored in `executable-spec/test-data/*.json` and are gitignored.

### C++ FRI Pinning Vectors

To regenerate C++ FRI pinning vectors (for `pil2-stark/tests/fri-pinning/fri_pinning_vectors.hpp`):

```bash
./generate-fri-vectors.sh          # regenerate all vectors (default)
./generate-fri-vectors.sh simple   # regenerate SimpleLeft only
./generate-fri-vectors.sh lookup   # regenerate Lookup2_12 only
```
