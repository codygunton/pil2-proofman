pil2-proofman is a SNARK library used by the zisk zkvm.

## Convevntions
Filenames use - (hyphen) for seperators, not _ (underscore) whenever possible.

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

### FRI Pinning

Validates FRI output matches expected golden values. Use to detect unintended changes or verify a new FRI implementation produces identical output.

Supported AIRs:
- **SimpleLeft**: 8 rows, basic permutation/lookup constraints
- **Lookup2_12**: 4096 rows, complex lookup operations (512x larger)
- **Permutation1_6**: 64 rows, permutation constraints

```bash
./test-fri.sh                # validate all AIRs (default)
./test-fri.sh simple         # validate SimpleLeft only
./test-fri.sh lookup         # validate Lookup2_12 only

./generate-fri-vectors.sh          # regenerate all vectors (default)
./generate-fri-vectors.sh simple   # regenerate SimpleLeft only
./generate-fri-vectors.sh lookup   # regenerate Lookup2_12 only
```

To test a new FRI implementation: capture vectors from original (`generate-fri-vectors.sh`), switch implementations, then run `test-fri.sh`.

### Python Executable Spec

Test vectors for the Python FRI implementation in `executable-spec/` must be generated before running tests:

```bash
./generate-test-vectors.sh              # generate all test vectors
./generate-test-vectors.sh simple       # generate SimpleLeft only
./generate-test-vectors.sh lookup       # generate Lookup2_12 only
./generate-test-vectors.sh permutation  # generate Permutation1_6 only

# Run Python tests
cd executable-spec && uv run python -m pytest test_fri.py -v
```

Test vectors are stored in `executable-spec/test-data/*.json` and are gitignored.

### Full System

Validates entire proof generation and verification:

```bash
./test-pinning.sh           # test all (default)
./test-pinning.sh simple    # test simple only
./test-pinning.sh lookup    # test lookup only
```
