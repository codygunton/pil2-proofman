pil2-proofman is a SNARK library used by the zisk zkvm.

## Tests

### Setup

Before running tests, set up the proving keys:

```bash
./setup.sh              # set up all tests (simple + lookup)
./setup.sh simple       # set up only simple test
./setup.sh lookup       # set up only lookup test
```

Requires `pil2-compiler` and `pil2-proofman-js` as sibling directories.

### FRI Pinning

Validates FRI output matches expected golden values. Use to detect unintended changes or verify a new FRI implementation produces identical output.

Supported AIRs:
- **SimpleLeft**: 8 rows, basic permutation/lookup constraints
- **Lookup2_12**: 4096 rows, complex lookup operations (512x larger)

```bash
./test-fri.sh                # validate all AIRs (default)
./test-fri.sh simple         # validate SimpleLeft only
./test-fri.sh lookup         # validate Lookup2_12 only

./generate-fri-vectors.sh          # regenerate all vectors (default)
./generate-fri-vectors.sh simple   # regenerate SimpleLeft only
./generate-fri-vectors.sh lookup   # regenerate Lookup2_12 only
```

To test a new FRI implementation: capture vectors from original (`generate-fri-vectors.sh`), switch implementations, then run `test-fri.sh`.

### Full System

Validates entire proof generation and verification:

```bash
./test-pinning.sh           # test all (default)
./test-pinning.sh simple    # test simple only
./test-pinning.sh lookup    # test lookup only
```
