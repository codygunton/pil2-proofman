pil2-proofman is a SNARK library used by the zisk zkvm.

## Tests

### FRI Pinning

Validates FRI output matches expected golden values. Use to detect unintended changes or verify a new FRI implementation produces identical output.

```bash
./test-fri.sh                # validate FRI output matches expected values
./generate-fri-vectors.sh    # regenerate expected values after intentional changes
```

To test a new FRI implementation: capture vectors from original (`generate-fri-vectors.sh`), switch implementations, then run `test-fri.sh`.

### Full System

Validates entire proof generation and verification:

```bash
./test-pinning.sh    # run full prover, check proof checksums
```
