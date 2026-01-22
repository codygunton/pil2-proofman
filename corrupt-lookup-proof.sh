#!/bin/bash
FILE="executable-spec/tests/test-data/lookup2-12.proof.bin"
OFFSET=1000

echo "=== Before ==="
xxd -s $OFFSET -l 16 "$FILE"

# Read byte, increment it, write it back
BYTE=$(xxd -s $OFFSET -l 1 -p "$FILE")
NEW_BYTE=$(printf '%02x' $(( (0x$BYTE + 1) % 256 )))
printf "\x$NEW_BYTE" | dd of="$FILE" bs=1 seek=$OFFSET count=1 conv=notrunc 2>/dev/null

echo "=== After ==="
xxd -s $OFFSET -l 16 "$FILE"
