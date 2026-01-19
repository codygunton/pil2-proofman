"""Fiat-Shamir transcript using Poseidon2 sponge."""

from typing import List
from poseidon2_ffi import poseidon2_hash
from field import GOLDILOCKS_PRIME

# --- Type Aliases ---

SpongeState = List[int]
Hash = List[int]
Challenge = List[int]

# --- Constants ---

HASH_SIZE = 4


# --- Transcript ---

class Transcript:
    """Fiat-Shamir transcript using Poseidon2 sponge construction."""

    def __init__(self, arity: int = 4, custom: bool = False):
        if arity not in [2, 3, 4]:
            raise ValueError(f"arity must be 2, 3, or 4, got {arity}")

        self.arity = arity
        self.transcript_state_size = HASH_SIZE
        self.transcript_pending_size = HASH_SIZE * (arity - 1)
        self.transcript_out_size = HASH_SIZE * arity
        self.sponge_width = HASH_SIZE * arity

        self.state: SpongeState = [0] * self.transcript_out_size
        self.pending: List[int] = [0] * self.transcript_out_size
        self.out: List[int] = [0] * self.transcript_out_size

        self.pending_cursor = 0
        self.out_cursor = 0

    # --- Core Operations ---

    def put(self, elements: List[int]) -> None:
        """Absorb field elements into the sponge."""
        for elem in elements:
            self._absorb_one(elem)

    def get_field(self) -> Challenge:
        """Squeeze 3 field elements as a cubic extension challenge."""
        return [self._squeeze_one() for _ in range(3)]

    def get_state(self, n_outputs: int = None) -> SpongeState:
        """Get current sponge state (for grinding challenge)."""
        if self.pending_cursor > 0:
            self._apply_permutation()

        if n_outputs is None:
            n_outputs = self.transcript_state_size

        return self.state[:n_outputs]

    def get_permutations(self, n: int, n_bits: int) -> List[int]:
        """Generate n pseudorandom indices, each using n_bits bits."""
        n_fields = ((n * n_bits - 1) // 63) + 1
        fields = [self._squeeze_one() for _ in range(n_fields)]

        result = []
        cur_bit = 0
        cur_field = 0

        for _ in range(n):
            index = 0
            for j in range(n_bits):
                bit = (fields[cur_field] >> cur_bit) & 1
                index |= bit << j
                cur_bit += 1
                if cur_bit == 63:
                    cur_bit = 0
                    cur_field += 1
            result.append(index)

        return result

    # --- Internal ---

    def _absorb_one(self, element: int) -> None:
        """Absorb a single field element."""
        self.pending[self.pending_cursor] = element % GOLDILOCKS_PRIME
        self.pending_cursor += 1
        self.out_cursor = 0

        if self.pending_cursor == self.transcript_pending_size:
            self._apply_permutation()

    def _squeeze_one(self) -> int:
        """Squeeze one field element from the sponge."""
        if self.out_cursor == 0:
            self._apply_permutation()

        # Read in reverse order (C++ compatibility)
        idx = (self.transcript_out_size - self.out_cursor) % self.transcript_out_size
        result = self.out[idx]
        self.out_cursor -= 1

        return result

    def _apply_permutation(self) -> None:
        """Apply Poseidon2 permutation."""
        while self.pending_cursor < self.transcript_pending_size:
            self.pending[self.pending_cursor] = 0
            self.pending_cursor += 1

        perm_input = [0] * self.sponge_width
        for i in range(self.transcript_pending_size):
            perm_input[i] = self.pending[i]
        for i in range(HASH_SIZE):
            perm_input[self.transcript_pending_size + i] = self.state[i]

        self.out = poseidon2_hash(perm_input, self.sponge_width)

        self.out_cursor = self.transcript_out_size
        self.pending = [0] * self.transcript_out_size
        self.pending_cursor = 0
        self.state = list(self.out)

    def set_state(self, state: List[int], out: List[int],
                  out_cursor: int, pending_cursor: int,
                  pending: List[int] = None) -> None:
        """Restore transcript state from captured values.

        Used to replay Fiat-Shamir transcript from a known state,
        enabling deterministic proof generation matching C++ output.

        Args:
            state: Sponge state (16 elements)
            out: Output buffer (16 elements)
            out_cursor: Position in output buffer
            pending_cursor: Position in pending buffer
            pending: Pending buffer contents (optional, defaults to zeros)
        """
        self.state = list(state)
        self.out = list(out)
        self.out_cursor = out_cursor
        self.pending_cursor = pending_cursor
        if pending is not None:
            self.pending = list(pending)
        else:
            self.pending = [0] * self.transcript_out_size
