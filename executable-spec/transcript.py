"""
Fiat-Shamir transcript implementation using Poseidon2 sponge.

This module implements challenge generation for non-interactive proofs.

C++ Reference: pil2-stark/src/starkpil/transcript/transcriptGL.hpp
"""
# QUESTION: this class is a bit more complex than I'd expect. Is that in reflection of complexity in the transcript class in the C++? Is it all in use? ANS: Yes, this mirrors TranscriptGL in transcriptGL.hpp almost exactly. The complexity comes from the sponge construction: separate state/pending/out buffers, cursors for tracking position, and the specific absorption/squeeze pattern. All of it is in use - the pending buffer accumulates inputs until full, then _update_state absorbs into the sponge. The out buffer caches squeezed challenges. This matches how C++ manages memory for the sponge. Can simplify at cost of C++ divergence? N - sponge construction is cryptographically required, not a C++ design choice.
from typing import List
from poseidon2_ffi import poseidon2_hash, CAPACITY
from field import GOLDILOCKS_PRIME


# Hash size (capacity of sponge)
HASH_SIZE = 4


class Transcript:
    """
    Fiat-Shamir transcript using Poseidon2 sponge construction.

    The transcript absorbs field elements and produces random challenges
    in a deterministic, pseudorandom manner.

    Attributes:
        arity: Determines sponge width (2, 3, or 4 → 8, 12, 16)
        state: Current sponge state (HASH_SIZE elements)
        pending: Accumulator for absorbing elements
        out: Output buffer from hash
    """

    def __init__(self, arity: int = 4, custom: bool = False):
        """
        Initialize transcript.

        Args:
            arity: Sponge arity (2, 3, or 4)
            custom: Custom flag (unused, for API compatibility)

        C++ Reference: TranscriptGL constructor
        """
        # QUESTION: do we really care about this check? Why? ANS: Yes - arity determines sponge width (8, 12, or 16), which must match Poseidon2 round constants. The C++ only has constants for these widths. Using an unsupported arity would produce incorrect hashes or crash. The C++ doesn't explicitly check (it's implicit in template instantiation), but we add it here for clearer error messages. Can simplify at cost of C++ divergence? N - constraint is from Poseidon2 spec, not C++ design.
        if arity not in [2, 3, 4]:
            raise ValueError(f"arity must be 2, 3, or 4, got {arity}")

        self.arity = arity

        # Buffer sizes based on arity
        self.transcript_state_size = HASH_SIZE  # 4
        self.transcript_pending_size = HASH_SIZE * (arity - 1)  # rate
        self.transcript_out_size = HASH_SIZE * arity  # full sponge width

        # Sponge width for Poseidon2
        self.sponge_width = HASH_SIZE * arity

        # Initialize buffers
        self.state = [0] * self.transcript_out_size
        self.pending = [0] * self.transcript_out_size
        self.out = [0] * self.transcript_out_size

        # Cursors
        self.pending_cursor = 0
        self.out_cursor = 0

    def put(self, input_data: List[int]) -> None:
        """
        Add field elements to the transcript.

        Args:
            input_data: List of field elements to absorb

        C++ Reference: TranscriptGL::put
        """
        for elem in input_data:
            self._add1(elem)

    def _add1(self, input_elem: int) -> None:
        """
        Add a single field element to pending buffer.

        C++ Reference: TranscriptGL::_add1
        """
        # QUESTION: does this function exist in the C++? ANS: Yes, TranscriptGL::_add1 in transcriptGL.hpp. It's a private helper that adds one element to pending and triggers _updateState when the buffer fills. Our implementation matches it exactly. Can simplify at cost of C++ divergence? Y - could inline into put() or use a simpler append-to-list pattern, but would diverge from C++ structure.
        self.pending[self.pending_cursor] = input_elem % GOLDILOCKS_PRIME
        self.pending_cursor += 1
        self.out_cursor = 0  # Invalidate cached output

        # If pending buffer is full, update state
        if self.pending_cursor == self.transcript_pending_size:
            self._update_state()

    def _update_state(self) -> None:
        """
        Execute Poseidon2 sponge absorption.

        C++ Reference: TranscriptGL::_updateState
        """
        # Pad remaining pending slots with zeros
        while self.pending_cursor < self.transcript_pending_size:
            self.pending[self.pending_cursor] = 0
            self.pending_cursor += 1

        # Assemble input: pending (rate) + state (capacity)
        inputs = [0] * self.sponge_width
        for i in range(self.transcript_pending_size):
            inputs[i] = self.pending[i]
        for i in range(HASH_SIZE):
            inputs[self.transcript_pending_size + i] = self.state[i]

        # Apply Poseidon2 permutation
        self.out = poseidon2_hash(inputs, self.sponge_width)

        # Update state and cursors
        self.out_cursor = self.transcript_out_size
        self.pending = [0] * self.transcript_out_size
        self.pending_cursor = 0

        # Copy output to state for next round
        self.state = list(self.out)

    def _get_fields1(self) -> int:
        """
        Squeeze one field element from sponge.

        C++ Reference: TranscriptGL::getFields1
        """
        if self.out_cursor == 0:
            self._update_state()

        # Read output buffer in reverse order
        idx = (self.transcript_out_size - self.out_cursor) % self.transcript_out_size
        result = self.out[idx]
        self.out_cursor -= 1

        return result

    def get_field(self) -> List[int]:
        """
        Get 3 field elements as a cubic extension challenge.

        Returns:
            List of 3 field elements

        C++ Reference: TranscriptGL::getField
        """
        result = []
        for _ in range(3):
            result.append(self._get_fields1())
        return result

    def get_state(self, n_outputs: int = None) -> List[int]:
        """
        Get current sponge state.

        Args:
            n_outputs: Number of elements to return (default: HASH_SIZE)

        Returns:
            List of state elements

        C++ Reference: TranscriptGL::getState
        """
        # Flush pending if needed
        if self.pending_cursor > 0:
            self._update_state()

        if n_outputs is None:
            n_outputs = self.transcript_state_size

        return self.state[:n_outputs]

    def set_state(
        self,
        state: List[int],
        out: List[int],
        out_cursor: int,
        pending_cursor: int = 0
    ) -> None:
        """
        Set transcript internal state (for testing with captured C++ state).

        Args:
            state: Sponge state (16 elements for arity=4)
            out: Output buffer (16 elements for arity=4)
            out_cursor: Current output cursor position
            pending_cursor: Current pending cursor position (usually 0)

        This allows initializing the transcript to match C++ state at FRI start.
        """
        if len(state) != self.transcript_out_size:
            raise ValueError(f"state must have {self.transcript_out_size} elements")
        if len(out) != self.transcript_out_size:
            raise ValueError(f"out must have {self.transcript_out_size} elements")

        self.state = list(state)
        self.out = list(out)
        self.out_cursor = out_cursor
        self.pending_cursor = pending_cursor
        self.pending = [0] * self.transcript_out_size

    def get_permutations(self, n: int, n_bits: int) -> List[int]:
        """
        Generate n permutation values, each using n_bits bits.

        This is used to derive query indices in FRI.

        Args:
            n: Number of permutation values to generate
            n_bits: Number of bits per value

        Returns:
            List of n values, each in range [0, 2^n_bits)

        C++ Reference: TranscriptGL::getPermutations
        """
        # Calculate number of field elements needed
        # Use 63 bits per field (leaving 1 bit margin for safety)
        n_fields = ((n * n_bits - 1) // 63) + 1

        # Extract random field elements
        fields = []
        for _ in range(n_fields):
            fields.append(self._get_fields1())

        # Extract bits to form permutation values
        result = []
        cur_bit = 0
        cur_field = 0

        for _ in range(n):
            a = 0
            for j in range(n_bits):
                # Get bit from current field
                bit = (fields[cur_field] >> cur_bit) & 1
                a += bit << j

                cur_bit += 1
                if cur_bit == 63:
                    cur_bit = 0
                    cur_field += 1

            result.append(a)

        return result
