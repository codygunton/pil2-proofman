"""Clean data structures for prover and verifier."""

from dataclasses import dataclass, field

from primitives.field import FF, FF3

# Type aliases
FF3Poly = FF3  # Array of extension field elements
FFPoly = FF    # Array of base field elements


@dataclass
class ProverData:
    """All polynomial data for proving."""
    columns: dict[tuple[str, int], FF3Poly] = field(default_factory=dict)
    constants: dict[str, FFPoly] = field(default_factory=dict)
    challenges: dict[str, FF3] = field(default_factory=dict)
    public_inputs: dict[str, FF] = field(default_factory=dict)

    def update_columns(self, new_columns: dict[tuple[str, int], FF3Poly]) -> None:
        """Add new columns (e.g., intermediates from witness generation)."""
        self.columns.update(new_columns)


@dataclass
class VerifierData:
    """All evaluation data for verification."""
    evals: dict[tuple[str, int, int], FF3] = field(default_factory=dict)  # (name, index, offset) -> value
    challenges: dict[str, FF3] = field(default_factory=dict)
    public_inputs: dict[str, FF] = field(default_factory=dict)
