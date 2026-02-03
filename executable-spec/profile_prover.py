#!/usr/bin/env python3
"""Profile the prover to identify performance bottlenecks.

Run with: uv run python profile_prover.py
"""

import time
from functools import wraps
from typing import Dict, List
import numpy as np

# Global timing storage
TIMINGS: Dict[str, List[float]] = {}

def timed(name: str):
    """Decorator to time function execution."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            result = func(*args, **kwargs)
            elapsed = time.perf_counter() - start
            if name not in TIMINGS:
                TIMINGS[name] = []
            TIMINGS[name].append(elapsed)
            return result
        return wrapper
    return decorator


def patch_prover():
    """Patch prover functions with timing instrumentation."""
    import protocol.prover as prover_module
    import protocol.stages as stages_module
    import protocol.expression_evaluator as expr_module
    import protocol.pcs as pcs_module
    import primitives.merkle_tree as merkle_module
    import primitives.ntt as ntt_module

    # Patch NTT operations
    original_ntt = ntt_module.NTT.ntt
    original_intt = ntt_module.NTT.intt
    original_extend_pol = ntt_module.NTT.extend_pol

    @timed("NTT.ntt")
    def timed_ntt(self, *args, **kwargs):
        return original_ntt(self, *args, **kwargs)

    @timed("NTT.intt")
    def timed_intt(self, *args, **kwargs):
        return original_intt(self, *args, **kwargs)

    @timed("NTT.extend_pol")
    def timed_extend_pol(self, *args, **kwargs):
        return original_extend_pol(self, *args, **kwargs)

    ntt_module.NTT.ntt = timed_ntt
    ntt_module.NTT.intt = timed_intt
    ntt_module.NTT.extend_pol = timed_extend_pol

    # Patch Starks methods
    original_commitStage = stages_module.Starks.commitStage
    original_calculateImPolsExpressions = stages_module.Starks.calculateImPolsExpressions
    original_calculateQuotientPolynomial = stages_module.Starks.calculateQuotientPolynomial
    original_calculateFRIPolynomial = stages_module.Starks.calculateFRIPolynomial
    original_computeLEv = stages_module.Starks.computeLEv
    original_computeEvals = stages_module.Starks.computeEvals
    original_evmap = stages_module.Starks.evmap

    @timed("Starks.commitStage")
    def timed_commitStage(self, *args, **kwargs):
        return original_commitStage(self, *args, **kwargs)

    @timed("Starks.calculateImPolsExpressions")
    def timed_calculateImPolsExpressions(self, *args, **kwargs):
        return original_calculateImPolsExpressions(self, *args, **kwargs)

    @timed("Starks.calculateQuotientPolynomial")
    def timed_calculateQuotientPolynomial(self, *args, **kwargs):
        return original_calculateQuotientPolynomial(self, *args, **kwargs)

    @timed("Starks.calculateFRIPolynomial")
    def timed_calculateFRIPolynomial(self, *args, **kwargs):
        return original_calculateFRIPolynomial(self, *args, **kwargs)

    @timed("Starks.computeLEv")
    def timed_computeLEv(self, *args, **kwargs):
        return original_computeLEv(self, *args, **kwargs)

    @timed("Starks.computeEvals")
    def timed_computeEvals(self, *args, **kwargs):
        return original_computeEvals(self, *args, **kwargs)

    @timed("Starks.evmap")
    def timed_evmap(self, *args, **kwargs):
        return original_evmap(self, *args, **kwargs)

    stages_module.Starks.commitStage = timed_commitStage
    stages_module.Starks.calculateImPolsExpressions = timed_calculateImPolsExpressions
    stages_module.Starks.calculateQuotientPolynomial = timed_calculateQuotientPolynomial
    stages_module.Starks.calculateFRIPolynomial = timed_calculateFRIPolynomial
    stages_module.Starks.computeLEv = timed_computeLEv
    stages_module.Starks.computeEvals = timed_computeEvals
    stages_module.Starks.evmap = timed_evmap

    # Patch witness generation (now uses witness modules)
    original_calculate_witness_with_module = stages_module.calculate_witness_with_module

    @timed("calculate_witness_with_module")
    def timed_calculate_witness_with_module(*args, **kwargs):
        return original_calculate_witness_with_module(*args, **kwargs)

    stages_module.calculate_witness_with_module = timed_calculate_witness_with_module

    # Patch expression evaluator
    original_calculate_expressions = expr_module.ExpressionsPack.calculate_expressions

    @timed("ExpressionsPack.calculate_expressions")
    def timed_calculate_expressions(self, *args, **kwargs):
        return original_calculate_expressions(self, *args, **kwargs)

    expr_module.ExpressionsPack.calculate_expressions = timed_calculate_expressions

    # Patch Merkle tree operations
    original_merkelize = merkle_module.MerkleTree.merkelize
    original_get_root = merkle_module.MerkleTree.get_root

    @timed("MerkleTree.merkelize")
    def timed_merkelize(self, *args, **kwargs):
        return original_merkelize(self, *args, **kwargs)

    @timed("MerkleTree.get_root")
    def timed_get_root(self, *args, **kwargs):
        return original_get_root(self, *args, **kwargs)

    merkle_module.MerkleTree.merkelize = timed_merkelize
    merkle_module.MerkleTree.get_root = timed_get_root

    # Patch FRI PCS
    original_fri_prove = pcs_module.FriPcs.prove

    @timed("FriPcs.prove")
    def timed_fri_prove(self, *args, **kwargs):
        return original_fri_prove(self, *args, **kwargs)

    pcs_module.FriPcs.prove = timed_fri_prove


def print_timings():
    """Print timing results."""
    print("\n" + "=" * 70)
    print("PERFORMANCE PROFILE")
    print("=" * 70)

    # Calculate totals and sort by total time
    timing_totals = []
    for name, times in TIMINGS.items():
        total = sum(times)
        count = len(times)
        avg = total / count if count > 0 else 0
        timing_totals.append((name, total, count, avg))

    timing_totals.sort(key=lambda x: -x[1])  # Sort by total time descending

    # Calculate grand total
    grand_total = sum(t[1] for t in timing_totals)

    print(f"\n{'Function':<45} {'Total (s)':<12} {'Count':<8} {'Avg (s)':<12} {'%':<8}")
    print("-" * 85)

    for name, total, count, avg in timing_totals:
        pct = (total / grand_total * 100) if grand_total > 0 else 0
        print(f"{name:<45} {total:<12.3f} {count:<8} {avg:<12.4f} {pct:<8.1f}")

    print("-" * 85)
    print(f"{'TOTAL':<45} {grand_total:<12.3f}")
    print("=" * 70)


def run_lookup_test():
    """Run the lookup test with profiling."""
    import sys
    sys.path.insert(0, '/home/cody/pil2-proofman/executable-spec')

    # Apply patches BEFORE importing prover
    patch_prover()

    # Now import and run
    from tests.test_stark_e2e import (
        load_setup_ctx, load_test_vectors,
        create_params_from_vectors
    )
    from protocol.prover import gen_proof

    air_name = "lookup"
    print(f"\nRunning profiler on {air_name} test...")

    setup_ctx = load_setup_ctx(air_name)
    if setup_ctx is None:
        print(f"Setup not found for {air_name}")
        return

    vectors = load_test_vectors(air_name)
    if vectors is None:
        print(f"Test vectors not found for {air_name}")
        return

    params, global_challenge = create_params_from_vectors(setup_ctx.stark_info, vectors)

    # Run gen_proof with timing
    print("Starting proof generation...")
    start = time.perf_counter()
    proof = gen_proof(setup_ctx, params, global_challenge=global_challenge)
    total_time = time.perf_counter() - start
    print(f"Proof generation complete in {total_time:.2f}s")

    # Print detailed timings
    print_timings()


if __name__ == "__main__":
    run_lookup_test()
