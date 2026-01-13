"""Validate galois custom omega matches _intt_small."""

import sys
import galois
from fri import FRI
from field import W, inv_mod, GOLDILOCKS_PRIME

# Use galois from the forked version with custom omega support
GF = galois.GF(GOLDILOCKS_PRIME)


def test_intt_component_match():
    """
    Test that galois intt with custom omega matches _intt_small for each component.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """

    # Test case: 8-element INTT
    n = 8
    n_bits = 3  # log2(8) = 3
    w_inv = inv_mod(W[n_bits])  # inverse of 8th root

    # Test data - cubic extension elements [c0, c1, c2]
    # Use simple values for debugging
    data_cubic = [
        [1, 0, 0],
        [2, 0, 0],
        [3, 0, 0],
        [4, 0, 0],
        [5, 0, 0],
        [6, 0, 0],
        [7, 0, 0],
        [8, 0, 0],
    ]

    # Run _intt_small
    result_original = FRI._intt_small(data_cubic.copy(), n, w_inv)

    # Run galois intt on component 0 with custom omega
    comp0 = GF([d[0] for d in data_cubic])
    result_galois_0 = galois.intt(comp0, omega=w_inv)

    # Compare component 0
    expected_0 = [r[0] for r in result_original]
    actual_0 = [int(x) for x in result_galois_0]

    print(f"Component 0 comparison:")
    print(f"  _intt_small:    {expected_0}")
    print(f"  galois (omega): {actual_0}")

    if expected_0 == actual_0:
        print("  MATCH!")
    else:
        print("  MISMATCH!")
        return False

    return True


def test_intt_full_cubic():
    """
    Test full cubic extension INTT match.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """

    n = 8
    n_bits = 3
    w_inv = inv_mod(W[n_bits])

    # Mixed cubic data
    data_cubic = [
        [100, 200, 300],
        [101, 201, 301],
        [102, 202, 302],
        [103, 203, 303],
        [104, 204, 304],
        [105, 205, 305],
        [106, 206, 306],
        [107, 207, 307],
    ]

    # Run _intt_small
    result_original = FRI._intt_small([list(d) for d in data_cubic], n, w_inv)

    # Run galois intt on each component
    comp0 = GF([d[0] for d in data_cubic])
    comp1 = GF([d[1] for d in data_cubic])
    comp2 = GF([d[2] for d in data_cubic])

    r0 = galois.intt(comp0, omega=w_inv)
    r1 = galois.intt(comp1, omega=w_inv)
    r2 = galois.intt(comp2, omega=w_inv)

    # Recombine
    result_galois = [[int(r0[i]), int(r1[i]), int(r2[i])] for i in range(n)]

    print(f"\nFull cubic comparison (n={n}):")
    all_match = True
    for i in range(n):
        match = result_original[i] == result_galois[i]
        status = "MATCH" if match else "MISMATCH"
        if not match:
            all_match = False
            print(f"  [{i}] original={result_original[i]}")
            print(f"      galois  ={result_galois[i]} <- {status}")

    if all_match:
        print("  All elements MATCH!")

    return all_match


def test_intt_size_4():
    """
    Test with size 4.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """
    n = 4
    n_bits = 2
    w_inv = inv_mod(W[n_bits])

    data_cubic = [
        [10, 20, 30],
        [11, 21, 31],
        [12, 22, 32],
        [13, 23, 33],
    ]

    result_original = FRI._intt_small([list(d) for d in data_cubic], n, w_inv)

    comp0 = GF([d[0] for d in data_cubic])
    comp1 = GF([d[1] for d in data_cubic])
    comp2 = GF([d[2] for d in data_cubic])

    r0 = galois.intt(comp0, omega=w_inv)
    r1 = galois.intt(comp1, omega=w_inv)
    r2 = galois.intt(comp2, omega=w_inv)

    result_galois = [[int(r0[i]), int(r1[i]), int(r2[i])] for i in range(n)]

    print(f"\nSize 4 comparison:")
    all_match = result_original == result_galois
    print(f"  original: {result_original}")
    print(f"  galois:   {result_galois}")
    print(f"  {'MATCH!' if all_match else 'MISMATCH!'}")

    return all_match


def run_tests():
    """
    Run all galois omega tests.

    C++ Reference: NO CORRESPONDING FUNCTION
                   (Python test utility)
    """
    print("Testing galois custom omega vs _intt_small\n")
    print("=" * 60)

    results = []
    results.append(("Component match (size 8)", test_intt_component_match()))
    results.append(("Full cubic (size 8)", test_intt_full_cubic()))
    results.append(("Size 4", test_intt_size_4()))

    print("\n" + "=" * 60)
    print("Summary:")
    all_passed = True
    for name, passed in results:
        status = "PASS" if passed else "FAIL"
        print(f"  {name}: {status}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\nSUCCESS: galois INTT with custom omega matches _intt_small!")
    else:
        print("\nFAILURE: Some tests did not match!")

    return all_passed


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
