"""Unit tests for Montgomery batch inversion."""

import pytest
import time
from primitives.field import FF, ff3, ff3_coeffs
from primitives.batch_inverse import batch_inverse_ff, batch_inverse_ff3


class TestBatchInverseFF:
    """Tests for base field batch inversion."""

    def test_empty_list(self):
        """Empty input returns empty output."""
        assert batch_inverse_ff([]) == []

    def test_single_element(self):
        """Single element is inverted correctly."""
        val = FF(12345)
        result = batch_inverse_ff([val])
        assert len(result) == 1
        assert result[0] * val == FF(1)

    def test_two_elements(self):
        """Two elements are inverted correctly."""
        vals = [FF(123), FF(456)]
        results = batch_inverse_ff(vals)
        assert len(results) == 2
        for v, r in zip(vals, results):
            assert v * r == FF(1)

    def test_many_elements(self):
        """Many elements are inverted correctly."""
        vals = [FF(i) for i in range(1, 101)]
        results = batch_inverse_ff(vals)
        assert len(results) == 100
        for v, r in zip(vals, results):
            assert v * r == FF(1)

    def test_matches_scalar_inversion(self):
        """Batch inversion matches scalar inversion."""
        vals = [FF(i * 7 + 13) for i in range(50)]
        batch_results = batch_inverse_ff(vals)
        scalar_results = [v ** -1 for v in vals]
        for b, s in zip(batch_results, scalar_results):
            assert b == s

    def test_performance(self):
        """4096 inversions complete in reasonable time."""
        vals = [FF(i + 1) for i in range(4096)]

        t0 = time.time()
        results = batch_inverse_ff(vals)
        elapsed = time.time() - t0

        # Verify correctness
        for v, r in zip(vals, results):
            assert v * r == FF(1)

        # Should be much faster than scalar (scalar takes ~0.07s, batch should be similar or faster)
        assert elapsed < 1.0, f"Batch inversion took {elapsed:.3f}s, expected < 1s"


class TestBatchInverseFF3:
    """Tests for cubic extension field batch inversion."""

    def test_empty_list(self):
        """Empty input returns empty output."""
        assert batch_inverse_ff3([]) == []

    def test_single_element(self):
        """Single element is inverted correctly."""
        val = ff3([12345, 67890, 11111])
        result = batch_inverse_ff3([val])
        assert len(result) == 1
        product = result[0] * val
        assert ff3_coeffs(product) == [1, 0, 0]

    def test_two_elements(self):
        """Two elements are inverted correctly."""
        vals = [ff3([1, 2, 3]), ff3([4, 5, 6])]
        results = batch_inverse_ff3(vals)
        assert len(results) == 2
        for v, r in zip(vals, results):
            product = v * r
            assert ff3_coeffs(product) == [1, 0, 0]

    def test_many_elements(self):
        """Many elements are inverted correctly."""
        vals = [ff3([i, i + 1, i + 2]) for i in range(1, 51)]
        results = batch_inverse_ff3(vals)
        assert len(results) == 50
        for v, r in zip(vals, results):
            product = v * r
            assert ff3_coeffs(product) == [1, 0, 0]

    def test_matches_scalar_inversion(self):
        """Batch inversion matches scalar inversion."""
        vals = [ff3([i * 3 + 1, i * 3 + 2, i * 3 + 3]) for i in range(20)]
        batch_results = batch_inverse_ff3(vals)
        scalar_results = [v ** -1 for v in vals]
        for b, s in zip(batch_results, scalar_results):
            assert ff3_coeffs(b) == ff3_coeffs(s)

    def test_performance(self):
        """4096 FF3 inversions complete much faster than scalar."""
        vals = [ff3([i + 1, i + 2, i + 3]) for i in range(4096)]

        t0 = time.time()
        results = batch_inverse_ff3(vals)
        batch_time = time.time() - t0

        # Verify first few for correctness
        for v, r in zip(vals[:10], results[:10]):
            product = v * r
            assert ff3_coeffs(product) == [1, 0, 0]

        # Batch should complete in < 1s (scalar would take ~14s)
        assert batch_time < 2.0, f"Batch FF3 inversion took {batch_time:.3f}s, expected < 2s"
        print(f"\nBatch FF3 inversion of 4096 elements: {batch_time:.3f}s")
