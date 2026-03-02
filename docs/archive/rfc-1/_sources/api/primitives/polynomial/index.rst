primitives.polynomial
=====================

.. py:module:: primitives.polynomial

.. autoapi-nested-parse::

   Abstract polynomial operations.

   This module provides protocol-level polynomial operations without exposing
   implementation details like NTT/INTT. The protocol layer should use these
   abstractions rather than directly invoking NTT primitives.

   Protocol Invariant: If you can change an implementation detail without changing
   the resulting proof bytes, that detail does NOT belong in the protocol specification.



Functions
---------

.. autoapisummary::

   primitives.polynomial.to_coefficients
   primitives.polynomial.to_evaluations
   primitives.polynomial.extend_to_domain
   primitives.polynomial.to_coefficients_cubic


Module Contents
---------------

.. py:function:: to_coefficients(evaluations: numpy.ndarray, domain_size: int, n_cols: int = 1) -> numpy.ndarray

   Convert polynomial from evaluation form to coefficient form.

   This is the protocol-level abstraction for interpolation. The fact that
   we use NTT/INTT internally is an implementation detail - the protocol
   only cares that we can convert between representations.

   Args:
       evaluations: Polynomial values at domain points (shape: (domain_size, n_cols) or flat)
       domain_size: Size of evaluation domain (must be power of 2)
       n_cols: Number of columns (for batched operations)

   Returns:
       Polynomial coefficients in same shape as input


.. py:function:: to_evaluations(coefficients: numpy.ndarray, domain_size: int, n_cols: int = 1) -> numpy.ndarray

   Convert polynomial from coefficient form to evaluation form.

   This is the protocol-level abstraction for evaluation. The fact that
   we use NTT internally is an implementation detail.

   Args:
       coefficients: Polynomial coefficients (shape: (domain_size, n_cols) or flat)
       domain_size: Size of evaluation domain (must be power of 2)
       n_cols: Number of columns (for batched operations)

   Returns:
       Polynomial evaluations in same shape as input


.. py:function:: extend_to_domain(evaluations: numpy.ndarray, original_size: int, extended_size: int, n_cols: int = 1) -> numpy.ndarray

   Extend polynomial from smaller domain to larger domain (Low-Degree Extension).

   This is the protocol-level operation for LDE. Implementation uses:
   1. Convert to coefficients (INTT)
   2. Zero-pad
   3. Convert back to evaluations (NTT on larger domain)

   But the protocol doesn't need to know these steps.

   Args:
       evaluations: Values on original domain
       original_size: Original domain size
       extended_size: Target extended domain size
       n_cols: Number of columns

   Returns:
       Values on extended domain


.. py:function:: to_coefficients_cubic(values: list[primitives.field.FF3], n: int) -> list[primitives.field.FF3]

   Convert cubic extension field elements from evaluation to coefficient form.

   For FF3 polynomials, we apply the transform component-wise over the base field.
   This is a protocol operation because it's about converting polynomial representations,
   not about how we implement the transform.

   Args:
       values: List of FF3 evaluations
       n: Domain size

   Returns:
       List of FF3 coefficients


