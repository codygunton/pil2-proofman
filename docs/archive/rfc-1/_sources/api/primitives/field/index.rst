primitives.field
================

.. py:module:: primitives.field

.. autoapi-nested-parse::

   Goldilocks field GF(p) and cubic extension GF(p^3).

   Uses galois library for all field arithmetic. FF and FF3 are the field types.

   Type Discipline
   ---------------
   When to use FF (base field):
   - Domain generators (omega, omega_extended)
   - Shift values for coset evaluation
   - Single field element constants
   - Hash outputs (4 base field elements)

   When to use FF3 (extension field):
   - Polynomial evaluations (prover and verifier)
   - Challenges (derived from Fiat-Shamir transcript)
   - Constraint polynomial values
   - FRI folding values
   - Polynomial batching coefficients (vf1, vf2)

   Interleaved Format (InterleavedFF3):
   - Used for C++ compatibility and bulk operations
   - Layout: [c0_0, c1_0, c2_0, c0_1, c1_1, c2_1, ...]
   - Each FF3 element has 3 consecutive coefficients
   - Convert with: ff3_from_interleaved_numpy(), ff3_to_interleaved_numpy()

   FF3 is loaded from a pre-computed cache file (ff3_cache.pkl) to avoid the ~7s
   initialization cost of galois.GF() for extension fields. To regenerate the cache:
       python -c "from primitives.field import _regenerate_ff3_cache; _regenerate_ff3_cache()"



Attributes
----------

.. autoapisummary::

   primitives.field.GOLDILOCKS_PRIME
   primitives.field.FIELD_EXTENSION_DEGREE
   primitives.field.FIELD_EXTENSION
   primitives.field.FF
   primitives.field.FF3
   primitives.field.FF3Poly
   primitives.field.FFPoly
   primitives.field.FF3Array
   primitives.field.FFArray
   primitives.field.HashOutput
   primitives.field.InterleavedFF3
   primitives.field.ntt
   primitives.field.intt
   primitives.field.SHIFT
   primitives.field.SHIFT_INV
   primitives.field.W
   primitives.field.W_INV


Functions
---------

.. autoapisummary::

   primitives.field.ff3_coeffs
   primitives.field.ff3_array
   primitives.field.ff3_array_from_base
   primitives.field.ff3_from_flat_list
   primitives.field.ff3_to_flat_list
   primitives.field.ff3_from_json
   primitives.field.ff3_to_json
   primitives.field.ff3_from_interleaved_numpy
   primitives.field.ff3_to_interleaved_numpy
   primitives.field.ff3
   primitives.field.ff3_from_base
   primitives.field.ff3_from_numpy_coeffs
   primitives.field.ff3_to_numpy_coeffs
   primitives.field.ff3_from_buffer_at
   primitives.field.ff3_store_to_buffer
   primitives.field.get_omega
   primitives.field.get_omega_inv
   primitives.field.batch_inverse


Module Contents
---------------

.. py:data:: GOLDILOCKS_PRIME
   :value: 18446744069414584321


.. py:data:: FIELD_EXTENSION_DEGREE
   :value: 3


.. py:data:: FIELD_EXTENSION
   :value: 3


.. py:data:: FF

   Base field GF(p) - Goldilocks prime field.


.. py:data:: FF3

.. py:data:: FF3Poly

.. py:data:: FFPoly

.. py:data:: FF3Array

.. py:data:: FFArray

.. py:data:: HashOutput

.. py:data:: InterleavedFF3

.. py:function:: ff3_coeffs(elem: FF3) -> list[int]

   Extract ascending-order coefficients [a0, a1, a2] from FF3 element.


.. py:function:: ff3_array(c0: list[int], c1: list[int], c2: list[int]) -> FF3

   Construct FF3 array from parallel coefficient lists.


.. py:function:: ff3_array_from_base(vals: list[int]) -> FF3

   Construct FF3 array from base field values (c1=c2=0).


.. py:function:: ff3_from_flat_list(coeffs: list[int]) -> FF3

   Convert flattened [c0,c1,c2,c0,c1,c2,...] to FF3 array.


.. py:function:: ff3_to_flat_list(arr: FF3) -> list[int]

   Convert FF3 array to flattened [c0,c1,c2,c0,c1,c2,...].


.. py:function:: ff3_from_json(json_arr: list[list[int]]) -> FF3

   Parse JSON [[c0,c1,c2],...] to FF3 array.


.. py:function:: ff3_to_json(arr: FF3) -> list[list[int]]

   Convert FF3 array to JSON [[c0,c1,c2],...] format.


.. py:function:: ff3_from_interleaved_numpy(arr: numpy.ndarray, n: int) -> FF3

   Convert interleaved numpy [c0,c1,c2,c0,c1,c2,...] to FF3 array.


.. py:function:: ff3_to_interleaved_numpy(arr: FF3) -> numpy.ndarray

   Convert FF3 array to interleaved numpy [c0,c1,c2,c0,c1,c2,...].


.. py:function:: ff3(coeffs: list[int]) -> FF3

   Construct FF3 scalar from ascending-order coefficients [c0, c1, c2].


.. py:function:: ff3_from_base(val: int) -> FF3

   Embed base field element into FF3 as (val, 0, 0).


.. py:function:: ff3_from_numpy_coeffs(arr: numpy.ndarray) -> FF3

   Convert numpy [c0, c1, c2] to FF3 scalar.


.. py:function:: ff3_to_numpy_coeffs(elem: FF3) -> numpy.ndarray

   Convert FF3 scalar to numpy [c0, c1, c2].


.. py:function:: ff3_from_buffer_at(buffer: numpy.ndarray, indices: list[int]) -> FF3

   Extract FF3 elements from buffer at coefficient indices.

   Each index points to c0, with c1 at index+1, c2 at index+2.


.. py:function:: ff3_store_to_buffer(arr: FF3, buffer: numpy.ndarray, indices: list[int]) -> None

   Store FF3 elements to buffer at coefficient indices.

   Each index points to c0, stores c1 at index+1, c2 at index+2.


.. py:data:: ntt

.. py:data:: intt

.. py:data:: SHIFT

.. py:data:: SHIFT_INV

.. py:data:: W
   :type:  list[int]
   :value: [1, 18446744069414584320, 281474976710656, 16777216, 4096, 64, 8, 2198989700608,...


.. py:data:: W_INV
   :type:  list[int]
   :value: [1, 18446744069414584320, 18446462594437873665, 18446742969902956801, 18442240469788262401,...


.. py:function:: get_omega(n_bits: int) -> int

   Return primitive 2^n_bits-th root of unity.


.. py:function:: get_omega_inv(n_bits: int) -> int

   Return inverse of primitive 2^n_bits-th root of unity.


.. py:function:: batch_inverse(values: galois.Array) -> galois.Array

   Montgomery batch inversion for any galois array.

   Converts N field inversions into 3N-3 multiplications + 1 inversion.
   Works with any galois FieldArray type (FF, FF3, or any GF).

   Algorithm:
   1. Forward pass: Compute prefix products cumprods[i] = a[0] * a[1] * ... * a[i]
   2. Single inversion: inv_total = cumprods[N-1]^(-1)
   3. Backward pass: Extract individual inverses using cumprods

   Args:
       values: Galois FieldArray to invert (must all be non-zero)

   Returns:
       Galois FieldArray where result[i] = values[i]^(-1)

   Raises:
       ZeroDivisionError: If any element is zero

   Reference: pil2-stark/src/goldilocks/src/goldilocks_base_field.hpp::batchInverse


