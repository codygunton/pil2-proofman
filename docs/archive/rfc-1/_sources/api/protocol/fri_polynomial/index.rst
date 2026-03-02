protocol.fri_polynomial
=======================

.. py:module:: protocol.fri_polynomial

.. autoapi-nested-parse::

   FRI polynomial computation.

   The FRI polynomial F combines all committed polynomial evaluations into a single
   polynomial for the FRI proximity test using polynomial batching.

   **Batching formula (matching C++ bytecode):**

   Within each opening position group g (with entries [e0, e1, ..., en] in evMap order):
       group_g = (vf2^n * (p0 - ev0) + vf2^{n-1} * (p1 - ev1) + ... + (pn - evn)) * xDivXSubXi[g]

   First entry in group gets highest vf2 power, last entry gets vf2^0.

   Between groups (with n_groups opening positions):
       F = vf1^{n_groups-1} * group_0 + vf1^{n_groups-2} * group_1 + ... + group_{n_groups-1}

   First group gets highest vf1 power, last group gets vf1^0.

   Where:
   - vf1, vf2 are FRI verification challenges (std_vf1, std_vf2)
   - xDivXSubXi[g] = 1/(x - xi * ω^openingPoints[g])



Attributes
----------

.. autoapisummary::

   protocol.fri_polynomial.QueryPolynomials


Functions
---------

.. autoapisummary::

   protocol.fri_polynomial.compute_fri_polynomial
   protocol.fri_polynomial.compute_fri_polynomial_verifier


Module Contents
---------------

.. py:data:: QueryPolynomials

.. py:function:: compute_fri_polynomial(stark_info: protocol.stark_info.StarkInfo, trace: numpy.ndarray, aux_trace: numpy.ndarray, const_pols_extended: numpy.ndarray, evals: numpy.ndarray, xi: primitives.field.FF3, vf1: primitives.field.FF3, vf2: primitives.field.FF3, domain_size: int, extended: bool = True, prover_helpers: protocol.air_config.ProverHelpers = None) -> numpy.ndarray

   Compute FRI polynomial on evaluation domain using polynomial batching.

   F(x) = Σ_i (vf1^i * vf2^openingPos[i]) * (poly_i(x) - eval_i) / (x - xi_i)

   Args:
       stark_info: StarkInfo with evMap and challenge mappings
       trace: Stage 1 trace buffer
       aux_trace: Auxiliary trace buffer
       const_pols_extended: Extended constant polynomials
       evals: Polynomial evaluations array
       xi: Evaluation point challenge
       vf1: FRI batching challenge 1
       vf2: FRI batching challenge 2
       domain_size: Size of evaluation domain
       extended: Whether using extended domain
       prover_helpers: ProverHelpers with x domain values (required for prover)

   Returns:
       FRI polynomial as interleaved numpy array (domain_size * 3)


.. py:function:: compute_fri_polynomial_verifier(stark_info: protocol.stark_info.StarkInfo, poly_values: QueryPolynomials, ev_id_to_poly_id: dict[int, primitives.pol_map.PolynomialId], evals: numpy.ndarray, x_div_x_sub: numpy.ndarray, challenges: numpy.ndarray, n_queries: int) -> numpy.ndarray

   Compute FRI polynomial at query points for verifier.

   The verifier computes:
   F(q) = Σ_i (vf1^i * vf2^openingPos[i]) * (poly_i(q) - eval_i) * xDivXSub[q][openingPos[i]]

   Where:
   - poly_i(q) are polynomial values at query point q (from poly_values dict)
   - eval_i are claimed evaluations at xi (from evals)
   - xDivXSub[q][i] = 1/(x_q - xi * ω^openingPoints[i])

   This version uses dict-based polynomial access, eliminating buffer offset arithmetic.

   Args:
       stark_info: StarkInfo with evMap and polynomial mappings
       poly_values: Dict mapping PolynomialId -> FF3 array (vectorized over queries)
       ev_id_to_poly_id: Mapping from ev_map index to PolynomialId
       evals: Polynomial evaluations from proof
       x_div_x_sub: Precomputed 1/(x - xi*w^k) values
       challenges: Challenge array (interleaved format)
       n_queries: Number of query points

   Returns:
       FRI polynomial values at query points as interleaved array (n_queries * 3)


