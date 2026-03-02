protocol.data
=============

.. py:module:: protocol.data

.. autoapi-nested-parse::

   Clean data structures for constraint and witness module evaluation.

   Architecture Overview:
       The STARK prover/verifier uses a two-layer data model:

       1. Raw numpy arrays (in protocol/stages.py and protocol/verifier.py)
          - Buffer-based storage with C++ compatible layout
          - Used by: Merkle tree building, NTT, FRI polynomial computation
          - Efficient for bulk protocol operations

       2. ProverData / VerifierData (this module)
          - Dict-based storage with named columns
          - Used by: Constraint modules, witness modules
          - Readable for AIR-specific code

       The bridge functions (_build_prover_data_base, _build_prover_data_extended
       in stages.py; _build_verifier_data in verifier.py) convert from the raw
       numpy arrays to ProverData/VerifierData when needed for constraint/witness
       module evaluation.

   Usage:
       # Prover: constraint module evaluation
       prover_data = _build_prover_data_extended(stark_info, params, constPolsExtended)
       ctx = ProverConstraintContext(prover_data)
       q = constraint_module.constraint_polynomial(ctx)

       # Verifier: constraint evaluation at single point
       verifier_data = _build_verifier_data(stark_info, evals, challenges, airgroup_values)
       ctx = VerifierConstraintContext(verifier_data)
       q_at_xi = constraint_module.constraint_polynomial(ctx)



Attributes
----------

.. autoapisummary::

   protocol.data.FF3Poly
   protocol.data.FFPoly


Classes
-------

.. autoapisummary::

   protocol.data.ProverData
   protocol.data.VerifierData


Module Contents
---------------

.. py:data:: FF3Poly

.. py:data:: FFPoly

.. py:class:: ProverData

   Polynomial data for constraint/witness module evaluation.

   This provides a clean dict-based interface for AIR-specific code.
   Columns are keyed by (name, index) tuples for array columns like im_cluster.

   Attributes:
       columns: Polynomial columns keyed by (name, index)
       constants: Constant polynomials keyed by (name, index)
       challenges: Fiat-Shamir challenges keyed by name (e.g., 'std_alpha')
       public_inputs: Public inputs keyed by name
       airgroup_values: AIR group values keyed by index
       extend: Blowup factor (N_ext / N), 1 for base domain, 4+ for extended


   .. py:attribute:: columns
      :type:  dict[tuple[str, int], FF3Poly]


   .. py:attribute:: constants
      :type:  dict[tuple[str, int], FFPoly]


   .. py:attribute:: challenges
      :type:  dict[str, primitives.field.FF3]


   .. py:attribute:: public_inputs
      :type:  dict[str, primitives.field.FF]


   .. py:attribute:: airgroup_values
      :type:  dict[int, primitives.field.FF3]


   .. py:attribute:: extend
      :type:  int
      :value: 1



   .. py:method:: update_columns(new_columns: dict[tuple[str, int], FF3Poly]) -> None

      Add new columns (e.g., intermediates from witness generation).



.. py:class:: VerifierData

   Evaluation data for constraint module verification.

   This provides a clean dict-based interface for verifier constraint evaluation.
   Evaluations are keyed by (name, index, offset) where offset indicates row shift.

   Attributes:
       evals: Polynomial evaluations keyed by (name, index, offset)
       challenges: Fiat-Shamir challenges keyed by name
       public_inputs: Public inputs keyed by name
       airgroup_values: AIR group values keyed by index


   .. py:attribute:: evals
      :type:  dict[tuple[str, int, int], primitives.field.FF3]


   .. py:attribute:: challenges
      :type:  dict[str, primitives.field.FF3]


   .. py:attribute:: public_inputs
      :type:  dict[str, primitives.field.FF]


   .. py:attribute:: airgroup_values
      :type:  dict[int, primitives.field.FF3]


   .. py:attribute:: publics_flat
      :type:  numpy.ndarray | None
      :value: None



   .. py:attribute:: air_values_flat
      :type:  numpy.ndarray | None
      :value: None



   .. py:attribute:: proof_values_flat
      :type:  numpy.ndarray | None
      :value: None



