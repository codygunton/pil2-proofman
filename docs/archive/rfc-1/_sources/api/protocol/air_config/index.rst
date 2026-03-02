protocol.air_config
===================

.. py:module:: protocol.air_config

.. autoapi-nested-parse::

   AIR configuration and precomputed prover data.

   This module provides the configuration bundle for STARK proving/verification:

   - AirConfig: Bundles StarkInfo (AIR specification) and optional GlobalInfo
     (cross-AIR coordination).
   - ProverHelpers: Precomputed zerofiers and evaluation points needed by both
     prover and verifier for constraint evaluation.

   The 'AIR' (Algebraic Intermediate Representation) defines the constraint system
   that the STARK proves. AirConfig packages everything needed to evaluate those
   constraints.

   Example:
       config = AirConfig.from_starkinfo("path/to/starkinfo.json")
       proof = gen_proof(config, params)



Classes
-------

.. autoapisummary::

   protocol.air_config.ProverHelpers
   protocol.air_config.AirConfig


Module Contents
---------------

.. py:class:: ProverHelpers

   Precomputed zerofiers and evaluation points for constraint evaluation.

   The prover and verifier both need to evaluate constraints at various points.
   This class precomputes values that would otherwise be redundantly calculated:

   Attributes:
       zi: Zerofier evaluations 1/Z_H(x) for each boundary constraint.
           Z_H(x) = x^N - 1 is the vanishing polynomial on the trace domain.
           Different boundaries (firstRow, lastRow, everyRow) have different
           zerofiers, all stored in this array.
       x: Coset evaluation points shift * w^i for i in [0, N_ext).
           These are the points where polynomials are evaluated on the
           extended domain (coset of the trace domain).
       x_n: Powers of x for PIL1 compatibility (legacy support).

   Usage:
       # For prover: precompute from domain parameters
       helpers = ProverHelpers.from_stark_info(stark_info)

       # For verifier: compute at challenge point z
       helpers = ProverHelpers.from_challenge(stark_info, z)


   .. py:attribute:: zi
      :type:  primitives.field.FF | numpy.ndarray | None
      :value: None



   .. py:attribute:: x
      :type:  primitives.field.FF | None
      :value: None



   .. py:attribute:: x_n
      :type:  primitives.field.FF | numpy.ndarray | None
      :value: None



   .. py:method:: from_stark_info(stark_info: protocol.stark_info.StarkInfo, pil1: bool = False) -> ProverHelpers
      :classmethod:


      Initialize from StarkInfo for prover mode.

      Precomputes zerofiers and evaluation points for the extended domain.

      Args:
          stark_info: AIR specification with domain sizes and boundaries
          pil1: Enable PIL1 compatibility mode (computes x_n powers)

      Returns:
          ProverHelpers with precomputed values for prover



   .. py:method:: from_challenge(stark_info: protocol.stark_info.StarkInfo, z: numpy.ndarray) -> ProverHelpers
      :classmethod:


      Initialize from challenge point z for verifier mode.

      Computes zerofiers at the random challenge point z (in extension field).

      Args:
          stark_info: AIR specification with domain sizes and boundaries
          z: Challenge point as numpy array [z0, z1, z2] (FF3 coefficients)

      Returns:
          ProverHelpers with zerofiers computed at challenge point



   .. py:method:: compute_x(n_bits: int, n_bits_ext: int, pil1: bool) -> None

      Compute coset points x[i] = shift * w^i using cumulative product.



   .. py:method:: compute_zerofier(n_bits: int, n_bits_ext: int, boundaries: list[protocol.stark_info.Boundary]) -> None

      Compute zerofier inverses 1/Z_H(x) for all boundaries.



   .. py:method:: build_zh_inv(n_bits: int, n_bits_ext: int) -> None

      Build 1/(x^N - 1) for all coset points. Writes to zi[0:N_ext].



   .. py:method:: build_one_row_zerofier_inv(n_bits: int, n_bits_ext: int, offset: int, row_index: int) -> None

      Build 1/((x - w^row) * Z_H(x)). Reads Z_H^(-1) from zi[0:N_ext].



   .. py:method:: build_frame_zerofier_inv(n_bits: int, n_bits_ext: int, offset: int, offset_min: int, offset_max: int) -> None

      Build frame zerofier (NOT inverted): product of (x - w^k) for excluded rows.



.. py:class:: AirConfig(stark_info: protocol.stark_info.StarkInfo, global_info: Optional[protocol.global_info.GlobalInfo] = None, expressions_bin: str | None = None)

   Configuration bundle for STARK proving and verification.

   AirConfig packages all read-only configuration needed to generate or verify
   a STARK proof for a specific AIR (Algebraic Intermediate Representation):

   Attributes:
       stark_info: The AIR specification containing domain sizes, stage counts,
           constraint definitions, polynomial mappings, and FRI parameters.
       global_info: Optional cross-AIR coordination data for VADCOP (Virtual
           Algebraic Distributed Computation Over Provers) mode.
       expressions_bin: Optional path to compiled expression bytecode (.bin).
           Auto-detected as the sibling .bin file of the starkinfo.json.
           Used as a Stage-2 witness fallback for AIRs without hand-written
           compute_intermediates/compute_grand_sums implementations.

   Usage:
       config = AirConfig.from_starkinfo("path/to/starkinfo.json")
       proof = gen_proof(config, params)


   .. py:attribute:: stark_info


   .. py:attribute:: global_info
      :value: None



   .. py:attribute:: expressions_bin
      :value: None



   .. py:method:: from_starkinfo(starkinfo_path: str, global_info_path: str | None = None) -> AirConfig
      :classmethod:


      Load AIR configuration from starkinfo.json.

      Args:
          starkinfo_path: Path to starkinfo.json (AIR specification)
          global_info_path: Optional path to pilout.globalInfo.json (VADCOP)

      Returns:
          AirConfig instance with loaded configuration



