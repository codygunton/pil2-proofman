witness
=======

.. py:module:: witness

.. autoapi-nested-parse::

   Witness generation modules.

   This module provides per-AIR witness generation that replaces the generic
   hint-driven witness computation. Each AIR has its own WitnessModule that
   computes intermediate columns and grand sums directly in readable Python code.

   For AIRs without hand-written modules, the bytecode adapter provides a fallback
   using compiled expression bytecode. The BYTECODE_AIRS dict controls which AIRs
   use bytecode vs hand-written modules.

   Zisk AIRs are auto-discovered from the proving key directory. All discovered
   AIRs without hand-written modules are registered for bytecode evaluation.



Submodules
----------

.. toctree::
   :maxdepth: 1

   /api/witness/base/index
   /api/witness/bytecode_adapter/index
   /api/witness/lookup2_12/index
   /api/witness/permutation1_6/index
   /api/witness/simple_left/index
   /api/witness/simple_right/index
   /api/witness/specified_ranges/index
   /api/witness/u16_air/index
   /api/witness/u8_air/index


Attributes
----------

.. autoapisummary::

   witness.WITNESS_REGISTRY
   witness.BYTECODE_AIRS


Functions
---------

.. autoapisummary::

   witness.get_witness_module


Package Contents
----------------

.. py:data:: WITNESS_REGISTRY
   :type:  dict[str, type[base.WitnessModule]]

.. py:data:: BYTECODE_AIRS
   :type:  dict[str, str]

.. py:function:: get_witness_module(air_name: str, expressions_bin: str | None = None) -> base.WitnessModule

   Get witness module instance for an AIR.

   When expressions_bin is provided (from AirConfig), prefers hand-written modules
   in WITNESS_REGISTRY to avoid naming collisions between pilouts that share an
   AIR name (e.g., SpecifiedRanges appears in both Simple pilout and Zisk). If the
   hand-written module does not implement Stage-2, wraps it with a bytecode fallback.

   Without expressions_bin, checks BYTECODE_AIRS first (Zisk AIRs), then falls
   back to hand-written modules in WITNESS_REGISTRY.

   Args:
       air_name: Name of the AIR (e.g., 'SimpleLeft', 'Lookup2_12')
       expressions_bin: Optional path to .bin bytecode. When provided, takes priority
           over BYTECODE_AIRS to prevent cross-pilout naming collisions.

   Returns:
       WitnessModule instance for the AIR

   Raises:
       KeyError: If no witness module is registered for the AIR (and no expressions_bin)


