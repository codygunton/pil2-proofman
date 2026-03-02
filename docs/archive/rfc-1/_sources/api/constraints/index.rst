constraints
===========

.. py:module:: constraints

.. autoapi-nested-parse::

   Constraint evaluation modules.

   This module provides per-AIR constraint evaluation that replaces the generic
   expression binary interpreter. Each AIR has its own ConstraintModule that
   evaluates the constraint polynomial directly in readable Python code.

   For AIRs without hand-written modules, the bytecode adapter provides a fallback
   using compiled expression bytecode. The BYTECODE_AIRS dict controls which AIRs
   use bytecode vs hand-written modules.

   Zisk AIRs are auto-discovered from the proving key at ZISK_PROVING_KEY_DIR.
   All discovered AIRs without hand-written modules are registered for bytecode
   evaluation.



Submodules
----------

.. toctree::
   :maxdepth: 1

   /api/constraints/base/index
   /api/constraints/bytecode_adapter/index
   /api/constraints/lookup2_12/index
   /api/constraints/permutation1_6/index
   /api/constraints/simple_left/index


Attributes
----------

.. autoapisummary::

   constraints.CONSTRAINT_REGISTRY
   constraints.BYTECODE_AIRS


Functions
---------

.. autoapisummary::

   constraints.get_constraint_module


Package Contents
----------------

.. py:data:: CONSTRAINT_REGISTRY
   :type:  dict[str, type[base.ConstraintModule]]

.. py:data:: BYTECODE_AIRS
   :type:  dict[str, str]

.. py:function:: get_constraint_module(air_name: str, expressions_bin: str | None = None) -> base.ConstraintModule

   Get constraint module instance for an AIR.

   When expressions_bin is provided (from AirConfig), prefers hand-written modules
   in CONSTRAINT_REGISTRY to avoid naming collisions between pilouts that share an
   AIR name (e.g., SpecifiedRanges appears in both Simple pilout and Zisk). Falls
   back to BytecodeConstraintModule with the provided path if no hand-written module
   exists.

   Without expressions_bin, checks BYTECODE_AIRS first (allowing bytecode override
   for validation), then falls back to hand-written modules in CONSTRAINT_REGISTRY.

   Args:
       air_name: Name of the AIR (e.g., 'SimpleLeft', 'Lookup2_12')
       expressions_bin: Optional path to .bin bytecode. When provided, takes priority
           over BYTECODE_AIRS to prevent cross-pilout naming collisions.

   Returns:
       ConstraintModule instance for the AIR

   Raises:
       KeyError: If no constraint module is registered for the AIR (and no expressions_bin)


