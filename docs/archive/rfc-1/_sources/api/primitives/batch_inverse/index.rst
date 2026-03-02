primitives.batch_inverse
========================

.. py:module:: primitives.batch_inverse

.. autoapi-nested-parse::

   Montgomery batch inversion for Goldilocks field and cubic extension.



Functions
---------

.. autoapisummary::

   primitives.batch_inverse.batch_inverse_ff
   primitives.batch_inverse.batch_inverse_ff3
   primitives.batch_inverse.batch_inverse_ff_array
   primitives.batch_inverse.batch_inverse_ff3_array


Module Contents
---------------

.. py:function:: batch_inverse_ff(values: list[primitives.field.FF]) -> list[primitives.field.FF]

   Montgomery batch inversion for base field (list interface).


.. py:function:: batch_inverse_ff3(values: list[primitives.field.FF3]) -> list[primitives.field.FF3]

   Montgomery batch inversion for cubic extension (list interface).


.. py:function:: batch_inverse_ff_array(values: primitives.field.FF) -> primitives.field.FF

   Montgomery batch inversion for FF galois array.


.. py:function:: batch_inverse_ff3_array(values: primitives.field.FF3) -> primitives.field.FF3

   Montgomery batch inversion for FF3 galois array.


