primitives.ntt
==============

.. py:module:: primitives.ntt

.. autoapi-nested-parse::

   Number Theoretic Transform for Goldilocks field.



Classes
-------

.. autoapisummary::

   primitives.ntt.NTT


Module Contents
---------------

.. py:class:: NTT(domain_size: int, extension: int = 1)

   NTT engine for polynomial operations over Goldilocks field.


   .. py:attribute:: n


   .. py:attribute:: n_bits
      :value: 0



   .. py:attribute:: extension
      :value: 1



   .. py:attribute:: roots


   .. py:attribute:: pow_two_inv


   .. py:attribute:: r
      :type:  numpy.ndarray | None
      :value: None



   .. py:attribute:: r_
      :type:  numpy.ndarray | None
      :value: None



   .. py:method:: ntt(coeffs: numpy.ndarray, n_cols: int = 1) -> numpy.ndarray

      Forward NTT: coefficients -> evaluations.



   .. py:method:: intt(evals: numpy.ndarray, n_cols: int = 1, extend: bool = False) -> numpy.ndarray

      Inverse NTT: evaluations -> coefficients.



   .. py:method:: extend_pol(src: numpy.ndarray, n_extended: int, n: int, n_cols: int = 1) -> numpy.ndarray

      Extend polynomial from domain N to N_extended via zero-padding.



