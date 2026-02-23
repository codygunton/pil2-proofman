(sec:notation)=
# Primitives

## Fields

The base field is the Goldilocks prime field

$$
\F = \mathbb{Z}/p\mathbb{Z}, \qquad p = 2^{64} - 2^{32} + 1.
$$

({src}`primitives/field.py:39` `GOLDILOCKS_PRIME`, {src}`primitives/field.py:43` `FF`)

The cubic extension field is

$$
\Fext = \F[\alpha] / (\alpha^3 - \alpha - 1),
$$

where $\alpha$ is a root of the irreducible polynomial $X^3 - X - 1$ over $\F$.
An element of $\Fext$ is written as $a_0 + a_1\alpha + a_2\alpha^2$ with $a_i \in \F$.

The Python executable spec implements field arithmetic using the
[galois](https://mhostetter.github.io/galois/) library. The extension field object is cached in `ff3_cache.pkl` to speed up testing, avoiding the
~7 s initialization cost of `galois.GF()` for extension fields.

## Domains

Let $N = 2^n$ be the *trace size* (number of rows in the execution trace).
The *trace domain* is

$$
H = \bigl\{\omega^i : i = 0, \ldots, N-1\bigr\},
$$

where $\omega \in \F$ is a primitive $N$-th root of unity
({src}`primitives/field.py:289` `get_omega()`).

The *extended evaluation domain* is a coset

$$
H^* = \bigl\{g \cdot \omega_{\mathrm{ext}}^{\,i} : i = 0, \ldots, N_{\mathrm{ext}}-1\bigr\},
$$

where $g = 7 \in \F$ is the coset shift
({src}`primitives/field.py:211` `SHIFT`),
$\omega_{\mathrm{ext}}$ is a primitive $N_{\mathrm{ext}}$-th root of unity,
and $N_{\mathrm{ext}} = 2^{n_{\mathrm{ext}}}$.
The *blowup factor* is $\beta = N_{\mathrm{ext}} / N$.

## Polynomials
The following terms for polynomials are in use:

- *Witness polynomials* $f_1, \ldots, f_m$:
  stage 1 committed columns (execution trace), each of degree $< N$.
- *Intermediate polynomials* $h_1, \ldots, h_k$:
  stage 2 committed columns (lookup / permutation support), degree $< N$.
- *Constant polynomials* $c_1, \ldots, c_\ell$:
  fixed by the AIR definition, committed during setup.
- *Quotient polynomial* $Q$:
  the result of dividing the constraint polynomial by the vanishing polynomial.
- *FRI polynomial* $F$:
  a linear combination of all committed polynomials used as input to FRI.

For a complete table of symbols used throughout the specification, see {ref}`sec:glossary`.

