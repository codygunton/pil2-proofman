(sec:notation)=
# Notation and Algebraic Setup

## Fields

The base field is the Goldilocks prime field

$$
\F = \mathbb{Z}/p\mathbb{Z}, \qquad p = 2^{64} - 2^{32} + 1.
$$

The cubic extension field is

$$
\Fext = \F[\alpha] / (\alpha^3 - \alpha - 1),
$$

where $\alpha$ is a root of the irreducible polynomial $X^3 - X - 1$ over $\F$.
An element of $\Fext$ is written as $a_0 + a_1\alpha + a_2\alpha^2$ with $a_i \in \F$.

## Domains

Let $N = 2^n$ be the *trace size* (number of rows in the execution trace).
The *trace domain* is

$$
H = \bigl\{\omega^i : i = 0, \ldots, N-1\bigr\},
$$

where $\omega \in \F$ is a primitive $N$-th root of unity.

The *extended evaluation domain* is a coset

$$
H^* = \bigl\{g \cdot \omega_{\mathrm{ext}}^{\,i} : i = 0, \ldots, N_{\mathrm{ext}}-1\bigr\},
$$

where $g = 7 \in \F$ is the coset shift,
$\omega_{\mathrm{ext}}$ is a primitive $N_{\mathrm{ext}}$-th root of unity,
and $N_{\mathrm{ext}} = 2^{n_{\mathrm{ext}}}$.
The *blowup factor* is $\beta = N_{\mathrm{ext}} / N$.

## Polynomials

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

## Key Quantities

| Symbol | Meaning |
|--------|---------|
| $\ZH(X) = X^N - 1$ | Vanishing polynomial on $H$ |
| $\mathcal{O} = \{o_0, o_1, \ldots\}$ | Opening point offsets (typically $\subseteq \{-1,0,1\}$) |
| $J$ | Number of constraint polynomials in the AIR |
| $d$ | Number of quotient polynomial pieces ($Q$ split degree) |
| $K$ | Number of FRI folding rounds |
| $Q_{\mathrm{queries}}$ | Number of FRI query repetitions |
| $b_{\mathrm{pow}}$ | Grinding difficulty (number of leading zero bits) |
| $a$ | Merkle tree arity (2, 3, or 4) |

## Notation Conventions

| Notation | Meaning |
|----------|---------|
| $[n]$ | The set $\{0, 1, \ldots, n-1\}$ |
| $\MT(\cdot)$ | Merkle tree root |
| $\T$ | Fiat-Shamir transcript |
| $\T.\abs(\cdot)$ | Absorb elements into transcript |
| $\T.\sq()$ | Squeeze one $\Fext$ challenge |
| $\T.\sqidx(q, b)$ | Squeeze $q$ pseudorandom $b$-bit indices |
| $\xi, \beta_k, v_1, v_2, v_c$ | Challenges in $\Fext$ |
| $\alpha, \gamma$ | Lookup/permutation challenges in $\Fext$ |
