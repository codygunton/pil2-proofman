(sec:full-protocol)=
# The Full Protocol, Rolled Out

This section presents the complete PIL2-STARK protocol as a single
sequential description.
All challenges are derived deterministically from the Fiat-Shamir
transcript $\T$ using $\Hash = \Poseidon$; no interactive verifier appears.
Every absorb and squeeze operation is shown explicitly.

This page is self-contained.
It draws on {ref}`app:constraints` for constraint structure,
{ref}`app:batching` for the FRI batching formula,
and {ref}`sec:challenge-binding` for multi-AIR challenge derivation.

**Notation and domains.**

- $\F = \mathbb{F}_p$ (Goldilocks, $p = 2^{64} - 2^{32} + 1$),
  $\Fext = \mathbb{F}_{p^3}$ (cubic extension).
- $H = \{1, \omega, \omega^2, \ldots, \omega^{N-1}\}$ is the trace domain
  ($N$ a power of 2, $\omega$ a primitive $N$-th root of unity).
- $H^* = \{g, g\omega, g\omega^2, \ldots, g\omega^{N_{\mathrm{ext}}-1}\}$
  is the evaluation domain
  ($N_{\mathrm{ext}} = 4N$, $g = \mathsf{SHIFT}$).
- $\ZH(X) = X^N - 1$ is the vanishing polynomial of $H$.
- $\MT(\cdot)$ denotes Merkle tree commitment using $\Poseidon$.
- $\LinHash$ is Poseidon2 linear hashing of long vectors to a fixed-size digest.

**Common preprocessed input.**

$$
\begin{array}{l}
N \text{ (trace size)},\quad
N_{\mathrm{ext}} = 4N,\quad
g = \mathsf{SHIFT}, \\[4pt]
\text{Constraint polynomials } C_0(X), \ldots, C_{J-1}(X)
  \text{ (see {ref}`app:constraints`)}, \\[4pt]
\text{Constant polynomials } c_1, \ldots, c_s : H \to \F, \\[4pt]
d = \lceil \deg(C) / N \rceil \text{ (number of quotient splits)}, \\[4pt]
\text{Evaluation map } \mathcal{E} = \{(p, o)\}
  \text{ pairing polynomials with opening offsets}, \\[4pt]
\text{FRI schedule } (b_0, b_1, \ldots, b_K) \text{ where }
  b_0 = \log_2 N_{\mathrm{ext}}, \\[4pt]
\text{Verification key } \mathrm{vk} \in \F^4, \quad
Q_{\mathrm{queries}} \text{ (number of queries)}, \quad
b_{\mathrm{pow}} \text{ (proof-of-work bits)}.
\end{array}
$$

**Public input.** $\mathrm{pub} \in \F^{\ell}$.

**Witness.** Values $(w_{j,i})$ for $j \in [m]$, $i \in [N]$,
defining polynomials $f_j : H \to \F$ with $f_j(\omega^i) = w_{j,i}$.

---

## Witness commitment

({src}`protocol/prover.py:202`)

1. For each witness polynomial $f_j$ ($j = 1, \ldots, m$):
   extend from $H$ to $H^*$ via $\NTT$ on the coset,
   obtaining $N_{\mathrm{ext}}$ evaluations.

2. Build a joint Merkle tree over all stage-1 columns
   ({src}`protocol/stages.py:424`).

3. Compute the root:

   $$
   r_1 = \MT(f_1, \ldots, f_m).
   $$

## Transcript initialization

({src}`protocol/prover.py:207`)

Initialize the Fiat-Shamir transcript $\T$.

- **Standalone mode.**

  $$
  \T.\abs\bigl(\mathrm{vk},\; \Hash(\mathrm{pub}),\; r_1\bigr),
  $$

  where $\mathrm{vk} \in \F^4$ is the verification key
  and $\Hash(\mathrm{pub})$ is a $\Poseidon$ hash of the public inputs.

- **Multi-AIR (VADCOP) mode.**
  Derive a global challenge $\chi \in \Fext$ from
  all per-AIR stage-1 commitments via the procedure in
  {ref}`sec:challenge-binding`.
  Then:

  $$
  \T.\abs(\chi).
  $$

## Intermediate polynomials

({src}`protocol/prover.py:247`)

1. Squeeze stage-2 challenges from the transcript:

   $$
   \alpha \leftarrow \T.\sq(), \qquad
   \gamma \leftarrow \T.\sq(),
   \qquad \alpha, \gamma \in \Fext.
   $$

2. Define the compressed expression:

   $$
   \mathrm{compress}(b,\; c_1, \ldots, c_w)
   = \bigl(\cdots\bigl((c_w \cdot \alpha + c_{w-1}) \cdot \alpha + \cdots\bigr)
     \cdot \alpha + b\bigr) + \gamma.
   $$

3. For each logup term with bus $b_j$, columns $\mathbf{c}_j$, numerator $s_j$:
   set $D_j = \mathrm{compress}(b_j, \mathbf{c}_j)$.

4. Compute intermediate columns
   ({src}`protocol/stages.py:320`):

   - Clustered intermediates:
     $\mathrm{im\_cluster} \cdot \prod D_j
     = \sum s_j \prod_{i \ne j} D_i$.
   - Singles: $\mathrm{im\_single} = s/D$.
   - Running sums:
     $\mathrm{gsum}[i] = \sum_{j \le i}
     \bigl(\sum_\ell \mathrm{im}_\ell[j] + s_0[j]/D_0[j]\bigr)$.
   - Running products:
     $\mathrm{gprod}[i] = \mathrm{gprod}[i{-}1] \cdot n_i/d_i$.

5. Extend all intermediate columns $h_1, \ldots, h_k$ to $H^*$.

6. Commit and absorb:

   $$
   r_2 = \MT(h_1, \ldots, h_k),
   \qquad \T.\abs(r_2).
   $$

## Quotient polynomial

({src}`protocol/prover.py:283`)

1. Squeeze the constraint-combination challenge:

   $$
   v_c \leftarrow \T.\sq(), \qquad v_c \in \Fext.
   $$

2. Evaluate the combined constraint on $H^*$
   ({src}`protocol/stages.py:566`):

   $$
   C(x) = v_c^{J-1} C_0(x) + v_c^{J-2} C_1(x)
          + \cdots + C_{J-1}(x),
   $$

   computed via Horner's method
   (see {ref}`app:constraints` for the constraint structure).

3. Divide by the vanishing polynomial:

   $$
   Q(x) = \frac{C(x)}{\ZH(x)} = \frac{C(x)}{x^N - 1}
   \quad \text{for } x \in H^*.
   $$

4. Split $Q$ into $d$ pieces of degree $< N$
   ({src}`protocol/stages.py:503`):

   $$
   Q(X) = Q_0(X) + X^N \cdot Q_1(X) + \cdots
          + X^{(d-1)N} \cdot Q_{d-1}(X).
   $$

   Concretely: convert $Q$ to coefficients via $\INTT_{N_{\mathrm{ext}}}$,
   extract each piece's coefficients,
   apply coset correction $S_j = g^{-jN}$,
   and extend each $Q_j$ back to $H^*$ via $\NTT_{N_{\mathrm{ext}}}$.

5. Commit and absorb:

   $$
   r_Q = \MT(Q_0, \ldots, Q_{d-1}),
   \qquad \T.\abs(r_Q).
   $$

## Polynomial evaluations

({src}`protocol/prover.py:318`)

1. Squeeze the evaluation challenge:

   $$
   \xi \leftarrow \T.\sq(), \qquad \xi \in \Fext.
   $$

2. For each committed polynomial $p$ and each opening offset $o \in \mathcal{O}$
   defined by the evaluation map, compute
   ({src}`protocol/stages.py:719`):

   $$
   e_{p,o} = p(\xi \cdot \omega^o) \in \Fext.
   $$

   This includes witness polynomials $f_j$,
   intermediate polynomials $h_j$,
   quotient pieces $Q_j$,
   and constant polynomials $c_j$.

3. Absorb a hash of all evaluations:

   $$
   \T.\abs\bigl(\LinHash(\{e_{p,o}\})\bigr).
   $$

## FRI polynomial

({src}`protocol/fri_polynomial.py:129`)

1. Squeeze the batching challenges:

   $$
   v_1 \leftarrow \T.\sq(), \qquad
   v_2 \leftarrow \T.\sq(),
   \qquad v_1, v_2 \in \Fext.
   $$

2. Group evaluation-map entries by opening-offset index.
   Let $\mathcal{G} = \{g_0, g_1, \ldots\}$ be the ordered set of
   distinct opening indices.

3. For each group $g$ with polynomials $p_0, \ldots, p_{n_g}$,
   evaluations $e_0, \ldots, e_{n_g}$, and offset $o_g$,
   compute the group polynomial:

   $$
   G_g(x) = \frac{1}{x - \xi \cdot \omega^{o_g}} \cdot
            \Bigl(
              v_2^{n_g}\bigl(p_0(x) - e_0\bigr) +
              v_2^{n_g-1}\bigl(p_1(x) - e_1\bigr) +
              \cdots +
              \bigl(p_{n_g}(x) - e_{n_g}\bigr)
            \Bigr).
   $$

4. Combine all groups (see {ref}`app:batching`):

   $$
   F(x) = v_1^{|\mathcal{G}|-1} \cdot G_{g_0}(x)
        + v_1^{|\mathcal{G}|-2} \cdot G_{g_1}(x)
        + \cdots + G_{g_{|\mathcal{G}|-1}}(x).
   $$

5. Evaluate $F$ on all of $H^*$.

## FRI commitment rounds

({src}`protocol/pcs.py:77`)

Set $F_0 = F$ and $b_0 = \log_2 N_{\mathrm{ext}}$.

For each FRI round $k = 0, 1, \ldots, K-1$:

1. **Commit** $F_k$ via Merkle tree.
   Tree height $2^{b_{k+1}}$,
   leaf width $2^{b_k - b_{k+1}} \cdot 3$ field elements.

   $$
   r_k^{\mathrm{FRI}} = \MT(F_k).
   $$

2. **Absorb** and **squeeze** the fold challenge:

   $$
   \T.\abs(r_k^{\mathrm{FRI}}),
   \qquad \beta_k \leftarrow \T.\sq(),
   \qquad \beta_k \in \Fext.
   $$

3. **Fold** ({src}`protocol/fri.py:25`):
   let $f_k = 2^{b_k - b_{k+1}}$ be the fold factor.
   For each output index $j \in [2^{b_{k+1}}]$:

   a. Gather $f_k$ evaluations:
      $\{F_k[j + i \cdot 2^{b_{k+1}}]\}_{i=0}^{f_k - 1}$.

   b. Interpolate to coefficients $(c_0, \ldots, c_{f_k-1})$
      via size-$f_k$ inverse transform.

   c. Coset correction:
      $c_i \leftarrow c_i \cdot
      (g^{-2^{n_{\mathrm{ext}} - b_k}} \cdot \omega_{b_k}^{-j})^i$.

   d. Evaluate at $\beta_k$ via Horner:
      $F_{k+1}[j] = \sum_i c_i \cdot \beta_k^i$.

After the final round, absorb a hash of the final polynomial:

$$
\T.\abs\bigl(\LinHash(F_K)\bigr).
$$

## Proof of work

({src}`protocol/pcs.py:98`)

1. Squeeze the grinding challenge:

   $$
   \chi_{\mathrm{grind}} \leftarrow \T.\sq().
   $$

2. Find a nonce $\eta \in \mathbb{Z}_{\geq 0}$ such that

   $$
   \Poseidon(\chi_{\mathrm{grind}} \,\|\, \eta)
   \text{ has } b_{\mathrm{pow}} \text{ leading zero bits}.
   $$

## Query openings

1. Seed a fresh transcript $\T'$ and derive query indices:

   $$
   \T'.\abs(\chi_{\mathrm{grind}},\; \eta),
   \qquad
   (q_1, \ldots, q_{Q_{\mathrm{queries}}})
   \leftarrow \T'.\sqidx(Q_{\mathrm{queries}},\; b_0).
   $$

2. For each query $q_i$ and each commitment tree
   (stages 1, 2, Q, constants, FRI layers $0, \ldots, K{-}1$):
   compute the Merkle opening proof at the appropriate index.

## Proof output

Return

$$
\pi = \bigl(
  r_1,\; r_2,\; r_Q,\;
  \{e_{p,o}\},\;
  \eta,\;
  \{r_k^{\mathrm{FRI}}\}_{k=0}^{K-1},\;
  F_K,\;
  \{\text{Merkle proofs}\}
\bigr).
$$

The total communication consists of $3 + K$ Merkle roots (each
$\in \F^4$), $|\{e_{p,o}\}|$ extension-field evaluations, the final
FRI polynomial $F_K \in \Fext^{2^{b_K}}$, one nonce $\eta$,
and Merkle authentication paths for each query.

---

## Verification

({src}`protocol/verifier.py:58`)

Given $(\mathrm{pub},\; \pi)$ and the common preprocessed input
(plus Merkle roots over constant columns),
the verifier replays the same transcript sequence
to rederive all challenges, then performs the following checks.

1. **Parse proof.** Extract from $\pi$:
   roots $(r_1, r_2, r_Q)$,
   evaluations $\{e_{p,o}\}$,
   FRI roots $\{r_k^{\mathrm{FRI}}\}$,
   final polynomial $F_K$,
   nonce $\eta$,
   Merkle proofs.

2. **Replay transcript** ({src}`protocol/verifier.py:382`).
   Execute the identical absorb/squeeze sequence as above:

   a. Seed $\T$ (standalone: $\T.\abs(\mathrm{vk}, \Hash(\mathrm{pub}), r_1)$;
      VADCOP: $\T.\abs(\chi)$).

   b. Squeeze $\alpha, \gamma \leftarrow \T.\sq()$.
      Absorb $\T.\abs(r_2)$.

   c. Squeeze $v_c \leftarrow \T.\sq()$.
      Absorb $\T.\abs(r_Q)$.

   d. Squeeze $\xi \leftarrow \T.\sq()$.
      Absorb $\T.\abs(\LinHash(\{e_{p,o}\}))$.

   e. Squeeze $v_1, v_2 \leftarrow \T.\sq()$.

   f. For each FRI round $k = 0, \ldots, K-1$:
      absorb $\T.\abs(r_k^{\mathrm{FRI}})$,
      squeeze $\beta_k \leftarrow \T.\sq()$.

   g. Absorb $\T.\abs(\LinHash(F_K))$.
      Squeeze $\chi_{\mathrm{grind}} \leftarrow \T.\sq()$.

3. **Proof-of-work check** ({src}`protocol/verifier.py:87`).

   $$
   \boxed{\Poseidon(\chi_{\mathrm{grind}} \| \eta)
   \text{ has } b_{\mathrm{pow}} \text{ leading zero bits.}}
   $$

4. **Constraint check** ({src}`protocol/verifier.py:724`).
   Evaluate the combined constraint at $\xi$ from the claimed evaluations:

   $$
   C(\xi) = v_c^{J-1} C_0(\xi) + v_c^{J-2} C_1(\xi) + \cdots + C_{J-1}(\xi),
   $$

   where each $C_j(\xi)$ is computed by substituting $\{e_{p,o}\}$ into
   the AIR constraint expressions
   (see {ref}`app:constraints`).
   Compute $\ZH(\xi) = \xi^N - 1$.
   Reconstruct $Q(\xi) = \sum_{j=0}^{d-1} \xi^{jN} \cdot e_{Q_j, 0}$.

   $$
   \boxed{Q(\xi) \stackrel{?}{=} \frac{C(\xi)}{\ZH(\xi)}.}
   $$

5. **Degree check** ({src}`protocol/verifier.py:964`).
   Convert $F_K$ to coefficient form via $\INTT$.
   Let $D = 2^{b_K - (n_{\mathrm{ext}} - n)}$.

   $$
   \boxed{\hat{F}_K[i] = 0 \quad \text{for all } i \ge D.}
   $$

6. **Query indices** ({src}`protocol/verifier.py:94`).
   Seed $\T'.\abs(\chi_{\mathrm{grind}}, \eta)$.
   Derive $(q_1, \ldots, q_{Q_{\mathrm{queries}}})
   \leftarrow \T'.\sqidx(Q_{\mathrm{queries}}, b_0)$.

7. **For each query $q \in \{q_1, \ldots, q_{Q_{\mathrm{queries}}}\}$:**

   a. **Merkle verification** ({src}`protocol/verifier.py:803`).
      For each commitment tree (stages 1, 2, Q, constants,
      FRI layers $0, \ldots, K{-}1$):
      hash the leaf, walk the authentication path,
      **check** computed root matches committed root.

   b. **FRI polynomial consistency** ({src}`protocol/verifier.py:758`).
      Let $x_q = g \cdot \omega_{\mathrm{ext}}^q$.
      From the polynomial values at $x_q$ (from Merkle proofs)
      and evaluations $\{e_{p,o}\}$,
      compute $F(x_q)$ via the batching formula
      ({ref}`app:batching`):

      $$
      F(x_q) = \sum_{g \in \mathcal{G}} v_1^{|\mathcal{G}|-1-g}
               \Biggl(
                 \frac{1}{x_q - \xi \omega^{o_g}}
                 \sum_{j=0}^{n_g} v_2^{n_g - j}
                 \bigl(p_j(x_q) - e_j\bigr)
               \Biggr).
      $$

      $$
      \boxed{F(x_q) \stackrel{?}{=} F_0[q].}
      $$

   c. **FRI fold verification** ({src}`protocol/verifier.py:905`).
      For each FRI round $k = 1, \ldots, K$:
      extract $f_k = 2^{b_{k-1} - b_k}$ sibling evaluations
      from the layer-$(k{-}1)$ Merkle proof.
      Interpolate to coefficients $(c_0, \ldots, c_{f_k - 1})$.
      Compute the transformed challenge point:

      $$
      \hat{\beta}_k = \frac{\beta_{k-1}}{g^{\,2^{n_{\mathrm{ext}} - b_{k-1}}}
                      \cdot \omega_{b_{k-1}}^{\,q}}.
      $$

      Evaluate:

      $$
      v = \sum_{i=0}^{f_k - 1} c_i \cdot \hat{\beta}_k^{\;i}.
      $$

      $$
      \boxed{v \stackrel{?}{=} F_k[q']
      \text{ (layer } k \text{ at folded index } q'\text{)}.}
      $$

      For the last round ($k = K$), check against $F_K$ directly.

8. **Accept** if and only if all boxed checks pass.
