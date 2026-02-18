(sec:full-protocol)=
# The Full Protocol, Rolled Out

For the reader's convenience, we present the complete PIL2-STARK protocol
as a self-contained description.
A few preliminary notes:

- The protocol is presented in the interactive model.
  In the actual (non-interactive) protocol, all verifier challenges
  are derived from the Fiat-Shamir transcript $\T$ using
  $\Hash = \Poseidon$.
  One can replace every "compute challenges" step below
  by the verifier sending random field elements to obtain
  the interactive protocol from which we derive the non-interactive one.
- $H = \{1, \omega, \omega^2, \ldots, \omega^{N-1}\}$ is the trace domain
  ($N$ a power of 2, $\omega$ a primitive $N$-th root of unity in $\F$).
  $H^* = \{g, g\omega, g\omega^2, \ldots, g\omega^{N_{\mathrm{ext}}-1}\}$
  is the evaluation domain (coset of a larger subgroup,
  $N_{\mathrm{ext}} = 4N$, $g = \mathsf{SHIFT}$).
- $\ZH(X) = X^N - 1$ is the vanishing polynomial of $H$.
- $\MT(\cdot)$ denotes Merkle tree commitment using $\Poseidon$ as the hash.
- All field elements are in $\F = \mathbb{F}_p$ (Goldilocks, $p = 2^{64} - 2^{32} + 1$)
  or $\Fext = \mathbb{F}_{p^3}$ (cubic extension).
  Challenges are drawn from $\Fext$.
- We use $\LinHash$ for Poseidon2 linear hashing of long vectors into
  a fixed-size digest.

**Common preprocessed input.**

$$
\begin{array}{l}
N \text{ (trace size)},\quad
N_{\mathrm{ext}} = 4N \text{ (evaluation domain size)},\quad
g = \mathsf{SHIFT} \text{ (coset generator)}, \\[4pt]
\text{Constraint polynomials } C_0(X), \ldots, C_{J-1}(X)
  \text{ defined by the AIR}, \\[4pt]
\text{Constant polynomials } c_1, \ldots, c_s : H \to \F, \\[4pt]
d = \lceil \deg(C) / N \rceil \text{ (number of quotient splits)}, \\[4pt]
\text{Evaluation map } \mathcal{E} = \{(p, o)\} \text{ pairing polynomials with opening offsets}, \\[4pt]
\text{FRI schedule } (b_0, b_1, \ldots, b_K) \text{ where }
  b_0 = \log_2 N_{\mathrm{ext}}, \\[4pt]
\text{Verification key } \mathrm{vk} \in \F^4, \quad
\text{Number of queries } Q_{\mathrm{queries}}, \quad
\text{Proof-of-work bits } b_{\mathrm{pow}}.
\end{array}
$$

**Public input.** $\mathrm{pub} \in \F^{\ell}$.

**Prover input.** Witness values $(w_{j,i})$ for $j \in [m]$, $i \in [N]$,
defining witness polynomials $f_j : H \to \F$ with $f_j(\omega^i) = w_{j,i}$.

## Prover algorithm

({src}`protocol/prover.py:58`)

```{list-table}
:widths: 42 8 42
:header-rows: 1
:class: protocol-table

* - **Prover**
  -
  - **Verifier**
* - ***Round 1: Witness commitment*** ({src}`protocol/prover.py:202`)
  -
  -
* - For each witness polynomial $f_j$ ($j = 1, \ldots, m$): extend from $H$ to $H^*$ via $\NTT$ on the coset, obtaining $N_{\mathrm{ext}}$ evaluations. Build Merkle tree over all stage-1 columns ({src}`protocol/stages.py:424`). Compute root $r_1 = \MT(f_1, \ldots, f_m)$.
  -
  -
* - $r_1$
  - $\longrightarrow$
  - $r_1$
* -
  -
  - **Seed transcript.** Standalone: $\T.\abs(\mathrm{vk},\; \Hash(\mathrm{pub}),\; r_1)$. VADCOP: $\T.\abs(\chi)$ where $\chi$ is the global challenge ({ref}`sec:challenge-binding`).
* - ***Round 2: Intermediate polynomials*** ({src}`protocol/prover.py:247`)
  -
  -
* - $(\alpha, \gamma)$
  - $\longleftarrow$
  - Compute challenges $\alpha, \gamma \in \Fext$: $\alpha \leftarrow \T.\sq()$, $\gamma \leftarrow \T.\sq()$.
* - Define the compressed expression: $\mathrm{compress}(b, c_1, \ldots, c_w) = ((\cdots((c_w \alpha + c_{w-1})\alpha + \cdots)\alpha + b) + \gamma$. For each logup term with bus $b_j$, columns $\mathbf{c}_j$, numerator $s_j$: set $D_j = \mathrm{compress}(b_j, \mathbf{c}_j)$. Compute intermediate columns ({src}`protocol/stages.py:320`): clustered intermediates $\mathrm{im\_cluster} \cdot \prod D_j = \sum s_j \prod_{i \ne j} D_i$, singles $\mathrm{im\_single} = s/D$, running sums $\mathrm{gsum}[i] = \sum_{j \le i} (\sum_\ell \mathrm{im}_\ell[j] + s_0[j]/D_0[j])$, running products $\mathrm{gprod}[i] = \mathrm{gprod}[i{-}1] \cdot n_i/d_i$. Extend all $h_1, \ldots, h_k$ to $H^*$. Commit: $r_2 = \MT(h_1, \ldots, h_k)$.
  -
  -
* - $r_2$
  - $\longrightarrow$
  - $r_2$
* -
  -
  - $\T.\abs(r_2)$
* - ***Round Q: Quotient polynomial*** ({src}`protocol/prover.py:283`)
  -
  -
* - $v_c$
  - $\longleftarrow$
  - $v_c \leftarrow \T.\sq()$
* - Evaluate the combined constraint on $H^*$ ({src}`protocol/stages.py:566`): $C(x) = v_c^{J-1} C_0(x) + v_c^{J-2} C_1(x) + \cdots + C_{J-1}(x)$ (Horner). Divide by vanishing polynomial: $Q(x) = C(x) / \ZH(x)$. Convert to coefficients via $\INTT_{N_{\mathrm{ext}}}$. Split into $d$ pieces of degree $< N$ ({src}`protocol/stages.py:503`): $Q(X) = Q_0(X) + X^N Q_1(X) + \cdots + X^{(d{-}1)N} Q_{d-1}(X)$, with coset correction $S_j = g^{-jN}$. Extend each $Q_j$ to $H^*$ via $\NTT_{N_{\mathrm{ext}}}$. Commit: $r_Q = \MT(Q_0, \ldots, Q_{d-1})$.
  -
  -
* - $r_Q$
  - $\longrightarrow$
  - $r_Q$
* -
  -
  - $\T.\abs(r_Q)$
* - ***Evaluation stage*** ({src}`protocol/prover.py:318`)
  -
  -
* - $\xi$
  - $\longleftarrow$
  - $\xi \leftarrow \T.\sq()$, $\xi \in \Fext$
* - For each committed polynomial $p$ (witness $f_j$, intermediate $h_j$, quotient $Q_j$, constant $c_j$) and each opening offset $o \in \mathcal{O}$ defined by the evaluation map ({src}`protocol/stages.py:719`): compute $e_{p,o} = p(\xi \cdot \omega^o) \in \Fext$.
  -
  -
* - $\{e_{p,o}\}$
  - $\longrightarrow$
  - $\{e_{p,o}\}$
* -
  -
  - $\T.\abs\bigl(\LinHash(\{e_{p,o}\})\bigr)$
* - ***FRI polynomial*** ({src}`protocol/fri_polynomial.py:129`)
  -
  -
* - $(v_1, v_2)$
  - $\longleftarrow$
  - $v_1, v_2 \leftarrow \T.\sq()$
* - Group evaluation-map entries by opening-offset index: $\mathcal{G} = \{g_0, g_1, \ldots\}$. For each group $g$ with polynomials $p_0, \ldots, p_{n_g}$, evaluations $e_0, \ldots, e_{n_g}$, and offset $o_g$: $G_g(x) = \frac{1}{x - \xi\omega^{o_g}} \bigl(v_2^{n_g}(p_0(x) - e_0) + v_2^{n_g-1}(p_1(x) - e_1) + \cdots + (p_{n_g}(x) - e_{n_g})\bigr)$. Combine: $F(x) = v_1^{|\mathcal{G}|-1} G_{g_0}(x) + v_1^{|\mathcal{G}|-2} G_{g_1}(x) + \cdots + G_{g_{|\mathcal{G}|-1}}(x)$.
  -
  -
* - ***FRI commitment rounds*** ({src}`protocol/pcs.py:77`)
  -
  -
* - Set $F_0 = F$, $b_0 = \log_2 N_{\mathrm{ext}}$.
  -
  -
* - Commit: $r_0^{\mathrm{FRI}} = \MT(F_0)$, tree height $2^{b_1}$, leaf width $2^{b_0 - b_1} \cdot 3$.
  - $\longrightarrow$
  - $r_0^{\mathrm{FRI}}$; $\T.\abs(r_0^{\mathrm{FRI}})$
* - $\beta_0$
  - $\longleftarrow$
  - $\beta_0 \leftarrow \T.\sq()$
* - $\Fold$: for each $j \in [2^{b_1}]$, gather $\{F_0[j + i \cdot 2^{b_1}]\}_{i=0}^{f_0 - 1}$ where $f_0 = 2^{b_0 - b_1}$. Interpolate to coefficients $(c_0, \ldots, c_{f_0-1})$. Coset correction: $c_i \leftarrow c_i \cdot (g^{-1} \cdot \omega_{b_0}^{-j})^i$. Evaluate at $\beta_0$: $F_1[j] = \sum_i c_i \beta_0^i$ ({src}`protocol/fri.py:25`).
  -
  -
* - $\vdots$
  -
  - $\vdots$
* - Commit: $r_{K-1}^{\mathrm{FRI}} = \MT(F_{K-1})$, tree height $2^{b_K}$, leaf width $2^{b_{K-1} - b_K} \cdot 3$.
  - $\longrightarrow$
  - $r_{K-1}^{\mathrm{FRI}}$; $\T.\abs(r_{K-1}^{\mathrm{FRI}})$
* - $\beta_{K-1}$
  - $\longleftarrow$
  - $\beta_{K-1} \leftarrow \T.\sq()$
* - $\Fold$: for each $j \in [2^{b_K}]$, gather $\{F_{K-1}[j + i \cdot 2^{b_K}]\}_{i=0}^{f_{K-1} - 1}$. Interpolate. Coset correct: $c_i \leftarrow c_i \cdot (g^{-2^{n_{\mathrm{ext}} - b_{K-1}}} \cdot \omega_{b_{K-1}}^{-j})^i$. Evaluate: $F_K[j] = \sum_i c_i \beta_{K-1}^i$.
  -
  -
* - $F_K$
  - $\longrightarrow$
  - $F_K$; $\T.\abs\bigl(\LinHash(F_K)\bigr)$.
* - ***Proof of work*** ({src}`protocol/pcs.py:98`)
  -
  -
* - $\chi_{\mathrm{grind}}$
  - $\longleftarrow$
  - $\chi_{\mathrm{grind}} \leftarrow \T.\sq()$
* - Find $\eta \in \mathbb{Z}_{\geq 0}$ such that $\Poseidon(\chi_{\mathrm{grind}} \,\|\, \eta)$ has $b_{\mathrm{pow}}$ leading zero bits.
  -
  -
* - $\eta$
  - $\longrightarrow$
  - $\eta$
* - ***Query phase***
  -
  -
* - Both sides derive query indices from $(\chi_{\mathrm{grind}}, \eta)$
  - $=$
  - Seed fresh transcript $\T'.\abs(\chi_{\mathrm{grind}}, \eta)$. Derive $(q_1, \ldots, q_{Q_{\mathrm{queries}}}) \leftarrow \T'.\sqidx(Q_{\mathrm{queries}}, b_0)$.
* - For each $q_i$ and each commitment tree: compute Merkle opening proof at the appropriate index.
  - $\longrightarrow$
  - $\{\text{Merkle proofs}\}$
```

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

The total prover communication consists of $3 + K$ Merkle roots (each
$\in \F^4$), $|\{e_{p,o}\}|$ extension-field evaluations, the final
FRI polynomial $F_K \in \Fext^{2^{b_K}}$, one nonce $\eta$,
and Merkle authentication paths for each query.

## Verifier algorithm

({src}`protocol/verifier.py:58`)

**Verifier preprocessed input.**
The same common preprocessed input as above, plus commitments to the
constant polynomials (Merkle root over the constant columns).

**Verifier input.** $(\mathrm{pub},\; \pi)$.

1. **Parse proof.** Extract from $\pi$:
   roots $(r_1, r_2, r_Q)$,
   evaluations $\{e_{p,o}\}$,
   FRI roots $\{r_k^{\mathrm{FRI}}\}$,
   final polynomial $F_K$,
   nonce $\eta$,
   Merkle proofs.

2. **Reconstruct transcript** ({src}`protocol/verifier.py:382`).
   Replay the prover's Fiat-Shamir transcript to rederive all challenges.
   The operations must occur in exactly the same order as during proving:

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
   the AIR constraint expressions.
   Compute the vanishing polynomial: $\ZH(\xi) = \xi^N - 1$.
   Reconstruct the quotient: $Q(\xi) = \sum_{j=0}^{d-1} \xi^{jN} \cdot e_{Q_j, 0}$.

   $$
   \boxed{Q(\xi) \stackrel{?}{=} \frac{C(\xi)}{\ZH(\xi)}.}
   $$

5. **Final polynomial degree check** ({src}`protocol/verifier.py:964`).
   Convert $F_K$ from evaluation form to coefficient form
   via $\INTT$.
   Let $D = 2^{b_K - (n_{\mathrm{ext}} - n)}$ be the degree bound.

   $$
   \boxed{\hat{F}_K[i] = 0 \quad \text{for all } i \ge D.}
   $$

6. **Derive query indices** ({src}`protocol/verifier.py:94`).
   Seed fresh transcript $\T'.\abs(\chi_{\mathrm{grind}}, \eta)$.
   Derive $(q_1, \ldots, q_{Q_{\mathrm{queries}}})
   \leftarrow \T'.\sqidx(Q_{\mathrm{queries}}, b_0)$.

7. **For each query $q \in \{q_1, \ldots, q_{Q_{\mathrm{queries}}}\}$:**

   a. **Merkle verification** ({src}`protocol/verifier.py:803`).
      For each commitment tree (stages 1, 2, Q, constants,
      FRI layers $0, \ldots, K{-}1$):
      hash the leaf values, walk the authentication path,
      **check** computed root matches the committed root.

   b. **FRI polynomial consistency** ({src}`protocol/verifier.py:758`).
      Let $x_q = g \cdot \omega_{\mathrm{ext}}^q$.
      From the polynomial values at $x_q$ (extracted from Merkle proofs)
      and the claimed evaluations $\{e_{p,o}\}$,
      compute $F(x_q)$ via the batching formula:

      $$
      F(x_q) = \sum_{g \in \mathcal{G}} v_1^{|\mathcal{G}|-1-g}
               \Biggl(
                 \frac{1}{x_q - \xi \omega^{o_g}}
                 \sum_{j=0}^{n_g} v_2^{n_g - j}
                 \bigl(p_j(x_q) - e_j\bigr)
               \Biggr).
      $$

      $$
      \boxed{F(x_q) \stackrel{?}{=} F_0[q] \text{ (FRI layer 0 at query } q\text{)}.}
      $$

   c. **FRI fold verification** ({src}`protocol/verifier.py:905`).
      For each FRI round $k = 1, \ldots, K$:
      extract the $f_k = 2^{b_{k-1} - b_k}$ sibling evaluations from the
      layer-$(k{-}1)$ Merkle proof.
      Interpolate to coefficients $(c_0, \ldots, c_{f_k - 1})$.
      Apply coset correction and evaluate at the transformed challenge:

      $$
      \hat{\beta}_k = \frac{\beta_{k-1}}{g^{\,2^{n_{\mathrm{ext}} - b_{k-1}}}
                      \cdot \omega_{b_{k-1}}^{\,q}}.
      $$

      $$
      v = \sum_{i=0}^{f_k - 1} c_i \cdot \hat{\beta}_k^{\;i}.
      $$

      $$
      \boxed{v \stackrel{?}{=} F_k[q'] \text{ (layer } k \text{ at the folded index } q'\text{)}.}
      $$

      For the last round ($k = K$), check against $F_K$ directly.

8. **Accept** if and only if all boxed checks pass.
