(sec:query-phase)=
(protocol:query-phase)=
# STARK Protocol: Query Phase

The query phase is the second half of the STARK protocol.
The verifier receives the proof $\pi$, the verification key $\mathrm{vk}$,
the public inputs, and the AIR constraint definitions.
It first replays the prover's transcript to rederive all challenges,
then performs the checks shown below.

**PIL2-STARK: Query Phase**

```{list-table}
:widths: 42 8 42
:header-rows: 1
:class: protocol-table

* - **Prover**
  -
  - **Verifier**
* - ***Setup: Transcript reconstruction***
  -
  -
* -
  -
  - Replay transcript from proof data to rederive all challenges $(\alpha, \gamma, v_c, \xi, v_1, v_2, \{\beta_k\}, \chi_{\mathrm{grind}})$
* - ***Constraint check***
  -
  -
* -
  -
  - Evaluate $C(\xi)$ from $\{e_{p,o}\}$. Reconstruct $Q(\xi) = \sum_j \xi^{jN} e_{Q_j,0}$. **Check:** $Q(\xi) = C(\xi)/\ZH(\xi)$
* - ***Proof-of-work check***
  -
  -
* -
  -
  - **Check:** $\Poseidon(\chi_{\mathrm{grind}} \| \eta)$ has $b_{\mathrm{pow}}$ leading zeros
* - ***Final polynomial degree check***
  -
  -
* -
  -
  - $\hat{F}_K = \INTT(F_K)$. **Check:** $\hat{F}_K[i] = 0$ for $i \geq D$
* - ***Query derivation and verification***
  -
  -
* - Both sides hold all commitments, challenges, and $\eta$
  - $=$
  - Both sides hold all commitments, challenges, and $\eta$
* -
  -
  - Seed $\T'$ from $(\chi_{\mathrm{grind}}, \eta)$
* - $(q_1, \ldots, q_{Q_{\mathrm{queries}}})$
  - $\longleftarrow$
  - $(q_1, \ldots, q_{Q_{\mathrm{queries}}}) \leftarrow \T'.\sqidx(Q_{\mathrm{queries}}, b_0)$
* - For each query $q_i$ and each commitment tree (stages $1, 2, Q$, constants, FRI layers $0, \ldots, K-1$): compute Merkle opening proof at the appropriate index
  - $\longrightarrow$
  - For each query $q_i$: **Check:** all Merkle proofs verify against committed roots. Let $x_{q_i} = g \cdot \omega_{\mathrm{ext}}^{q_i}$. **Check:** $F(x_{q_i})$ from batching formula matches FRI layer 0 at $q_i$. For each FRI round $k = 1, \ldots, K$: interpolate coset siblings, apply coset correction, evaluate at $\hat\beta_k$. **Check:** result matches layer $k$
* -
  -
  - **Accept** iff all checks pass
```

The following subsections detail each check shown in the diagram above.

(sec:transcript-reconstruction)=
## Transcript Reconstruction

The verifier replays the prover's Fiat-Shamir transcript to rederive all challenges.
The transcript operations must occur in exactly the same order as during proving:

1. Seed the transcript (same as prover: multi-AIR or standalone mode).

2. For each stage $s = 2, \ldots, S+1$:
   squeeze the stage-$s$ challenges, then absorb $r_s$ and any
   intermediate values for stage $s$.

3. Squeeze the evaluation challenge $\xi$.

4. Absorb the evaluation hash $\LinHash(\{e_{p,o}\})$.

5. Squeeze the batching challenges $v_1, v_2$.

6. For each FRI round $k = 0, \ldots, K-1$:
   absorb $r_k^{\mathrm{FRI}}$ and squeeze the fold challenge $\beta_k$.

7. Absorb $\LinHash(F_K)$.

8. Squeeze the grinding challenge $\chi_{\mathrm{grind}}$.

(sec:constraint-check)=
## Constraint Check

Verify that the quotient polynomial is consistent with the constraint polynomial.

1. Evaluate the combined constraint polynomial at $\xi$
   using the claimed evaluations $\{e_{p,o}\}$:

   $$
   C(\xi) = v_c^{J-1} \cdot C_0(\xi) + v_c^{J-2} \cdot C_1(\xi)
            + \cdots + C_{J-1}(\xi),
   $$

   where each $C_j(\xi)$ is computed from the evaluations via the
   AIR constraint expressions and $J$ is the number of constraints.

2. Compute the vanishing polynomial at $\xi$:

   $$
   \ZH(\xi) = \xi^N - 1.
   $$

3. Reconstruct the quotient evaluation from the split pieces:

   ```{math}
   :label: eq-quotient-reconstruct
   Q(\xi) = \sum_{j=0}^{d-1} \xi^{jN} \cdot e_{Q_j, 0}.
   ```

4. **Check:**

   ```{math}
   :label: eq-constraint-check
   \boxed{Q(\xi) = \frac{C(\xi)}{\ZH(\xi)}.}
   ```

(sec:pow-check)=
## Proof-of-Work Check

**Check:**

$$
\Poseidon(\chi_{\mathrm{grind}} \,\|\, \eta)
\text{ has } b_{\mathrm{pow}} \text{ leading zero bits}.
$$

(sec:degree-check)=
## Final Polynomial Degree Check

1. Convert the final polynomial $F_K$ from evaluation form to coefficient form
   via $\INTT$.

2. Let $D = 2^{b_K - (n_{\mathrm{ext}} - n)}$ be the degree bound.

3. **Check:** all coefficients above degree $D$ are zero:

   $$
   \hat{F}_K[i] = 0 \quad \text{for all } i \geq D.
   $$

(sec:queries)=
## Query Derivation

1. Initialize a fresh transcript $\T'$ and seed it:

   $$
   \T'.\abs(\chi_{\mathrm{grind}},\; \eta).
   $$

2. Derive $Q_{\mathrm{queries}}$ query indices:

   $$
   (q_1, \ldots, q_{Q_{\mathrm{queries}}})
   \;\leftarrow\; \T'.\sqidx(Q_{\mathrm{queries}},\; b_0).
   $$

(sec:merkle-check)=
## Merkle Tree Verification

For each query $q$ and each commitment
(stage 1, stage 2, quotient, constants, and any custom commits):

1. Hash the leaf values via Poseidon2 linear hashing.
2. Walk the authentication path using the provided siblings.
3. **Check:** the computed root matches the committed root.

(sec:fri-consistency)=
## FRI Polynomial Consistency

For each query point $q \in \{q_1, \ldots, q_{Q_{\mathrm{queries}}}\}$:

1. Let $x_q = g \cdot \omega_{\mathrm{ext}}^q \in H^*$ be the evaluation point.

2. Using the polynomial values extracted from Merkle proofs at index $q$,
   compute $F(x_q)$ via the batching formula {eq}`eq-fri-polynomial`:

   $$
   F(x_q) = \sum_{g \in \mathcal{G}} v_1^{|\mathcal{G}|-1-g}
            \Biggl(
              \frac{1}{x_q - \xi \cdot \omega^{o_g}}
              \sum_{j=0}^{n_g} v_2^{n_g - j}
              \bigl(p_j(x_q) - e_j\bigr)
            \Biggr).
   $$

3. **Check:** $F(x_q)$ matches the value committed in the first FRI layer
   at the corresponding index.

(sec:fri-fold-verify)=
## FRI Folding Verification

For each FRI round $k = 1, \ldots, K$ and each query $q$:

1. Extract the $f = 2^{b_{k-1} - b_k}$ sibling evaluations from the
   layer-$(k-1)$ Merkle proof (all members of the coset group
   containing query $q$).

2. Interpolate the siblings to coefficient form
   (size-$f$ interpolation).

3. Apply coset correction and evaluate at the transformed challenge point:

   $$
   \hat{\beta}_k = \frac{\beta_{k-1}}{g^{\,2^{n_{\mathrm{ext}} - b_{k-1}}} \cdot \omega_{b_{k-1}}^{\,q}},
   $$

   where $\omega_{b_{k-1}}$ is the primitive $2^{b_{k-1}}$-th root of unity
   and $g^{2^{n_{\mathrm{ext}} - b_{k-1}}}$ is the accumulated coset shift
   at FRI level $k-1$.

4. Compute the folded value:

   $$
   v = \sum_{i=0}^{f-1} c_i \cdot \hat{\beta}_k^{\;i},
   $$

   where $c_0, \ldots, c_{f-1}$ are the interpolated coefficients.

5. **Check:**
   $v$ matches the committed value in layer $k$
   (or in the final polynomial $F_K$ for the last round).

**Acceptance.**
The verifier accepts if and only if all checks in
{ref}`sec:constraint-check`, {ref}`sec:pow-check`, {ref}`sec:degree-check`, {ref}`sec:merkle-check`, {ref}`sec:fri-consistency`, {ref}`sec:fri-fold-verify` pass.
