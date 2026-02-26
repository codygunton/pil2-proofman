(sec:full-protocol)=
# The Full Protocol, Rolled Out

This section presents the complete PIL2-STARK protocol
as a single self-contained reference.
All notation and parameters follow {ref}`sec:notation`.
The table references
{ref}`app:constraints`,
{ref}`app:batching`,
and {ref}`sec:challenge-binding`.

```{list-table}
:widths: 42 8 42
:header-rows: 1
:class: protocol-table

* - **Prover**
  -
  - **Verifier**
* - ***Round 1: Witness commitment*** ({src}`protocol/prover.py#witness-commit`)
  -
  -
* - Extend each $f_j$ from $H$ to $H^*$ via $\NTT$ ({src}`protocol/stages.py#extend-to-coset`).
    <br>$r_1 := \MT(f_1, \ldots, f_m)$.
  -
  -
* - $r_1$
  - $\longrightarrow$
  - $r_1$
* -
  -
  - **Seed transcript** ({src}`protocol/verifier.py#transcript-reconstruct`).
    <br>Standalone: $\T.\abs(\mathrm{vk},\; \Hash(\mathrm{pub}),\; r_1)$ ({src}`protocol/prover.py#transcript-seed-standalone`).
    <br>VADCOP: $\T.\abs(\chi)$, $\chi$ = global challenge ({ref}`sec:challenge-binding`, {src}`protocol/prover.py#transcript-seed-vadcop`).
* - ***Round 2: Intermediate polynomials*** ({src}`protocol/prover.py#derive-stage2-challenges`)
  -
  -
* - $(\alpha, \gamma)$
  - $\longleftarrow$
  - $\alpha \leftarrow \T.\sq(),\; \gamma \leftarrow \T.\sq()$, both $\in \Fext$.
* - $\mathrm{compress}(b, c_1, \ldots, c_w) := ((\cdots((c_w \alpha + c_{w-1})\alpha + \cdots)\alpha + b) + \gamma$ ({src}`constraints.base.compress_2col`).
    <br>$D_j := \mathrm{compress}(b_j, \mathbf{c}_j)$ for bus $b_j$, columns $\mathbf{c}_j$, numerator $s_j$.
    <br>$\mathrm{im\_cluster} \cdot \prod D_j = \sum s_j \prod_{i \ne j} D_i$ ({src}`protocol/stages.py#compute-intermediates`).
    <br>$\mathrm{im\_single} = s/D$.
    <br>$\mathrm{gsum}[i] = \sum_{j \le i} (\sum_\ell \mathrm{im}_\ell[j] + s_0[j]/D_0[j])$ ({src}`protocol/stages.py#compute-grand-sums`).
    <br>$\mathrm{gprod}[i] = \mathrm{gprod}[i{-}1] \cdot n_i/d_i$.
    <br>Extend $h_1, \ldots, h_k$ to $H^*$ ({src}`protocol/stages.py#extend-to-coset`).
    <br>$r_2 := \MT(h_1, \ldots, h_k)$.
  -
  -
* - $r_2$
  - $\longrightarrow$
  - $r_2$; $\T.\abs(r_2)$
* - ***Round Q: Quotient polynomial*** ({src}`protocol/prover.py#derive-stageq-challenges`)
  -
  -
* - $v_c$
  - $\longleftarrow$
  - $v_c \leftarrow \T.\sq()$, $v_c \in \Fext$
* - $C(x) := v_c^{J-1} C_0(x) + v_c^{J-2} C_1(x) + \cdots + C_{J-1}(x)$ ({ref}`app:constraints`, {src}`protocol/stages.py#calc-constraint-polynomial`).
    <br>$Q(x) := C(x) / \ZH(x)$ ({src}`protocol/stages.py#divide-by-zerofier`).
    <br>$\INTT_{N_{\mathrm{ext}}}$ to coefficients ({src}`protocol/stages.py#intt-to-coeffs`).
    <br>$Q(X) = Q_0(X) + X^N Q_1(X) + \cdots + X^{(d{-}1)N} Q_{d-1}(X)$, $S_j := g^{-jN}$ ({src}`protocol/stages.py#quotient-split`).
    <br>$\NTT_{N_{\mathrm{ext}}}$ each $Q_j$ to $H^*$ ({src}`protocol/stages.py#ntt-quotient-pieces`).
    <br>$r_Q := \MT(Q_0, \ldots, Q_{d-1})$.
  -
  -
* - $r_Q$
  - $\longrightarrow$
  - $r_Q$; $\T.\abs(r_Q)$
* - ***Evaluation stage*** ({src}`protocol/prover.py#derive-eval-challenges`)
  -
  -
* - $\xi$
  - $\longleftarrow$
  - $\xi \leftarrow \T.\sq()$, $\xi \in \Fext$
* - $e_{p,o} := p(\xi \cdot \omega^o) \in \Fext$ for each polynomial $p$, offset $o \in \mathcal{O}$ ({src}`protocol/stages.py#compute-evals`).
    <br>Includes witness $f_j$, intermediate $h_j$, quotient $Q_j$, constant $c_j$.
  -
  -
* - $\{e_{p,o}\}$
  - $\longrightarrow$
  - $\{e_{p,o}\}$; $\T.\abs\bigl(\LinHash(\{e_{p,o}\})\bigr)$
* - ***FRI polynomial*** ({src}`protocol/fri_polynomial.py#batching-prover`)
  -
  -
* - $(v_1, v_2)$
  - $\longleftarrow$
  - $v_1, v_2 \leftarrow \T.\sq()$, both $\in \Fext$
* - $\mathcal{G} := \{g_0, g_1, \ldots\}$ grouped by opening offset ({src}`protocol/fri_polynomial.py#group-by-opening`).
    <br>$G_g(x) := \frac{1}{x - \xi\omega^{o_g}} \bigl(v_2^{n_g}(p_0(x) - e_0) + \cdots + (p_{n_g}(x) - e_{n_g})\bigr)$.
    <br>$F(x) := v_1^{|\mathcal{G}|-1} G_{g_0}(x) + v_1^{|\mathcal{G}|-2} G_{g_1}(x) + \cdots + G_{g_{|\mathcal{G}|-1}}(x)$ ({ref}`app:batching`).
  -
  -
* - ***FRI commitment rounds*** ({src}`protocol.pcs.FriPcs.prove`)
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
  - $\beta_0 \leftarrow \T.\sq()$, $\beta_0 \in \Fext$
* - $\Fold$ ({src}`protocol.fri.FRI.fold`):
    <br>$f_0 := 2^{b_0 - b_1}$; gather $\{F_0[j + i \cdot 2^{b_1}]\}_{i=0}^{f_0 - 1}$ per $j \in [2^{b_1}]$.
    <br>Interpolate to $(c_0, \ldots, c_{f_0-1})$.
    <br>$c_i \leftarrow c_i \cdot (g^{-1} \cdot \omega_{b_0}^{-j})^i$.
    <br>$F_1[j] := \sum_i c_i \beta_0^i$.
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
* - $\Fold$:
    <br>$f_{K-1} := 2^{b_{K-1} - b_K}$; gather $\{F_{K-1}[j + i \cdot 2^{b_K}]\}_{i=0}^{f_{K-1} - 1}$ per $j \in [2^{b_K}]$.
    <br>Interpolate.
    <br>$c_i \leftarrow c_i \cdot (g^{-2^{n_{\mathrm{ext}} - b_{K-1}}} \cdot \omega_{b_{K-1}}^{-j})^i$.
    <br>$F_K[j] := \sum_i c_i \beta_{K-1}^i$.
  -
  -
* - $F_K$
  - $\longrightarrow$
  - $F_K$; $\T.\abs\bigl(\LinHash(F_K)\bigr)$
* - ***Grinding*** ({src}`protocol.pcs.FriPcs.prove`)
  -
  -
* - $\chi_{\mathrm{grind}}$
  - $\longleftarrow$
  - $\chi_{\mathrm{grind}} \leftarrow \T.\sq()$
* - Find $\eta$: $\Poseidon(\chi_{\mathrm{grind}} \| \eta)$ has $b_{\mathrm{pow}}$ leading zeros.
  -
  -
* - $\eta$
  - $\longrightarrow$
  - $\eta$.
    <br>**Check:** $\Poseidon(\chi_{\mathrm{grind}} \| \eta)$ has $b_{\mathrm{pow}}$ leading zeros.
* - ***Constraint check*** ({src}`protocol/verifier.py#constraint-check`)
  -
  -
* -
  -
  - $C(\xi) := v_c^{J-1} C_0(\xi) + \cdots + C_{J-1}(\xi)$ from $\{e_{p,o}\}$ ({ref}`app:constraints`, {src}`protocol/verifier.py#compute-constraint`).
    <br>$\ZH(\xi) := \xi^N - 1$ ({src}`protocol/verifier.py#compute-vanishing`).
    <br>$Q(\xi) := \sum_{j=0}^{d-1} \xi^{jN} e_{Q_j, 0}$ ({src}`protocol/verifier.py#quotient-reconstruct`).
    <br>**Check:** $Q(\xi) = C(\xi)/\ZH(\xi)$ ({src}`protocol/verifier.py#verify-quotient-div`).
* - ***Degree check*** ({src}`protocol/verifier.py#degree-check`)
  -
  -
* -
  -
  - $\hat{F}_K := \INTT(F_K)$ ({src}`protocol/verifier.py#final-poly-intt`).
    <br>$D := 2^{b_K - (n_{\mathrm{ext}} - n)}$ ({src}`protocol/verifier.py#degree-bound`).
    <br>**Check:** $\hat{F}_K[i] = 0$ for $i \ge D$ ({src}`protocol/verifier.py#check-high-coeffs`).
* - ***Query phase*** ({src}`protocol.verifier.stark_verify`)
  -
  -
* - Both sides derive query indices
  - $=$
  - $\T'.\abs(\chi_{\mathrm{grind}}, \eta)$ ({src}`protocol/verifier.py#derive-queries`).
    <br>$(q_1, \ldots, q_{Q_{\mathrm{queries}}}) \leftarrow \T'.\sqidx(Q_{\mathrm{queries}}, b_0)$ ({src}`protocol/verifier.py#verifier-squeeze-query-indices`).
* - Merkle opening proof at $q_i$ for each tree ({src}`protocol/prover.py#collect-query-proofs`).
  - $\longrightarrow$
  - $\{\text{Merkle proofs}\}$
* - ***Per-query checks*** ({src}`protocol/verifier.py#stage-merkle-check`)
  -
  -
* -
  -
  - For each query $q$:
    <br>**Merkle.** Hash leaf, walk path for each tree (stages 1, 2, Q, constants, FRI $0, \ldots, K{-}1$) ({src}`protocol/verifier.py#stage-merkle-check`).
    <br>**Check:** root $=$ committed root.
* -
  -
  - **FRI polynomial consistency** ({src}`protocol.verifier._verify_fri_consistency`).
    <br>$x_q := g \cdot \omega_{\mathrm{ext}}^q$.
    <br>$F(x_q) := \sum_{g \in \mathcal{G}} v_1^{|\mathcal{G}|-1-g} \bigl(\frac{1}{x_q - \xi\omega^{o_g}} \sum_{j} v_2^{n_g-j} (p_j(x_q) - e_j)\bigr)$ ({ref}`app:batching`, {src}`protocol/fri_polynomial.py#batching-formula`).
    <br>**Check:** $F(x_q) = F_0[q]$.
* -
  -
  - **FRI fold verification** ({src}`protocol.verifier._verify_fri_folding`, {src}`protocol.fri.FRI.verify_fold`).
    <br>$f_k := 2^{b_{k-1}-b_k}$ siblings from layer-$(k{-}1)$ proof, per round $k = 1, \ldots, K$.
    <br>Interpolate to $(c_0, \ldots, c_{f_k-1})$.
    <br>$\hat\beta_k := \beta_{k-1} / (g^{2^{n_{\mathrm{ext}}-b_{k-1}}} \cdot \omega_{b_{k-1}}^q)$.
    <br>$v := \sum_i c_i \hat\beta_k^i$.
    <br>**Check:** $v = F_k[q']$; last round against $F_K$ directly.
* -
  -
  - **Accept** iff all checks pass.
```

**Proof output.** $\pi = \bigl(r_1, r_2, r_Q, \{e_{p,o}\}, \eta, \{r_k^{\mathrm{FRI}}\}_{k=0}^{K-1}, F_K, \{\text{Merkle proofs}\}\bigr)$,
plus $\chi$ (the global challenge used to seed the transcript, needed for verifier replay).

Communication: $3 + K$ Merkle roots ($\in \F^4$ each),
$|\{e_{p,o}\}|$ extension-field evaluations,
$F_K \in \Fext^{2^{b_K}}$, nonce $\eta$,
and Merkle paths for each query.
