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
* - ***Round 1: Witness commitment*** ({src}`protocol/prover.py:202`)
  -
  -
* - For each witness polynomial $f_j$: extend from $H$ to $H^*$ via $\NTT$ on the coset. Build Merkle tree ({src}`protocol/stages.py:424`). Compute $r_1 = \MT(f_1, \ldots, f_m)$.
  -
  -
* - $r_1$
  - $\longrightarrow$
  - $r_1$
* -
  -
  - **Seed transcript** ({src}`protocol/prover.py:207`). Standalone: $\T.\abs(\mathrm{vk},\; \Hash(\mathrm{pub}),\; r_1)$. VADCOP: $\T.\abs(\chi)$ where $\chi$ is the global challenge ({ref}`sec:challenge-binding`).
* - ***Round 2: Intermediate polynomials*** ({src}`protocol/prover.py:247`)
  -
  -
* - $(\alpha, \gamma)$
  - $\longleftarrow$
  - $\alpha \leftarrow \T.\sq(),\; \gamma \leftarrow \T.\sq()$, both $\in \Fext$.
* - Define $\mathrm{compress}(b, c_1, \ldots, c_w) = ((\cdots((c_w \alpha + c_{w-1})\alpha + \cdots)\alpha + b) + \gamma$. For each logup term with bus $b_j$, columns $\mathbf{c}_j$, numerator $s_j$: set $D_j = \mathrm{compress}(b_j, \mathbf{c}_j)$. Compute intermediate columns ({src}`protocol/stages.py:320`): clustered intermediates $\mathrm{im\_cluster} \cdot \prod D_j = \sum s_j \prod_{i \ne j} D_i$, singles $\mathrm{im\_single} = s/D$, running sums $\mathrm{gsum}[i] = \sum_{j \le i} (\sum_\ell \mathrm{im}_\ell[j] + s_0[j]/D_0[j])$, running products $\mathrm{gprod}[i] = \mathrm{gprod}[i{-}1] \cdot n_i/d_i$. Extend all $h_1, \ldots, h_k$ to $H^*$. Commit: $r_2 = \MT(h_1, \ldots, h_k)$.
  -
  -
* - $r_2$
  - $\longrightarrow$
  - $r_2$; $\T.\abs(r_2)$
* - ***Round Q: Quotient polynomial*** ({src}`protocol/prover.py:283`)
  -
  -
* - $v_c$
  - $\longleftarrow$
  - $v_c \leftarrow \T.\sq()$, $v_c \in \Fext$
* - Evaluate combined constraint on $H^*$ ({src}`protocol/stages.py:566`): $C(x) = v_c^{J-1} C_0(x) + v_c^{J-2} C_1(x) + \cdots + C_{J-1}(x)$ (Horner; see {ref}`app:constraints`). Divide: $Q(x) = C(x) / \ZH(x)$. $\INTT_{N_{\mathrm{ext}}}$ to coefficients. Split into $d$ pieces of degree $< N$ ({src}`protocol/stages.py:503`): $Q(X) = Q_0(X) + X^N Q_1(X) + \cdots + X^{(d{-}1)N} Q_{d-1}(X)$, coset correction $S_j = g^{-jN}$. $\NTT_{N_{\mathrm{ext}}}$ each $Q_j$ back to $H^*$. Commit: $r_Q = \MT(Q_0, \ldots, Q_{d-1})$.
  -
  -
* - $r_Q$
  - $\longrightarrow$
  - $r_Q$; $\T.\abs(r_Q)$
* - ***Evaluation stage*** ({src}`protocol/prover.py:318`)
  -
  -
* - $\xi$
  - $\longleftarrow$
  - $\xi \leftarrow \T.\sq()$, $\xi \in \Fext$
* - For each committed polynomial $p$ and each opening offset $o \in \mathcal{O}$ from the evaluation map ({src}`protocol/stages.py:719`): compute $e_{p,o} = p(\xi \cdot \omega^o) \in \Fext$. This includes witness $f_j$, intermediate $h_j$, quotient $Q_j$, and constant $c_j$.
  -
  -
* - $\{e_{p,o}\}$
  - $\longrightarrow$
  - $\{e_{p,o}\}$; $\T.\abs\bigl(\LinHash(\{e_{p,o}\})\bigr)$
* - ***FRI polynomial*** ({src}`protocol/fri_polynomial.py:129`)
  -
  -
* - $(v_1, v_2)$
  - $\longleftarrow$
  - $v_1, v_2 \leftarrow \T.\sq()$, both $\in \Fext$
* - Group evaluation-map entries by opening-offset index: $\mathcal{G} = \{g_0, g_1, \ldots\}$. For each group $g$ with polynomials $p_0, \ldots, p_{n_g}$, evaluations $e_0, \ldots, e_{n_g}$, offset $o_g$: $G_g(x) = \frac{1}{x - \xi\omega^{o_g}} \bigl(v_2^{n_g}(p_0(x) - e_0) + \cdots + (p_{n_g}(x) - e_{n_g})\bigr)$. Combine ({ref}`app:batching`): $F(x) = v_1^{|\mathcal{G}|-1} G_{g_0}(x) + v_1^{|\mathcal{G}|-2} G_{g_1}(x) + \cdots + G_{g_{|\mathcal{G}|-1}}(x)$.
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
  - $\beta_0 \leftarrow \T.\sq()$, $\beta_0 \in \Fext$
* - $\Fold$ ({src}`protocol/fri.py:25`): for each $j \in [2^{b_1}]$, gather $\{F_0[j + i \cdot 2^{b_1}]\}_{i=0}^{f_0 - 1}$ where $f_0 = 2^{b_0 - b_1}$. Interpolate to $(c_0, \ldots, c_{f_0-1})$. Coset correction: $c_i \leftarrow c_i \cdot (g^{-1} \cdot \omega_{b_0}^{-j})^i$. Evaluate: $F_1[j] = \sum_i c_i \beta_0^i$.
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
  - $F_K$; $\T.\abs\bigl(\LinHash(F_K)\bigr)$
* - ***Grinding*** ({src}`protocol/pcs.py:98`)
  -
  -
* - $\chi_{\mathrm{grind}}$
  - $\longleftarrow$
  - $\chi_{\mathrm{grind}} \leftarrow \T.\sq()$
* - Find $\eta$ such that $\Poseidon(\chi_{\mathrm{grind}} \| \eta)$ has $b_{\mathrm{pow}}$ leading zero bits.
  -
  -
* - $\eta$
  - $\longrightarrow$
  - $\eta$; **Check:** $\Poseidon(\chi_{\mathrm{grind}} \| \eta)$ has $b_{\mathrm{pow}}$ leading zeros.
* - ***Constraint check*** ({src}`protocol/verifier.py:724`)
  -
  -
* -
  -
  - Evaluate $C(\xi) = v_c^{J-1} C_0(\xi) + \cdots + C_{J-1}(\xi)$ from $\{e_{p,o}\}$ ({ref}`app:constraints`). Compute $\ZH(\xi) = \xi^N - 1$. Reconstruct $Q(\xi) = \sum_{j=0}^{d-1} \xi^{jN} e_{Q_j, 0}$. **Check:** $Q(\xi) = C(\xi)/\ZH(\xi)$.
* - ***Degree check*** ({src}`protocol/verifier.py:964`)
  -
  -
* -
  -
  - $\hat{F}_K = \INTT(F_K)$. Let $D = 2^{b_K - (n_{\mathrm{ext}} - n)}$. **Check:** $\hat{F}_K[i] = 0$ for all $i \ge D$.
* - ***Query phase*** ({src}`protocol/verifier.py:94`)
  -
  -
* - Both sides derive query indices
  - $=$
  - Seed fresh $\T'.\abs(\chi_{\mathrm{grind}}, \eta)$. Derive $(q_1, \ldots, q_{Q_{\mathrm{queries}}}) \leftarrow \T'.\sqidx(Q_{\mathrm{queries}}, b_0)$.
* - For each $q_i$ and each commitment tree: compute Merkle opening proof at appropriate index.
  - $\longrightarrow$
  - $\{\text{Merkle proofs}\}$
* - ***Per-query checks*** ({src}`protocol/verifier.py:803`)
  -
  -
* -
  -
  - For each query $q$: **Merkle verification.** For each tree (stages 1, 2, Q, constants, FRI layers $0, \ldots, K{-}1$): hash leaf, walk authentication path. **Check:** computed root $=$ committed root.
* -
  -
  - **FRI polynomial consistency** ({src}`protocol/verifier.py:758`). Let $x_q = g \cdot \omega_{\mathrm{ext}}^q$. From polynomial values at $x_q$ and evaluations $\{e_{p,o}\}$, compute $F(x_q)$ via batching formula ({ref}`app:batching`): $F(x_q) = \sum_{g \in \mathcal{G}} v_1^{|\mathcal{G}|-1-g} \bigl(\frac{1}{x_q - \xi\omega^{o_g}} \sum_{j} v_2^{n_g-j} (p_j(x_q) - e_j)\bigr)$. **Check:** $F(x_q) = F_0[q]$.
* -
  -
  - **FRI fold verification** ({src}`protocol/verifier.py:905`). For each round $k = 1, \ldots, K$: extract $f_k = 2^{b_{k-1}-b_k}$ siblings from layer-$(k{-}1)$ Merkle proof. Interpolate to $(c_0, \ldots, c_{f_k-1})$. Compute $\hat\beta_k = \beta_{k-1} / (g^{2^{n_{\mathrm{ext}}-b_{k-1}}} \cdot \omega_{b_{k-1}}^q)$. Evaluate $v = \sum_i c_i \hat\beta_k^i$. **Check:** $v = F_k[q']$. For last round, check against $F_K$ directly.
* -
  -
  - **Accept** iff all checks pass.
```

**Proof output.** $\pi = \bigl(r_1, r_2, r_Q, \{e_{p,o}\}, \eta, \{r_k^{\mathrm{FRI}}\}_{k=0}^{K-1}, F_K, \{\text{Merkle proofs}\}\bigr)$.

Communication: $3 + K$ Merkle roots ($\in \F^4$ each),
$|\{e_{p,o}\}|$ extension-field evaluations,
$F_K \in \Fext^{2^{b_K}}$, nonce $\eta$,
and Merkle paths for each query.
