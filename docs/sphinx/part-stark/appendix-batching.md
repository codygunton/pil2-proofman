(app:batching)=
# FRI Polynomial Batching Formula

The FRI polynomial $F$ batches all polynomial openings into a single polynomial
using challenges $v_1, v_2 \in \Fext$
({src}`protocol/fri_polynomial.py:129` for the prover,
{src}`protocol/fri_polynomial.py:246` for the verifier).

**Setup.**
The evaluation map specifies triples $(p_i, o_i, e_i)$ where
$p_i$ is a committed polynomial,
$o_i \in \mathcal{O}$ is an opening offset, and
$e_i = p_i(\xi \cdot \omega^{o_i})$ is the claimed evaluation.

Group these triples by opening offset index.
Let $\mathcal{G} = \{g_0, g_1, \ldots, g_{|\mathcal{G}|-1}\}$
be the ordered set of distinct opening indices,
and for each $g \in \mathcal{G}$ let
$(p_{g,0}, e_{g,0}), \ldots, (p_{g,n_g}, e_{g,n_g})$
be the entries in that group (in evaluation-map order).

**Intra-group accumulation** (Horner with $v_2$).
For each group $g$ and evaluation point $x \in H^*$:

```{math}
:label: eq-intra-group
\hat{G}_g(x)
= v_2^{n_g}\bigl(p_{g,0}(x) - e_{g,0}\bigr)
+ v_2^{n_g-1}\bigl(p_{g,1}(x) - e_{g,1}\bigr)
+ \cdots
+ \bigl(p_{g,n_g}(x) - e_{g,n_g}\bigr).
```

This is computed via Horner's method:
start with accumulator $A = 0$;
for each entry $(p_{g,j}, e_{g,j})$ in order,
set $A \leftarrow A \cdot v_2 + \bigl(p_{g,j}(x) - e_{g,j}\bigr)$.

Then divide by the DEEP quotient denominator
({src}`protocol/verifier.py:634`):

$$
G_g(x) = \frac{\hat{G}_g(x)}{x - \xi \cdot \omega^{o_g}}.
$$

**Inter-group accumulation** (Horner with $v_1$).
Combine groups:

```{math}
:label: eq-inter-group
F(x) = v_1^{|\mathcal{G}|-1} \cdot G_{g_0}(x)
     + v_1^{|\mathcal{G}|-2} \cdot G_{g_1}(x)
     + \cdots
     + G_{g_{|\mathcal{G}|-1}}(x).
```

Again via Horner: start with $A = 0$;
for each group $g_i$ in order,
set $A \leftarrow A \cdot v_1 + G_{g_i}(x)$.

**Result.**
$F$ is evaluated on all of $H^*$ to produce the FRI input polynomial of
degree $< N_{\mathrm{ext}}$.
