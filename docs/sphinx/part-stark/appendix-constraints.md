(app:constraints)=
# Constraint Polynomial Structure

Each AIR (Algebraic Intermediate Representation) defines a set of constraint
polynomials $C_0, C_1, \ldots, C_{J-1}$.
Each $C_j$ is a polynomial expression over:

- Committed columns $f_i(X)$, $f_i(X \cdot \omega)$, $f_i(X \cdot \omega^{-1})$
  (current, next, and previous row evaluations);
- Constant polynomials $c_i(X)$;
- Challenges $\alpha, \gamma, \ldots \in \Fext$.

Column and challenge access is mediated by a `ConstraintContext` ABC
({src}`constraints.base.ConstraintContext`) that provides a uniform interface
for both prover (array) and verifier (scalar) evaluation.

**Constraint types.**

- *Transition constraints*: relate row $i$ to row $i+1$,
  e.g. $f(X \cdot \omega) - f(X) - 1 = 0$.
- *Boundary constraints*: fix specific rows,
  typically row $0$ or row $N-1$,
  enforced via Lagrange polynomials $L_0(X)$, $L_{N-1}(X)$.
- *Lookup / permutation constraints*:
  grand-sum or grand-product accumulation polynomials
  using compressed expressions
  $(\text{col}_2 \cdot \alpha + \text{col}_1) \cdot \alpha + \text{busid} + \gamma$
  ({src}`constraints.base.compress_2col`).

**Per-AIR modules.**
Each AIR implements the `ConstraintModule` ABC
({src}`constraints.base.ConstraintModule`), which defines a single
`constraint_polynomial(ctx)` method returning the combined $C(X)$.
The Python spec provides hand-written modules for the test AIRs
(e.g., {src}`constraints.simple_left.SimpleLeftConstraints`) and a bytecode adapter
({src}`constraints.bytecode_adapter.BytecodeConstraintModule`) that wraps the compiled
expression interpreter for Zisk AIRs.

**Combination.**
The individual constraints are combined into a single polynomial using
a random challenge $v_c \in \Fext$ via Horner's method
({src}`constraints.base.ConstraintModule._combine_constraints`):

```{math}
:label: eq-combine
C(X) = \bigl(\cdots\bigl(\bigl(C_0 \cdot v_c + C_1\bigr) \cdot v_c + C_2\bigr)
       \cdot v_c + \cdots\bigr) + C_{J-1}
     = \sum_{j=0}^{J-1} v_c^{J-1-j} \cdot C_j(X).
```

If the AIR is satisfied, then $C(x) = 0$ for all $x \in H$,
meaning $\ZH(X) = X^N - 1$ divides $C(X)$ and
the quotient $Q(X) = C(X)/\ZH(X)$ is a polynomial.
