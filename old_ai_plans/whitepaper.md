# PIL2 STARK Protocol Whitepaper — Implementation Plan

## Executive Summary

Create a mathematical whitepaper describing the PIL2 STARK proving system as implemented in the Python executable spec. The document describes **exactly what the prover and verifier compute**, in sequence, using mathematical notation (LaTeX). It contains no proofs, no theorem statements — only the concrete protocol specification.

The target audience is cryptographers who want to understand the protocol by reading mathematics, not code.

### Key Decisions
- **Format**: LaTeX document (`.tex` file) producing a PDF
- **Location**: `docs/protocol-spec.tex` (with a `docs/Makefile` for building)
- **Style**: Definition-style sections ("The prover computes...", "The verifier checks..."), numbered protocol steps, displayed equations
- **No code**: Zero Python/pseudocode. All computation described via mathematical formulas
- **Self-contained**: Includes notation table, field definitions, and all sub-protocols inline

### Expected Outcomes
- A single `.tex` file that compiles to a clean ~15-25 page PDF
- Any cryptographer can read it and understand exactly what is computed at each step
- Can serve as a reference for implementing the protocol in any language

## Solution Overview

### Document Structure

```
1. Notation and Algebraic Setup
2. Polynomial Commitment via Merkle Trees
3. Fiat-Shamir Transcript
4. The Prover Protocol
   4.1 Witness Commitment (Stage 1)
   4.2 Transcript Seeding
   4.3 Intermediate Polynomials (Stage 2)
   4.4 Quotient Polynomial (Stage Q)
   4.5 Polynomial Evaluations
   4.6 FRI Polynomial Construction
   4.7 FRI Commitment Phase
   4.8 Proof-of-Work
   4.9 Query Phase
5. The Verifier Protocol
   5.1 Transcript Reconstruction
   5.2 Constraint Check: Q(ξ) = C(ξ)/Z_H(ξ)
   5.3 FRI Polynomial Consistency
   5.4 Merkle Tree Verification
   5.5 FRI Folding Verification
   5.6 Final Polynomial Degree Check
6. FRI Sub-Protocol
   6.1 Folding Operation
   6.2 Commitment per Round
   6.3 Verification of a Fold Step
Appendix A: Constraint Polynomial Structure
Appendix B: FRI Polynomial Batching Formula
```

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. All content is mathematical — no pseudocode, no Python
2. Every formula must correspond to an actual computation in the executable spec
3. Variable names should match standard cryptographic convention (ξ for xi, ω for omega, etc.)
4. The document must be compilable with standard `pdflatex`

### Visual Dependency Tree

```
docs/
├── protocol-spec.tex    (Task #0-#7: Main document, written section by section)
└── Makefile             (Task #8: Build infrastructure)
```

### Execution Plan

#### Group A: Foundation (Execute in parallel)

- [x] **Task #0**: Create LaTeX skeleton and notation section
  - File: `docs/protocol-spec.tex`
  - Implements: Document preamble, packages, title page, and Section 1 (Notation and Algebraic Setup)
  - Content for Section 1 — **Notation and Algebraic Setup**:
    - Base field: $\mathbb{F}_p$ where $p = 2^{64} - 2^{32} + 1$ (Goldilocks prime)
    - Extension field: $\mathbb{F}_{p^3} = \mathbb{F}_p[X]/(X^3 - X - 1)$, elements written as $a_0 + a_1\alpha + a_2\alpha^2$
    - Trace domain: $H = \{\omega^i : i = 0, \ldots, N-1\}$ where $\omega$ is a primitive $N$-th root of unity, $N = 2^n$
    - Extended domain: $H^* = \{g \cdot \omega_{\text{ext}}^i : i = 0, \ldots, N_{\text{ext}}-1\}$ where $g$ is the coset shift ($g = 7$), $\omega_{\text{ext}}$ is a primitive $N_{\text{ext}}$-th root, $N_{\text{ext}} = 2^{n_{\text{ext}}}$
    - Blowup factor: $\beta = N_{\text{ext}} / N$
    - Vanishing polynomial: $Z_H(X) = X^N - 1$
    - Opening points: $\mathcal{O} = \{o_0, o_1, \ldots\} \subset \mathbb{Z}$ (typically $\{-1, 0, 1\}$)
    - Notation table: $[n]$ for $\{0,\ldots,n-1\}$, $\textsf{MT}(\cdot)$ for Merkle tree root, $\mathcal{T}$ for transcript, etc.
    - Committed polynomials: $f_1, \ldots, f_m$ (stage 1 witness), $h_1, \ldots, h_k$ (stage 2 intermediates)
    - Constant polynomials: $c_1, \ldots, c_\ell$ (fixed by the AIR, committed in setup)
    - Challenges: $\alpha, \gamma, \xi, v_1, v_2 \in \mathbb{F}_{p^3}$ derived from Fiat-Shamir transcript

- [x] **Task #1**: Create build infrastructure
  - File: `docs/Makefile`
  - Implements: `make pdf` target that runs `pdflatex` twice (for references)
  - Also: `make clean` to remove build artifacts
  - Simple — just needs pdflatex, no bibliography

#### Group B: Polynomial Commitment and Transcript (Execute in parallel after Group A)

- [x] **Task #2**: Write Section 2 (Polynomial Commitment via Merkle Trees) and Section 3 (Fiat-Shamir Transcript)
  - File: `docs/protocol-spec.tex` (append to skeleton)
  - **Section 2 — Polynomial Commitment via Merkle Trees**:
    - Given polynomial $f$ of degree $< N$ over $\mathbb{F}_{p^3}$:
      1. Extend to $N_{\text{ext}}$ points: compute $\hat{f} = \text{INTT}_N(f)$, zero-pad to $N_{\text{ext}}$ coefficients, evaluate $\tilde{f} = \text{NTT}_{N_{\text{ext}}}(\hat{f})$
      2. Arrange evaluations into a matrix: row $i$ contains all polynomial values at domain point $i$
      3. Hash each row via Poseidon2 linear hash to get leaf $\ell_i$
      4. Build arity-$a$ Merkle tree (typically $a=4$) over leaves $\ell_0, \ldots, \ell_{N_{\text{ext}}-1}$
      5. Root $r = \textsf{MT}(\tilde{f})$ is the commitment
    - Opening proof at index $j$: siblings along path from leaf $j$ to root
    - Verification: recompute leaf hash, walk path using siblings, check root matches
    - (Optional) Last-level verification optimization: store internal nodes at depth $d$ from root
  - **Section 3 — Fiat-Shamir Transcript**:
    - Sponge construction over Poseidon2 with width $w = 4 \cdot a$ (arity $a \in \{2,3,4\}$)
    - State: capacity $c = 4$ field elements, rate $r = 4(a-1)$
    - $\mathcal{T}.\textsf{absorb}(x_1, \ldots, x_k)$: feed elements into rate portion, apply permutation when full
    - $\mathcal{T}.\textsf{squeeze}() \to (c_0, c_1, c_2) \in \mathbb{F}_{p^3}$: extract 3 field elements (one extension field challenge)
    - $\mathcal{T}.\textsf{squeeze\_indices}(q, b) \to (i_1, \ldots, i_q)$: extract $q$ pseudorandom $b$-bit indices by packing squeezed bits

#### Group C: Prover Protocol (Execute sequentially, sections depend on each other for notation)

- [x] **Task #3**: Write Section 4 (The Prover Protocol)
  - File: `docs/protocol-spec.tex` (append)
  - This is the largest section. Content:

  **4.1 Witness Commitment (Stage 1)**
  - The prover holds witness polynomials $f_1, \ldots, f_m: H \to \mathbb{F}_p$
  - Commit: $r_1 = \textsf{MT}(f_1, \ldots, f_m)$ (joint Merkle tree over all stage-1 columns)
  - Output: $r_1$

  **4.2 Transcript Seeding**
  - Two modes:
    - **VADCOP (per-AIR)**: Compute global challenge $\chi$ from verification key, public inputs, and $r_1$ via lattice expansion. Seed transcript: $\mathcal{T}.\textsf{absorb}(\chi)$
    - **Standalone**: $\mathcal{T}.\textsf{absorb}(\textsf{vk}, \textsf{Hash}(\textsf{pub}), r_1)$

  **4.3 Intermediate Polynomials (Stage 2)**
  - Derive challenges: $\alpha, \gamma, \ldots \leftarrow \mathcal{T}.\textsf{squeeze}()$ for each challenge in stage 2
  - Compute intermediate columns (lookup/permutation support):
    - Grand sum: $s_i = s_{i-1} + \text{numerator}_i / \text{denominator}_i$ for $i \in [N]$, $s_0 = 0$
    - Intermediate cluster: linear combinations of trace columns weighted by $\alpha$
  - Commit: $r_2 = \textsf{MT}(h_1, \ldots, h_k)$
  - $\mathcal{T}.\textsf{absorb}(r_2)$

  **4.4 Quotient Polynomial (Stage Q)**
  - Derive quotient challenges: $v_c \leftarrow \mathcal{T}.\textsf{squeeze}()$
  - Evaluate constraint polynomial on extended domain:
    $$C(x) = \sum_{j} v_c^j \cdot C_j(x) \quad \text{for } x \in H^*$$
    where $C_j$ are the individual AIR constraints
  - Compute quotient: $Q(x) = C(x) / Z_H(x)$ for $x \in H^*$
  - Split $Q$ into $d$ pieces of degree $< N$:
    $$Q(X) = Q_0(X) + X^N \cdot Q_1(X) + \cdots + X^{(d-1)N} \cdot Q_{d-1}(X)$$
    Implementation: INTT, apply shift factors $S_j = (g^{-1})^{jN}$, rearrange, NTT
  - Commit: $r_Q = \textsf{MT}(Q_0, \ldots, Q_{d-1})$
  - $\mathcal{T}.\textsf{absorb}(r_Q)$

  **4.5 Polynomial Evaluations**
  - Derive evaluation point: $\xi \leftarrow \mathcal{T}.\textsf{squeeze}()$ (an element of $\mathbb{F}_{p^3}$)
  - For each polynomial $p$ in the evaluation map and each opening point $o \in \mathcal{O}$:
    $$e_{p,o} = p(\xi \cdot \omega^o)$$
    Computed via inner product with Lagrange coefficients:
    $$p(\xi \cdot \omega^o) = \sum_{i=0}^{N-1} \hat{p}_i \cdot (\xi \cdot \omega^o \cdot g^{-1})^i$$
    where $\hat{p}_i$ are the polynomial coefficients
  - Absorb evaluations: $\mathcal{T}.\textsf{absorb}(\textsf{Hash}(e_{p,o} \text{ for all } p, o))$

  **4.6 FRI Polynomial Construction**
  - Derive batching challenges: $v_1, v_2 \leftarrow \mathcal{T}.\textsf{squeeze}()$
  - Group evaluation map entries by opening position index $g$
  - Within each group $g$ (with entries $e_0, e_1, \ldots, e_{n_g}$), compute via Horner:
    $$G_g(x) = \frac{1}{x - \xi \cdot \omega^{o_g}} \cdot \bigl( v_2^{n_g}(p_0(x) - e_0) + v_2^{n_g-1}(p_1(x) - e_1) + \cdots + (p_{n_g}(x) - e_{n_g}) \bigr)$$
  - Combine groups via Horner:
    $$F(x) = v_1^{|\mathcal{G}|-1} \cdot G_0(x) + v_1^{|\mathcal{G}|-2} \cdot G_1(x) + \cdots + G_{|\mathcal{G}|-1}(x)$$
  - $F$ is the FRI input polynomial, evaluated on $H^*$

  **4.7 FRI Commitment Phase**
  - See Section 6 for the FRI sub-protocol. The prover executes:
    - For each FRI round $k = 0, \ldots, K-1$:
      1. Commit to current polynomial: $r_k^{\text{FRI}} = \textsf{MT}(F_k)$
      2. $\mathcal{T}.\textsf{absorb}(r_k^{\text{FRI}})$
      3. Derive fold challenge: $\beta_k \leftarrow \mathcal{T}.\textsf{squeeze}()$
      4. Fold: $F_{k+1} = \textsf{Fold}(F_k, \beta_k)$ (degree halved)
    - After last round: absorb $\textsf{Hash}(F_K)$ (the final polynomial)

  **4.8 Proof-of-Work (Grinding)**
  - Derive grinding challenge: $\chi_{\text{grind}} \leftarrow \mathcal{T}.\textsf{squeeze}()$
  - Find nonce $\eta$ such that $\textsf{Poseidon2}(\chi_{\text{grind}} \| \eta)$ has $b$ leading zero bits

  **4.9 Query Phase**
  - Derive query indices: $(q_1, \ldots, q_Q) \leftarrow \mathcal{T}'.\textsf{squeeze\_indices}(Q, n_{\text{ext}})$
    where $\mathcal{T}'$ is a fresh transcript seeded with $(\chi_{\text{grind}}, \eta)$
  - For each query $q_i$ and each commitment tree (stages 1, 2, Q, constants, FRI layers):
    - Output Merkle opening proof at index $q_i$

  **Proof output**: $(r_1, r_2, r_Q, \{e_{p,o}\}, \eta, \{r_k^{\text{FRI}}\}, F_K, \{\text{Merkle proofs}\})$

#### Group D: Verifier Protocol (Execute after Group C)

- [x] **Task #4**: Write Section 5 (The Verifier Protocol)
  - File: `docs/protocol-spec.tex` (append)
  - Content:

  **5.1 Transcript Reconstruction**
  - The verifier replays the prover's transcript to rederive all challenges:
    1. Seed $\mathcal{T}$ (same as prover: VADCOP or standalone mode)
    2. For each stage $s = 2, \ldots, S+1$: squeeze challenges, absorb $r_s$, absorb air values if present
    3. Squeeze $\xi$, absorb evaluations (or their hash)
    4. Squeeze $v_1, v_2$
    5. For each FRI round: squeeze fold challenge, absorb next FRI root (or final polynomial)
    6. Squeeze grinding challenge $\chi_{\text{grind}}$

  **5.2 Constraint Check: $Q(\xi) = C(\xi) / Z_H(\xi)$**
  - Evaluate constraint polynomial at $\xi$ using claimed evaluations $\{e_{p,o}\}$:
    $$C(\xi) = \sum_j v_c^j \cdot C_j(\xi)$$
    where each $C_j(\xi)$ is computed from the evaluations via the AIR constraint expressions
  - Compute $Z_H(\xi) = \xi^N - 1$
  - Reconstruct $Q(\xi)$ from split quotient pieces:
    $$Q(\xi) = \sum_{i=0}^{d-1} \xi^{iN} \cdot e_{Q_i, 0}$$
  - **Check**: $Q(\xi) = C(\xi) / Z_H(\xi)$

  **5.3 FRI Polynomial Consistency**
  - For each query point $q$, compute $F(q)$ from claimed polynomial values using the batching formula:
    $$F(q) = \sum_g v_1^g \left( \sum_{j \in \text{group}_g} v_2^j \cdot \frac{p_j(q) - e_j}{x_q - \xi \cdot \omega^{o_g}} \right)$$
    where $x_q = g \cdot \omega_{\text{ext}}^q$ is the evaluation point
  - **Check**: $F(q)$ matches the value committed in the first FRI layer

  **5.4 Merkle Tree Verification**
  - For each query $q$ and each commitment (stages, constants, custom commits):
    - Hash leaf values via Poseidon2
    - Walk authentication path using siblings
    - **Check**: computed root matches committed root

  **5.5 FRI Folding Verification**
  - For each FRI round $k = 1, \ldots, K-1$ and each query $q$:
    1. Extract sibling evaluations $\{s_0, \ldots, s_{f-1}\}$ from proof (coset members)
    2. Interpolate to coefficient form
    3. Evaluate at transformed challenge point:
       $$\hat{\beta}_k = \beta_k \cdot \bigl(g^{2^k} \cdot \omega^{-q}\bigr)^{-1}$$
    4. Compute folded value: $v = \sum_{i=0}^{f-1} c_i \cdot \hat{\beta}_k^i$
    5. **Check**: $v$ matches the committed value in layer $k+1$ (or final polynomial)

  **5.6 Final Polynomial Degree Check**
  - Convert final polynomial $F_K$ from evaluation form to coefficient form (via INTT)
  - **Check**: all coefficients above the degree bound are zero
    $$\hat{F}_K[i] = 0 \quad \text{for } i \geq 2^{n_{\text{ext}} - n - \text{(total fold bits)}}$$

  **5.7 Proof-of-Work Check**
  - **Check**: $\textsf{Poseidon2}(\chi_{\text{grind}} \| \eta)$ has $b$ leading zero bits

  **Acceptance**: The verifier accepts if and only if all checks in 5.2–5.7 pass.

#### Group E: FRI Sub-Protocol and Appendices (Execute after Group C)

- [x] **Task #5**: Write Section 6 (FRI Sub-Protocol)
  - File: `docs/protocol-spec.tex` (append)
  - Content:

  **6.1 Folding Operation**
  - Input: polynomial $F_k$ on domain of size $2^{b_k}$, challenge $\beta_k \in \mathbb{F}_{p^3}$
  - Output: polynomial $F_{k+1}$ on domain of size $2^{b_{k+1}}$ where $b_{k+1} < b_k$
  - Let $f = 2^{b_k - b_{k+1}}$ be the fold factor (number of points per group)
  - For each output index $j \in [2^{b_{k+1}}]$:
    1. Gather $f$ evaluations: $\{F_k[j + i \cdot 2^{b_{k+1}}]\}_{i=0}^{f-1}$
    2. Interpolate to coefficients $c_0, \ldots, c_{f-1}$ (via size-$f$ INTT)
    3. Apply coset correction: $c_i \leftarrow c_i \cdot \bigl(g^{-2^{n_{\text{ext}} - b_k}} \cdot \omega_{b_k}^{-j}\bigr)^i$
    4. Evaluate at challenge: $F_{k+1}[j] = \sum_{i=0}^{f-1} c_i \cdot \beta_k^i$ (Horner's method)

  **6.2 Commitment per Round**
  - Merkelize $F_{k+1}$ with the following layout:
    - Height: $2^{b_{k+2}}$ leaves
    - Each leaf contains $2^{b_{k+1} - b_{k+2}} \cdot 3$ field elements (groups of FF3 values)
  - Transpose data for Merkle tree leaf ordering

  **6.3 Verification of a Fold Step**
  - Verifier receives siblings $\{s_0, \ldots, s_{f-1}\}$ for a query at index $q$
  - Interpolate siblings to coefficients $c_0, \ldots, c_{f-1}$
  - Compute evaluation point: $\hat{\beta}_k = \beta_k \cdot \bigl(g^{2^{n_{\text{ext}} - b_k}} \cdot \omega_{b_k}^{-q}\bigr)^{-1}$
  - Evaluate: $v = \sum_i c_i \cdot \hat{\beta}_k^i$
  - Check $v$ against next layer value

- [x] **Task #6**: Write Appendix A (Constraint Polynomial Structure) and Appendix B (FRI Batching Formula)
  - File: `docs/protocol-spec.tex` (append)
  - **Appendix A**: How constraints combine
    - Individual constraints $C_j$: each is a polynomial expression over trace columns, constants, and challenges
    - Combined constraint: $C(X) = \sum_j v_c^j \cdot C_j(X)$ with random $v_c$
    - Constraint types: transition (relate row $i$ to row $i+1$), boundary (fix row 0 or $N-1$), lookup/permutation (grand sum)
    - Example: simple transition constraint $f(X \cdot \omega) - f(X) - 1 = 0$ for every row
  - **Appendix B**: Detailed batching formula
    - Precise grouping and Horner evaluation order
    - Explicit formula matching the `fri_polynomial.py` docstring

#### Group F: Polish (Execute after Groups D and E)

- [x] **Task #7**: Review, cross-reference, and finalize
  - File: `docs/protocol-spec.tex` (final pass)
  - Ensure all notation is consistent between sections
  - Add equation numbers to key formulas
  - Add cross-references between prover and verifier sections
  - Verify every formula against the Python executable spec
  - Add any missing details discovered during writing

- [x] **Task #8**: Create build infrastructure
  - File: `docs/Makefile`
  - Content:
    ```makefile
    .PHONY: pdf clean

    pdf: protocol-spec.pdf

    protocol-spec.pdf: protocol-spec.tex
    	pdflatex protocol-spec.tex
    	pdflatex protocol-spec.tex

    clean:
    	rm -f *.aux *.log *.out *.toc *.pdf
    ```

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Sync Tasks**: Create TodoWrite tasks matching the checkboxes below
3. **Execute & Update**: For each task:
   - Mark TodoWrite as `in_progress` when starting
   - Update checkbox `[ ]` to `[x]` when completing
   - Mark TodoWrite as `completed` when done
4. **Maintain Sync**: Keep this file and TodoWrite synchronized throughout

### Critical Rules
- This plan file is the source of truth for progress
- Update checkboxes in real-time as work progresses
- Never lose synchronization between plan file and TodoWrite
- Mark tasks complete only when fully implemented (no placeholders)
- Tasks should be run in parallel, unless there are dependencies, using subtasks, to avoid context bloat.

### Progress Tracking
The checkboxes above represent the authoritative status of each task. Keep them updated as you work.

### Key Reference: Python Executable Spec Files
- `protocol/prover.py` — Main prover flow (gen_proof)
- `protocol/verifier.py` — Main verifier flow (stark_verify)
- `protocol/fri.py` — FRI fold/verify operations
- `protocol/pcs.py` — FRI PCS (commit-fold loop, grinding, queries)
- `protocol/fri_polynomial.py` — FRI polynomial batching (prover + verifier)
- `protocol/stages.py` — Polynomial commitment stages, quotient computation
- `primitives/transcript.py` — Poseidon2 Fiat-Shamir transcript
- `primitives/merkle_tree.py` — Merkle tree construction and verification
- `primitives/field.py` — Goldilocks field and cubic extension
- `constraints/base.py` — Constraint evaluation interface
