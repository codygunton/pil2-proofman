(sec:glossary)=
# Glossary of Notation

| Symbol | Meaning | Python name |
|--------|---------|-------------|
| $N = 2^n$ | Trace size (number of rows in the execution trace) | `2 ** stark_info.stark_struct.n_bits` |
| $\F, \Fext$ | Base field and cubic extension field | `FF`, `FF3` |
| $\ZH(X) = X^N - 1$ | Vanishing polynomial on $H$ | `ProverHelpers.zi` (stores $1/\ZH$) |
| $\mathcal{O} = \{o_0, o_1, \ldots\}$ | Opening point offsets (typically $\subseteq \{-1,0,1\}$) | --- |
| $J$ | Number of constraint polynomials in the AIR | (implicit) |
| $d$ | Number of quotient polynomial pieces ($Q$ split degree) | `stark_info.q_deg` |
| $K$ | Number of FRI folding rounds | `len(stark_struct.fri_fold_steps)` |
| $Q_{\mathrm{queries}}$ | Number of FRI query repetitions | `stark_struct.n_queries` |
| $b_{\mathrm{pow}}$ | Grinding difficulty (number of leading zero bits) | `stark_struct.pow_bits` |
| $a$ | Merkle tree arity (2, 3, or 4) | `stark_struct.merkle_tree_arity` |
| $[n]$ | The set $\{0, 1, \ldots, n-1\}$ | --- |
| $\MT(\cdot)$ | Merkle tree root | `MerkleTree.get_root()` |
| $\T$ | Fiat-Shamir transcript | `Transcript` |
| $\T.\abs(\cdot)$ | Absorb elements into transcript | `Transcript.put()` |
| $\T.\sq()$ | Squeeze one $\Fext$ challenge | `Transcript.get_field()` |
| $\xi, \beta_k, v_1, v_2, v_c$ | Challenges in $\Fext$ | `xi`, `beta`, `vf1`, `vf2` |
| $\alpha, \gamma$ | Lookup/permutation challenges in $\Fext$ | `alpha`, `gamma` |

## Defined Terms

**Constant polynomial tree**
: Merkle tree built over the constant (precomputed) polynomials of an AIR. Its root is the
  *verification key* (`verkey`) — a 4-element base-field hash that uniquely identifies the
  AIR's fixed parameters. AIRs with no constant polynomials use a zero verkey by convention.
  Python: `committer.build_const_tree(const_pols_extended)` in `protocol/prover.py`.

**Auxiliary trace buffer** (`aux_trace`)
: A single pre-allocated flat `uint64` array that holds all stage polynomial evaluations.
  It is partitioned into non-overlapping slices by `stark_info.map_offsets`:
  - Stage 1 (`cm1`): base-domain at `map_offsets[("cm1", False)]`,
    extended at `map_offsets[("cm1", True)]`
  - Stage 2 (`cm2`, e.g. im_cluster, gsum): base-domain at `map_offsets[("cm2", False)]`,
    extended at `map_offsets[("cm2", True)]`
  - Quotient polynomial Q(x): extended-only at `map_offsets[("q", True)]`
  - FRI polynomial f(x): extended-only at `map_offsets[("f", True)]`

  Total size: `stark_info.map_total_n` uint64 elements.
  Python: `aux_trace` in `_commit_stage1` in `protocol/prover.py`.
