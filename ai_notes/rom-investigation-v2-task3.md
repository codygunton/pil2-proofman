# Task #3: Compare Custom Commit Operand Loading in Bytecode

## Summary

The Python bytecode evaluator's verify-mode custom commit loading is **functionally correct**
for the Rom AIR. The ev_map search correctly matches all 11 custom commit polynomials and
loads the right evals values. However, the Python uses the **prover binary** (Rom.bin) while
the C++ verifier uses the **verifier binary** (Rom.verifier.bin), which have fundamentally
different encodings for custom commits. Despite this difference, the Python workaround
(ev_map search) produces the same result as the C++ verifier binary's direct evals encoding.

**Verdict: Custom commit operand loading is NOT the cause of the Rom xfail.**

---

## Key Finding: Two Different Binary Encodings

### Prover Binary (Rom.bin) -- used by Python
Custom commits encoded as buffer type references:
```
type = nStages + 4 + commitId = 2 + 4 + 0 = 6
args[i_args+1] = stagePos (polynomial index within commit, 0-10)
args[i_args+2] = opening point index (1, corresponding to prime=0)
```

Example bytecode operand: `(type=6, id=10, opening=1)` means custom commit polynomial #10
at opening point index 1.

### Verifier Binary (Rom.verifier.bin) -- used by C++
Custom commits encoded as evals array references:
```
type = bufferCommitsSize + EVALS_OFFSET = 7 + 8 = 15
args[i_args+1] = ev_map_index * FIELD_EXTENSION_DEGREE (direct evals offset)
args[i_args+2] = 0 (unused)
```

Example bytecode operand: `(type=15, id=33, 0)` means evals[33..35] = ev_map entry 11
(which is custom id=10, commit_id=0).

### Why They Differ
The verifier binary is compiled differently from the prover binary:
- **Prover binary**: `expressions_info.cpp:addRef()` for `opType::custom` emits
  `type = nStages + 4 + commitId`, followed by the polynomial id and opening point index.
  The prover evaluator loads from the physical buffer `pCustomCommitsFixed`.
- **Verifier binary**: The `qVerifier` JSON represents custom commit references as
  `opType::eval` with pre-resolved eval IDs. The verifier binary compiler emits
  `type = bufferCommitsSize + EVALS_OFFSET`, with the evals array offset directly.
  The verifier evaluator loads from the evals array.

This is confirmed by examining the `Rom.expressionsinfo.json` which has an `expressionsCode`
section (for the prover) with `type="custom"` references, and a separate `qVerifier` section
(for the verifier) that replaces custom references with `type="eval"` references.

---

## Detailed Analysis

### C++ Verifier Path (Rom.verifier.bin, type=15)

In `stark_verify.hpp`, the C++ verifier:
1. Loads `Rom.verifier.bin` as the expression binary
2. Calls `expressionsPack.calculateExpressions(params, dest, 1, false, false)` with domainSize=1
3. When encountering type=15, `expressions_pack.hpp:load()` falls through to the scalar
   params branch: `return &expressions_params[type][args[i_args + 1]]`
4. `expressions_params[15] = params.evals` (set at line 362)
5. So it reads `evals[args[i_args+1]]` directly -- no search needed

The verifier binary pre-resolves all custom commit references to evals indices at compile time.

### C++ Verifier Custom Commit Buffer (NOT used for evaluation check)

The `pCustomCommitsFixed` buffer IS populated from the proof JSON:
```cpp
trace_custom_commits_fixed[offset + q*nPols + stagePos] = jproof["s0_vals_rom_0"][q][stagePos]
```
But this data is only used for the **FRI query consistency check** (friExpId=74), not the
evaluation check (cExpId=73). The evaluation check uses the evals array via the verifier binary.

### Python Verifier Path (Rom.bin, type=6 with ev_map fallback)

The Python bytecode adapter:
1. Loads `Rom.bin` (prover binary) since `_discover_zisk_airs()` uses `{d.name}.bin`
2. In verify mode (domainSize=1), `_load_operand()` encounters type=6 (custom commit)
3. The code performs a linear search over `ev_map`:
   ```python
   for idx, e in enumerate(self.stark_info.ev_map):
       if (e.type == EvMap.Type.custom and e.id == stage_pos
               and e.opening_pos == opening_idx and e.commit_id == index):
           base = idx * FIELD_EXTENSION_DEGREE
           return ff3([evals[base], evals[base+1], evals[base+2]])
   ```
4. The search parameters:
   - `stage_pos = args[i_args+1]` = polynomial index (0-10)
   - `opening_idx = args[i_args+2]` = 1
   - `index = type_arg - (n_stages + 4)` = 0

### Matching Verification

All 11 custom commit ev_map entries match correctly:

| Polynomial | stage_pos | ev_map idx | evals base | Verifier.bin evals offset |
|-----------|-----------|------------|------------|---------------------------|
| line      | 0         | 1          | 3          | 3                         |
| a_offset_imm0 | 1    | 2          | 6          | 6                         |
| a_imm1    | 2         | 3          | 9          | 9                         |
| b_offset_imm0 | 3    | 4          | 12         | 12                        |
| b_imm1    | 4         | 5          | 15         | 15                        |
| ind_width | 5         | 6          | 18         | 18                        |
| op        | 6         | 7          | 21         | 21                        |
| store_offset | 7      | 8          | 24         | 24                        |
| jmp_offset1 | 8       | 9          | 27         | 27                        |
| jmp_offset2 | 9       | 10         | 30         | 30                        |
| flags     | 10        | 11         | 33         | 33                        |

The Python ev_map search produces identical evals indices to the C++ verifier binary encoding.

---

## Checklist Results

- [x] Read C++ custom commit loading (prover mode and verify mode paths)
  - Prover mode: loads from `pCustomCommitsFixed` buffer
  - Verify mode: verifier binary uses type=15 (evals), NOT type=6 (buffer)
- [x] Read Python custom commit loading (verify mode ev_map search)
  - Uses prover binary (type=6), with ev_map search as verify-mode fallback
- [x] Compare field names: id vs stage_pos, opening_pos vs row_offset, commit_id vs index
  - `e.id == stage_pos`: both are the polynomial index within the commit (0-10)
  - `e.opening_pos == opening_idx`: both are the opening point array index (1)
  - `e.commit_id == index`: both are the custom commit index (0)
- [x] Verify all 18 ev_map entries for Rom are correctly matched
  - 11 custom entries: all matched correctly
  - 7 other entries (cm/const): not involved in custom commit loading
- [x] Check if args[1]/args[2] semantics match between C++ and Python
  - Yes: args[i_args+1] = polynomial index, args[i_args+2] = opening point index
- [x] Record findings

---

## Silent Fallthrough Analysis

**Q: If the ev_map search fails, does the code silently fall through?**

A: If the ev_map search fails, the code falls through to the buffer-loading path:
```python
offset = int(map_offsets_custom_exps[index])
n_cols = int(self.map_sections_n_custom_fixed[index])
...
vals.append(int(buffers.custom_commits[buf_idx]))
```

In verify mode, `buffers.custom_commits` is `None` (not populated by
`_build_buffers_from_verifier_data`), which would cause a `TypeError` -- not a silent
zero return. So a failed search would crash, not silently produce wrong results.

For Rom, all 11 custom commit lookups succeed, so this fallthrough is never triggered.

---

## Architectural Observations

1. **Binary mismatch is safe**: The Python uses the prover binary but adds an ev_map search
   workaround for verify mode. This produces the same result as the C++ verifier binary's
   direct evals encoding, because both ultimately index into the same evals array at the
   same positions.

2. **Potential optimization**: The Python could instead load `Rom.verifier.bin` with
   `verifier_bin=True`, which would eliminate the ev_map search overhead. The verifier binary
   has pre-resolved all references to evals indices.

3. **The ev_map `id` field for custom commits is the polynomial index** (matching `stagePos`
   in customCommitsMap), NOT a global polynomial ID. This is consistent with the bytecode
   encoding which emits `r.id` directly (expressions_info.cpp line 484).
