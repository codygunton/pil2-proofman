# Verifier Clarity Questions (Top 32)

A curated list of the most impactful readability concerns when reading `executable-spec/protocol/verifier.py` as a cryptography-literate human.

---

## Type Aliases and Global Constants

### 1. Challenge vs InterleavedFF3
Why are these the same type? The name "Challenge" suggests semantic meaning, but what distinguishes a challenge from any other interleaved FF3? When should I think "this is a challenge" vs "this is just an FF3 element"?

> I agree, a challenge type is probably not needed.

### 2. QueryIdx
This is just an `int`. What does it actually represent? An index into what? The FRI domain? The extended domain? The trace domain?

> It seems like a helpful alias to have but maybe the name could be clarified as you suggest.

### 3. SPONGE_WIDTH_BY_ARITY
This maps arity to `arity * HASH_SIZE`. Why is this a lookup table instead of a computation? Is there something non-obvious about this relationship?

> I agree, but I'd go further--is this detail something that needs to be exposed to the auditor? it seems some explicitly named merkle tree classes or instantiations would be more helpful.

### 4. QUOTIENT_STAGE_OFFSET, EVAL_STAGE_OFFSET, FRI_STAGE_OFFSET
These are stage number offsets. But offsets from what base? The comment says "from n_stages" but I had to read it twice. Why are these 1, 2, 3 instead of being computed from actual stage semantics?

> Agree, this is opaque. In general offsets are useful for engineering but I'm very skeptical they are needed to express the core protocol cleanly.

### 5. EVALS_HASH_WIDTH = 16
Why 16? Is this tied to the Poseidon2 width? To field size? Magic number with no derivation.

> Could just be a magic number in the C++, but also I suspect you're right.

---

## Pervasive Patterns

### 6. Interleaved Buffer Arithmetic
The pattern `[buffer[base+2], buffer[base+1], buffer[base]]` appears 15+ times throughout the code. Why the 2,1,0 reversal? Is this endianness? This should be abstracted into `from_interleaved_buffer()` or similar.
> Agree, and perhaps if we don't need both endiannesses then ther emight be an abstraction in the galois library that lets us not even think about these issues (idk, worth investigating.)

### 7. The Mysterious `[0]` Subscript
Throughout the code, we access `.v[i][0]` and `.mp[i][j]` where the final `[0]` peels off a wrapper. What is this wrapper? Why does `v` contain single-element lists instead of scalars?
> Yeah good question, where this can be gotten rid of it couldn't hurt.

### 8. Stage Numbering vs Array Indexing
Stages are 1-indexed, arrays are 0-indexed. We constantly see `stage - 1` or `tree_idx = stage - 1`. Could we use consistent numbering throughout?
> I agree it's irritating but I think it's not wroth pursuing

### 9. Challenge Slicing Pattern
Challenges is a flat interleaved array. We slice it with `challenges[idx*FIELD_EXTENSION_DEGREE:(idx+1)*FIELD_EXTENSION_DEGREE]` repeatedly. We have `_get_challenge` helper but it's only used twice while inline slicing appears everywhere else.
> Good thing to simplify with use of the function

---

## Naming Issues

### 10. `prime` for Row Offset
In ev_map, `.prime` means row offset. This is terrible naming—"prime" suggests derivatives (f'(x)) or prime numbers. Should be renamed to `row_offset`.
> Yes

### 11. `airgroup_values` vs `air_values`
These names are confusingly similar. What's an "airgroup value" vs an "air value"? The distinction is not clear from names alone.
> Agree

### 12. `cm` Abbreviation
`section = f"cm{stage}"` appears multiple times. What does "cm" stand for? Committed? Constraint module? The abbreviation is never explained.
> Agree

### 13. `x_div_x_sub`
This name is cryptic. It computes `1/(x - xi*w^openingPoint)`. Why not call it `deep_quotient_denominators` or `opening_point_inverses`?
> Double check in the C++ to see what's this is called. Maybe x_div_x_sub is a good name. If not rename

### 14. `buff` Variable Name
`buff = compute_fri_polynomial_verifier(...)` — "buff" tells us nothing. What does it contain? FRI polynomial evaluations at query points? Name it accordingly.
> Agree

---

## Long Functions

### 15. `_reconstruct_transcript` (77 lines)
By line 380 I lose context about what we've absorbed and when. The function handles: stage roots, stage challenges, airgroup values, air values, evals, FRI steps, grinding. Could be broken into phases.
> Idk, you just look for all put calls. I think it's alright. That said, we could attach a unique metadata label to each put call and then allow for sequentially printing the trancript. Could be useful 

### 16. `_build_verifier_data` (75 lines)
The three data structures (evals, challenges, airgroup_values) are built with similar but slightly different patterns. Tiring to read by the end.
> For me the use of field triples plus not knowing what ev_map is makes it hard to read. Maybe other perts of the plan will fix this?

### 17. `_fill_trace_from_proof` (20+ lines of nested loops)
I lose track of what `buffer_idx` represents by line 275. The manual indexing with `stage_pos + dim_offset` needs semantic clarity.
> I mean, tbh, buffers are not a friendl high level abstraction at all. Does the verifier even need to work with these? Maybe that's a big separate project, if so we could make a marginal improvement

---

## Algorithmic Complexity

### 18. Linear Searches Through Maps
`cm_pols_map`, `ev_map`, `challenges_map` are lists searched linearly. We have O(n²) patterns like "Find index by counting same-name entries before this one". Why not use hash maps for O(1) lookup?
> can this be done with without loss of clarity?

### 19. Challenge Finding Loop
`_find_xi_challenge` loops through all challenges looking for one with specific stage and stage_id. Why not index directly? Returns zeros if not found—silent error that would cause mysterious downstream failures.
> Agree

### 20. Double Loop for Stage Challenges
Outer loop iterates stages, inner loop searches `challenges_map` for matching stage. Pre-grouping challenges by stage would eliminate this.
> I can't tell if this would come at a loss of clarity

---

## Missing Context

### 21. What is DEEP-ALI?
`_compute_x_div_x_sub` docstring mentions "DEEP-ALI quotient". The acronym ALI is not expanded. Is this standard STARK terminology?
> This will make sense when we implement recursion, so just keep it for now.

### 22. What is `blowup_factor`?
`blowup_factor = stark_struct.n_bits_ext - stark_struct.n_bits`. What's "blowing up"? The domain size? The name is jargon without explanation.
> Experts understand

### 23. What is `last_level_verification`?
This parameter appears everywhere in Merkle verification. I assume it's an optimization to cache intermediate levels, but it's never explained.
> Agree, I have no idea, and if it's an engineering optimization and not a protocol level optimization then it should probably go away.

### 24. Why Split the Quotient?
"The quotient polynomial Q is split into q_deg pieces". The comment mentions degree management but doesn't explain what constraint we're working around.
> experts understand

---

## Structural Issues

### 25. Late Imports for Circular Dependencies
Multiple functions have late imports "to avoid circular dependency". This suggests the module structure needs refactoring.
> Yeah sounds ugly, agree

### 26. No Separation of Parsing and Verification
The main function mixes parsing proof components and verifying them. Could parsing be a separate phase?
> Worth investigating

### 27. Error Messages Lack Context
"ERROR: FRI folding verification failed" doesn't say which query, which step, what values were wrong. Hard to debug.
> Agree

### 28. Boolean Return with Prints
Every verification function returns bool and prints errors. Why not return a Result type with error details?
> Disagre, this is python

---

## Type System Friction

### 29. FF vs FF3 Conversions
We constantly convert between int, FF, FF3, numpy arrays. Each conversion is a cognitive bump. The pattern `FF3.Vector([int(...), int(...), int(...)])` appears everywhere.
> Agree, really we just want to use aliases of FF or FF3 since these are natively numpy-ish. I have an extremely hard time getting ai agents to undestand and adhere to this.

---

## Proof Structure Mysteries

### 30. `proof.fri.trees.pol_queries` vs `proof.fri.trees_fri` vs `proof.last_levels` vs `proof.fri.pol`
The structure is deeply nested and hard to visualize. Where is the structure of STARKProof documented?
> Agree

### 31. `stark_struct` vs `stark_info`
We have both. `stark_info` contains `stark_struct`. What's the distinction? Both seem to be about STARK configuration.
> Agree

---

## Protocol-Level Questions

### 32. What's the Soundness Argument?
If all checks pass, what have we proven? The connection between these mechanical checks and "the computation was done correctly" is implicit in the code.
> OUt of scope
