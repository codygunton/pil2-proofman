Simplify the Python executable spec file: $1

## Process

1. **Read the file** and identify simplification opportunities
2. **Create a minimal plan** in `./ai_plans/simplify-{filename}.md` with:
   - What to change (bullet list)
   - Why (one sentence each)
   - Test command to verify
3. **Run agent reviews** (pass context, don't let them re-read):
   - type-enforcer: Check for `np.ndarray` red flags, type annotation issues
   - crypto-spec-simplifier: Flag unused args, dead code, over-abstraction
   - human-simplicity-enforcer: Flag readability issues
   - protocol-purity-guardian: Flag implementation details leaking into protocol
4. **Update plan** based on agent feedback
5. **Get user approval** before implementing
6. **Implement changes**, running `uv run pytest tests/ -v` after each
7. **Final paranoid-skeptic verification** (run tests, confirm no regressions)

## Agent Invocation Rules

- Pass relevant context in the prompt (e.g., "Line 27 uses `np.ndarray` for challenges")
- Do NOT tell agents to "ultrathink" or re-read files you've already read
- Ask for concise responses (bullet points, not essays)
- Run independent reviews in parallel when possible

## What To Simplify

- Unused function arguments → remove if tests pass
- `np.ndarray` where `FF3`/`FF` should be used → flag for refactoring
- Functions over 40 lines → consider splitting
- Missing type annotations → add them
- Dead code, redundant abstractions → remove

## What NOT To Change

- Logic that affects test output
- The explicit loop in `_compute_xi_to_trace_size` (C++ compatibility)
- Protocol-level abstractions that hide implementation details correctly

## Constraints

- All 146 tests must pass after every change
- Binary equivalence with C++ must be maintained
- Changes should be minimal - don't refactor what doesn't need it
