# Style Enforcement Implementation Plan

## Executive Summary

**Problem Statement:** The executable-spec codebase has a well-defined zksnark-python-style agent with 10 readability-first principles, but no systematic enforcement. The prover.py (732 lines) and verifier.py (842 lines) need style compliance review, and there's no tooling configured to support automated checks.

**Proposed Solution:**
1. Create a canonical STYLE_GUIDE.md that agents and humans can reference
2. Configure ruff and mypy in pyproject.toml for automated style checking
3. Run the zksnark-python-style agent on both prover.py and verifier.py
4. Fix identified issues while maintaining test compatibility

**Technical Approach:**
- Extract style rules from the agent definition into a standalone reference document
- Add ruff configuration enforcing the specific rules (no walrus, simple comprehensions, etc.)
- Add mypy configuration for strict type checking
- Apply fixes incrementally with test verification after each file

**Expected Outcomes:**
- Both prover.py and verifier.py pass `ruff check` and `mypy --strict`
- All 146 tests continue to pass
- Code reads like mathematical documentation
- Future changes automatically checked by tooling

## Goals & Objectives

### Primary Goals
- Establish automated style enforcement via ruff and mypy configuration
- Bring prover.py and verifier.py into full compliance with zksnark-python-style
- Maintain 100% test compatibility (146 tests passing)

### Secondary Objectives
- Create reusable STYLE_GUIDE.md for human reference
- Enable CI-ready style checking commands
- Document the style workflow for future contributors

## Solution Overview

### Approach
Three-phase approach:
1. **Setup Phase**: Create documentation and configure tooling
2. **Review Phase**: Run zksnark-python-style agent on both files to identify violations
3. **Fix Phase**: Apply fixes file-by-file with test verification

### Key Components

1. **STYLE_GUIDE.md**: Human-readable style reference extracted from agent definition
2. **pyproject.toml [tool.ruff]**: Automated linting rules matching style principles
3. **pyproject.toml [tool.mypy]**: Strict type checking configuration
4. **prover.py fixes**: Style compliance for the prover
5. **verifier.py fixes**: Style compliance for the verifier

### Architecture

```
executable-spec/
├── STYLE_GUIDE.md          (NEW: Human-readable style reference)
├── pyproject.toml          (MODIFIED: Add [tool.ruff] and [tool.mypy])
├── protocol/
│   ├── prover.py           (MODIFIED: Style compliance)
│   └── verifier.py         (MODIFIED: Style compliance)
└── .claude/agents/
    └── zksnark-python-style.md  (EXISTING: Agent definition)
```

### Expected Outcomes
- `uv run ruff check protocol/prover.py protocol/verifier.py` passes
- `uv run mypy --strict protocol/prover.py protocol/verifier.py` passes (or documents acceptable exceptions)
- All 146 tests pass
- Code is maximally readable for cryptographers

---

## Implementation Tasks

### CRITICAL IMPLEMENTATION RULES
1. **TEST AFTER EVERY CHANGE**: Run `uv run python -m pytest tests/ -q` after each modification
2. **NO BEHAVIOR CHANGES**: Style fixes must not change any logic
3. **PRESERVE MATH NOTATION**: Single-letter variables with citations are acceptable
4. **INCREMENTAL FIXES**: Fix one category of issues at a time for easy rollback

### Visual Dependency Tree

```
executable-spec/
├── STYLE_GUIDE.md (Task #1: Create canonical style reference)
│
├── pyproject.toml (Task #2: Configure ruff + mypy)
│
├── protocol/
│   ├── prover.py (Task #4: Apply style fixes after Task #3 review)
│   └── verifier.py (Task #5: Apply style fixes after Task #3 review)
│
└── Task #3: Run zksnark-python-style agent reviews (depends on #1, #2)
```

### Execution Plan

#### Group A: Setup (Execute in parallel)

- [x] **Task #1**: Create STYLE_GUIDE.md
  - File: `executable-spec/STYLE_GUIDE.md`
  - Content: Extract and format the 10 readability-first principles from zksnark-python-style agent
  - Sections:
    1. Overview (purpose, audience)
    2. Base Requirements (Google Style Guide refs, mypy --strict, ruff check)
    3. The 10 Readability-First Principles (with code examples)
    4. Type Aliases (document FF, FF3, FFArray, InterleavedFF3, etc.)
    5. What We Flag vs What We Preserve
    6. Quick Reference Checklist
  - Note: This is a reference document, not the agent definition (avoid duplication)
  - Integration: Link from main CLAUDE.md if one exists

- [x] **Task #2**: Configure ruff and mypy in pyproject.toml
  - File: `executable-spec/pyproject.toml`
  - Add `[tool.ruff]` section:
    ```toml
    [tool.ruff]
    target-version = "py310"
    line-length = 100

    [tool.ruff.lint]
    select = [
        "E",      # pycodestyle errors
        "W",      # pycodestyle warnings
        "F",      # pyflakes
        "I",      # isort
        "UP",     # pyupgrade
        "ANN",    # flake8-annotations (type hints)
        "C4",     # flake8-comprehensions
        "SIM",    # flake8-simplify
    ]
    ignore = [
        "ANN101", # missing self type annotation
        "ANN102", # missing cls type annotation
        "ANN401", # Dynamically typed expressions (Any)
    ]

    [tool.ruff.lint.flake8-comprehensions]
    allow-dict-calls-with-keyword-arguments = true

    [tool.ruff.lint.isort]
    known-first-party = ["primitives", "protocol"]
    ```
  - Add `[tool.mypy]` section:
    ```toml
    [tool.mypy]
    python_version = "3.10"
    warn_return_any = true
    warn_unused_configs = true
    disallow_untyped_defs = true
    disallow_incomplete_defs = true
    check_untyped_defs = true
    ignore_missing_imports = true  # For external deps without stubs
    ```
  - Test: `uv run ruff check --help` and `uv run mypy --help` work
  - Note: Initial config may need tuning based on actual violations found

#### Group B: Review (Execute after Group A)

- [x] **Task #3**: Run zksnark-python-style agent reviews
  - **Task #3a**: Review protocol/prover.py
    - Invoke: `Task` tool with `subagent_type="zksnark-python-style"`
    - Prompt: "Review protocol/prover.py for style compliance. Check all 10 readability-first principles. For each violation found, report: (1) line number, (2) principle violated, (3) current code snippet, (4) suggested fix. Group findings by category."
    - Output format:
      ```markdown
      ## prover.py Style Review
      ### Summary: X violations found
      ### 1. Type Annotations (N issues)
      - Line XX: `def foo(x):` → `def foo(x: int) -> int:`
      ### 2. Docstrings (N issues)
      ...
      ```
    - Save findings to `ai_plans/prover-style-review.md`
  - **Task #3b**: Review protocol/verifier.py
    - Invoke: `Task` tool with `subagent_type="zksnark-python-style"`
    - Prompt: "Review protocol/verifier.py for style compliance. Check all 10 readability-first principles. For each violation found, report: (1) line number, (2) principle violated, (3) current code snippet, (4) suggested fix. Group findings by category."
    - Save findings to `ai_plans/verifier-style-review.md`
  - Note: Run both reviews in parallel (single message with two Task tool calls)
  - Integration: Review findings drive Task #4 and #5 fix priorities

#### Group C: Fix Prover (Execute after Group B)

- [x] **Task #4**: Apply style fixes to protocol/prover.py
  - Depends on: Task #3a review findings
  - Fix categories (in order):
    1. **Type annotations**: Add missing parameter and return types
    2. **Docstrings**: Add/enhance Google-format docstrings
    3. **Dense expressions**: Break into named intermediate variables
    4. **Magic numbers**: Extract to named constants
    5. **Abbreviations**: Expand non-math abbreviations
    6. **Comprehensions**: Simplify multi-clause comprehensions to loops
  - Verification after each category:
    - `uv run python -m pytest tests/ -q` (all 146 tests pass)
    - `uv run ruff check protocol/prover.py`
  - **Re-verify with agent**: After all fixes, re-run zksnark-python-style agent:
    - Invoke: `Task` tool with `subagent_type="zksnark-python-style"`
    - Prompt: "Re-review protocol/prover.py after style fixes. Confirm compliance or identify remaining issues."
    - Expected: "Passes" or minimal remaining issues with justification
  - Constraint: gen_proof() is 572 lines - may need to extract helper functions
  - Note: Preserve existing section headers (`# === SECTION ===`)

#### Group D: Fix Verifier (Execute after Group B, parallel with Group C)

- [x] **Task #5**: Apply style fixes to protocol/verifier.py
  - Depends on: Task #3b review findings
  - Fix categories (same order as Task #4):
    1. **Type annotations**: Add missing parameter and return types
    2. **Docstrings**: Add/enhance Google-format docstrings
    3. **Dense expressions**: Break into named intermediate variables
    4. **Magic numbers**: Extract to named constants
    5. **Abbreviations**: Expand non-math abbreviations
    6. **Comprehensions**: Simplify multi-clause comprehensions to loops
  - Verification after each category:
    - `uv run python -m pytest tests/ -q` (all 146 tests pass)
    - `uv run ruff check protocol/verifier.py`
  - **Re-verify with agent**: After all fixes, re-run zksnark-python-style agent:
    - Invoke: `Task` tool with `subagent_type="zksnark-python-style"`
    - Prompt: "Re-review protocol/verifier.py after style fixes. Confirm compliance or identify remaining issues."
    - Expected: "Passes" or minimal remaining issues with justification
  - Note: verifier.py already has good structure from recent simplification work

#### Group E: Final Verification (Execute after Groups C and D)

- [x] **Task #6**: Final verification and documentation
  - Run full tooling checks:
    ```bash
    uv run ruff check protocol/prover.py protocol/verifier.py
    uv run mypy protocol/prover.py protocol/verifier.py
    uv run python -m pytest tests/ -v
    ```
  - **Final agent sign-off**: Run zksnark-python-style on both files in parallel:
    - Invoke: `Task` tool with `subagent_type="zksnark-python-style"` (two parallel calls)
    - Prompt: "Final style review of protocol/[prover|verifier].py. Provide pass/fail verdict with any documented exceptions."
  - Document any intentional exceptions in STYLE_GUIDE.md under "Accepted Exceptions"
  - Update pyproject.toml ruff/mypy config if needed based on learnings
  - Commit with: `style(protocol): enforce zksnark-python-style on prover.py and verifier.py`

---

## Implementation Workflow

This plan file serves as the authoritative checklist for implementation. When implementing:

### Required Process
1. **Load Plan**: Read this entire plan file before starting
2. **Execute Tasks**: Work through tasks in group order (A → B → C/D parallel → E)
3. **Test After Each Change**: Run `uv run python -m pytest tests/ -q`
4. **Update Checkboxes**: Mark `[ ]` to `[x]` when completing

### Agent Usage Pattern
The zksnark-python-style agent is invoked via the `Task` tool:
```
Task(
  subagent_type="zksnark-python-style",
  prompt="Review protocol/[file].py for style compliance...",
  description="Style review [file]"
)
```
- **Task #3**: Initial review (identifies all violations)
- **Tasks #4, #5**: Re-verify after fixes (confirms compliance)
- **Task #6**: Final sign-off (pass/fail verdict)

### Critical Rules
- This plan file is the source of truth for progress
- Update checkboxes in real-time as work progresses
- NO BEHAVIOR CHANGES - only style fixes
- All 146 tests must pass after every change
- Fix one category at a time for easy rollback

### Verification Commands

```bash
# Quick test (use after each change)
uv run python -m pytest tests/ -q

# Style check
uv run ruff check protocol/prover.py protocol/verifier.py

# Type check
uv run mypy protocol/prover.py protocol/verifier.py

# Full verification
uv run python -m pytest tests/ -v && uv run ruff check protocol/ && uv run mypy protocol/prover.py protocol/verifier.py
```

### Progress Tracking
The checkboxes above represent the authoritative status of each task.

---

## Risk Assessment

**Low Risk:**
- Task #1 (STYLE_GUIDE.md) - Documentation only
- Task #2 (pyproject.toml config) - Tool configuration only

**Medium Risk:**
- Task #4, #5 (Style fixes) - Code changes, but no logic changes
- Mitigation: Fix one category at a time, test after each

**Potential Blockers:**
- gen_proof() at 572 lines may have deeply nested logic that's hard to refactor without behavior changes
- Some existing code may use "clever" patterns intentionally for performance
- Mitigation: Document exceptions rather than force changes that risk correctness

---

## Appendix: Style Categories Reference

| # | Principle | What to Fix |
|---|-----------|-------------|
| 1 | Explicit Intermediate Variables | Break `a(b(c(d)))` into named steps |
| 2 | Type Aliases for Domain Concepts | Use FF, FF3, FFArray, etc. |
| 3 | Functions Compute One Thing | Extract multi-purpose functions |
| 4 | No Clever Python | Remove `:=`, complex comprehensions |
| 5 | Mathematical Notation Requires Citation | Add comments for single-letter vars |
| 6 | Docstrings as Specifications | Google format with Args/Returns |
| 7 | Vertical Whitespace | Blank lines between logical steps |
| 8 | Explicit Loops Over Functional Magic | Replace map/filter/reduce with for |
| 9 | No Abbreviations | `polynomial_degree` not `poly_deg` |
| 10 | Constants at Module Level | No magic numbers inline |
