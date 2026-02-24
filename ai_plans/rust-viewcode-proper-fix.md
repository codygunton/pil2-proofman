# Rust Viewcode Proper Fix

## Goal
Make Rust source viewing match Python's sphinx.ext.viewcode quality:
1. Full Sphinx theme integration (not bare HTML)
2. Named anchors for struct/enum/impl definitions
3. Support `{src}path/to/file.rs#StructName` syntax
4. Update all Part II references to use meaningful anchors

## Phase 1: Rust Symbol Analyzer
Create `docs/sphinx/_ext/rust_analyzer.py`:
- Parse Rust files line-by-line (regex-based, simple but robust)
- Extract: `pub struct Name`, `pub enum Name`, `impl Name`, `pub fn name()`
- Build tags dict: `{name: (type, start_line, end_line)}`
- Handle common Rust patterns (generics, where clauses, etc.)

## Phase 2: Update rust_viewcode.py
Rewrite to match viewcode pattern:
- Use `collect_pages()` instead of `build-finished` hook
- Yield `(pagename, context, 'page.html')` tuples
- Generate named anchors `<div id="{name}">` for each symbol
- Include full Sphinx theme via page.html template

## Phase 3: Update {src} role in conf.py
Extend `_src_role()` to support:
- `{src}zisk/path/file.rs#StructName` → link to `#StructName` anchor
- `{src}zisk/path/file.rs:42` → link to `#L-42` (line number)
- Fallback to line 1 if neither provided

## Phase 4: Update all Part II references
Go through all .md files and replace `:1` with meaningful anchors:
- Main AIR: `#MainInstance`
- Rom AIR: `#RomSM` or similar
- etc. for all 21 AIRs

## Implementation order
1. rust_analyzer.py (new file)
2. rust_viewcode.py (rewrite)
3. conf.py (update _src_role)
4. Test build
5. Update all markdown references
