"""Anchor scanner for Sphinx documentation cross-references.

This module scans Python source files for doc-anchor comments and function/class
definitions, building a mapping from anchor IDs and symbols to line numbers.
The mapping is cached to disk for fast incremental builds.

Anchor syntax:
    # <doc-anchor id="anchor-id">

Usage in Sphinx docs:
    {src}`protocol/prover.py#witness-commit`  # Anchor reference
    {src}`protocol.prover.gen_proof`          # Symbol reference
"""

import ast
import pickle
import re
from pathlib import Path
from typing import Dict, Set


ANCHOR_PATTERN = re.compile(r'#\s*<doc-anchor\s+id="([^"]+)"\s*>')


def extract_anchors(source: str) -> Dict[str, int]:
    """Extract doc-anchor comments from Python source code.

    Args:
        source: Python source code as a string

    Returns:
        Dictionary mapping anchor IDs to line numbers (1-indexed)

    Raises:
        ValueError: If duplicate anchor IDs are found in the same file
    """
    anchors: Dict[str, int] = {}
    duplicates: Dict[str, list[int]] = {}

    for line_num, line in enumerate(source.splitlines(), start=1):
        match = ANCHOR_PATTERN.search(line)
        if match:
            anchor_id = match.group(1)
            if anchor_id in anchors:
                if anchor_id not in duplicates:
                    duplicates[anchor_id] = [anchors[anchor_id]]
                duplicates[anchor_id].append(line_num)
            else:
                anchors[anchor_id] = line_num

    if duplicates:
        dup_info = ', '.join(
            f"'{anchor_id}' at lines {sorted(lines)}"
            for anchor_id, lines in duplicates.items()
        )
        raise ValueError(f"Duplicate anchor IDs found: {dup_info}")

    return anchors


class SymbolExtractor(ast.NodeVisitor):
    """AST visitor to extract function, class, and constant definitions with line numbers."""

    def __init__(self, module_path: str):
        """Initialize symbol extractor.

        Args:
            module_path: Dotted module path (e.g., "protocol.prover")
        """
        self.module_path = module_path
        self.symbols: Dict[str, int] = {}
        self.class_stack: list[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit a class definition."""
        # Record the class itself
        class_name = '.'.join(self.class_stack + [node.name])
        full_name = f"{self.module_path}.{class_name}"
        self.symbols[full_name] = node.lineno

        # Visit nested definitions
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit a function definition."""
        func_name = '.'.join(self.class_stack + [node.name])
        full_name = f"{self.module_path}.{func_name}"
        self.symbols[full_name] = node.lineno
        # Don't visit nested functions - they're not typically referenced from docs

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit an async function definition."""
        func_name = '.'.join(self.class_stack + [node.name])
        full_name = f"{self.module_path}.{func_name}"
        self.symbols[full_name] = node.lineno

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit an assignment (extract module-level constants)."""
        # Only extract top-level assignments (not inside classes/functions)
        if not self.class_stack:
            # Extract simple name assignments: FOO = 42, not complex ones like a, b = 1, 2
            for target in node.targets:
                if isinstance(target, ast.Name):
                    # Check if it looks like a constant (uppercase or TypeAlias)
                    name = target.id
                    if name.isupper() or name[0].isupper():  # CONSTANT or TypeAlias
                        full_name = f"{self.module_path}.{name}"
                        self.symbols[full_name] = node.lineno


def extract_symbols(source: str, filepath: str) -> Dict[str, int]:
    """Extract function, class, and constant definitions from Python source using AST.

    Args:
        source: Python source code as a string
        filepath: Relative path to the file (e.g., "protocol/prover.py")

    Returns:
        Dictionary mapping dotted symbol names to line numbers (1-indexed)
        Includes functions, classes, and module-level constants (uppercase names)

    Example:
        For file "protocol/prover.py" with function "gen_proof" at line 42:
        Returns {"protocol.prover.gen_proof": 42}
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        # Return empty dict for unparseable files - caller will log warning
        return {}

    # Convert file path to module path: "protocol/prover.py" -> "protocol.prover"
    module_path = filepath.replace('.py', '').replace('/', '.')

    extractor = SymbolExtractor(module_path)
    extractor.visit(tree)
    return extractor.symbols


def scan_python_files(base_path: Path) -> Dict[str, Dict[str, int]]:
    """Scan Python files for anchors and symbols.

    Args:
        base_path: Base directory to scan (e.g., Path("executable-spec"))

    Returns:
        Nested dictionary: {relative_path: {anchor_or_symbol: line_number}}

    Example:
        {
            "protocol/prover.py": {
                "witness-commit": 202,  # anchor
                "protocol.prover.gen_proof": 42,  # symbol
            }
        }
    """
    if not base_path.exists():
        raise FileNotFoundError(f"Base path does not exist: {base_path}")

    if not base_path.is_dir():
        raise NotADirectoryError(f"Base path is not a directory: {base_path}")

    result: Dict[str, Dict[str, int]] = {}
    warnings: list[str] = []

    for py_file in base_path.rglob("*.py"):
        try:
            source = py_file.read_text(encoding='utf-8')
            relative_path = str(py_file.relative_to(base_path))

            # Combine anchors and symbols
            file_mapping: Dict[str, int] = {}

            # Extract anchors
            try:
                anchors = extract_anchors(source)
                file_mapping.update(anchors)
            except ValueError as e:
                warnings.append(f"{relative_path}: {e}")

            # Extract symbols
            symbols = extract_symbols(source, relative_path)
            if not symbols and source.strip():
                # Only warn if file is non-empty but couldn't be parsed
                try:
                    ast.parse(source)
                except SyntaxError:
                    warnings.append(f"{relative_path}: Invalid Python syntax, skipping symbol extraction")

            file_mapping.update(symbols)

            if file_mapping:
                result[relative_path] = file_mapping

        except Exception as e:
            warnings.append(f"{relative_path}: Unexpected error: {e}")

    # Print warnings to stderr
    if warnings:
        import sys
        for warning in warnings:
            print(f"WARNING: {warning}", file=sys.stderr)

    return result


def _should_rebuild_cache(base_path: Path, cache_path: Path) -> bool:
    """Check if cache needs rebuilding based on file modification times.

    Args:
        base_path: Base directory containing Python files
        cache_path: Path to the cache pickle file

    Returns:
        True if cache should be rebuilt, False otherwise
    """
    if not cache_path.exists():
        return True

    cache_mtime = cache_path.stat().st_mtime

    # Check if any Python file is newer than cache
    for py_file in base_path.rglob("*.py"):
        if py_file.stat().st_mtime > cache_mtime:
            return True

    return False


def build_anchor_cache(base_path: Path, cache_path: Path) -> Dict[str, Dict[str, int]]:
    """Build and cache the anchor/symbol mapping.

    Args:
        base_path: Base directory to scan (e.g., Path("executable-spec"))
        cache_path: Path to save the cache pickle file

    Returns:
        Nested dictionary: {relative_path: {anchor_or_symbol: line_number}}
    """
    mapping = scan_python_files(base_path)

    # Save to cache
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with cache_path.open('wb') as f:
        pickle.dump(mapping, f, protocol=pickle.HIGHEST_PROTOCOL)

    return mapping


def load_anchor_cache(cache_path: Path, base_path: Path) -> Dict[str, Dict[str, int]]:
    """Load anchor cache from disk, rebuilding if stale or missing.

    Args:
        cache_path: Path to the cache pickle file
        base_path: Base directory containing Python files (for rebuilding if needed)

    Returns:
        Nested dictionary: {relative_path: {anchor_or_symbol: line_number}}
    """
    if _should_rebuild_cache(base_path, cache_path):
        return build_anchor_cache(base_path, cache_path)

    try:
        with cache_path.open('rb') as f:
            return pickle.load(f)
    except Exception as e:
        import sys
        print(f"WARNING: Failed to load cache ({e}), rebuilding...", file=sys.stderr)
        return build_anchor_cache(base_path, cache_path)


def format_cache_stats(cache: Dict[str, Dict[str, int]]) -> str:
    """Format cache statistics for display.

    Args:
        cache: The anchor/symbol cache

    Returns:
        Human-readable string describing cache contents
    """
    total_files = len(cache)
    total_entries = sum(len(entries) for entries in cache.values())

    # Count anchors vs symbols (symbols have dots in module path)
    anchor_count = 0
    symbol_count = 0

    for file_entries in cache.values():
        for key in file_entries.keys():
            if '.' in key and not key.startswith('#'):
                symbol_count += 1
            else:
                anchor_count += 1

    return (
        f"Scanned {total_files} Python files\n"
        f"Found {total_entries} total entries: "
        f"{anchor_count} anchors, {symbol_count} symbols"
    )


if __name__ == '__main__':
    """Standalone testing: scan executable-spec and print results."""
    import sys
    from pprint import pprint

    # Determine base path
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent.parent.parent  # docs/sphinx/_ext -> project root
    base_path = project_root / 'executable-spec'
    cache_path = script_dir.parent / '_anchor_cache.pkl'

    print(f"Scanning: {base_path}")
    print(f"Cache file: {cache_path}")
    print()

    try:
        cache = load_anchor_cache(cache_path, base_path)

        print(format_cache_stats(cache))
        print()

        # Show sample entries
        print("Sample entries (first 5 files):")
        for i, (filepath, entries) in enumerate(cache.items()):
            if i >= 5:
                break
            print(f"\n{filepath}:")
            for key, line in sorted(entries.items(), key=lambda x: x[1])[:5]:
                entry_type = "symbol" if '.' in key else "anchor"
                print(f"  {line:4d}: {key} ({entry_type})")

        sys.exit(0)

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
