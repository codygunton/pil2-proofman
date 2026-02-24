"""JavaScript source code analyzer for extracting symbol definitions.

Extracts function declarations, exports, class definitions, and const functions
from JavaScript files for documentation linking.
"""

import re
from pathlib import Path
from typing import Dict, Tuple
from sphinx.util import logging

logger = logging.getLogger(__name__)

# Type alias for tags: {name: (type, start_line, end_line)}
Tags = Dict[str, Tuple[str, int, int]]


class JavaScriptAnalyzer:
    """Analyze JavaScript source files to extract symbol definitions."""

    # Regex patterns for JavaScript symbols
    # Match: function foo(, async function foo(
    FUNCTION_RE = re.compile(r'^\s*(?:async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(')

    # Match: const foo = function(, const foo = async function(
    CONST_FUNC_RE = re.compile(r'^\s*const\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?function\s*\(')

    # Match: const foo = (args) =>, const foo = async (args) =>
    ARROW_FUNC_RE = re.compile(r'^\s*const\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>')

    # Match: class Foo, class Foo extends Bar
    CLASS_RE = re.compile(r'^\s*class\s+([A-Z][a-zA-Z0-9_$]*)\b')

    # Match: module.exports.foo = function, exports.foo = function
    MODULE_EXPORT_RE = re.compile(r'^\s*(?:module\.)?exports\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?function')

    # Match: module.exports = { foo, bar }
    EXPORT_OBJECT_RE = re.compile(r'^\s*module\.exports\s*=\s*\{')

    def __init__(self, source_path: Path):
        """Initialize analyzer for a JavaScript source file.

        Args:
            source_path: Path to the .js file
        """
        self.source_path = source_path
        self.code = ""
        self.tags: Tags = {}

    def analyze(self) -> None:
        """Analyze the source file and extract symbol definitions."""
        try:
            self.code = self.source_path.read_text(encoding='utf-8')
        except Exception as e:
            logger.warning(f"[js_analyzer] Failed to read {self.source_path}: {e}")
            return

        lines = self.code.splitlines()
        self._extract_symbols(lines)

    def _extract_symbols(self, lines: list[str]) -> None:
        """Extract symbols from source lines.

        Args:
            lines: List of source code lines
        """
        i = 0
        while i < len(lines):
            line = lines[i]
            lineno = i + 1  # Line numbers are 1-indexed

            # Try each pattern
            for pattern, symbol_type in [
                (self.FUNCTION_RE, 'function'),
                (self.CONST_FUNC_RE, 'function'),
                (self.ARROW_FUNC_RE, 'function'),
                (self.CLASS_RE, 'class'),
                (self.MODULE_EXPORT_RE, 'export'),
            ]:
                match = pattern.match(line)
                if match:
                    name = match.group(1)
                    start_line = lineno

                    # Find the end of the definition
                    end_line = self._find_block_end(lines, i, start_line)

                    # Avoid duplicates - keep the first occurrence
                    if name not in self.tags:
                        self.tags[name] = (symbol_type, start_line, end_line)

                    break

            i += 1

    def _find_block_end(self, lines: list[str], start_idx: int, start_line: int) -> int:
        """Find the end line of a code block.

        Simple heuristic: count braces for function/class bodies.

        Args:
            lines: All source lines
            start_idx: Starting line index (0-based)
            start_line: Starting line number (1-based)

        Returns:
            End line number (1-based)
        """
        # Simple heuristic: count braces
        brace_count = 0
        found_open_brace = False

        for i in range(start_idx, len(lines)):
            line = lines[i]

            # Count braces
            for char in line:
                if char == '{':
                    brace_count += 1
                    found_open_brace = True
                elif char == '}':
                    brace_count -= 1

                    # When we close all braces, we're done
                    if found_open_brace and brace_count == 0:
                        return i + 1  # Line number is 1-indexed

            # Arrow functions might not have braces
            if '=>' in line and not found_open_brace:
                # Single-line arrow function
                if ';' in line or i == len(lines) - 1:
                    return i + 1

        # Fallback: assume it goes to the end
        return len(lines)

    @classmethod
    def for_file(cls, source_path: Path) -> 'JavaScriptAnalyzer':
        """Create and analyze a JavaScript source file.

        Args:
            source_path: Path to the .js file

        Returns:
            Analyzed JavaScriptAnalyzer instance
        """
        analyzer = cls(source_path)
        analyzer.analyze()
        return analyzer
