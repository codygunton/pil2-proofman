"""Rust source code analyzer for extracting symbol definitions.

Similar to Python's ModuleAnalyzer but for Rust files.
Extracts struct, enum, impl, and function definitions with their line numbers.
"""

import re
from pathlib import Path
from typing import Dict, Tuple
from sphinx.util import logging

logger = logging.getLogger(__name__)

# Type alias for tags: {name: (type, start_line, end_line)}
Tags = Dict[str, Tuple[str, int, int]]


class RustAnalyzer:
    """Analyze Rust source files to extract symbol definitions."""

    # Regex patterns for Rust symbols
    # Match: pub struct Name, pub struct Name<T>, etc.
    STRUCT_RE = re.compile(r'^\s*pub\s+struct\s+([A-Z][A-Za-z0-9_]*)\b')

    # Match: pub enum Name, pub enum Name<T>, etc.
    ENUM_RE = re.compile(r'^\s*pub\s+enum\s+([A-Z][A-Za-z0-9_]*)\b')

    # Match: impl Name, impl<T> Name<T>, impl Name for Trait, etc.
    IMPL_RE = re.compile(r'^\s*impl(?:<[^>]+>)?\s+([A-Z][A-Za-z0-9_]*)\b')

    # Match: pub fn name(, pub async fn name(, pub const fn name(, etc.
    FN_RE = re.compile(r'^\s*pub\s+(?:async\s+)?(?:const\s+)?(?:unsafe\s+)?fn\s+([a-z_][a-z0-9_]*)\s*[(<]')

    # Match: pub trait Name
    TRAIT_RE = re.compile(r'^\s*pub\s+trait\s+([A-Z][A-Za-z0-9_]*)\b')

    def __init__(self, source_path: Path):
        """Initialize analyzer for a Rust source file.

        Args:
            source_path: Path to the .rs file
        """
        self.source_path = source_path
        self.code = ""
        self.tags: Tags = {}

    def analyze(self) -> None:
        """Analyze the source file and extract symbol definitions."""
        try:
            self.code = self.source_path.read_text(encoding='utf-8')
        except Exception as e:
            logger.warning(f"[rust_analyzer] Failed to read {self.source_path}: {e}")
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
                (self.STRUCT_RE, 'struct'),
                (self.ENUM_RE, 'enum'),
                (self.TRAIT_RE, 'trait'),
                (self.IMPL_RE, 'impl'),
                (self.FN_RE, 'function'),
            ]:
                match = pattern.match(line)
                if match:
                    name = match.group(1)
                    start_line = lineno

                    # Find the end of the definition
                    end_line = self._find_block_end(lines, i, start_line)

                    # For impl blocks, use "impl_StructName" as the tag
                    if symbol_type == 'impl':
                        tag_name = f"impl_{name}"
                    else:
                        tag_name = name

                    # Avoid duplicates - keep the first occurrence
                    if tag_name not in self.tags:
                        self.tags[tag_name] = (symbol_type, start_line, end_line)

                    break

            i += 1

    def _find_block_end(self, lines: list[str], start_idx: int, start_line: int) -> int:
        """Find the end line of a code block.

        For simple heuristic: find matching closing brace or semicolon.

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

            # Check for semicolon-terminated declarations (no body)
            if not found_open_brace and ';' in line:
                return i + 1

        # Fallback: assume it goes to the end
        return len(lines)

    @classmethod
    def for_file(cls, source_path: Path) -> 'RustAnalyzer':
        """Create and analyze a Rust source file.

        Args:
            source_path: Path to the .rs file

        Returns:
            Analyzed RustAnalyzer instance
        """
        analyzer = cls(source_path)
        analyzer.analyze()
        return analyzer
