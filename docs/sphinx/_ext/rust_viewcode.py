"""Rust source code viewer extension for Sphinx.

Mimics sphinx.ext.viewcode for Rust source files:
- Generates syntax-highlighted HTML pages with full Sphinx theme
- Creates named anchors for struct/enum/impl/function definitions
- Enables {src}`path/to/file.rs#SymbolName` references in documentation
"""

from pathlib import Path
from typing import Dict, Set, Iterator, Tuple, Any
from sphinx.application import Sphinx
from sphinx.util import logging
from sphinx.builders.html import StandaloneHTMLBuilder
from pygments import highlight
from pygments.lexers import RustLexer
from pygments.formatters import HtmlFormatter
from _ext.rust_analyzer import RustAnalyzer

logger = logging.getLogger(__name__)

OUTPUT_DIRNAME = '_modules'


def collect_rust_files(app: Sphinx) -> Dict[str, Tuple[str, Dict, Path]]:
    """Collect all Rust files to process.

    Returns:
        Dict mapping relative path to (code, tags, source_path)
    """
    zisk_root = Path(app.confdir) / 'zisk'
    if not zisk_root.exists():
        logger.warning(f"[rust_viewcode] zisk submodule not found at {zisk_root}")
        return {}

    rust_source_paths = getattr(app.config, 'rust_source_paths', ['state-machines', 'precompiles', 'data-bus'])

    # Find all Rust files
    rust_files: Set[Path] = set()
    for source_path in rust_source_paths:
        search_root = zisk_root / source_path
        if search_root.exists():
            rust_files.update(search_root.rglob('*.rs'))

    if not rust_files:
        logger.warning(f"[rust_viewcode] No Rust files found in {rust_source_paths}")
        return {}

    # Analyze each file
    result = {}
    for rust_file in sorted(rust_files):
        try:
            # Relative path from zisk root
            rel_path = str(rust_file.relative_to(zisk_root))

            # Analyze for symbol definitions
            analyzer = RustAnalyzer.for_file(rust_file)

            result[rel_path] = (analyzer.code, analyzer.tags, rust_file)

        except Exception as e:
            logger.warning(f"[rust_viewcode] Failed to analyze {rust_file}: {e}")

    return result


def collect_pages(app: Sphinx) -> Iterator[Tuple[str, Dict[str, Any], str]]:
    """Generate Rust source code pages with full Sphinx theme.

    Yields:
        Tuples of (pagename, context, template) for Sphinx to render
    """
    if app.builder.name != 'html':
        return

    builder = app.builder
    if not isinstance(builder, StandaloneHTMLBuilder):
        return

    highlighter = builder.highlighter
    urito = builder.get_relative_uri

    # Collect all Rust files
    rust_modules = collect_rust_files(app)

    if not rust_modules:
        return

    logger.info(f"[rust_viewcode] Generating pages for {len(rust_modules)} Rust files...")

    # Process each Rust file
    for rel_path, (code, tags, source_path) in rust_modules.items():
        # Page name: _modules/zisk/state-machines/main/src/main_sm.rs
        # (without .rs extension for the pagename, Sphinx adds .html)
        pagename = f"{OUTPUT_DIRNAME}/zisk/{rel_path.replace('.rs', '')}"

        # Highlight the source
        highlighted = highlighter.highlight_block(code, 'rust', linenos='inline')

        # Split into lines
        lines = highlighted.splitlines()

        # Split off wrap markup from the first line
        if lines and '<pre>' in lines[0]:
            before, after = lines[0].split('<pre>')
            lines[0:1] = [before + '<pre>', after]

        # Insert named anchors for symbols
        max_index = len(lines) - 1
        for name, (symbol_type, start, end) in tags.items():
            if 0 < start <= len(lines):
                # Insert anchor div at start line (1-indexed)
                lines[start - 1] = (
                    f'<div class="viewcode-block" id="{name}">\n'
                    + lines[start - 1]
                )

                # Close div at end line
                end_idx = min(end - 1, max_index)
                if 0 <= end_idx < len(lines):
                    lines[end_idx] += '\n</div>'

        # Prepare context for template
        title = f"zisk/{rel_path}"
        body_html = f'<h1>Source code for {title}</h1>\n' + '\n'.join(lines)

        context = {
            'title': title,
            'body': body_html,
        }

        # Yield for Sphinx to render with page.html template
        yield pagename, context, 'page.html'


def setup(app: Sphinx) -> Dict[str, any]:
    """Register the extension."""
    app.add_config_value('rust_source_paths', ['state-machines', 'precompiles', 'data-bus'], 'html')
    app.connect('html-collect-pages', collect_pages)

    return {
        'version': '0.2',
        'parallel_read_safe': True,
        'parallel_write_safe': False,  # collect_pages is not parallel-safe
    }
