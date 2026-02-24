"""JavaScript source code viewer extension for Sphinx.

Similar to rust_viewcode but for JavaScript files in stark-recurser/:
- Generates syntax-highlighted HTML pages with full Sphinx theme
- Creates named anchors for function/class/export definitions
- Enables {src}`stark-recurser/path/file.js#functionName` references
"""

from pathlib import Path
from typing import Dict, Set, Iterator, Tuple, Any
from sphinx.application import Sphinx
from sphinx.util import logging
from sphinx.builders.html import StandaloneHTMLBuilder
from _ext.js_analyzer import JavaScriptAnalyzer

logger = logging.getLogger(__name__)

OUTPUT_DIRNAME = '_modules'


def collect_js_files(app: Sphinx) -> Dict[str, Tuple[str, Dict, Path]]:
    """Collect all JavaScript files to process.

    Returns:
        Dict mapping relative path to (code, tags, source_path)
    """
    recurser_root = Path(app.confdir).parent.parent / 'stark-recurser'
    if not recurser_root.exists():
        logger.warning(f"[js_viewcode] stark-recurser not found at {recurser_root}")
        return {}

    js_source_paths = getattr(app.config, 'js_source_paths', ['src'])

    # Find all JavaScript files
    js_files: Set[Path] = set()
    for source_path in js_source_paths:
        search_root = recurser_root / source_path
        if search_root.exists():
            js_files.update(search_root.rglob('*.js'))

    if not js_files:
        logger.warning(f"[js_viewcode] No JavaScript files found in {js_source_paths}")
        return {}

    # Analyze each file
    result = {}
    for js_file in sorted(js_files):
        try:
            # Relative path from stark-recurser root
            rel_path = str(js_file.relative_to(recurser_root))

            # Analyze for symbol definitions
            analyzer = JavaScriptAnalyzer.for_file(js_file)

            result[rel_path] = (analyzer.code, analyzer.tags, js_file)

        except Exception as e:
            logger.warning(f"[js_viewcode] Failed to analyze {js_file}: {e}")

    return result


def collect_pages(app: Sphinx) -> Iterator[Tuple[str, Dict[str, Any], str]]:
    """Generate JavaScript source code pages with full Sphinx theme.

    Yields:
        Tuples of (pagename, context, template) for Sphinx to render
    """
    if app.builder.name != 'html':
        return

    builder = app.builder
    if not isinstance(builder, StandaloneHTMLBuilder):
        return

    highlighter = builder.highlighter

    # Collect all JavaScript files
    js_modules = collect_js_files(app)

    if not js_modules:
        return

    logger.info(f"[js_viewcode] Generating pages for {len(js_modules)} JavaScript files...")

    # Process each JavaScript file
    for rel_path, (code, tags, source_path) in js_modules.items():
        # Page name: _modules/stark-recurser/src/vadcop/is_compressor_needed
        # (without .js extension for the pagename, Sphinx adds .html)
        pagename = f"{OUTPUT_DIRNAME}/stark-recurser/{rel_path.replace('.js', '')}"

        # Highlight the source
        highlighted = highlighter.highlight_block(code, 'javascript', linenos='inline')

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
        title = f"stark-recurser/{rel_path}"
        body_html = f'<h1>Source code for {title}</h1>\n' + '\n'.join(lines)

        context = {
            'title': title,
            'body': body_html,
        }

        # Yield for Sphinx to render with page.html template
        yield pagename, context, 'page.html'


def setup(app: Sphinx) -> Dict[str, any]:
    """Register the extension."""
    app.add_config_value('js_source_paths', ['src'], 'html')
    app.connect('html-collect-pages', collect_pages)

    return {
        'version': '0.1',
        'parallel_read_safe': True,
        'parallel_write_safe': False,
    }
