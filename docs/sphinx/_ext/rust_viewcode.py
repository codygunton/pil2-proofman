"""Rust source code viewer extension for Sphinx.

Mimics sphinx.ext.viewcode for Rust source files:
- Copies Rust source files from the zisk submodule
- Generates syntax-highlighted HTML with per-line anchors
- Enables {src}`path/to/file.rs:line` references in documentation
"""

from pathlib import Path
from typing import Dict, Set
from sphinx.application import Sphinx
from sphinx.util import logging
from pygments import highlight
from pygments.lexers import RustLexer
from pygments.formatters import HtmlFormatter

logger = logging.getLogger(__name__)


def copy_rust_sources(app: Sphinx, exception: Exception) -> None:
    """Copy and highlight Rust source files during build.

    Called at build-finished event.
    """
    if exception is not None:
        return  # Build failed, skip

    if app.builder.name != 'html':
        return  # Only for HTML builds

    # Paths
    zisk_root = Path(app.confdir).parent.parent / 'zisk'
    if not zisk_root.exists():
        logger.warning(f"[rust_viewcode] zisk submodule not found at {zisk_root}")
        return

    output_dir = Path(app.outdir) / '_modules' / 'zisk'
    rust_source_paths = getattr(app.config, 'rust_source_paths', ['state-machines'])

    logger.info("[rust_viewcode] Copying and highlighting Rust sources...")

    # Find all Rust files
    rust_files: Set[Path] = set()
    for source_path in rust_source_paths:
        search_root = zisk_root / source_path
        if search_root.exists():
            rust_files.update(search_root.rglob('*.rs'))

    if not rust_files:
        logger.warning(f"[rust_viewcode] No Rust files found in {rust_source_paths}")
        return

    # Highlight and copy each file
    formatter = HtmlFormatter(
        linenos='table',
        lineanchors='L',  # Line anchors like #L-42
        anchorlinenos=True,
        cssclass='highlight',
        style='friendly'
    )
    lexer = RustLexer()

    for rust_file in sorted(rust_files):
        try:
            # Relative path from zisk root
            rel_path = rust_file.relative_to(zisk_root)

            # Output path
            out_file = output_dir / f"{rel_path}.html"
            out_file.parent.mkdir(parents=True, exist_ok=True)

            # Read and highlight
            source_code = rust_file.read_text(encoding='utf-8')
            highlighted = highlight(source_code, lexer, formatter)

            # Wrap in minimal HTML
            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{rel_path}</title>
    <link rel="stylesheet" href="{'../' * (len(rel_path.parts) - 1)}_static/pygments.css">
    <style>
        body {{ font-family: monospace; margin: 20px; }}
        .highlight {{ font-size: 14px; }}
        h1 {{ font-size: 18px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>{rel_path}</h1>
    {highlighted}
</body>
</html>
"""
            out_file.write_text(html, encoding='utf-8')

        except Exception as e:
            logger.warning(f"[rust_viewcode] Failed to process {rust_file}: {e}")

    logger.info(f"[rust_viewcode] Processed {len(rust_files)} Rust files")


def setup(app: Sphinx) -> Dict[str, any]:
    """Register the extension."""
    app.add_config_value('rust_source_paths', ['state-machines'], 'html')
    app.connect('build-finished', copy_rust_sources)

    return {
        'version': '0.1',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
