"""PIL source code viewer extension for Sphinx.

Generates syntax-highlighted HTML pages for PIL (Polynomial Interactive Language) files.
- Creates simple pages with line numbers
- Enables {src}`zisk/pil/file.pil:line` references
"""

from pathlib import Path
from typing import Dict, Iterator, Tuple, Any
from sphinx.application import Sphinx
from sphinx.util import logging
from sphinx.builders.html import StandaloneHTMLBuilder

logger = logging.getLogger(__name__)

OUTPUT_DIRNAME = '_modules'


def collect_pil_files(app: Sphinx) -> Dict[str, Tuple[str, Path]]:
    """Collect all PIL files to process.

    Returns:
        Dict mapping relative path to (code, source_path)
    """
    zisk_root = Path(app.confdir).parent.parent / 'zisk'
    if not zisk_root.exists():
        logger.warning(f"[pil_viewcode] zisk not found at {zisk_root}")
        return {}

    # Find all PIL files
    pil_files = list(zisk_root.rglob('*.pil'))

    if not pil_files:
        logger.warning("[pil_viewcode] No PIL files found")
        return {}

    # Read each file
    result = {}
    for pil_file in sorted(pil_files):
        try:
            # Relative path from zisk root
            rel_path = str(pil_file.relative_to(zisk_root))
            code = pil_file.read_text(encoding='utf-8')
            result[rel_path] = (code, pil_file)

        except Exception as e:
            logger.warning(f"[pil_viewcode] Failed to read {pil_file}: {e}")

    return result


def collect_pages(app: Sphinx) -> Iterator[Tuple[str, Dict[str, Any], str]]:
    """Generate PIL source pages during html-collect-pages phase.

    Yields:
        (pagename, context, template) for each PIL file
    """
    if not isinstance(app.builder, StandaloneHTMLBuilder):
        return

    pil_modules = collect_pil_files(app)
    if not pil_modules:
        return

    logger.info(f"[pil_viewcode] Generating pages for {len(pil_modules)} PIL files...")

    for rel_path, (code, source_path) in pil_modules.items():
        # Generate HTML with line numbers and highlighting
        lines = code.splitlines()
        html_lines = [
            '<style>',
            '  /* Highlight target line when jumping to anchor */',
            '  .highlight pre span:target {',
            '    background-color: #ffa;',
            '    display: block;',
            '  }',
            '  .highlight pre .linenos {',
            '    color: #666;',
            '    text-decoration: none;',
            '    margin-right: 1em;',
            '  }',
            '  /* Enable word wrapping for long lines */',
            '  .highlight pre {',
            '    white-space: pre-wrap;',
            '    word-wrap: break-word;',
            '  }',
            '</style>',
            '<div class="highlight"><pre>'
        ]

        for i, line in enumerate(lines, start=1):
            # Escape HTML
            line_escaped = (line
                          .replace('&', '&amp;')
                          .replace('<', '&lt;')
                          .replace('>', '&gt;'))
            # Add line number anchor
            html_lines.append(
                f'<span id="L-{i}"><a href="#L-{i}" class="linenos">{i:4d}</a> {line_escaped}</span>'
            )

        html_lines.append('</pre></div>')
        html_code = '\n'.join(html_lines)

        # Page name: _modules/zisk/pil/zisk
        # (Sphinx adds .html, so remove .pil extension)
        pagename = f"{OUTPUT_DIRNAME}/zisk/{rel_path.replace('.pil', '')}"

        # Context for Sphinx template
        context = {
            'title': f"zisk/{rel_path}",
            'body': html_code,
        }

        yield pagename, context, 'page.html'


def setup(app: Sphinx):
    """Register the extension."""
    app.connect('html-collect-pages', collect_pages)
    return {
        'version': '0.1',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
