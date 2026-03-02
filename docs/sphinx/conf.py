# conf.py — Sphinx configuration for ZisK Prover Specification
#
# Build HTML:  cd docs/sphinx && uv run --group docs make html
# Build PDF:   cd docs/sphinx && uv run --group docs make latexpdf
# Serve:       cd docs/sphinx && uv run --group docs make serve

import os
import pickle
import sys
from unittest.mock import MagicMock

# -- Path setup ---------------------------------------------------------------
# Add executable-spec to sys.path so autodoc can import Python modules.
sys.path.insert(0, os.path.abspath("../../executable-spec"))
# Add docs/sphinx to sys.path so _ext can be imported.
sys.path.insert(0, os.path.abspath("."))

# -- Mock galois and FFI for autodoc/viewcode ---------------------------------
# The executable-spec uses galois (Galois field arithmetic) and poseidon2_ffi
# (Rust FFI for Poseidon2 hashing) which aren't available in the docs build.
# We mock them so autodoc can import the modules and viewcode can generate
# browsable, syntax-highlighted source pages.
for _mod in ["galois", "galois._fields", "galois._fields._gf",
             "galois._fields._array", "galois._domains", "galois._polys",
             "poseidon2_ffi"]:
    sys.modules[_mod] = MagicMock()

# galois field types are pickled in ff3_cache.pkl; patch pickle.load to
# return a mock instead of failing on the missing galois internals.
_orig_pickle_load = pickle.load
def _safe_pickle_load(f, **kwargs):
    try:
        return _orig_pickle_load(f, **kwargs)
    except Exception:
        return MagicMock()
pickle.load = _safe_pickle_load

# -- Project information ------------------------------------------------------
project = "ZisK Prover Specification"
author = "Derived from the Python Executable Specification"
release = ""  # intentionally blank — suppresses "Release X" in PDF header

# -- General configuration ----------------------------------------------------
extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
    "autoapi.extension",
    "sphinx_copybutton",
    "sphinx_design",
    "_ext.rust_viewcode",  # Rust source code viewer
    "_ext.js_viewcode",    # JavaScript source code viewer
    "_ext.pil_viewcode",   # PIL source code viewer
    "sphinxcontrib.mermaid",
]

# MyST extensions for math + structured content
myst_enable_extensions = [
    "dollarmath",
    "amsmath",
    "deflist",
    "colon_fence",
]

# Numbered figures / tables / code blocks for cross-refs
numfig = True

# Source file suffixes
source_suffix = {
    ".md": "markdown",
    ".rst": "restructuredtext",
}

# -- Autodoc ------------------------------------------------------------------
autodoc_member_order = "bysource"

# -- AutoAPI (browsable module tree) ------------------------------------------
# Generates one page per module with a navigable sidebar tree.
_spec = os.path.abspath("../../executable-spec")
autoapi_dirs = [
    os.path.join(_spec, "primitives"),
    os.path.join(_spec, "protocol"),
    os.path.join(_spec, "constraints"),
    os.path.join(_spec, "witness"),
]
autoapi_root = "api"
autoapi_type = "python"
autoapi_options = [
    "members",
    "undoc-members",
    "show-inheritance",
    "show-module-summary",
]
autoapi_own_page_level = "module"
autoapi_member_order = "bysource"

# -- Rust source code viewing -------------------------------------------------
rust_source_paths = ["state-machines", "precompiles"]  # Relative to zisk/ submodule
autoapi_add_toctree_entry = False
autoapi_keep_files = True
autoapi_python_use_implicit_namespaces = True
autoapi_ignore = [
    "*/tests/*",
    "*/poseidon2-ffi/*",
    "*/.venv/*",
]

# -- HTML theme ---------------------------------------------------------------
html_theme = "sphinx_book_theme"
html_static_path = ["_static"]
html_css_files = ["custom.css"]
html_title = "ZisK Prover Spec"
html_theme_options = {
    "repository_url": "https://github.com/codygunton/pil2-proofman/tree/executable-specs",
    "use_repository_button": True,
    "use_fullscreen_button": False,
    "use_download_button": False,
    "show_toc_level": 2,
}

# -- Custom math macros -------------------------------------------------------
# Translated from docs/preamble.tex.  Shared by MathJax (HTML) and LaTeX (PDF).
# NOTE: \textsf is not available in MathJax; use \mathsf instead.
_MACROS = {
    r"\F":        r"\mathbb{F}_p",
    r"\Fext":     r"\mathbb{F}_{p^3}",
    r"\ZH":       r"Z_H",
    r"\MT":       r"\mathsf{MT}",
    r"\Hash":     r"\mathsf{H}",
    r"\Poseidon": r"\mathsf{Poseidon2}",
    r"\LinHash":  r"\mathsf{LinearHash}",
    r"\T":        r"\mathcal{T}",
    r"\abs":      r"\mathsf{absorb}",
    r"\sq":       r"\mathsf{squeeze}",
    r"\sqidx":    r"\mathsf{squeeze\_indices}",
    r"\Fold":     r"\mathsf{Fold}",
    r"\INTT":     r"\mathsf{INTT}",
    r"\NTT":      r"\mathsf{NTT}",
    r"\longto":   r"\longrightarrow",
    r"\longfrom": r"\longleftarrow",
}

# MathJax 3 configuration
mathjax3_config = {
    "tex": {
        "macros": {
            # Strip leading backslash for MathJax macro names
            k.lstrip("\\"): v
            for k, v in _MACROS.items()
        },
    },
}

# -- PDF download button in header --------------------------------------------
def _add_pdf_header_button(app, pagename, templatename, context, doctree):
    context.setdefault("header_buttons", [])
    pdf_url = context["pathto"]("_static/zisk-prover-spec.pdf", 1)
    context["header_buttons"].insert(0, {
        "type": "link",
        "url": pdf_url,
        "tooltip": "Download PDF",
        "icon": "fas fa-file-pdf",
        "label": "download-pdf-button",
    })

def _src_role(_name, rawtext, text, lineno, inliner, options=None, content=None):
    """Inline role for linking to viewcode source lines.

    Supports three reference formats:
    1. Legacy line number:  {src}`protocol/prover.py:202`
       - Direct line number reference (backwards compatible)
       - Works without anchor cache
       - Brittle: breaks when code changes

    2. Symbol reference:    {src}`protocol.prover.gen_proof`
       - Automatic function/class definition lookup via AST
       - Requires anchor cache (built by anchor_scanner.py)
       - Survives code refactoring

    3. Anchor reference:    {src}`protocol/prover.py#witness-commit`
       - Links to code anchor comments: # <doc-anchor id="witness-commit">
       - Requires anchor cache (built by anchor_scanner.py)
       - Self-documenting, survives refactoring

    All formats render as clickable links to the viewcode page at the correct line.

    Error Handling:
    - Missing anchor cache: Clear error for symbol/anchor refs
    - Missing file/anchor/symbol: Detailed error with suggestions
    - Invalid format: Clear error message with expected formats
    - Legacy refs always work (backwards compatible)
    """
    import posixpath
    from docutils import nodes

    env = inliner.document.settings.env
    docname = env.docname  # e.g., "part-stark/commitment-phase"

    # Check for custom display text: {src}`Custom Text <path#anchor>`
    custom_text = None
    if '<' in text and text.endswith('>'):
        custom_text, path_part = text.rsplit('<', 1)
        custom_text = custom_text.strip()
        text = path_part.rstrip('>')

    # Check if this is a PIL file reference (check before Rust since zisk/ overlaps)
    is_pil = '.pil' in text

    # Check if this is a Rust file reference
    is_rust = (text.endswith('.rs') or text.startswith('zisk/')) and not is_pil

    # Check if this is a JavaScript file reference
    is_js = text.endswith('.js') or text.startswith('stark-recurser/')

    # PIL files: support :line syntax (anchors not implemented yet)
    if is_pil:
        if ':' in text:
            # Line number format: zisk/pil/zisk.pil:40
            file_path, line_str = text.rsplit(':', 1)
            try:
                line_num = int(line_str)
            except ValueError:
                msg = f"Invalid line number in PIL reference '{text}'"
                return [inliner.reporter.error(msg, line=lineno)], []

            # Display: custom text or filename:line
            display = custom_text if custom_text else (file_path.rsplit('/', 1)[-1] + ':' + line_str)

            # Generate link to PIL viewcode with line anchor
            target = f"_modules/{file_path.replace('.pil', '')}"
            rel = posixpath.relpath(target, posixpath.dirname(docname))
            url = f"{rel}.html#L-{line_num}"

        else:
            msg = f"PIL references require :line syntax: {text}"
            return [inliner.reporter.error(msg, line=lineno)], []

        node = nodes.reference(rawtext, "", refuri=url, **(options or {}))
        # Use inline text for custom display, literal (code) for default
        if custom_text:
            node += nodes.inline(display, display)
        else:
            node += nodes.literal(display, display)
        return [node], []

    # Rust files: support both #anchor and :line syntax
    if is_rust:
        if '#' in text:
            # Anchor format: zisk/state-machines/main/src/main_sm.rs#MainInstance
            file_path, anchor_name = text.rsplit('#', 1)

            # Display: custom text or filename#anchor
            display = custom_text if custom_text else (file_path.rsplit('/', 1)[-1] + '#' + anchor_name)

            # Generate link to Rust viewcode with anchor
            # Remove .rs extension from file_path for target (Sphinx adds .html)
            target = f"_modules/{file_path.replace('.rs', '')}"
            rel = posixpath.relpath(target, posixpath.dirname(docname))
            url = f"{rel}.html#{anchor_name}"

        elif ':' in text:
            # Line number format: zisk/state-machines/main/src/main_sm.rs:40
            file_path, line_str = text.rsplit(':', 1)
            try:
                line_num = int(line_str)
            except ValueError:
                msg = f"Invalid line number in Rust reference '{text}'"
                return [inliner.reporter.error(msg, line=lineno)], []

            # Display: custom text or filename:line
            display = custom_text if custom_text else (file_path.rsplit('/', 1)[-1] + ':' + line_str)

            # Generate link to Rust viewcode with line anchor
            target = f"_modules/{file_path.replace('.rs', '')}"
            rel = posixpath.relpath(target, posixpath.dirname(docname))
            url = f"{rel}.html#L-{line_num}"

        else:
            msg = f"Rust references require #anchor or :line syntax: {text}"
            return [inliner.reporter.error(msg, line=lineno)], []

        node = nodes.reference(rawtext, "", refuri=url, **(options or {}))
        # Use inline text for custom display, literal (code) for default
        if custom_text:
            node += nodes.inline(display, display)
        else:
            node += nodes.literal(display, display)
        return [node], []

    # JavaScript files: support both #anchor and :line syntax
    if is_js:
        if '#' in text:
            # Anchor format: stark-recurser/src/vadcop/is_compressor_needed.js#isCompressorNeeded
            file_path, anchor_name = text.rsplit('#', 1)

            # Display: custom text or filename#anchor
            display = custom_text if custom_text else (file_path.rsplit('/', 1)[-1] + '#' + anchor_name)

            # Generate link to JS viewcode with anchor
            # Remove .js extension from file_path for target (Sphinx adds .html)
            target = f"_modules/{file_path.replace('.js', '')}"
            rel = posixpath.relpath(target, posixpath.dirname(docname))
            url = f"{rel}.html#{anchor_name}"

        elif ':' in text:
            # Line number format: stark-recurser/src/vadcop/is_compressor_needed.js:14
            file_path, line_str = text.rsplit(':', 1)
            try:
                line_num = int(line_str)
            except ValueError:
                msg = f"Invalid line number in JavaScript reference '{text}'"
                return [inliner.reporter.error(msg, line=lineno)], []

            # Display: custom text or filename:line
            display = custom_text if custom_text else (file_path.rsplit('/', 1)[-1] + ':' + line_str)

            # Generate link to JS viewcode with line anchor
            target = f"_modules/{file_path.replace('.js', '')}"
            rel = posixpath.relpath(target, posixpath.dirname(docname))
            url = f"{rel}.html#L-{line_num}"

        else:
            msg = f"JavaScript references require #anchor or :line syntax: {text}"
            return [inliner.reporter.error(msg, line=lineno)], []

        node = nodes.reference(rawtext, "", refuri=url, **(options or {}))
        # Use inline text for custom display, literal (code) for default
        if custom_text:
            node += nodes.inline(display, display)
        else:
            node += nodes.literal(display, display)
        return [node], []

    # Python files: full anchor/symbol support
    if '#' in text:
        # Anchor format: protocol/prover.py#witness-commit
        file_path, anchor_id = text.rsplit('#', 1)
        if not file_path.endswith('.py'):
            file_path += '.py'

        # Look up anchor in cache
        anchor_cache = getattr(env.config, 'anchor_cache', None)
        if anchor_cache is None:
            msg = f"Anchor cache not available for reference '{text}'"
            return [inliner.reporter.error(msg, line=lineno)], []

        if file_path not in anchor_cache:
            msg = f"File '{file_path}' not found in anchor cache for reference '{text}'"
            return [inliner.reporter.error(msg, line=lineno)], []

        if anchor_id not in anchor_cache[file_path]:
            available = ', '.join(sorted(anchor_cache[file_path].keys())[:5])
            msg = f"Anchor '{anchor_id}' not found in {file_path}. Available anchors: {available}..."
            return [inliner.reporter.error(msg, line=lineno)], []

        line_num = anchor_cache[file_path][anchor_id]
        display = f"{file_path.rsplit('/', 1)[-1]}#{anchor_id}"

    elif '.' in text and ':' not in text and '#' not in text:
        # Symbol format: protocol.prover.gen_proof
        anchor_cache = getattr(env.config, 'anchor_cache', None)
        if anchor_cache is None:
            msg = f"Anchor cache not available for symbol reference '{text}'"
            return [inliner.reporter.error(msg, line=lineno)], []

        # Convert module path to file path
        # Symbols are stored as full paths (e.g., "protocol.prover.gen_proof")
        # in the cache, so we need to find which file contains this symbol
        parts = text.split('.')
        file_path = None
        symbol_name = text  # Full symbol path for lookup
        line_num = None

        # Try longest path first (most specific): protocol/prover/gen_proof.py -> protocol/prover.py -> protocol.py
        for i in range(len(parts) - 1, 0, -1):
            candidate_path = '/'.join(parts[:i]) + '.py'

            if candidate_path in anchor_cache:
                # Symbols are stored with full module path as key
                if symbol_name in anchor_cache[candidate_path]:
                    file_path = candidate_path
                    line_num = anchor_cache[candidate_path][symbol_name]
                    break

        if file_path is None or line_num is None:
            msg = f"Symbol '{text}' not found in anchor cache. Tried module paths: {', '.join(['/'.join(parts[:i]) + '.py' for i in range(len(parts)-1, 0, -1)])}"
            return [inliner.reporter.error(msg, line=lineno)], []

        display = f"{parts[-1]}" if len(parts) > 1 else text

    elif ':' in text:
        # Legacy format: protocol/prover.py:202
        file_path, line_str = text.rsplit(':', 1)
        try:
            line_num = int(line_str)
        except ValueError:
            msg = f"Invalid line number in reference '{text}'"
            return [inliner.reporter.error(msg, line=lineno)], []
        display = file_path.rsplit('/', 1)[-1] + ':' + line_str

    else:
        msg = f"Invalid reference format '{text}'. Expected 'path:line', 'module.symbol', or 'path#anchor'"
        return [inliner.reporter.error(msg, line=lineno)], []

    # Generate viewcode link
    module_path = file_path.replace('.py', '')  # "protocol/prover"
    target = f"_modules/{module_path}"
    rel = posixpath.relpath(target, posixpath.dirname(docname))
    url = f"{rel}.html#L-{line_num}"

    node = nodes.reference(rawtext, "", refuri=url, **(options or {}))
    node += nodes.literal(display, display)
    return [node], []


def _patch_viewcode_line_anchors(app):
    """Patch Sphinx's Pygments bridge so viewcode pages get per-line anchors.

    Sphinx Issue #747: viewcode doesn't expose HtmlFormatter's lineanchors option.
    This monkey-patch injects lineanchors='L' so each line gets an id like #L-42,
    enabling GitHub-style line-level permalink links from the spec prose.
    """
    from sphinx.highlighting import PygmentsBridge
    _orig_init = PygmentsBridge.__init__

    def _patched_init(self, *args, **kwargs):
        _orig_init(self, *args, **kwargs)
        if hasattr(self, 'formatter') and self.formatter is not None:
            self.formatter.lineanchors = 'L'
            self.formatter.anchorlinenos = True
        if hasattr(self, 'formatter_args'):
            self.formatter_args['lineanchors'] = 'L'
            self.formatter_args['anchorlinenos'] = True

    PygmentsBridge.__init__ = _patched_init

def _init_anchor_cache(app, config):
    """Initialize anchor cache on config-inited event (before env is available)."""
    from pathlib import Path

    # Build anchor cache for symbol and anchor references
    try:
        # Import the scanner from the _ext directory
        from _ext.anchor_scanner import load_anchor_cache

        base_path = Path(__file__).parent.parent.parent / "executable-spec"
        cache_path = Path(__file__).parent / "_anchor_cache.pkl"

        # Load the anchor cache (rebuilds if stale or missing)
        anchor_cache = load_anchor_cache(cache_path, base_path)

        # Store in config for later retrieval by _src_role
        config.anchor_cache = anchor_cache

    except ImportError as e:
        # Scanner not yet implemented - anchor/symbol refs will fail gracefully
        config.anchor_cache = None
        print(f"Warning: anchor_scanner not available ({e})")
    except Exception as e:
        # Cache build failed - log but don't break the build
        config.anchor_cache = None
        print(f"Warning: Failed to build anchor cache: {e}")


def setup(app):
    """Sphinx setup hook: initialize anchor cache and register custom roles."""
    _patch_viewcode_line_anchors(app)
    app.add_role("src", _src_role)
    app.connect("html-page-context", _add_pdf_header_button, priority=600)
    app.connect("config-inited", _init_anchor_cache)

# -- Mermaid (diagrams) -------------------------------------------------------
# HTML uses client-side JS rendering (default "raw" mode).
# PDF uses a pre-rendered PNG (via {only} latex blocks in the source).

# -- LaTeX (PDF) output -------------------------------------------------------
# Goal: clean academic-style PDF that looks like a proper specification,
# not a software manual.

# Part-level structure: part-stark/index → \part{}, notation → \chapter{}, etc.
latex_toplevel_sectioning = "part"

# Custom macros for LaTeX
_latex_preamble = "\n".join(
    rf"\newcommand{{{k}}}{{{v}}}" for k, v in _MACROS.items()
)

latex_elements = {
    "papersize": "a4paper",
    "pointsize": "11pt",
    "extraclassoptions": "oneside",

    # Latin Modern fonts — the standard academic LaTeX look
    "fontpkg": r"\usepackage{lmodern}",

    # Disable fancy chapter headings (Bjarne style → clean default)
    "fncychap": "",

    # Custom preamble: macros + typography tweaks
    "preamble": _latex_preamble + r"""

% Fix fancyhdr headheight warning
\setlength{\headheight}{13.6pt}

% Tighter page margins (Sphinx default is generous)
\geometry{margin=1in}

% Clean hyperlink colors (not garish default red/green)
\hypersetup{
  colorlinks=true,
  linkcolor=blue!70!black,
  citecolor=blue!70!black,
  urlcolor=blue!70!black,
}

% Slightly more compact lists
\usepackage{enumitem}
\setlist{nosep,leftmargin=*}

% Remove "Release" from the running header
\renewcommand{\releasename}{}
""",

    # Custom title page with abstract — academic style, no "Release" badge
    "maketitle": r"""
\begin{titlepage}
\centering
\vspace*{3cm}
{\Huge\bfseries ZisK Prover Specification\par}
\vspace{1.5cm}
{\Large Derived from the Python Executable Specification\par}
\vspace{2cm}
{\large \today\par}
\vspace{3cm}
\begin{minipage}{0.85\textwidth}
\noindent This document is the complete specification for the PIL2
proving system as used by the ZisK zkVM.
It specifies \emph{exactly} what the prover and verifier compute,
in sequence, using mathematical notation.
It contains no proofs and no security analysis---only the concrete protocol.

\medskip
\noindent The specification comprises three parts:
\begin{enumerate}[nosep]
  \item \textbf{STARK Protocol} --- the parametric FRI-STARK proving system
        that works with any AIR over the Goldilocks field.
  \item \textbf{ZisK Machine} --- the concrete chip architecture:
        21~AIRs, bus interconnections, memory layout, coprocessors,
        precompile circuits, lookup tables, and global constraints.
  \item \textbf{Recursion Pipeline} --- the VADCOP recursive aggregation
        from per-AIR STARKs to a single proof.
\end{enumerate}
\end{minipage}
\vfill
\end{titlepage}
""",

    # Proper table of contents
    "tableofcontents": r"\tableofcontents\clearpage",

    # No index at the end (not useful for a spec)
    "printindex": "",

    # Sphinx styling
    "sphinxsetup": "verbatimwithframe=false, verbatimwrapslines=true",
}

latex_documents = [
    ("index", "zisk-prover-spec.tex", project, author, "manual"),
]
