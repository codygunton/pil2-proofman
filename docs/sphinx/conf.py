# conf.py — Sphinx configuration for Zisk Prover Specification
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
project = "Zisk Prover Specification"
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
html_title = "Zisk Prover Spec"
html_theme_options = {
    "repository_url": "https://github.com/pil2-proofman/pil2-proofman",
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

    Usage in MyST:  {src}`protocol/prover.py:202`
    Renders as:     prover.py:202  (clickable link to viewcode page, line 202)
    """
    import posixpath
    from docutils import nodes
    # Parse "package/file.py:line"
    file_path, line_str = text.rsplit(":", 1)
    module_path = file_path.replace(".py", "")  # "protocol/prover"
    display = file_path.rsplit("/", 1)[-1] + ":" + line_str
    # Compute relative path from current document to _modules/
    env = inliner.document.settings.env
    docname = env.docname  # e.g., "part-stark/commitment-phase"
    target = f"_modules/{module_path}"
    rel = posixpath.relpath(target, posixpath.dirname(docname))
    url = f"{rel}.html#L-{line_str}"
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

def setup(app):
    _patch_viewcode_line_anchors(app)
    app.add_role("src", _src_role)
    app.connect("html-page-context", _add_pdf_header_button, priority=600)

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
{\Huge\bfseries Zisk Prover Specification\par}
\vspace{1.5cm}
{\Large Derived from the Python Executable Specification\par}
\vspace{2cm}
{\large \today\par}
\vspace{3cm}
\begin{minipage}{0.85\textwidth}
\noindent This document is the complete specification for the PIL2
proving system as used by the Zisk zkVM.
It specifies \emph{exactly} what the prover and verifier compute,
in sequence, using mathematical notation.
It contains no proofs and no security analysis---only the concrete protocol.

\medskip
\noindent The specification comprises three parts:
\begin{enumerate}[nosep]
  \item \textbf{STARK Protocol} --- the parametric FRI-STARK proving system
        that works with any AIR over the Goldilocks field.
  \item \textbf{Zisk Machine} --- the concrete chip architecture:
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
