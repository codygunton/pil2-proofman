# Makefile for Sphinx documentation
#
# Usage:
#   make all        Build HTML website with downloadable PDF
#   make html       Build HTML website only
#   make latexpdf   Build PDF via LaTeX
#   make serve      Build all + serve on localhost:8000
#   make clean      Remove build artifacts

SPHINXBUILD = uv run --project ../../executable-spec --group docs sphinx-build
SOURCEDIR   = .
BUILDDIR    = _build
PDF_NAME    = zisk-prover-spec.pdf

.PHONY: all html latexpdf serve clean help figures

help:
	@echo "Targets: all  html  latexpdf  serve  clean"

# Render Mermaid diagrams to PNG (for PDF build).
# Requires: docker  OR  mmdc (npm i -g @mermaid-js/mermaid-cli)
figures: _static/pipeline.png

_static/pipeline.png: _static/pipeline.mmd
	@echo "Rendering Mermaid diagram → PNG"
	docker run --rm -u $$(id -u):$$(id -g) -v $(CURDIR)/_static:/data \
		minlag/mermaid-cli -i /data/pipeline.mmd -o /data/pipeline.png -b white -w 1200
	@echo "Generated _static/pipeline.png"

all: html latexpdf
	cp $(BUILDDIR)/latex/$(PDF_NAME) $(BUILDDIR)/html/_static/$(PDF_NAME)
	@echo "PDF available at _build/html/_static/$(PDF_NAME)"

html:
	$(SPHINXBUILD) -b html $(SOURCEDIR) $(BUILDDIR)/html

latexpdf: figures
	$(SPHINXBUILD) -b latex $(SOURCEDIR) $(BUILDDIR)/latex
	$(MAKE) -C $(BUILDDIR)/latex all-pdf

serve: all
	@echo "Serving at http://localhost:8000"
	python3 -m http.server 8000 --directory $(BUILDDIR)/html

clean:
	rm -rf $(BUILDDIR)
