.PHONY: all protocol stark machine recursion clean

SPECS := protocol-spec stark-spec machine-spec recursion-spec
PDFS  := $(addsuffix .pdf,$(SPECS))

all: protocol-spec.pdf

protocol: protocol-spec.pdf
stark: stark-spec.pdf
machine: machine-spec.pdf
recursion: recursion-spec.pdf

# Body files are shared dependencies
BODY := stark-body.tex machine-body.tex recursion-body.tex stark-appendix.tex

protocol-spec.pdf: protocol-spec.tex preamble.tex $(BODY)
	pdflatex $<
	pdflatex $<

stark-spec.pdf: stark-spec.tex preamble.tex stark-body.tex stark-appendix.tex
	pdflatex $<
	pdflatex $<

machine-spec.pdf: machine-spec.tex preamble.tex machine-body.tex
	pdflatex $<
	pdflatex $<

recursion-spec.pdf: recursion-spec.tex preamble.tex recursion-body.tex
	pdflatex $<
	pdflatex $<

clean:
	rm -f *.aux *.log *.out *.toc *.pdf
