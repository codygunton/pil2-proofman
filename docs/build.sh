#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
pdflatex -interaction=nonstopmode protocol-spec.tex > /dev/null 2>&1
pdflatex -interaction=nonstopmode protocol-spec.tex > /dev/null 2>&1
echo "Built protocol-spec.pdf"
