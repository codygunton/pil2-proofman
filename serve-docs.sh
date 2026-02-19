#!/usr/bin/env bash
# serve-docs.sh — build and serve the Sphinx documentation site
#
# Usage:
#   ./serve-docs.sh          # build HTML + serve on localhost:1234
#   ./serve-docs.sh --build  # build only (no server)
#   ./serve-docs.sh --clean  # clean build artifacts
#   ./serve-docs.sh --pdf    # build PDF via LaTeX
#   ./serve-docs.sh --svg    # re-render LaTeX figures to SVG
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPHINX_DIR="${REPO_ROOT}/docs/sphinx"
SPEC_DIR="${REPO_ROOT}/executable-spec"
SPHINX_BUILD="uv run --project ${SPEC_DIR} --group docs sphinx-build"
BUILD_DIR="${SPHINX_DIR}/_build"

case "${1:-}" in
    --clean)
        echo "Cleaning ${BUILD_DIR}"
        rm -rf "${BUILD_DIR}"
        ;;
    --build)
        ${SPHINX_BUILD} -b html "${SPHINX_DIR}" "${BUILD_DIR}/html"
        echo "HTML pages in ${BUILD_DIR}/html"
        ;;
    --pdf)
        ${SPHINX_BUILD} -b latex "${SPHINX_DIR}" "${BUILD_DIR}/latex"
        make -C "${BUILD_DIR}/latex" all-pdf
        echo "PDF in ${BUILD_DIR}/latex/"
        ;;
    --svg)
        "${SPHINX_DIR}/render-figures.sh"
        ;;
    *)
        echo "Live-reload server at http://localhost:1234"
        uv run --project "${SPEC_DIR}" --group docs \
            sphinx-autobuild "${SPHINX_DIR}" "${BUILD_DIR}/html" \
            --port 1234 --open-browser
        ;;
esac
