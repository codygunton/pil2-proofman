#!/usr/bin/env bash
# Serve a spec PDF on localhost:7000 with optional live-reload on .tex changes.
# Usage: ./preview.sh [protocol|stark|machine|recursion] [--watch]
#   protocol   Preview protocol-spec.pdf (default) — combined document
#   stark      Preview stark-spec.pdf
#   machine    Preview machine-spec.pdf
#   recursion  Preview recursion-spec.pdf
#   --watch    Rebuild PDF automatically when .tex files change (requires inotifywait)

set -euo pipefail
cd "$(dirname "$0")"

PORT=1234
WATCH=false

# Parse arguments
SPEC=""
for arg in "$@"; do
    case "$arg" in
        protocol)  SPEC=protocol-spec ;;
        stark)     SPEC=stark-spec ;;
        machine)   SPEC=machine-spec ;;
        recursion) SPEC=recursion-spec ;;
        --watch)   WATCH=true ;;
        *)
            echo "Usage: $0 [protocol|stark|machine|recursion] [--watch]"
            exit 1
            ;;
    esac
done

# Default to protocol-spec (combined document)
SPEC="${SPEC:-protocol-spec}"
PDF="${SPEC}.pdf"
TEX="${SPEC}.tex"

build_pdf() {
    echo "Building $PDF ..."
    pdflatex -interaction=nonstopmode "$TEX" >/dev/null 2>&1 || true
    pdflatex -interaction=nonstopmode "$TEX" >/dev/null 2>&1 || true
    echo "Build complete: $PDF"
}

# Initial build
build_pdf

# Generate index.html that embeds the PDF
cat > index.html <<HTMLEOF
<!DOCTYPE html>
<html>
<head>
  <title>${SPEC}</title>
  <style>
    body { margin: 0; }
    iframe { width: 100vw; height: 100vh; border: none; }
  </style>
</head>
<body>
  <iframe src="${PDF}"></iframe>
</body>
</html>
HTMLEOF

# Start watcher in background if --watch
WATCHER_PID=""
if [[ "$WATCH" == true ]]; then
    if ! command -v inotifywait &>/dev/null; then
        echo "Install inotify-tools for --watch: sudo pacman -S inotify-tools"
        exit 1
    fi
    (
        while inotifywait -q -e modify --include '\.tex$' .; do
            echo "Change detected, rebuilding..."
            build_pdf
        done
    ) &
    WATCHER_PID=$!
    echo "Watching for .tex changes (PID $WATCHER_PID)"
fi

cleanup() {
    [[ -n "$WATCHER_PID" ]] && kill "$WATCHER_PID" 2>/dev/null || true
    rm -f index.html
    echo ""
    echo "Stopped."
}
trap cleanup EXIT

echo ""
echo "Serving $PDF at http://localhost:$PORT"
echo "Press Ctrl-C to stop."
echo ""

python3 -m http.server "$PORT" --bind 127.0.0.1
