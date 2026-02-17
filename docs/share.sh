#!/usr/bin/env bash
# Serve a spec PDF on localhost:7000 and expose via ngrok tunnel.
# Usage: ./share.sh [protocol|stark|machine|recursion] [--watch]
#   protocol   Share protocol-spec.pdf (default) — combined document
#   stark      Share stark-spec.pdf
#   machine    Share machine-spec.pdf
#   recursion  Share recursion-spec.pdf
#   --watch    Rebuild PDF automatically when .tex files change (requires inotifywait)

set -euo pipefail
cd "$(dirname "$0")"

PORT=7000
WATCH=false

# Parse arguments
SPEC=""
for arg in "$@"; do
    case "$arg" in
        protocol) SPEC=protocol-spec ;;
        stark) SPEC=stark-spec ;;
        machine) SPEC=machine-spec ;;
        recursion) SPEC=recursion-spec ;;
        --watch) WATCH=true ;;
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

NGROK="$HOME/ngrok"

# --- Build PDF ---
build_pdf() {
    echo "Building $PDF ..."
    pdflatex -interaction=nonstopmode "$TEX" > /dev/null 2>&1 || true
    pdflatex -interaction=nonstopmode "$TEX" > /dev/null 2>&1 || true
    echo "Build complete: $PDF"
}

build_pdf

# --- Generate index.html that embeds the PDF ---
cat > index.html << HTMLEOF
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

# --- Start watcher in background if --watch ---
WATCHER_PID=""
if [[ "$WATCH" == true ]]; then
    if ! command -v inotifywait &> /dev/null; then
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

# --- Start HTTP server in background ---
python3 -m http.server "$PORT" --bind 127.0.0.1 &
HTTP_PID=$!

# # --- Start ngrok in background ---
# "$NGROK" http "$PORT" --log=stdout --log-format=term > /tmp/ngrok.log 2>&1 &
# NGROK_PID=$!
#
# # --- Cleanup on exit ---
# cleanup() {
#     kill "$NGROK_PID" 2>/dev/null || true
#     kill "$HTTP_PID" 2>/dev/null || true
#     [[ -n "$WATCHER_PID" ]] && kill "$WATCHER_PID" 2>/dev/null || true
#     rm -f index.html /tmp/ngrok.log
#     echo ""
#     echo "Stopped."
# }
# trap cleanup EXIT
#
# # --- Wait for ngrok to start and extract URL ---
# echo ""
# echo "Starting ngrok tunnel..."
# NGROK_URL=""
# for i in $(seq 1 30); do
#     NGROK_URL=$(curl -s http://127.0.0.1:4040/api/tunnels 2>/dev/null \
#         | python3 -c "import sys,json; print(json.load(sys.stdin)['tunnels'][0]['public_url'])" 2>/dev/null) \
#         && break
#     sleep 0.5
# done
#
# if [[ -z "$NGROK_URL" ]]; then
#     echo "Failed to get ngrok URL. Check: ngrok authtoken <token>"
#     echo "Get a free token at https://dashboard.ngrok.com"
#     cleanup
#     exit 1
# fi
#
# echo "========================================"
# echo "  Local:  http://localhost:$PORT"
# echo "  Public: $NGROK_URL"
# echo "========================================"
# echo ""
# echo "Share this link: ${NGROK_URL}/${PDF}"
# echo ""
# echo "Press Ctrl-C to stop."
#
# # Keep running until interrupted
# wait "$HTTP_PID"
