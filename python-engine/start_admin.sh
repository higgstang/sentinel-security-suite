#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  Sentinel Admin — starts the admin server + Cloudflare tunnel
#  Usage: bash start_admin.sh
# ─────────────────────────────────────────────────────────────
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=18082

echo ""
echo "  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     "
echo "  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     "
echo "  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     "
echo "  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     "
echo "  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗"
echo "  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝"
echo ""
echo "  Super User Admin Panel"
echo "─────────────────────────────────────────────────────────────"

# Start admin server in background
python3 "$SCRIPT_DIR/admin_server.py" --port $PORT &
ADMIN_PID=$!
echo "  ✓ Admin server started (PID $ADMIN_PID) on port $PORT"

# Wait for it to be ready
sleep 2

# Start cloudflare tunnel, capture the public URL
CF_LOG=$(mktemp)
cloudflared tunnel --url "http://127.0.0.1:$PORT" --no-autoupdate 2>"$CF_LOG" &
CF_PID=$!

echo "  ⏳ Waiting for Cloudflare tunnel..."
PUBLIC_URL=""
for i in {1..30}; do
    PUBLIC_URL=$(grep -o 'https://[a-zA-Z0-9\-]*\.trycloudflare\.com' "$CF_LOG" 2>/dev/null | head -1)
    if [ -n "$PUBLIC_URL" ]; then break; fi
    sleep 1
done

if [ -z "$PUBLIC_URL" ]; then
    echo "  ✗ Could not get Cloudflare URL — check cloudflared is installed"
    echo "    Falling back to local: http://127.0.0.1:$PORT"
    PUBLIC_URL="http://127.0.0.1:$PORT"
fi

echo ""
echo "─────────────────────────────────────────────────────────────"
echo "  🌐 PUBLIC URL:  $PUBLIC_URL"
echo "  🔐 Admin Panel: $PUBLIC_URL/admin"
echo "─────────────────────────────────────────────────────────────"
echo ""
echo "  ► Paste this into the 'Admin Server URL' field when"
echo "    generating invite links so testers anywhere can connect."
echo ""
echo "  Press Ctrl+C to stop everything."
echo ""

# Cleanup on exit
trap "kill $ADMIN_PID $CF_PID 2>/dev/null; rm -f $CF_LOG; echo 'Stopped.'" EXIT INT TERM
wait
