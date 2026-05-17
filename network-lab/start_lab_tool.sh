#!/usr/bin/env bash
# Start DCN Network Tool wired to the local Docker lab
set -e

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$LAB_DIR/../04_Scripts_Tools/DCN_Network_Tool"
DEMO_DIR="$LAB_DIR/.."

echo "═══════════════════════════════════════════════════"
echo "  DCN Network Tool — LAB MODE"
echo "═══════════════════════════════════════════════════"

# Verify lab containers are running
RUNNING=$(docker compose -f "$LAB_DIR/docker-compose.yml" ps --status running -q 2>/dev/null | wc -l | tr -d ' ')
if [ "$RUNNING" -lt 10 ]; then
  echo "Lab containers not fully running ($RUNNING/10). Starting lab..."
  docker compose -f "$LAB_DIR/docker-compose.yml" up -d
  sleep 5
  RUNNING=$(docker compose -f "$LAB_DIR/docker-compose.yml" ps --status running -q 2>/dev/null | wc -l | tr -d ' ')
fi
echo "Lab network: $RUNNING containers running"

# Extract ANTHROPIC_API_KEY safely (avoids bash-sourcing files with special chars)
if [ -f "$HOME/.env" ]; then
  ANTHROPIC_API_KEY=$(python3 -c "
import re, sys
with open('$HOME/.env') as f:
    m = re.search(r'^ANTHROPIC_API_KEY=(.+)', f.read(), re.M)
    print(m.group(1).strip() if m else '')
" 2>/dev/null)
  export ANTHROPIC_API_KEY
fi

# Load lab env
set -a
source "$LAB_DIR/.env.lab"
set +a

echo "SSH mode : $DCN_SSH_MODE (user=$DCN_SSH_USER)"
echo "Inventory: $DCN_SECURECRT_CSV"
echo "LLM      : $LLM_ENABLED ($LLM_MODEL)"

# Start static file server for demo UI (port 8080) from project root
pkill -f "http.server 8080" 2>/dev/null || true
sleep 1
python3 -m http.server 8080 --directory "$DEMO_DIR/demo" > /tmp/http8080.log 2>&1 &
echo "Demo UI  : http://localhost:8080/ (PID $!)"

echo ""
echo "  Flask API: http://localhost:$DCN_PORT"
echo "  Demo UI  : http://localhost:8080/"
echo "═══════════════════════════════════════════════════"

cd "$APP_DIR"
source venv_lab/bin/activate
python3 app.py
