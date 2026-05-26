#!/usr/bin/env bash
# ============================================================================
#  GESH Multi-Vendor Lab — Quick Connect
#  Usage: ./connect.sh <node-name>
#  Examples:
#    ./connect.sh spine1          # SSH to Nokia SR Linux
#    ./connect.sh leaf1           # SSH to Arista cEOS
#    ./connect.sh leaf3           # vtysh to FRR (Cisco-style CLI)
#    ./connect.sh host1           # bash into Linux host
# ============================================================================

set -euo pipefail

NODE="${1:-}"

if [[ -z "$NODE" ]]; then
    echo "Usage: ./connect.sh <node-name>"
    echo ""
    echo "Running nodes:"
    docker ps --format '  {{.Names}}' 2>/dev/null | grep "^  clab-" | sed 's/  clab-[^-]*-/  /' | sort
    exit 0
fi

# Find the full container name
CONTAINER=$(docker ps --format '{{.Names}}' 2>/dev/null | grep "^clab-" | grep -- "$NODE" | head -1)

if [[ -z "$CONTAINER" ]]; then
    echo "Node '$NODE' not found. Running nodes:"
    docker ps --format '  {{.Names}}' 2>/dev/null | grep "^  clab-" | sort
    exit 1
fi

# Detect vendor type from image
IMAGE=$(docker inspect --format '{{.Config.Image}}' "$CONTAINER" 2>/dev/null)

case "$IMAGE" in
    *srlinux*)
        echo "Connecting to $CONTAINER (Nokia SR Linux)..."
        docker exec -it "$CONTAINER" sr_cli
        ;;
    *ceos*|*ceosimage*)
        echo "Connecting to $CONTAINER (Arista cEOS)..."
        docker exec -it "$CONTAINER" Cli
        ;;
    *frr*)
        echo "Connecting to $CONTAINER (FRR)..."
        docker exec -it "$CONTAINER" vtysh
        ;;
    *multitool*|*alpine*)
        echo "Connecting to $CONTAINER (Linux host)..."
        docker exec -it "$CONTAINER" bash 2>/dev/null || docker exec -it "$CONTAINER" sh
        ;;
    *)
        echo "Connecting to $CONTAINER (generic)..."
        docker exec -it "$CONTAINER" bash 2>/dev/null || docker exec -it "$CONTAINER" sh
        ;;
esac
