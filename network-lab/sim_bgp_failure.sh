#!/usr/bin/env bash
# Simulate BGP session failures and recovery for demo purposes
# Usage:
#   ./sim_bgp_failure.sh break   -- drops de-fra-core-01 <-> uk-lon-core-01 session
#   ./sim_bgp_failure.sh fix     -- restores all sessions
#   ./sim_bgp_failure.sh chaos   -- random 30s failure on random peer
#   ./sim_bgp_failure.sh status  -- show BGP summary for all routers

set -euo pipefail

ALL_DEVICES=(
  de-fra-core-01
  de-fra-core-02
  uk-lon-core-01
  nl-ams-core-01
  us-nyc-core-01
  de-fra-edge-01
  uk-lon-edge-01
  nl-ams-edge-01
  uk-lon-dist-01
  de-fra-dist-01
)

bgp_summary() {
  local host=$1
  echo "── $host ──────────────────────────────────────"
  docker exec "$host" vtysh -c "show bgp summary" 2>/dev/null | grep -E "Neighbor|established|Active|Idle|^[0-9]" || echo "  (no BGP)"
}

case "${1:-status}" in

  status)
    for h in "${ALL_DEVICES[@]}"; do
      bgp_summary "$h"
    done
    ;;

  break)
    echo "Breaking BGP: de-fra-core-01 <-> uk-lon-core-01"
    docker exec de-fra-core-01 vtysh -c "clear bgp 10.200.0.13"
    docker exec uk-lon-core-01 vtysh -c "clear bgp 10.200.0.11"
    echo "Sessions cleared — topology will show red link in ~15s"
    ;;

  fix)
    echo "Restoring all BGP sessions..."
    for h in "${ALL_DEVICES[@]}"; do
      docker exec "$h" vtysh -c "clear bgp * soft" 2>/dev/null || true
    done
    echo "Soft-reset sent — sessions reconverge in ~15s"
    ;;

  chaos)
    PEERS=(
      "de-fra-core-01:10.200.0.13"
      "de-fra-core-01:10.200.0.14"
      "de-fra-core-02:10.200.0.15"
      "uk-lon-core-01:10.200.0.14"
      "uk-lon-core-01:10.200.0.15"
      "nl-ams-core-01:10.200.0.23"
    )
    PICK=${PEERS[$RANDOM % ${#PEERS[@]}]}
    HOST=${PICK%%:*}; PEER=${PICK##*:}
    echo "Chaos: clearing $HOST -> $PEER for 30s"
    docker exec "$HOST" vtysh -c "clear bgp $PEER"
    echo "   Waiting 30s... (reload topology in demo to see red link)"
    sleep 30
    docker exec "$HOST" vtysh -c "clear bgp $PEER soft"
    echo "Chaos resolved — sessions recovering"
    ;;

  *)
    echo "Usage: $0 {status|break|fix|chaos}"
    exit 1
    ;;
esac
