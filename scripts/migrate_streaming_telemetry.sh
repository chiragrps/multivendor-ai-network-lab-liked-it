#!/usr/bin/env bash
# Migrate cEOS + FRR clab nodes from docker-exec polling to gNMI streaming.
# Idempotent: safe to re-run. See docs/STREAMING_TELEMETRY_GAPS.md for context.
set -euo pipefail

CLAB_DIR=$(cd "$(dirname "$0")/../containerlab-multivendor" && pwd)
TOPO=$CLAB_DIR/topologies/clos-evpn.clab.yml

case "${1:-help}" in
  ceos-image)
    grep -q "image: ceos:4.33" "$TOPO" || { echo "image already swapped"; exit 0; }
    sed -i.bak 's|image: ceos:4.33.*|image: ceos:4.34.0F|' "$TOPO"
    echo "cEOS image bumped to 4.34.0F — run '$0 redeploy' next."
    ;;
  frr-grpc)
    docker build -t frr:8.4-grpc -f "$CLAB_DIR/topologies/frr-grpc/Dockerfile" "$CLAB_DIR" || {
      echo "Dockerfile not present yet — create $CLAB_DIR/topologies/frr-grpc/Dockerfile per docs."
      exit 1
    }
    echo "Custom FRR built. Edit clab.yml to use 'image: frr:8.4-grpc' for spine3, leaf3, leaf6."
    ;;
  redeploy)
    cd "$CLAB_DIR/topologies"
    containerlab destroy --topo clos-evpn.clab.yml --cleanup
    containerlab deploy  --topo clos-evpn.clab.yml
    echo "Redeployed. Confirm gnmic picks up all 9 routing nodes via 'curl localhost:7890/api/v1/targets'."
    ;;
  verify)
    echo "Probing :6030 on every routing node…"
    for h in spine1 spine2 spine3 leaf1 leaf2 leaf3 leaf4 leaf5 leaf6; do
      printf "  %-8s :6030 " "$h"
      docker exec "clab-clos-evpn-$h" sh -c "(nc -zv 127.0.0.1 6030 2>&1 | head -1) || echo no-gnmi"
    done
    ;;
  *)
    cat <<USAGE
usage: $0 <command>
  ceos-image   bump cEOS to 4.34.0F (unblocks Octa)
  frr-grpc     build custom FRR image with --enable-grpc
  redeploy     containerlab destroy && deploy
  verify       check :6030 reachability on all 9 routing nodes
USAGE
    ;;
esac
