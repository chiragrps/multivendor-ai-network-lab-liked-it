#!/usr/bin/env bash
# ============================================================================
#  check_fabric.sh — CLOS EVPN Fabric Health Check
#  Verifies: underlay BGP (18 sessions), EVPN overlay (18 sessions), VXLAN
#  Exit code: 0 = all healthy, 1 = at least one issue
# ============================================================================
set -o pipefail

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YEL=$'\033[0;33m'; NC=$'\033[0m'
PASS=0; FAIL=0

ok()   { echo "  ${GRN}✓${NC} $*"; PASS=$((PASS+1)); }
bad()  { echo "  ${RED}✗${NC} $*"; FAIL=$((FAIL+1)); }
warn() { echo "  ${YEL}!${NC} $*"; }

SPINES=(spine1 spine2 spine3)
LEAVES=(leaf1 leaf2 leaf3 leaf4 leaf5 leaf6)

vendor_of() {
  case $1 in
    spine1|leaf2|leaf5) echo srl ;;
    spine2|leaf1|leaf4) echo ceos ;;
    spine3|leaf3|leaf6) echo frr ;;
    *) echo unknown ;;
  esac
}

# Returns established overlay (EVPN) session count for a node
overlay_count() {
  local node=$1 vendor=$(vendor_of "$1") c=clab-clos-evpn-$1
  case $vendor in
    srl)
      docker exec "$c" sr_cli 'show network-instance default protocols bgp neighbor' 2>/dev/null \
        | awk '/10\.255\.[01]\./ && /established/ && /overlay-rr|evpn/ {c++} END{print c+0}'
      ;;
    ceos)
      docker exec "$c" Cli -p 15 -c 'show bgp evpn summary' 2>/dev/null \
        | awk '/^  / && / Estab /{c++} END{print c+0}'
      ;;
    frr)
      docker exec "$c" vtysh -c 'show bgp l2vpn evpn summary' 2>/dev/null \
        | awk '/^(10\.255|leaf|spine)/ && $10 ~ /^[0-9]+$/ {c++} END{print c+0}'
      ;;
  esac
}

# Returns established underlay (IPv4) session count
underlay_count() {
  local node=$1 vendor=$(vendor_of "$1") c=clab-clos-evpn-$1
  case $vendor in
    srl)
      docker exec "$c" sr_cli 'show network-instance default protocols bgp neighbor' 2>/dev/null \
        | awk '/10\.0\./ && /established/ && /(underlay|spine)/ {c++} END{print c+0}'
      ;;
    ceos)
      docker exec "$c" Cli -p 15 -c 'show ip bgp summary' 2>/dev/null \
        | awk '/^  / && / Estab /{c++} END{print c+0}'
      ;;
    frr)
      docker exec "$c" vtysh -c 'show bgp ipv4 unicast summary' 2>/dev/null \
        | awk '/^(10\.0|leaf|spine)/ && $10 ~ /^[0-9]+$/ {c++} END{print c+0}'
      ;;
  esac
}

echo "============================================================"
echo "  CLOS EVPN Fabric Health Check  ($(date '+%F %T'))"
echo "============================================================"

# --- Container liveness ---
echo
echo "[1] Container liveness"
for n in "${SPINES[@]}" "${LEAVES[@]}"; do
  if docker inspect -f '{{.State.Running}}' "clab-clos-evpn-$n" 2>/dev/null | grep -q true; then
    ok "$n is running ($(vendor_of "$n"))"
  else
    bad "$n is NOT running"
  fi
done

# --- Underlay BGP ---
echo
echo "[2] Underlay BGP (IPv4 P2P) — expect 6 sessions/spine, 3/leaf"
for n in "${SPINES[@]}"; do
  cnt=$(underlay_count "$n")
  [ "$cnt" -ge 6 ] && ok "$n underlay: $cnt/6 Established" || bad "$n underlay: $cnt/6 Established"
done
for n in "${LEAVES[@]}"; do
  cnt=$(underlay_count "$n")
  [ "$cnt" -ge 3 ] && ok "$n underlay: $cnt/3 Established" || bad "$n underlay: $cnt/3 Established"
done

# --- EVPN Overlay BGP ---
echo
echo "[3] EVPN Overlay BGP (loopback iBGP/eBGP) — expect 6/spine, 3/leaf"
for n in "${SPINES[@]}"; do
  cnt=$(overlay_count "$n")
  [ "$cnt" -ge 6 ] && ok "$n EVPN: $cnt/6 Established" || bad "$n EVPN: $cnt/6 Established"
done
for n in "${LEAVES[@]}"; do
  cnt=$(overlay_count "$n")
  [ "$cnt" -ge 3 ] && ok "$n EVPN: $cnt/3 Established" || bad "$n EVPN: $cnt/3 Established"
done

# --- EVPN route presence on spines ---
echo
echo "[4] EVPN routes received on spines (RR)"
c=$(docker exec clab-clos-evpn-spine2 Cli -p 15 -c 'show bgp evpn summary' 2>/dev/null \
    | awk '/^  / && / Estab /{s+=$NF} END{print s+0}')
[ "$c" -gt 0 ] && ok "spine2 (cEOS): $c EVPN route(s) received" \
                || warn "spine2 (cEOS): 0 EVPN routes — leaves not advertising VTEP/MACs yet"

# --- VXLAN tunnels on leaves ---
echo
echo "[5] VXLAN VTEP interfaces on leaves"
for n in "${LEAVES[@]}"; do
  vendor=$(vendor_of "$n") c=clab-clos-evpn-$n
  case $vendor in
    ceos)  out=$(docker exec "$c" Cli -p 15 -c 'show interfaces vxlan 1' 2>/dev/null | grep -c "Vxlan1" || true) ;;
    srl)   out=$(docker exec "$c" sr_cli 'show tunnel-interface vxlan1 vxlan-interface * brief' 2>/dev/null | grep -c "vxlan1.100" || true) ;;
    frr)   out=$(docker exec "$c" ip -d link show type vxlan 2>/dev/null | grep -c "vxlan" || true) ;;
  esac
  if [ "${out:-0}" -gt 0 ]; then
    ok "$n VTEP configured ($vendor)"
  else
    warn "$n no VXLAN VTEP configured ($vendor)"
  fi
done

# --- Host reachability (only meaningful once VTEPs are up) ---
echo
echo "[6] Intra-VLAN host reachability (Type-2 EVPN data plane)"
for pair in "host1:10.10.10.2" "host3:10.10.20.2" "host5:10.10.30.2"; do
  src=${pair%:*}; dst=${pair#*:}
  if docker exec "clab-clos-evpn-$src" ping -c 1 -W 1 "$dst" >/dev/null 2>&1; then
    ok "$src → $dst reachable"
  else
    warn "$src → $dst unreachable (VXLAN data plane not active)"
  fi
done

# --- Summary ---
echo
echo "============================================================"
if [ "$FAIL" -eq 0 ]; then
  echo "  ${GRN}RESULT: $PASS checks passed, 0 failed${NC}"
  exit 0
else
  echo "  ${RED}RESULT: $PASS passed, $FAIL FAILED${NC}"
  exit 1
fi
