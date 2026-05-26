#!/usr/bin/env bash
# ============================================================================
#  GESH Multi-Vendor Lab — Fabric Verification
#  Runs multi-vendor verification commands across all node types
# ============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  GESH Multi-Vendor Lab — Fabric Verification               ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Detect running topology
TOPO=$(docker ps --format '{{.Names}}' 2>/dev/null | grep "^clab-" | head -1 | sed 's/clab-//' | sed 's/-.*//')
if [[ -z "$TOPO" ]]; then
    echo -e "${RED}[ERROR]${NC} No running containerlab topology detected."
    echo "  Deploy first: ./scripts/deploy.sh clos-evpn"
    exit 1
fi

echo -e "${CYAN}[INFO]${NC}  Detected topology: ${BOLD}${TOPO}${NC}"
echo ""

PASS=0
FAIL=0
WARN=0

check() {
    local desc="$1"
    local result="$2"
    if [[ "$result" == "PASS" ]]; then
        echo -e "  ${GREEN}✓${NC} $desc"
        PASS=$((PASS + 1))
    elif [[ "$result" == "WARN" ]]; then
        echo -e "  ${YELLOW}⚠${NC} $desc"
        WARN=$((WARN + 1))
    else
        echo -e "  ${RED}✗${NC} $desc"
        FAIL=$((FAIL + 1))
    fi
}

# ── Node Health ─────────────────────────────────────────────────────────────
echo -e "${BOLD}[1/5] Node Health${NC}"

for node in $(docker ps --format '{{.Names}}' 2>/dev/null | grep "^clab-" | sort); do
    status=$(docker inspect --format '{{.State.Status}}' "$node" 2>/dev/null)
    short_name=$(echo "$node" | sed "s/clab-${TOPO}-//")
    if [[ "$status" == "running" ]]; then
        check "$short_name is running" "PASS"
    else
        check "$short_name is $status" "FAIL"
    fi
done

# ── BGP Underlay (per vendor) ──────────────────────────────────────────────
echo ""
echo -e "${BOLD}[2/5] BGP Underlay Sessions${NC}"

# Nokia SR Linux nodes
for node in $(docker ps --format '{{.Names}}' 2>/dev/null | grep "^clab-" | grep -E "spine1|leaf2|leaf5" | sort); do
    short_name=$(echo "$node" | sed "s/clab-${TOPO}-//")
    bgp_out=$(docker exec "$node" sr_cli "show network-instance default protocols bgp neighbor" 2>/dev/null || echo "ERROR")
    established=$(echo "$bgp_out" | grep -c "established" || true)
    if (( established > 0 )); then
        check "SRL $short_name: $established BGP sessions established" "PASS"
    else
        check "SRL $short_name: BGP not yet established" "WARN"
    fi
done

# Arista cEOS nodes
for node in $(docker ps --format '{{.Names}}' 2>/dev/null | grep "^clab-" | grep -E "spine2|leaf1|leaf4" | sort); do
    short_name=$(echo "$node" | sed "s/clab-${TOPO}-//")
    bgp_out=$(docker exec "$node" Cli -p 15 -c "show bgp summary" 2>/dev/null || echo "ERROR")
    established=$(echo "$bgp_out" | grep -c "Estab" || true)
    if (( established > 0 )); then
        check "cEOS $short_name: $established BGP sessions established" "PASS"
    else
        check "cEOS $short_name: BGP not yet established" "WARN"
    fi
done

# FRR nodes
for node in $(docker ps --format '{{.Names}}' 2>/dev/null | grep "^clab-" | grep -E "spine3|leaf3|leaf6" | sort); do
    short_name=$(echo "$node" | sed "s/clab-${TOPO}-//")
    bgp_out=$(docker exec "$node" vtysh -c "show bgp summary" 2>/dev/null || echo "ERROR")
    established=$(echo "$bgp_out" | grep -c "Estab" || true)
    if (( established > 0 )); then
        check "FRR $short_name: $established BGP sessions established" "PASS"
    else
        check "FRR $short_name: BGP not yet established" "WARN"
    fi
done

# ── EVPN Overlay ───────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[3/5] EVPN Overlay${NC}"

# Check EVPN routes on cEOS leaf
EVPN_NODE=$(docker ps --format '{{.Names}}' 2>/dev/null | grep "^clab-" | grep "leaf1" | head -1)
if [[ -n "$EVPN_NODE" ]]; then
    evpn_out=$(docker exec "$EVPN_NODE" Cli -p 15 -c "show bgp evpn summary" 2>/dev/null || echo "ERROR")
    evpn_peers=$(echo "$evpn_out" | grep -c "Estab" || true)
    if (( evpn_peers > 0 )); then
        check "leaf1 (cEOS): $evpn_peers EVPN peers established" "PASS"
    else
        check "leaf1 (cEOS): EVPN overlay not yet established" "WARN"
    fi
fi

# Check EVPN on SRL leaf
EVPN_SRL=$(docker ps --format '{{.Names}}' 2>/dev/null | grep "^clab-" | grep "leaf2" | head -1)
if [[ -n "$EVPN_SRL" ]]; then
    evpn_out=$(docker exec "$EVPN_SRL" sr_cli "show network-instance default protocols bgp neighbor" 2>/dev/null || echo "ERROR")
    evpn_count=$(echo "$evpn_out" | grep -c "evpn" || true)
    if (( evpn_count > 0 )); then
        check "leaf2 (SRL): EVPN routes present" "PASS"
    else
        check "leaf2 (SRL): EVPN routes not yet populated" "WARN"
    fi
fi

# Check EVPN on FRR leaf
EVPN_FRR=$(docker ps --format '{{.Names}}' 2>/dev/null | grep "^clab-" | grep "leaf3" | head -1)
if [[ -n "$EVPN_FRR" ]]; then
    evpn_out=$(docker exec "$EVPN_FRR" vtysh -c "show bgp l2vpn evpn summary" 2>/dev/null || echo "ERROR")
    evpn_peers=$(echo "$evpn_out" | grep -c "Estab" || true)
    if (( evpn_peers > 0 )); then
        check "leaf3 (FRR): $evpn_peers EVPN peers established" "PASS"
    else
        check "leaf3 (FRR): EVPN overlay not yet established" "WARN"
    fi
fi

# ── VXLAN Tunnels ──────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[4/5] VXLAN Tunnels${NC}"

if [[ -n "${EVPN_NODE:-}" ]]; then
    vxlan_out=$(docker exec "$EVPN_NODE" Cli -p 15 -c "show vxlan vtep" 2>/dev/null || echo "ERROR")
    vteps=$(echo "$vxlan_out" | grep -cE "10\.255\." || true)
    if (( vteps > 0 )); then
        check "leaf1 (cEOS): $vteps remote VTEPs discovered" "PASS"
    else
        check "leaf1 (cEOS): No remote VTEPs yet" "WARN"
    fi
fi

# ── Host Connectivity ──────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[5/5] Host-to-Host Connectivity${NC}"

# Ping from host1 to host2 (same VLAN 10, different leafs)
HOST1=$(docker ps --format '{{.Names}}' 2>/dev/null | grep "^clab-" | grep "host1" | head -1)
if [[ -n "$HOST1" ]]; then
    ping_result=$(docker exec "$HOST1" ping -c 2 -W 2 10.10.10.2 2>/dev/null || echo "FAIL")
    if echo "$ping_result" | grep -q "2 packets received\|2 received"; then
        check "host1 → host2 (intra-VLAN 10 via VXLAN): reachable" "PASS"
    else
        check "host1 → host2 (intra-VLAN 10): not yet reachable (EVPN may need time)" "WARN"
    fi

    # Cross-VLAN ping (L3 EVPN / symmetric IRB)
    ping_cross=$(docker exec "$HOST1" ping -c 2 -W 2 10.10.20.1 2>/dev/null || echo "FAIL")
    if echo "$ping_cross" | grep -q "2 packets received\|2 received"; then
        check "host1 → host3 (inter-VLAN L3 EVPN): reachable" "PASS"
    else
        check "host1 → host3 (inter-VLAN L3 EVPN): not yet reachable" "WARN"
    fi
fi

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  Verification Summary                                      ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║  ${GREEN}PASS: ${PASS}${NC}${BOLD}  ${YELLOW}WARN: ${WARN}${NC}${BOLD}  ${RED}FAIL: ${FAIL}${NC}${BOLD}                            ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if (( WARN > 0 )); then
    echo -e "${YELLOW}[NOTE]${NC} Warnings are normal within 2-3 minutes of deployment."
    echo "       BGP convergence and EVPN route propagation take time."
    echo "       Re-run this script after waiting: ./scripts/verify.sh"
fi

if (( FAIL > 0 )); then
    echo -e "${RED}[NOTE]${NC} Failures indicate nodes that didn't start properly."
    echo "       Check: docker logs clab-${TOPO}-<node-name>"
fi
echo ""
