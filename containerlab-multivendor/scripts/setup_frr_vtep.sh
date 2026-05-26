#!/usr/bin/env bash
# ============================================================================
#  setup_frr_vtep.sh — Bootstrap Linux bridge + VXLAN netdev on FRR leaves
#  Required after `containerlab deploy` because the FRR bind-mount only
#  persists /etc/frr/frr.conf — netdev/bridge state lives in container kernel
#  namespace and is rebuilt fresh each deploy.
#
#  Usage:  ./scripts/setup_frr_vtep.sh
# ============================================================================
set -o pipefail

configure_frr_vtep() {
  local node=$1 vtep_ip=$2 vni=$3 host_iface=$4
  local bridge=br$vni vxlan=vxlan$vni
  echo "  → $node : VTEP $vtep_ip, VNI $vni, bridge $bridge"
  docker exec "clab-clos-evpn-$node" bash -c "
    ip link add lo1 type dummy 2>/dev/null || true
    ip link set lo1 up
    ip addr add $vtep_ip/32 dev lo1 2>/dev/null || true

    ip link add $bridge type bridge 2>/dev/null || true
    ip link set $bridge up

    ip link add $vxlan type vxlan id $vni dstport 4789 local $vtep_ip nolearning 2>/dev/null || true
    ip link set $vxlan master $bridge
    ip link set $vxlan up
    bridge link set dev $vxlan learning off
    bridge link set dev $vxlan neigh_suppress on

    ip addr flush dev $host_iface 2>/dev/null || true
    ip link set $host_iface master $bridge
    ip link set $host_iface up
  "
}

echo "Setting up FRR VTEP netdevs..."
configure_frr_vtep leaf3 10.255.100.3 10020 eth4
configure_frr_vtep leaf6 10.255.100.6 10030 eth4
echo "Done."
echo "Run ./scripts/check_fabric.sh to verify."
