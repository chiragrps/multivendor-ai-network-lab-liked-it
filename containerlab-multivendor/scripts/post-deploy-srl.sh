#!/bin/bash
# Post-deploy: push SRL configs after containerlab deploy
# Usage: ./post-deploy-srl.sh [--wait SECONDS]
set -e
WAIT="${1:-30}"
CFGDIR="$(dirname "$0")/../configs"

echo "⏳ Waiting ${WAIT}s for SRL nodes to boot..."
sleep "$WAIT"

push_srl() {
  local node="$1" cfg="$2"
  echo "📤 Pushing config to $node..."
  docker cp "$cfg" "clab-clos-evpn-${node}:/tmp/config.cfg"
  docker exec "clab-clos-evpn-${node}" bash -c '
    grep -v "^#" /tmp/config.cfg | grep -v "^$" | \
    grep -v "description\|information\|contact\|location\|community\|trap-group\|snmp" | \
    sed "1i enter candidate" | sed "\$a commit now" | sr_cli
  ' 2>&1 | tail -1
}

push_srl "spine1" "$CFGDIR/spine/spine1-srl.cfg"
push_srl "leaf2"  "$CFGDIR/leaf/leaf2-srl.cfg"
push_srl "leaf5"  "$CFGDIR/leaf/leaf5-srl.cfg"

echo ""
echo "⏳ Waiting 10s for spine3/spine2 EVPN overlay fix..."
sleep 10

# Fix spine3 EVPN overlay (per-leaf AS)
echo "📤 Fixing spine3 EVPN overlay..."
docker exec clab-clos-evpn-spine3 vtysh -c "conf t" \
  -c "router bgp 65100" \
  -c "no neighbor OVERLAY remote-as 65100" \
  -c "neighbor OVERLAY ebgp-multihop 3" \
  -c "neighbor OVERLAY update-source lo" \
  -c "neighbor 10.255.1.1 remote-as 65001" -c "neighbor 10.255.1.1 peer-group OVERLAY" \
  -c "neighbor 10.255.1.2 remote-as 65002" -c "neighbor 10.255.1.2 peer-group OVERLAY" \
  -c "neighbor 10.255.1.3 remote-as 65003" -c "neighbor 10.255.1.3 peer-group OVERLAY" \
  -c "neighbor 10.255.1.4 remote-as 65004" -c "neighbor 10.255.1.4 peer-group OVERLAY" \
  -c "neighbor 10.255.1.5 remote-as 65005" -c "neighbor 10.255.1.5 peer-group OVERLAY" \
  -c "neighbor 10.255.1.6 remote-as 65006" -c "neighbor 10.255.1.6 peer-group OVERLAY" \
  -c "address-family l2vpn evpn" -c "neighbor OVERLAY activate" -c "exit-address-family" \
  -c "exit" -c "exit" 2>&1 | tail -1

# Fix spine2 EVPN overlay (per-leaf AS)
echo "📤 Fixing spine2 EVPN overlay..."
docker exec clab-clos-evpn-spine2 Cli -p 15 -c "configure
router bgp 65100
neighbor 10.255.1.1 remote-as 65001
neighbor 10.255.1.2 remote-as 65002
neighbor 10.255.1.3 remote-as 65003
neighbor 10.255.1.4 remote-as 65004
neighbor 10.255.1.5 remote-as 65005
neighbor 10.255.1.6 remote-as 65006" 2>&1 | tail -1

# Fix leaf4 interface mapping
echo "📤 Fixing leaf4 interface mapping..."
docker exec clab-clos-evpn-leaf4 Cli -p 15 -c "configure
interface Ethernet2
 no switchport
 ip address 10.0.1.7/31
interface Ethernet3
 no switchport
 ip address 10.0.2.7/31
interface Ethernet4
 no switchport
 ip address 10.0.3.7/31" 2>&1 | tail -1

# IRB anycast gateway
echo "📤 Pushing IRB anycast gateway..."
docker exec clab-clos-evpn-leaf1 Cli -p 15 -c "configure
ip virtual-router mac-address 00:00:5E:00:53:01
vrf instance TENANT-A
ip routing vrf TENANT-A
interface Vxlan1
 vxlan vrf TENANT-A vni 50001
interface Vlan10
 vrf TENANT-A
 ip address virtual 10.10.10.254/24
router bgp 65001
 vrf TENANT-A
  rd 10.255.1.1:1
  route-target import evpn 1:50001
  route-target export evpn 1:50001
  redistribute connected" 2>&1 | tail -1

docker exec clab-clos-evpn-leaf4 Cli -p 15 -c "configure
ip virtual-router mac-address 00:00:5E:00:53:01
vrf instance TENANT-A
ip routing vrf TENANT-A
interface Vxlan1
 vxlan vrf TENANT-A vni 50001
interface Vlan20
 vrf TENANT-A
 ip address virtual 10.10.20.254/24
router bgp 65004
 vrf TENANT-A
  rd 10.255.1.4:1
  route-target import evpn 1:50001
  route-target export evpn 1:50001
  redistribute connected" 2>&1 | tail -1

# FRR gateway IPs on bridges
docker exec clab-clos-evpn-leaf3 bash -c "ip link set br10020 address 00:00:5E:00:53:01; ip addr add 10.10.20.254/24 dev br10020 2>/dev/null || true"
docker exec clab-clos-evpn-leaf6 bash -c "ip link set br10030 address 00:00:5E:00:53:01; ip addr add 10.10.30.254/24 dev br10030 2>/dev/null || true"

echo ""
echo "✅ Post-deploy complete. Run: ./scripts/verify.sh"
