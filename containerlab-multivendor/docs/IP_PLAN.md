# IP Addressing Plan — Clos EVPN Fabric

## Loopbacks

| Node | Role | Vendor | Loopback0 (RID) | Loopback1 (VTEP) | ASN |
|------|------|--------|-----------------|-------------------|-----|
| spine1 | Spine/RR | Nokia SRL | 10.255.0.1/32 | — | 65100 |
| spine2 | Spine/RR | Arista cEOS | 10.255.0.2/32 | — | 65100 |
| spine3 | Spine/RR | FRR | 10.255.0.3/32 | — | 65100 |
| leaf1 | Leaf/VTEP | Arista cEOS | 10.255.1.1/32 | 10.255.100.1/32 | 65001 |
| leaf2 | Leaf/VTEP | Nokia SRL | 10.255.1.2/32 | 10.255.100.2/32 | 65002 |
| leaf3 | Leaf/VTEP | FRR | 10.255.1.3/32 | 10.255.100.3/32 | 65003 |
| leaf4 | Leaf/VTEP | Arista cEOS | 10.255.1.4/32 | 10.255.100.4/32 | 65004 |
| leaf5 | Leaf/VTEP | Nokia SRL | 10.255.1.5/32 | 10.255.100.5/32 | 65005 |
| leaf6 | Leaf/VTEP | FRR | 10.255.1.6/32 | 10.255.100.6/32 | 65006 |

## EVPN Overlay ASN

All EVPN iBGP sessions use **AS 65199** (overlay ASN, distinct from underlay).
Spines are Route Reflectors with `cluster-id` matching their loopback.

## P2P Links (Spine-to-Leaf, /31)

### Spine1 (10.0.1.x)

| Link | Spine1 Side | Leaf Side | Leaf |
|------|-------------|-----------|------|
| spine1 ↔ leaf1 | 10.0.1.0/31 | 10.0.1.1/31 | cEOS |
| spine1 ↔ leaf2 | 10.0.1.2/31 | 10.0.1.3/31 | SRL |
| spine1 ↔ leaf3 | 10.0.1.4/31 | 10.0.1.5/31 | FRR |
| spine1 ↔ leaf4 | 10.0.1.6/31 | 10.0.1.7/31 | cEOS |
| spine1 ↔ leaf5 | 10.0.1.8/31 | 10.0.1.9/31 | SRL |
| spine1 ↔ leaf6 | 10.0.1.10/31 | 10.0.1.11/31 | FRR |

### Spine2 (10.0.2.x)

| Link | Spine2 Side | Leaf Side | Leaf |
|------|-------------|-----------|------|
| spine2 ↔ leaf1 | 10.0.2.0/31 | 10.0.2.1/31 | cEOS |
| spine2 ↔ leaf2 | 10.0.2.2/31 | 10.0.2.3/31 | SRL |
| spine2 ↔ leaf3 | 10.0.2.4/31 | 10.0.2.5/31 | FRR |
| spine2 ↔ leaf4 | 10.0.2.6/31 | 10.0.2.7/31 | cEOS |
| spine2 ↔ leaf5 | 10.0.2.8/31 | 10.0.2.9/31 | SRL |
| spine2 ↔ leaf6 | 10.0.2.10/31 | 10.0.2.11/31 | FRR |

### Spine3 (10.0.3.x)

| Link | Spine3 Side | Leaf Side | Leaf |
|------|-------------|-----------|------|
| spine3 ↔ leaf1 | 10.0.3.0/31 | 10.0.3.1/31 | cEOS |
| spine3 ↔ leaf2 | 10.0.3.2/31 | 10.0.3.3/31 | SRL |
| spine3 ↔ leaf3 | 10.0.3.4/31 | 10.0.3.5/31 | FRR |
| spine3 ↔ leaf4 | 10.0.3.6/31 | 10.0.3.7/31 | cEOS |
| spine3 ↔ leaf5 | 10.0.3.8/31 | 10.0.3.9/31 | SRL |
| spine3 ↔ leaf6 | 10.0.3.10/31 | 10.0.3.11/31 | FRR |

## VXLAN / EVPN Segments

| VLAN | VNI | Network | Gateway (anycast) | Rack | Leaf |
|------|-----|---------|-------------------|------|------|
| 10 | 10010 | 10.10.10.0/24 | 10.10.10.254 | 1 | leaf1, leaf2 |
| 20 | 10020 | 10.10.20.0/24 | 10.10.20.254 | 2 | leaf3, leaf4 |
| 30 | 10030 | 10.10.30.0/24 | 10.10.30.254 | 3 | leaf5, leaf6 |

## L3 VRF (Symmetric IRB)

| VRF | L3 VNI | RD | RT Import | RT Export |
|-----|--------|-----|-----------|-----------|
| TENANT-A | 50001 | {loopback}:1 | 1:50001 | 1:50001 |

## Host Addressing

| Host | IP | Gateway | VLAN | Connected Leaf |
|------|-----|---------|------|---------------|
| host1 | 10.10.10.1/24 | 10.10.10.254 | 10 | leaf1 (cEOS) |
| host2 | 10.10.10.2/24 | 10.10.10.254 | 10 | leaf2 (SRL) |
| host3 | 10.10.20.1/24 | 10.10.20.254 | 20 | leaf3 (FRR) |
| host4 | 10.10.20.2/24 | 10.10.20.254 | 20 | leaf4 (cEOS) |
| host5 | 10.10.30.1/24 | 10.10.30.254 | 30 | leaf5 (SRL) |
| host6 | 10.10.30.2/24 | 10.10.30.254 | 30 | leaf6 (FRR) |

## Management Network

| Network | Subnet | Purpose |
|---------|--------|---------|
| clos-mgmt | 172.20.20.0/24 | Clos EVPN topology |
| minimal-mgmt | 172.20.30.0/24 | Minimal topology |
| enterprise-mgmt | 172.20.40.0/24 | 3-tier enterprise |

## BGP Design

```
Underlay: eBGP (RFC 7938)
  Spines: AS 65100 (shared)
  Leafs:  AS 65001–65006 (unique per leaf)

Overlay: iBGP EVPN
  All nodes: AS 65199
  Route Reflectors: spine1, spine2, spine3
  EVPN address family: l2vpn evpn
  Peering: loopback-to-loopback, ebgp-multihop 3
```
