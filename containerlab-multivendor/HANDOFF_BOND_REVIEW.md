# 🚨 HANDOFF — Review needed before next `containerlab deploy`

**From:** Claude session #1 (spine RR fix + initial leaf VTEP rollout)
**To:** Claude session #2 (bond / ESI-LAG rollout)
**Date:** 2026-05-25
**Lab state at handoff:** 37/37 `./scripts/check_fabric.sh` passing on the *previous* single-homed topology. The new bond/ESI-LAG configs you committed are on disk but **NOT deployed yet**.

---

## Why this file exists

Owner ran `verify-don't-deploy` after your bond/ESI-LAG work landed. Five issues found that will block clean redeploy. Fix them in the configs you own, then deploy. My `check_fabric.sh` will tell you if anything regressed on the underlay/overlay side.

---

## Issues (in priority order)

### 1. ❌ CRITICAL — Cross-vendor ESI mismatch on Rack-2 & Rack-3

**Cause:** FRR's `evpn mh es-id N` + `es-sys-mac` auto-generates a **Type-3 ESI** = `03:<sys-mac:6>:<es-id:3>`. Your cEOS and SRL pair configs use explicit **Type-0** 10-byte ESIs. They will never match, so all-active EVPN ES will not form (no split-horizon, no DF election, duplicate/dropped frames).

| Rack | Pair | FRR computes | Partner expects |
|---|---|---|---|
| 2 (VLAN 20) | leaf3 FRR ↔ leaf4 cEOS | `03:00:22:22:22:11:11:00:00:01` | `00:22:22:22:22:22:22:22:11:11` |
| 2 (VLAN 20) | leaf3 FRR ↔ leaf4 cEOS | `03:00:22:22:22:22:22:00:00:02` | `00:22:22:22:22:22:22:22:22:22` |
| 3 (VLAN 30) | leaf6 FRR ↔ leaf5 SRL | `03:00:33:33:33:11:11:00:00:01` | `00:33:33:33:33:33:33:33:11:11` |
| 3 (VLAN 30) | leaf6 FRR ↔ leaf5 SRL | `03:00:33:33:33:22:22:00:00:02` | `00:33:33:33:33:33:33:33:22:22` |

**Fix — change FRR side to use Type-0 manual ESI matching the partner exactly:**

```diff
# configs/leaf/leaf3-frr.conf
 interface eth4
   description host3-leg (ESI-LAG rack-2)
-  evpn mh es-id 1
-  evpn mh es-sys-mac 00:22:22:22:11:11
+  evpn mh es-id 00:22:22:22:22:22:22:22:11:11   # Type-0, matches leaf4 Port-Channel1
+  evpn mh es-df-pref 50000
 exit

 interface eth5
   description host4-leg (ESI-LAG rack-2)
-  evpn mh es-id 2
-  evpn mh es-sys-mac 00:22:22:22:22:22
+  evpn mh es-id 00:22:22:22:22:22:22:22:22:22   # Type-0, matches leaf4 Port-Channel2
+  evpn mh es-df-pref 50000
 exit

# configs/leaf/leaf6-frr.conf — same pattern with 00:33:33:33:33:33:33:33:11:11 / :22:22
```

Validate by checking FRR sees the partner's ES via Type-1 routes:
`docker exec clab-clos-evpn-leaf3 vtysh -c 'show evpn es detail'`

### 2. ❌ CRITICAL — FRR references bridges that YAML doesn't create

| File | Refers to | YAML creates |
|---|---|---|
| `configs/leaf/leaf3-frr.conf:11` | `interface br-vlan20` | `br10020` |
| `configs/leaf/leaf6-frr.conf` | `interface br-vlan30` | `br10030` |

**Pick one convention** (recommend `br10020` / `br10030` since it encodes the VNI), and align both files. The bridge SVI carries the anycast gateway IP — if FRR can't find it, `10.10.20.254` / `10.10.30.254` never come up.

### 3. ❌ CRITICAL — FRR has VRF TENANT-A but no Linux VRF device

`configs/leaf/leaf3-frr.conf:7-9`:
```
vrf TENANT-A
 vni 50001
exit-vrf
```

FRR/zebra needs a kernel VRF netdev to manage. The `topologies/clos-evpn.clab.yml` `exec:` blocks for leaf3/leaf6 don't create it. Either:

**(a) Drop the FRR VRF block** (no L3 IRB on FRR leaves — only cEOS leaves do L3 routing for TENANT-A), OR

**(b) Bootstrap the VRF in YAML `exec:`** — add after the existing netdev lines:
```yaml
- bash -c "ip link add TENANT-A type vrf table 100 2>/dev/null; ip link set TENANT-A up"
- bash -c "ip link set br10020 master TENANT-A"   # for leaf3
# leaf6: ip link set br10030 master TENANT-A
- bash -c "ip link add vxlan50001 type vxlan id 50001 dstport 4789 local 10.255.100.3 nolearning 2>/dev/null; ip link set vxlan50001 up"
- bash -c "ip link add brTENANT type bridge 2>/dev/null; ip link set brTENANT master TENANT-A; ip link set vxlan50001 master brTENANT; ip link set brTENANT up"
```

Decision is yours — but pick one before deploying.

### 4. ⚠️ MEDIUM — host6 active-backup vs leaf-side LACP mismatch

`topologies/clos-evpn.clab.yml:272-276`: host6 uses `bond mode active-backup`, but:
- leaf5 SRL `lag2` is `lag-type lacp` (90s fallback to static, so it'll converge eventually)
- leaf6 FRR `eth5` is bare (no bond)

Will work after 90s fallback, but for symmetry with hosts 1-5 (all LACP), either:
- Switch host6 to `802.3ad`, OR
- Document the asymmetry as intentional in the YAML comment

The current comment says *"leaf6 FRR lacks kernel VRF for L3 VNI"* — that justification is unrelated to bond mode choice.

### 5. ⚠️ MEDIUM — leaf4 cEOS VXLAN source changed

`configs/leaf/leaf4-ceos.cfg`:
```
interface Vxlan1
 vxlan source-interface Loopback0   ← was Loopback1 (10.255.100.4) in working state
```

Other leaves source from lo1 (10.255.100.X). leaf4 now sources from lo0 (10.255.1.4). Both reachable, so EVPN will still build tunnels — but remote VTEPs will see a different next-hop than the documented `10.255.100.4` convention. Pick one:
- Restore `vxlan source-interface Loopback1` on leaf4 (matches rest), OR
- Migrate all leaves to source from lo0 router-id loopback (drop lo1 entirely from spine VTEPs)

---

## Post-fix workflow

```bash
cd containerlab-multivendor
sudo containerlab destroy -t topologies/clos-evpn.clab.yml
sudo containerlab deploy  -t topologies/clos-evpn.clab.yml

# Underlay/overlay sanity (should still be 37/37 — pings will fail until ES is up)
./scripts/check_fabric.sh

# ES-specific checks (post-bond)
for L in leaf1 leaf2 leaf3 leaf4 leaf5 leaf6; do
  echo "── $L ──"
  case $L in
    leaf1|leaf4) docker exec clab-clos-evpn-$L Cli -p 15 -c 'show bgp evpn route-type ethernet-segment' ;;
    leaf2|leaf5) docker exec clab-clos-evpn-$L sr_cli 'show system network-instance ethernet-segments' ;;
    leaf3|leaf6) docker exec clab-clos-evpn-$L vtysh -c 'show evpn es detail' ;;
  esac
done

# LACP state on hosts (should see "MII Status: up" + 2 slaves)
for h in host1 host2 host3 host4 host5 host6; do
  echo "── $h ──"
  docker exec clab-clos-evpn-$h cat /proc/net/bonding/bond0 | head -10
done

# Real test: kill one leaf in a pair, ping should keep working
docker stop clab-clos-evpn-leaf1
docker exec clab-clos-evpn-host1 ping -c 5 10.10.10.2
docker start clab-clos-evpn-leaf1
```

---

## Reference — files you've changed since the handoff

```
topologies/clos-evpn.clab.yml     — added bond0 LACP on hosts, dual-leaf endpoints
configs/leaf/leaf1-ceos.cfg       — Port-Channel1/2 ESI-LAG, host1/2 channel-groups
configs/leaf/leaf2-srl.cfg        — lag1/lag2 LACP, ethernet-segments host1-es/host2-es
configs/leaf/leaf3-frr.conf       — eth4/eth5 evpn mh, vrf TENANT-A, br-vlan20 SVI
configs/leaf/leaf4-ceos.cfg       — Port-Channel1/2 ESI-LAG, Vxlan1 source-interface changed
configs/leaf/leaf5-srl.cfg        — lag1/lag2 LACP, ethernet-segments host5-es/host6-es
configs/leaf/leaf6-frr.conf       — eth4/eth5 evpn mh, br-vlan30 SVI
```

## My contract

Once you've reconciled the 5 issues and pushed the deploy, ping the owner — they'll run `./scripts/check_fabric.sh` to confirm I (the previous session) haven't left underlay/overlay regressions. If it shows red, holler back here.
