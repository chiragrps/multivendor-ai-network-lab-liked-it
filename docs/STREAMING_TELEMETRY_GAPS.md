# Streaming Telemetry Coverage Gaps (cEOS gNMI + FRR openconfigd)

The 2026-05-25 gNMI rollout (roadmap #2) covered **3 of 9 routing nodes** —
the Nokia SR Linux fabric members. The remaining 6 nodes (3 cEOS + 3 FRR)
are still on the 15-second docker-exec polling path. This doc explains why
and provides the migration script for each.

## Current state

| Vendor | Nodes | Streaming path | Polling path |
| --- | --- | --- | --- |
| Nokia SR Linux | spine1, leaf2, leaf5 | **gnmic + InfluxDB · ON_CHANGE + 10/15 s SAMPLE** | (decom candidate) |
| Arista cEOS    | spine2, leaf1, leaf4 | ❌ blocked (see §1) | `Cli -p 15 -c "show ... | json"` via docker exec every 15 s |
| FRR            | spine3, leaf3, leaf6 | ❌ blocked (see §2) | `vtysh -c "show ... json"` via docker exec every 15 s |

## §1. cEOS gNMI — `management api gnmi` rejects `no shutdown`

The cEOS-Lab 4.33.1F image (the one our clab topology pulls) accepts the
gNMI configuration *block* but rejects the `no shutdown` that activates the
Octa agent:

```
spine2# config
spine2(config)# management api gnmi
spine2(config-mgmt-api-gnmi)# transport grpc default
spine2(config-mgmt-api-gnmi)# no shutdown
% Incomplete command at token 1: shutdown
```

The Octa process never binds `:6030`, so gnmic's `dial-in` connection fails.

### Options (pick one)

#### Option A — Newer cEOS-Lab image (lowest risk)

Arista has fixed this in cEOS-Lab 4.34+. The fix is a topology change:

```yaml
# containerlab-multivendor/topologies/clos-evpn.clab.yml
topology:
  kinds:
    arista_ceos:
      image: ceos:4.34.0F   # was 4.33.1F-Lab
```

Then `containerlab destroy && containerlab deploy`. The startup-config
already includes the gNMI block — Octa will bind on first boot.

#### Option B — Octa sidecar container

If you can't change the cEOS image (license/test reasons), run Octa as a
sidecar:

```bash
docker run -d --name=octa-spine2 --net=container:clab-clos-evpn-spine2 \
  ghcr.io/aristanetworks/octa:latest \
  --target=127.0.0.1:6042 --listen=:6030
```

Then point gnmic at `127.0.0.1:6030` (via `--net=container:clab-clos-evpn-spine2`
the sidecar shares the cEOS network namespace, so :6030 reaches Octa
which talks to cEOS's eAPI on :6042 inside the same netns).

#### Option C — gNMI-over-eAPI bridge (lab only)

Run a small Python shim that turns gnmic SUBSCRIBE into eAPI long-polling:

```python
# Sketch — file: scripts/eapi_to_gnmic_bridge.py
import jsonrpc, paho.mqtt.publish  # eAPI client
def subscribe_loop(host, paths):
    while True:
        rsp = eapi.run(host, ["show ip bgp summary | json"])
        publish.single(f"gnmic/{host}/bgp", json.dumps(rsp))
        time.sleep(10)
```

`gnmic-config` would point at the MQTT broker. **Not recommended** — adds
moving parts for no real-world fidelity.

### Recommended

**Option A**. The image swap is one yaml edit + `clab redeploy` (~3 min).
Same startup-config keeps working.

## §2. FRR — no native gNMI

FRR ships with no gNMI server. The community options:

| Project | Status | Verdict |
| --- | --- | --- |
| [coreswitch/openconfigd](https://github.com/coreswitch/openconfigd) | Last commit 2021; partial OpenConfig coverage | Workable for static topologies; fragile under churn |
| [FRR northbound + gNMI plugin](https://docs.frrouting.org/en/latest/grpc.html) | Native gRPC since FRR 8.2; OpenConfig subset; needs `--enable-grpc` build | **Best path** |
| [openconfig/gnmi-gateway](https://github.com/openconfig/gnmi-gateway) + show-cmd shim | Heavy; designed for dial-out aggregation | Overkill for 3 lab routers |

### Recommended: FRR gRPC plugin

Rebuild the FRR container image with `--enable-grpc`:

```dockerfile
# containerlab-multivendor/topologies/frr-grpc/Dockerfile (new)
FROM quay.io/frrouting/frr:8.4_git
USER root
RUN apt-get update && apt-get install -y protobuf-compiler libprotobuf-c-dev
RUN cd /src && ./configure --enable-grpc && make -j$(nproc) && make install
```

Then in clab.yml swap `kind: linux` (which we currently use for FRR) for a
custom kind that exposes `:6030`. Updates to gnmic.yaml:

```yaml
targets:
  172.20.20.13:6030:
    name: spine3
    tags: [host=spine3, vendor=frr, role=spine, fabric=clos-evpn]
  172.20.20.23:6030: {name: leaf3,  tags: [host=leaf3, vendor=frr, role=leaf]}
  172.20.20.26:6030: {name: leaf6,  tags: [host=leaf6, vendor=frr, role=leaf]}

subscriptions:
  frr-bgp:
    paths:
      - /network-instances/network-instance/protocols/protocol/bgp/neighbors
    mode: stream
    stream-mode: on-change
```

## §3. Migration script

Save as `scripts/migrate_streaming_telemetry.sh`:

```bash
#!/usr/bin/env bash
# Migrate cEOS + FRR clab nodes from docker-exec polling to gNMI streaming.
# Idempotent: safe to re-run.
set -euo pipefail

CLAB_DIR=/Users/georgigaydarov/02_Projects/Network_Automation/VSS_Code_Georgi/04_Scripts_Tools/DCN_Network_Tool/containerlab-multivendor
TOPO=$CLAB_DIR/topologies/clos-evpn.clab.yml

case "${1:-help}" in
  ceos-image)
    # Option A from STREAMING_TELEMETRY_GAPS.md §1
    grep -q "image: ceos:4.33" "$TOPO" || { echo "image already swapped"; exit 0; }
    sed -i.bak 's|image: ceos:4.33.*|image: ceos:4.34.0F|' "$TOPO"
    echo "cEOS image bumped to 4.34.0F — run 'clab redeploy' next."
    ;;
  frr-grpc)
    # Option B — rebuild FRR with --enable-grpc
    docker build -t frr:8.4-grpc -f $CLAB_DIR/topologies/frr-grpc/Dockerfile $CLAB_DIR
    echo "Custom FRR built. Edit clab.yml to use 'image: frr:8.4-grpc' for spine3, leaf3, leaf6."
    ;;
  redeploy)
    cd $CLAB_DIR/topologies
    containerlab destroy --topo clos-evpn.clab.yml --cleanup
    containerlab deploy  --topo clos-evpn.clab.yml
    echo "Redeployed. Confirm gnmic picks up all 9 routing nodes via 'curl localhost:7890/api/v1/targets'."
    ;;
  verify)
    echo "Probing :6030 on every node…"
    for h in spine1 spine2 spine3 leaf1 leaf2 leaf3 leaf4 leaf5 leaf6; do
      printf "  %-8s :6030 " "$h"
      docker exec clab-clos-evpn-$h sh -c "(nc -zv 127.0.0.1 6030 2>&1 | head -1) || echo no-gnmi"
    done
    ;;
  *)
    cat <<EOF
usage: $0 <command>
  ceos-image   bump cEOS to 4.34.0F (unblocks Octa)
  frr-grpc     build custom FRR image with --enable-grpc
  redeploy     containerlab destroy && deploy
  verify       check :6030 reachability on all 9 routing nodes
EOF
    ;;
esac
```

## §4. After migration

Once all 9 routing nodes stream:

1. Update `network-lab/telemetry/gnmic/gnmic.yaml` to include all 9 targets
   (current file only has 3 SRL nodes — copy the SRL block, swap addresses
   and paths per vendor).
2. Restart the gnmic sidecar: `docker restart clab-gnmic`
3. Decommission the docker-exec polling for the 6 newly-streamed nodes:
   - In `clab_collector.py` move them to a `skip = {...}` set so they're
     not docker-exec'd every 15 s.
4. Update `/api/telemetry/gnmic-status` expectations: `target_count` should
   read 9, not 3.

The roadmap A/B confidence window (2 weeks) starts *after* this migration.

## §5. Why it's deferred (not blocking)

The 6 non-streaming nodes still produce correct data via the 15-second
docker-exec collector. The user-visible cost is **15 s freshness instead
of sub-second on state events**. For the lab + demo + screenshots this is
acceptable; for a real production deployment streaming is required.

Until migration, the tool reports honestly:
- `gnmic-status.target_count = 3` (SRL only)
- `clab-status` shows all 9 nodes from the polling collector

There is no false-green path — operators can tell at a glance which nodes
are streamed vs polled.
