#!/usr/bin/env python3
"""FRR Streaming Telemetry Collector — SSH → vtysh → InfluxDB line protocol."""
import json
import logging
import os
import time

import paramiko
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

DEVICES = [
    {"hostname": "de-fra-core-01", "ip": "10.200.0.11", "port": 22},
    {"hostname": "de-fra-core-02", "ip": "10.200.0.12", "port": 22},
    {"hostname": "uk-lon-core-01", "ip": "10.200.0.13", "port": 22},
    {"hostname": "nl-ams-core-01", "ip": "10.200.0.14", "port": 22},
    {"hostname": "us-nyc-core-01", "ip": "10.200.0.15", "port": 22},
    {"hostname": "de-fra-edge-01", "ip": "10.200.0.21", "port": 22},
    {"hostname": "uk-lon-edge-01", "ip": "10.200.0.22", "port": 22},
    {"hostname": "nl-ams-edge-01", "ip": "10.200.0.23", "port": 22},
    {"hostname": "uk-lon-dist-01", "ip": "10.200.0.31", "port": 22},
    {"hostname": "de-fra-dist-01", "ip": "10.200.0.33", "port": 22},
]

SSH_KEY_PATH   = os.environ.get("SSH_KEY_PATH", "/ssh-keys/lab_key")
SSH_USER       = os.environ.get("SSH_USER", "root")
INFLUX_URL     = os.environ.get("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN   = os.environ.get("INFLUXDB_TOKEN", "dcn-lab-token-secret")
INFLUX_ORG     = os.environ.get("INFLUXDB_ORG", "dcn-lab")
INFLUX_BUCKET  = os.environ.get("INFLUXDB_BUCKET", "network-telemetry")
POLL_INTERVAL  = int(os.environ.get("POLL_INTERVAL", "10"))


def _tag(value: str) -> str:
    """Escape InfluxDB line-protocol tag values."""
    return value.replace(",", r"\,").replace(" ", r"\ ").replace("=", r"\=")


def _vtysh(ip: str, port: int, cmd: str) -> str:
    key = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=port, username=SSH_USER, pkey=key, timeout=10)
    _, stdout, _ = client.exec_command(f"vtysh -c '{cmd}'")
    out = stdout.read().decode()
    client.close()
    return out


def collect_bgp(hostname: str, ip: str, port: int, ts: int) -> list[str]:
    lines: list[str] = []
    try:
        raw = _vtysh(ip, port, "show bgp summary json")
        data = json.loads(raw)
        # FRR 9.x: top-level may be {"ipv4Unicast": {...}} or {"peers": {...}}
        peers: dict = {}
        if "ipv4Unicast" in data:
            peers = data["ipv4Unicast"].get("peers", {})
        elif "peers" in data:
            peers = data["peers"]

        for peer_ip, p in peers.items():
            established = 1 if p.get("state") == "Established" else 0
            pfx_rcvd   = int(p.get("pfxRcd", 0) or 0)
            uptime_ms  = int(p.get("peerUptimeMsec", 0) or 0)
            remote_as  = int(p.get("remoteAs", 0) or 0)
            state      = p.get("state", "unknown")

            lines.append(
                f"bgp_neighbor,"
                f"host={_tag(hostname)},"
                f"peer={_tag(peer_ip)},"
                f"state={_tag(state)},"
                f"remote_as={remote_as} "
                f"established={established}i,"
                f"pfx_received={pfx_rcvd}i,"
                f"uptime_ms={uptime_ms}i "
                f"{ts}"
            )
        log.info(f"  {hostname}: {len(peers)} BGP peers collected")
    except Exception as exc:
        log.warning(f"  {hostname}: BGP collect failed — {exc}")
    return lines


def collect_ospf(hostname: str, ip: str, port: int, ts: int) -> list[str]:
    lines: list[str] = []
    try:
        raw = _vtysh(ip, port, "show ip ospf neighbor json")
        data = json.loads(raw)
        # FRR: {"neighbors": {"10.x.x.x": [{"nbrState": "Full/DR", ...}]}}
        neighbors: dict = data.get("neighbors", {})
        for nbr_ip, nbr_list in neighbors.items():
            entries = nbr_list if isinstance(nbr_list, list) else [nbr_list]
            for nbr in entries:
                state  = nbr.get("nbrState", "unknown")
                full   = 1 if "Full" in state else 0
                iface  = nbr.get("ifaceName", "unknown")
                lines.append(
                    f"ospf_neighbor,"
                    f"host={_tag(hostname)},"
                    f"neighbor={_tag(nbr_ip)},"
                    f"state={_tag(state)},"
                    f"interface={_tag(iface)} "
                    f"full={full}i "
                    f"{ts}"
                )
        log.info(f"  {hostname}: {len(neighbors)} OSPF neighbors collected")
    except Exception as exc:
        log.warning(f"  {hostname}: OSPF collect failed — {exc}")
    return lines


def collect_interfaces(hostname: str, ip: str, port: int, ts: int) -> list[str]:
    lines: list[str] = []
    try:
        raw = _vtysh(ip, port, "show interface json")
        data = json.loads(raw)
        for iface_name, iface in data.items():
            if iface_name == "lo":
                continue
            stats   = iface.get("statistics", {})
            rx_b    = int(stats.get("inputBytes", 0) or 0)
            tx_b    = int(stats.get("outputBytes", 0) or 0)
            rx_p    = int(stats.get("inputPackets", 0) or 0)
            tx_p    = int(stats.get("outputPackets", 0) or 0)
            rx_drop = int(stats.get("inputDropped", 0) or 0)
            tx_drop = int(stats.get("outputDropped", 0) or 0)
            mtu     = int(iface.get("mtu", 1500) or 1500)
            link_up = 1 if iface.get("operationalStatus", "down") == "up" else 0

            lines.append(
                f"interface_stats,"
                f"host={_tag(hostname)},"
                f"interface={_tag(iface_name)} "
                f"rx_bytes={rx_b}i,"
                f"tx_bytes={tx_b}i,"
                f"rx_packets={rx_p}i,"
                f"tx_packets={tx_p}i,"
                f"rx_dropped={rx_drop}i,"
                f"tx_dropped={tx_drop}i,"
                f"mtu={mtu}i,"
                f"link_up={link_up}i "
                f"{ts}"
            )
        log.info(f"  {hostname}: {len(data)} interfaces collected")
    except Exception as exc:
        log.warning(f"  {hostname}: interface collect failed — {exc}")
    return lines


def write_to_influx(lines: list[str]) -> None:
    if not lines:
        return
    url = (
        f"{INFLUX_URL}/api/v2/write"
        f"?org={INFLUX_ORG}&bucket={INFLUX_BUCKET}&precision=ns"
    )
    headers = {
        "Authorization": f"Token {INFLUX_TOKEN}",
        "Content-Type": "text/plain; charset=utf-8",
    }
    resp = requests.post(url, data="\n".join(lines).encode(), headers=headers, timeout=10)
    if resp.status_code not in (204, 200):
        log.error(f"InfluxDB write failed: {resp.status_code} — {resp.text[:200]}")
    else:
        log.info(f"Wrote {len(lines)} metrics to InfluxDB")


def collect_all() -> None:
    ts = time.time_ns()
    all_lines: list[str] = []
    for dev in DEVICES:
        h, ip, port = dev["hostname"], dev["ip"], dev["port"]
        log.info(f"Polling {h} ({ip})")
        all_lines += collect_bgp(h, ip, port, ts)
        all_lines += collect_ospf(h, ip, port, ts)
        all_lines += collect_interfaces(h, ip, port, ts)
    write_to_influx(all_lines)


def wait_for_influx(max_attempts: int = 30) -> None:
    log.info(f"Waiting for InfluxDB at {INFLUX_URL} …")
    for attempt in range(max_attempts):
        try:
            r = requests.get(f"{INFLUX_URL}/ping", timeout=3)
            if r.status_code == 204:
                log.info("InfluxDB is ready")
                return
        except Exception:
            pass
        log.info(f"  attempt {attempt + 1}/{max_attempts} — retrying in 2s")
        time.sleep(2)
    log.warning("InfluxDB did not become ready — continuing anyway")


def main() -> None:
    log.info(
        f"FRR Telemetry Collector starting — "
        f"poll_interval={POLL_INTERVAL}s  "
        f"influx={INFLUX_URL}  "
        f"org={INFLUX_ORG}  bucket={INFLUX_BUCKET}"
    )
    wait_for_influx()
    # Give FRR containers time to converge BGP/OSPF
    log.info("Waiting 15s for FRR convergence …")
    time.sleep(15)

    while True:
        try:
            collect_all()
        except Exception as exc:
            log.error(f"Collection cycle error: {exc}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
