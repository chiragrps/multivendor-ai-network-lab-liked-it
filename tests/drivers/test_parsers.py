"""Tests for the standalone vendor-tagged parsers.

Raw fixtures are inline so there's no network/docker dependency. We assert the
normalized shapes and that every parser soft-fails on garbage / empty input.
"""
from __future__ import annotations

import json

import pytest

from drivers import parsers

# ─────────────────────────────── fixtures ─────────────────────────────────────

FRR_BGP_JSON = json.dumps({
    "ipv4Unicast": {
        "peers": {
            "10.200.0.12": {"remoteAs": 65002, "state": "Established", "pfxRcd": 8, "peerUptime": 5025},
            "10.200.0.13": {"remoteAs": 65003, "state": "Active", "pfxRcd": 0},
        }
    }
})

EOS_BGP_JSON = json.dumps({
    "vrfs": {
        "default": {
            "peers": {
                "10.1.1.1": {"asn": 65010, "peerState": "Established", "prefixReceived": 12},
                "10.1.1.2": {"asn": 65011, "peerState": "Idle", "prefixReceived": 0},
            }
        }
    }
})

# SRL `show network-instance default protocols bgp neighbor` flat table.
SRL_BGP_TABLE = """\
-----------------------------------------------------------------------------------------------
| Net-Inst | Peer        | Group   | Flags  | Peer-AS | State        | Uptime    | AFI/SAFI    |
-----------------------------------------------------------------------------------------------
| default  | 10.0.0.1    | spines  | S      | 65001   | established  | 0d:1h:2m  | ipv4-unicast|
| default  | 10.0.0.2    | spines  | S      | 65002   | active       | -         | ipv4-unicast|
-----------------------------------------------------------------------------------------------
"""

FRR_OSPF_JSON = json.dumps({
    "neighbors": {
        "1.1.1.1": [{"nbrState": "Full/DR", "ifaceName": "eth1", "deadTimeMsecs": 39000}],
        "2.2.2.2": [{"nbrState": "Init", "ifaceName": "eth2", "deadTimeMsecs": 40000}],
    }
})

EOS_INTF_JSON = json.dumps({
    "interfaceStatuses": {
        "Ethernet1": {"linkStatus": "connected", "ipAddresses": [{"address": "10.0.1.1/31"}]},
        "Ethernet2": {"linkStatus": "notconnect"},
    }
})

FRR_INTF_TEXT = """\
Interface       Status     VRF             Addresses
eth0            up         default         10.200.0.11/24
eth1            down       default
"""

SRL_INTF_TEXT = """\
ethernet-1/1 is up, speed 25G
  ethernet-1/1.0 is up
    IPv4 addr    : 10.0.1.0/31 (static, preferred)
ethernet-1/2 is down, speed 25G
"""

FRR_INTF_COUNTERS_JSON = json.dumps({
    "eth1": {"inputBytes": 1000, "outputBytes": 2000, "inputPackets": 10,
             "outputPackets": 20, "inputErrors": 1, "outputErrors": 0},
    "lo": {"inputBytes": 5, "outputBytes": 5},
    "eth0": {"inputBytes": 9, "outputBytes": 9},
})

EOS_INTF_COUNTERS_JSON = json.dumps({
    "interfaces": {
        "Ethernet1": {"inOctets": 500, "outOctets": 600,
                      "inUcastPkts": 5, "inMulticastPkts": 1, "inBroadcastPkts": 0,
                      "outUcastPkts": 6, "outMulticastPkts": 0, "outBroadcastPkts": 0,
                      "inErrors": 0, "outErrors": 2},
        "Management1": {"inOctets": 1},
    }
})

# Real SRL `show interface detail` two-column (Rx Tx) format
SRL_INTF_COUNTERS_TEXT = """\
Interface: ethernet-1/1
  Oper state          : up
Traffic statistics for ethernet-1/1
                       Rx       Tx
  Octets              1234     5678
  Unicast packets     11       22
  Errored packets     3        4
Interface: ethernet-1/2
  Oper state          : up
Traffic statistics for ethernet-1/2
                       Rx       Tx
  Octets              9        0
  Unicast packets     0        0
  Errored packets     0        N/A
"""

FRR_ROUTES_JSON = json.dumps({"routesTotal": 42, "routes": {"bgp": 30, "connected": 12}})

FRR_VERSION_TEXT = "FRRouting 9.1.0 (de-fra-core-01) compiled on 2024-01-15.\n uptime is 3d4h"

EOS_VERSION_JSON = json.dumps({"version": "4.30.1F", "uptime": 123456})


# ─────────────────────────────── bgp ──────────────────────────────────────────

def test_parse_bgp_frr_json():
    out = parsers.parse_bgp("frr", FRR_BGP_JSON)
    assert out["total"] == 2
    assert out["established"] == 1
    states = {p["neighbor"]: p["state"] for p in out["peers"]}
    assert states["10.200.0.12"] == "Established"
    assert states["10.200.0.13"] != "Established"
    assert set(out["peers"][0]) == {"neighbor", "asn", "state", "uptime", "prefixes"}


def test_parse_bgp_eos_json():
    out = parsers.parse_bgp("arista-eos", EOS_BGP_JSON)
    assert out["total"] == 2
    assert out["established"] == 1


def test_parse_bgp_srl_table():
    out = parsers.parse_bgp("nokia-srl", SRL_BGP_TABLE)
    assert out["total"] == 2
    assert out["established"] == 1
    assert out["peers"][0]["neighbor"] == "10.0.0.1"
    assert out["peers"][0]["asn"] == 65001


def test_parse_bgp_empty_and_garbage():
    for bad in ("", "   ", "not json at all", "{broken"):
        out = parsers.parse_bgp("frr", bad)
        assert out == {"peers": [], "established": 0, "total": 0}


# ─────────────────────────────── ospf ─────────────────────────────────────────

def test_parse_ospf_frr_json():
    out = parsers.parse_ospf("frr", FRR_OSPF_JSON)
    assert out["total"] == 2
    assert out["full"] == 1
    full = [n for n in out["neighbors"] if n["state"] == "Full"]
    assert full and full[0]["neighbor"] == "1.1.1.1"


def test_parse_ospf_soft_fail():
    assert parsers.parse_ospf("frr", "") == {"neighbors": [], "full": 0, "total": 0}


# ─────────────────────────── interfaces ───────────────────────────────────────

def test_parse_interfaces_eos_json():
    out = parsers.parse_interfaces("arista-eos", EOS_INTF_JSON)
    assert out["total"] == 2
    assert out["up"] == 1
    eth1 = next(i for i in out["list"] if i["name"] == "Ethernet1")
    assert eth1["status"] == "up"
    assert eth1["addresses"] == ["10.0.1.1/31"]


def test_parse_interfaces_frr_text():
    out = parsers.parse_interfaces("frr", FRR_INTF_TEXT)
    assert out["total"] == 2
    assert out["up"] == 1


def test_parse_interfaces_srl_text():
    out = parsers.parse_interfaces("nokia-srl", SRL_INTF_TEXT)
    assert out["total"] == 2
    assert out["up"] == 1
    up_intf = next(i for i in out["list"] if i["status"] == "up")
    assert "10.0.1.0/31" in up_intf["addresses"]


def test_parse_interfaces_soft_fail():
    assert parsers.parse_interfaces("frr", "") == {"list": [], "up": 0, "total": 0}


# ───────────────────── interface counters ─────────────────────────────────────

def test_parse_interface_counters_frr():
    out = parsers.parse_interface_counters("frr", FRR_INTF_COUNTERS_JSON)
    names = [i["interface"] for i in out["interfaces"]]
    assert names == ["eth1"]  # lo + eth0 filtered
    row = out["interfaces"][0]
    assert set(row) == {"interface", "in_octets", "out_octets", "in_packets",
                        "out_packets", "in_errors", "out_errors"}
    assert row["in_octets"] == 1000
    assert row["out_errors"] == 0


def test_parse_interface_counters_arista():
    out = parsers.parse_interface_counters("arista-eos", EOS_INTF_COUNTERS_JSON)
    names = [i["interface"] for i in out["interfaces"]]
    assert names == ["Ethernet1"]  # Management1 filtered (Ma prefix)
    row = out["interfaces"][0]
    assert row["in_packets"] == 6  # 5 + 1 + 0
    assert row["out_errors"] == 2


def test_parse_interface_counters_srl():
    out = parsers.parse_interface_counters("nokia-srl", SRL_INTF_COUNTERS_TEXT)
    assert len(out["interfaces"]) == 2
    e1 = out["interfaces"][0]
    assert e1["interface"] == "ethernet-1/1"
    assert e1["in_octets"] == 1234
    assert e1["out_packets"] == 22
    assert e1["in_errors"] == 3


def test_parse_interface_counters_soft_fail():
    assert parsers.parse_interface_counters("frr", "") == {"interfaces": []}
    assert parsers.parse_interface_counters("arista-eos", "garbage") == {"interfaces": []}


# ─────────────────────────────── routes ───────────────────────────────────────

def test_parse_routes_frr_json():
    out = parsers.parse_routes("frr", FRR_ROUTES_JSON)
    assert out["total"] == 42
    assert out["by_protocol"]["bgp"] == 30


def test_parse_routes_text_fallback():
    text = "Route Source   Routes  FIB\nbgp            30      30\nconnected      12      12\n"
    out = parsers.parse_routes("frr", text)
    assert out["by_protocol"] == {"bgp": 30, "connected": 12}
    assert out["total"] == 42


def test_parse_routes_soft_fail():
    assert parsers.parse_routes("frr", "") == {"total": None, "by_protocol": {}}


# ─────────────────────────────── version ──────────────────────────────────────

def test_parse_version_frr():
    out = parsers.parse_version("frr", FRR_VERSION_TEXT)
    assert out["version"] == "9.1.0"
    assert "raw" in out


def test_parse_version_eos_json():
    out = parsers.parse_version("arista-eos", EOS_VERSION_JSON)
    assert out["version"] == "4.30.1F"
    assert out["uptime"] == "123456s"


def test_parse_version_soft_fail():
    out = parsers.parse_version("frr", "")
    assert out == {"raw": "", "version": None, "uptime": None}


# ─────────────────── every parser tolerates None input ────────────────────────

@pytest.mark.parametrize("fn", [
    parsers.parse_bgp, parsers.parse_ospf, parsers.parse_interfaces,
    parsers.parse_interface_counters, parsers.parse_routes, parsers.parse_version,
])
def test_parsers_never_raise_on_none(fn):
    # Defensive: raw may arrive as None from a failed transport.
    result = fn("frr", None)  # type: ignore[arg-type]
    assert isinstance(result, dict)


# ─────────────────────────────── Junos ────────────────────────────────────────

import json as _json

JUNOS_BGP_JSON = _json.dumps({
    "bgp-information": [{
        "bgp-peer": [
            {"peer-address": [{"data": "10.0.0.1+179"}], "peer-as": [{"data": "65001"}],
             "peer-state": [{"data": "Established"}], "elapsed-time": [{"data": "1d 2h"}],
             "received-prefix-count": [{"data": "12"}]},
            {"peer-address": [{"data": "10.0.0.2"}], "peer-as": [{"data": "65002"}],
             "peer-state": [{"data": "Active"}]},
        ]
    }]
})

JUNOS_OSPF_JSON = _json.dumps({
    "ospf-neighbor-information": [{
        "ospf-neighbor": [
            {"neighbor-address": [{"data": "10.0.0.1"}], "ospf-neighbor-state": [{"data": "Full"}],
             "interface-name": [{"data": "ge-0/0/0.0"}], "activity-timer": [{"data": "38"}]},
            {"neighbor-address": [{"data": "10.0.0.2"}], "ospf-neighbor-state": [{"data": "Init"}],
             "interface-name": [{"data": "ge-0/0/1.0"}]},
        ]
    }]
})

JUNOS_INTF_JSON = _json.dumps({
    "interface-information": [{
        "physical-interface": [
            {"name": [{"data": "ge-0/0/0"}], "oper-status": [{"data": "up"}],
             "logical-interface": [{"address-family": [{"interface-address": [{"ifa-local": [{"data": "10.0.0.1/31"}]}]}]}]},
            {"name": [{"data": "ge-0/0/1"}], "oper-status": [{"data": "down"}]},
        ]
    }]
})


def test_parse_bgp_junos():
    out = parsers.parse_bgp("junos", JUNOS_BGP_JSON)
    assert out["total"] == 2
    assert out["established"] == 1
    p0 = out["peers"][0]
    assert p0["neighbor"] == "10.0.0.1"      # +port stripped
    assert p0["asn"] == 65001
    assert p0["state"] == "Established"
    assert p0["prefixes"] == 12
    assert out["peers"][1]["state"] == "Active"


def test_parse_ospf_junos():
    out = parsers.parse_ospf("junos", JUNOS_OSPF_JSON)
    assert out["total"] == 2
    assert out["full"] == 1
    assert out["neighbors"][0]["neighbor"] == "10.0.0.1"
    assert out["neighbors"][0]["interface"] == "ge-0/0/0.0"


def test_parse_interfaces_junos():
    out = parsers.parse_interfaces("junos", JUNOS_INTF_JSON)
    assert out["total"] == 2
    assert out["up"] == 1
    assert out["list"][0]["name"] == "ge-0/0/0"
    assert out["list"][0]["addresses"] == ["10.0.0.1/31"]


def test_parse_junos_soft_fail():
    assert parsers.parse_bgp("junos", "") == {"peers": [], "established": 0, "total": 0}
    assert parsers.parse_ospf("junos", "garbage") == {"neighbors": [], "full": 0, "total": 0}


# ─────────────────────────────── Cisco IOS-XR ─────────────────────────────────

# IOS-XR `show bgp summary` — standard Cisco 11-column text table
IOSXR_BGP_TEXT = """\
BGP router identifier 1.1.1.1, local AS number 65000

Neighbor        Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down  St/PfxRcd
10.0.0.1          0 65001     100     100       50    0    0 01:23:45         12
10.0.0.2          0 65002       0       0        0    0    0 00:00:00       Idle
"""

# IOS-XR `show ipv4 interface brief` — Interface / IP-Address / Status / Protocol
IOSXR_INTF_TEXT = """\
Interface                      IP-Address      Status          Protocol
GigabitEthernet0/0/0/0         10.0.0.1        Up              Up
Loopback0                      1.1.1.1         Up              Up
MgmtEth0/RP0/CPU0/0            unassigned      Shutdown        Down
"""

IOSXR_VERSION_TEXT = "Cisco IOS XR Software, Version 7.5.2\n Copyright (c) 2022 by Cisco Systems, Inc."


def test_parse_bgp_iosxr_text():
    out = parsers.parse_bgp("cisco-iosxr", IOSXR_BGP_TEXT)
    assert out["total"] == 2
    assert out["established"] == 1            # 10.0.0.1 has pfxrcd=12 → established
    p0 = next(p for p in out["peers"] if p["neighbor"] == "10.0.0.1")
    assert p0["asn"] == "65001"
    assert p0["prefixes"] == 12
    idle = next(p for p in out["peers"] if p["neighbor"] == "10.0.0.2")
    assert idle["state"] == "Idle"


def test_parse_interfaces_iosxr_text():
    out = parsers.parse_interfaces("cisco-iosxr", IOSXR_INTF_TEXT)
    assert out["total"] == 3
    assert out["up"] == 2                      # two Up, one Shutdown
    gi = next(i for i in out["list"] if i["name"] == "GigabitEthernet0/0/0/0")
    assert gi["status"] == "up"
    assert gi["addresses"] == ["10.0.0.1"]
    mg = next(i for i in out["list"] if i["name"].startswith("MgmtEth"))
    assert mg["addresses"] == []               # 'unassigned' dropped


def test_parse_version_iosxr():
    out = parsers.parse_version("cisco-iosxr", IOSXR_VERSION_TEXT)
    assert out["version"] == "7.5.2"


def test_parse_iosxr_soft_fail():
    assert parsers.parse_bgp("cisco-iosxr", "") == {"peers": [], "established": 0, "total": 0}
    assert parsers.parse_interfaces("cisco-iosxr", "") == {"list": [], "up": 0, "total": 0}


def test_iosxr_aliases_resolve():
    from drivers.commands import canonical_vendor
    for alias in ("iosxr", "ios-xr", "xr", "cisco-iosxr", "cisco"):
        assert canonical_vendor(alias) == "cisco-iosxr"
