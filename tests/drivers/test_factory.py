"""Tests for the driver factory, transports, and base template methods.

All transport interaction is mocked — no docker, no SSH, no network.
"""
from __future__ import annotations

import json

import pytest

from drivers import (BaseNetworkDriver, DriverResult, UnsupportedVendorError,
                     get_driver)
from drivers.eos import EOSDriver
from drivers.frr import FRRDriver
from drivers.srl import SRLDriver
from drivers.transport import (DockerExecTransport, SSHRunnerTransport,
                               ScrapliTransport)

FRR_BGP_JSON = json.dumps({
    "ipv4Unicast": {"peers": {
        "10.0.0.1": {"remoteAs": 65001, "state": "Established", "pfxRcd": 5},
    }}
})


# ───────────────────────── vendor resolution ──────────────────────────────────

@pytest.mark.parametrize("alias,cls", [
    ("frr", FRRDriver),
    ("arista", EOSDriver),
    ("arista-eos", EOSDriver),
    ("eos", EOSDriver),
    ("EOS", EOSDriver),            # case-insensitive
    ("nokia-srl", SRLDriver),
    ("srl", SRLDriver),
    ("nokia", SRLDriver),
    (" Nokia ", SRLDriver),        # whitespace tolerant
])
def test_get_driver_resolves_aliases(alias, cls, fake_transport_factory):
    drv = get_driver(alias, transport=fake_transport_factory())
    assert isinstance(drv, cls)


def test_unknown_vendor_raises(fake_transport_factory):
    with pytest.raises(UnsupportedVendorError):
        get_driver("cisco-ios", transport=fake_transport_factory())


def test_junos_resolves_to_driver(fake_transport_factory):
    # junos now has a registered JunosDriver.
    from drivers.junos import JunosDriver
    drv = get_driver("junos", transport=fake_transport_factory())
    assert isinstance(drv, JunosDriver)
    assert drv.vendor == "junos"


# ─────────────────────── transport auto-selection ─────────────────────────────

def test_container_selects_docker_transport():
    drv = get_driver("frr", container="clab-clos-evpn-spine3")
    assert isinstance(drv.transport, DockerExecTransport)
    assert drv.transport.container == "clab-clos-evpn-spine3"


def test_runner_selects_ssh_transport():
    runner = lambda ip, dtype, cmd, port=22: {"success": True, "output": "x"}
    drv = get_driver("frr", runner=runner, ip="10.0.0.1", port=2201)
    assert isinstance(drv.transport, SSHRunnerTransport)


def test_runner_without_ip_raises():
    runner = lambda *a, **k: {"success": True, "output": "x"}
    with pytest.raises(UnsupportedVendorError):
        get_driver("frr", runner=runner)


def test_no_transport_raises():
    with pytest.raises(UnsupportedVendorError):
        get_driver("frr")


def test_explicit_transport_wins(fake_transport_factory):
    ft = fake_transport_factory()
    drv = get_driver("frr", transport=ft, container="ignored")
    assert drv.transport is ft


# ─────────────────────── base template methods ────────────────────────────────

def test_get_bgp_summary_parses(fake_transport_factory):
    ft = fake_transport_factory({"show ip bgp summary json": (FRR_BGP_JSON, True)})
    drv = get_driver("frr", transport=ft)
    res = drv.get_bgp_summary()
    assert isinstance(res, DriverResult)
    assert res.ok is True
    assert res.section == "bgp"
    assert res.vendor == "frr"
    assert res.normalized["established"] == 1
    assert res.elapsed_ms >= 0.0


def test_command_fallback_to_second_variant(fake_transport_factory):
    # First (json) variant fails, second (text) succeeds.
    text = ("Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd\n"
            "10.0.0.1 4 65001 10 10 0 0 0 01:00:00 5\n")
    ft = fake_transport_factory({
        "show ip bgp summary json": ("", False),
        "show ip bgp summary": (text, True),
    })
    drv = get_driver("frr", transport=ft)
    res = drv.get_bgp_summary()
    assert res.ok is True
    assert res.command == "show ip bgp summary"
    assert [c[1] for c in ft.calls] == ["show ip bgp summary json", "show ip bgp summary"]


def test_all_commands_fail_returns_unsuccessful(fake_transport_factory):
    ft = fake_transport_factory(default=("", False))
    drv = get_driver("frr", transport=ft)
    res = drv.get_ospf_neighbors()
    assert res.ok is False
    assert res.error
    assert res.normalized == {"neighbors": [], "full": 0, "total": 0}


def test_transport_exception_does_not_propagate(fake_transport_factory):
    class Boom:
        def exec(self, vendor, command):
            raise RuntimeError("docker down")
    drv = get_driver("frr", transport=Boom())
    res = drv.get_bgp_summary()
    assert res.ok is False  # never raised


def test_run_command_raw(fake_transport_factory):
    ft = fake_transport_factory({"show running-config": ("hostname r1", True)})
    drv = get_driver("arista-eos", transport=ft)
    res = drv.run_command("show running-config")
    assert res.ok is True
    assert res.raw == "hostname r1"
    assert res.normalized == {}
    assert res.section == "raw"


def test_get_interface_counters_uses_counter_section(fake_transport_factory):
    counters = json.dumps({"eth1": {"inputBytes": 5, "outputBytes": 6}})
    ft = fake_transport_factory({"show interface json": (counters, True)})
    drv = get_driver("frr", transport=ft)
    res = drv.get_interface_counters()
    assert res.ok is True
    assert res.section == "interface_counters"
    assert res.normalized["interfaces"][0]["interface"] == "eth1"


def test_get_health_shape(fake_transport_factory):
    ft = fake_transport_factory({
        "show version": ("FRRouting 9.1.0 compiled", True),
        "show ip bgp summary json": (FRR_BGP_JSON, True),
    }, default=("", False))
    drv = get_driver("frr", transport=ft, hostname="spine3", ip="127.0.0.1")
    health = drv.get_health()
    assert set(health) == {"meta", "version", "bgp", "ospf", "interfaces", "routes"}
    assert health["meta"]["hostname"] == "spine3"
    assert health["meta"]["dtype"] == "frr"
    assert health["bgp"]["established"] == 1
    assert isinstance(health["meta"]["errors"], list)
    # ospf/interfaces/routes failed cleanly -> empty shapes, not crashes
    assert health["ospf"] == {"neighbors": [], "full": 0, "total": 0}


# ───────────────────────── base is abstract ───────────────────────────────────

def test_base_cannot_instantiate(fake_transport_factory):
    with pytest.raises(TypeError):
        BaseNetworkDriver(fake_transport_factory())  # abstract _parse


# ───────────────────────── DockerExec argv translation ────────────────────────

def test_docker_argv_per_vendor():
    captured = {}

    def fake_runner(container, *cmd, timeout=15):
        captured["container"] = container
        captured["cmd"] = cmd
        return "ok-output"

    t_frr = DockerExecTransport("c1", runner=fake_runner)
    raw, ok, via = t_frr.exec("frr", "show ip bgp summary json")
    assert captured["cmd"] == ("vtysh", "-c", "show ip bgp summary json")
    assert ok is True and via == "docker-exec"

    t_eos = DockerExecTransport("c2", runner=fake_runner)
    t_eos.exec("arista-eos", "show ip bgp summary | json")
    assert captured["cmd"] == ("Cli", "-p", "15", "-c", "show ip bgp summary | json")

    t_srl = DockerExecTransport("c3", runner=fake_runner)
    t_srl.exec("nokia-srl", "show interface")
    assert captured["cmd"] == ("sr_cli", "-d", "show interface")


def test_docker_transport_swallows_errors():
    def boom(container, *cmd, timeout=15):
        raise RuntimeError("no docker")
    t = DockerExecTransport("c", runner=boom)
    raw, ok, via = t.exec("frr", "show version")
    assert raw == "" and ok is False


# ───────────────────────── SSHRunner adaptation ───────────────────────────────

def test_ssh_runner_transport_maps_result():
    def runner(ip, dtype, cmd, port=22):
        return {"success": True, "output": "hello"}
    t = SSHRunnerTransport(runner, ip="10.0.0.1", port=2201, dtype="frr")
    raw, ok, via = t.exec("frr", "show version")
    assert raw == "hello" and ok is True and via == "ssh"


def test_ssh_runner_transport_handles_no_port_kwarg():
    def runner(ip, dtype, cmd):  # no port kwarg
        return {"success": True, "output": "ok"}
    t = SSHRunnerTransport(runner, ip="10.0.0.1")
    raw, ok, _ = t.exec("frr", "show version")
    assert ok is True and raw == "ok"


def test_ssh_runner_failure_result():
    t = SSHRunnerTransport(lambda *a, **k: {"success": False, "output": ""},
                           ip="10.0.0.1")
    raw, ok, _ = t.exec("frr", "show version")
    assert ok is False


# ───────────────────────── Scrapli stub ───────────────────────────────────────

def test_scrapli_transport_raises_not_implemented():
    t = ScrapliTransport("10.0.0.1", platform="arista_eos")
    with pytest.raises(NotImplementedError):
        t.exec("arista-eos", "show version")
