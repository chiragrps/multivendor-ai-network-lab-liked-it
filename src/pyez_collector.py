"""
PyEZ Collector — Structured Junos statistics via NETCONF.

Provides 4 data collection functions:
  1. collect_port_stats()   — real-time per-port bps/pps + error counts
  2. collect_optics()       — SFP/optic diagnostics (rx/tx dBm, temp, voltage)
  3. collect_fpc_health()   — FPC/linecard state, CPU %, memory %
  4. collect_port_errors()  — detailed error counters (CRC, runts, drops, FIFO, etc.)

Plus a convenience wrapper collect_all() that gathers everything in one call.

Connection uses the same SSH credentials (netadmin key / PKCS#11) as the main app.
Falls back gracefully if NETCONF is not enabled on a device.
"""

import os
import time
import traceback
from jnpr.junos import Device
from jnpr.junos.exception import ConnectError, ConnectAuthError, ConnectTimeoutError, RpcError
from jnpr.junos.op.phyport import PhyPortStatsTable, PhyPortErrorTable, PhyPortTable
from jnpr.junos.op.intopticdiag import PhyPortDiagTable
from jnpr.junos.op.fpc import FpcInfoTable, FpcHwTable
from jnpr.junos.op.xcvr import XcvrTable
from jnpr.junos.op.systemstorage import SystemStorageTable


def _open_device(ip, ssh_mode, ssh_user, ssh_key_path, ssh_timeout=15,
                 pkcs11_pkey=None):
    """Open a PyEZ NETCONF connection using the same auth as the main app."""
    kwargs = dict(
        host=ip,
        user=ssh_user,
        port=22,
        timeout=ssh_timeout,
        auto_probe=0,          # don't probe — we know port 22 works
        gather_facts=True,
    )
    if ssh_mode == "pkcs11" and pkcs11_pkey is not None:
        # PyEZ doesn't natively support PKCS#11 PKeys, but we can pass
        # the paramiko pkey via the internal transport after open().
        # Workaround: use ssh_config=False and pass key object.
        # Actually, ncclient doesn't accept a PKey object directly.
        # Fall back to ssh-agent for PKCS#11 mode.
        kwargs["ssh_config"] = False
    else:
        kwargs["ssh_private_key_file"] = ssh_key_path

    dev = Device(**kwargs)
    dev.open()
    return dev


# ── 1. Port Statistics (real-time bps/pps) ──────────────────────────────────

def collect_port_stats(dev):
    """Collect per-port traffic stats: rx/tx bytes, bps, pps, basic errors."""
    results = []
    try:
        stats = PhyPortStatsTable(dev).get()
        for port in stats:
            results.append({
                "name": port.name,
                "rx_bytes": _int(port.rx_bytes),
                "rx_packets": _int(port.rx_packets),
                "rx_bps": _int(port.rx_bps),
                "rx_pps": _int(port.rx_pps),
                "tx_bytes": _int(port.tx_bytes),
                "tx_packets": _int(port.tx_packets),
                "tx_bps": _int(port.tx_bps),
                "tx_pps": _int(port.tx_pps),
                "rx_errors": _int(port.rx_err_input),
                "rx_drops": _int(port.rx_err_drops),
            })
    except RpcError as e:
        return {"error": f"RPC error: {e}", "data": []}
    except Exception as e:
        return {"error": f"Collection error: {e}", "data": []}
    return {"error": None, "data": results}


# ── 2. Optic Diagnostics ────────────────────────────────────────────────────

def collect_optics(dev):
    """Collect SFP/optic diagnostics: rx/tx power, temperature, voltage."""
    results = []
    try:
        optics = PhyPortDiagTable(dev).get()
        for port in optics:
            rx = port.rx_optic_power
            tx = port.tx_optic_power
            temp = port.module_temperature
            volts = port.module_voltage
            if rx is None and tx is None and temp is None:
                continue  # Skip ports with no optic data
            results.append({
                "name": port.name,
                "rx_power_dbm": _parse_dbm(rx),
                "tx_power_dbm": _parse_dbm(tx),
                "temperature_c": _parse_temp(temp),
                "voltage_v": _parse_voltage(volts),
                "rx_power_raw": str(rx) if rx else None,
                "tx_power_raw": str(tx) if tx else None,
                "temp_raw": str(temp) if temp else None,
                "status": _optic_status(rx, tx, temp),
            })
    except RpcError as e:
        return {"error": f"RPC error: {e}", "data": []}
    except Exception as e:
        return {"error": f"Collection error: {e}", "data": []}
    return {"error": None, "data": results}


# ── 3. FPC / Linecard Health ────────────────────────────────────────────────

def collect_fpc_health(dev):
    """Collect FPC/linecard status: state, CPU %, memory heap %."""
    results = []
    try:
        fpcs = FpcInfoTable(dev).get()
        for fpc in fpcs:
            state = str(fpc.state) if fpc.state else "Unknown"
            if state.lower() == "empty":
                continue  # Skip empty slots
            results.append({
                "slot": str(fpc.name),
                "state": state,
                "cpu_percent": _int(fpc.cpu),
                "memory_percent": _int(fpc.memory),
                "status": _fpc_status(state, fpc.cpu, fpc.memory),
            })
    except RpcError as e:
        return {"error": f"RPC error: {e}", "data": []}
    except Exception as e:
        return {"error": f"Collection error: {e}", "data": []}
    return {"error": None, "data": results}


# ── 4. Detailed Error Counters ──────────────────────────────────────────────

def collect_port_errors(dev):
    """Collect detailed per-port error counters (CRC, runts, drops, etc.)."""
    results = []
    try:
        errors = PhyPortErrorTable(dev).get()
        for port in errors:
            entry = {
                "name": port.name,
                "rx_bytes": _int(port.rx_bytes),
                "tx_bytes": _int(port.tx_bytes),
                "rx_errors": _int(port.rx_err_input),
                "rx_drops": _int(port.rx_err_drops),
                "rx_frame_errors": _int(port.rx_err_frame),
                "rx_runts": _int(port.rx_err_runts),
                "rx_discards": _int(getattr(port, "rx_err_discards", None)),
                "rx_l3_incompletes": _int(getattr(port, "rx_err_l3-incompletes", None)),
                "rx_l2_channel_errors": _int(getattr(port, "rx_err_l2-channel", None)),
                "rx_l2_mismatch": _int(getattr(port, "rx_err_l2-mismatch", None)),
                "rx_fifo_errors": _int(port.rx_err_fifo),
                "rx_resource_errors": _int(port.rx_err_resource),
                "tx_errors": _int(port.tx_err_output),
                "tx_drops": _int(port.tx_err_drops),
                "tx_collisions": _int(port.tx_err_collisions),
                "tx_carrier_transitions": _int(getattr(port, "tx_err_carrier-transitions", None)),
                "tx_mtu_errors": _int(port.tx_err_mtu),
                "tx_hs_crc_errors": _int(getattr(port, "tx_err_hs-crc", None)),
                "tx_fifo_errors": _int(port.tx_err_fifo),
                "tx_resource_errors": _int(port.tx_err_resource),
                "tx_aged_packets": _int(port.tx_err_aged),
            }
            total_errors = (entry["rx_errors"] + entry["rx_drops"] +
                           entry["tx_errors"] + entry["tx_drops"])
            entry["has_errors"] = total_errors > 0
            entry["total_errors"] = total_errors
            results.append(entry)
    except RpcError as e:
        return {"error": f"RPC error: {e}", "data": []}
    except Exception as e:
        return {"error": f"Collection error: {e}", "data": []}
    return {"error": None, "data": results}


# ── 5. System Storage ───────────────────────────────────────────────────────

def collect_storage(dev):
    """Collect filesystem usage (detect /var full, disk issues)."""
    results = []
    try:
        storage = SystemStorageTable(dev).get()
        for fs in storage:
            # SystemStorageTable has nested _FsTable; iterate filesystems
            fstable = fs.filesystems
            if fstable:
                for f in fstable:
                    used_pct = str(f.used_percent).replace("%", "").strip()
                    results.append({
                        "filesystem": f.name,
                        "total_blocks": str(f.total_blocks),
                        "used_blocks": str(f.used_blocks),
                        "available_blocks": str(f.available_blocks),
                        "used_percent": _int(used_pct),
                        "mounted_on": str(f.mounted_on),
                    })
    except RpcError as e:
        return {"error": f"RPC error: {e}", "data": []}
    except Exception as e:
        return {"error": f"Collection error: {e}", "data": []}
    return {"error": None, "data": results}


# ── Convenience: Collect All ────────────────────────────────────────────────

def collect_all(ip, ssh_mode="key", ssh_user="netadmin", ssh_key_path=None,
                ssh_timeout=15, pkcs11_pkey=None):
    """
    Open a NETCONF connection and collect all structured statistics.
    Returns a dict with device facts + all 5 data categories.
    Gracefully handles NETCONF not being available.
    """
    t0 = time.time()
    result = {
        "hostname": None,
        "model": None,
        "version": None,
        "serial": None,
        "uptime": None,
        "netconf_available": False,
        "collection_time_s": 0,
        "error": None,
        "port_stats": {"error": "Not collected", "data": []},
        "optics": {"error": "Not collected", "data": []},
        "fpc_health": {"error": "Not collected", "data": []},
        "port_errors": {"error": "Not collected", "data": []},
        "storage": {"error": "Not collected", "data": []},
    }

    try:
        dev = _open_device(ip, ssh_mode, ssh_user, ssh_key_path,
                          ssh_timeout, pkcs11_pkey)
    except (ConnectError, ConnectAuthError, ConnectTimeoutError) as e:
        result["error"] = f"NETCONF connection failed: {e}"
        result["collection_time_s"] = round(time.time() - t0, 2)
        return result
    except Exception as e:
        result["error"] = f"NETCONF error: {e}"
        result["collection_time_s"] = round(time.time() - t0, 2)
        return result

    try:
        result["netconf_available"] = True
        facts = dev.facts
        result["hostname"] = facts.get("hostname")
        result["model"] = facts.get("model")
        result["version"] = facts.get("version")
        result["serial"] = facts.get("serialnumber")
        re0 = facts.get("RE0", {})
        result["uptime"] = re0.get("up_time") if isinstance(re0, dict) else None

        # Collect all 5 categories
        result["port_stats"] = collect_port_stats(dev)
        result["optics"] = collect_optics(dev)
        result["fpc_health"] = collect_fpc_health(dev)
        result["port_errors"] = collect_port_errors(dev)
        result["storage"] = collect_storage(dev)

    except Exception as e:
        result["error"] = f"Collection error: {e}\n{traceback.format_exc()}"
    finally:
        try:
            dev.close()
        except Exception:
            pass

    result["collection_time_s"] = round(time.time() - t0, 2)
    return result


# ── Helper functions ────────────────────────────────────────────────────────

def _int(val):
    """Safely convert to int, return 0 for None/empty."""
    if val is None:
        return 0
    try:
        return int(val)
    except (ValueError, TypeError):
        return 0


def _parse_dbm(val):
    """Parse dBm value from PyEZ string like '-2.00 dBm'."""
    if val is None:
        return None
    s = str(val).strip()
    try:
        return float(s.split()[0])
    except (ValueError, IndexError):
        return None


def _parse_temp(val):
    """Parse temperature from PyEZ string like '47 degrees C / 117 degrees F'."""
    if val is None:
        return None
    s = str(val).strip()
    try:
        return float(s.split()[0])
    except (ValueError, IndexError):
        return None


def _parse_voltage(val):
    """Parse voltage from PyEZ string like '3.30 V'."""
    if val is None:
        return None
    s = str(val).strip()
    try:
        return float(s.split()[0])
    except (ValueError, IndexError):
        return None


def _optic_status(rx, tx, temp):
    """Determine optic health status based on power levels and temperature."""
    rx_dbm = _parse_dbm(rx)
    tx_dbm = _parse_dbm(tx)
    temp_c = _parse_temp(temp)

    warnings = []
    if rx_dbm is not None and rx_dbm < -25.0:
        warnings.append("rx_low")
    if rx_dbm is not None and rx_dbm < -30.0:
        return "critical"  # Very low rx — likely failing or disconnected
    if tx_dbm is not None and tx_dbm < -10.0:
        warnings.append("tx_low")
    if temp_c is not None and temp_c > 75.0:
        warnings.append("high_temp")
    if temp_c is not None and temp_c > 85.0:
        return "critical"

    if warnings:
        return "warning"
    return "ok"


def _fpc_status(state, cpu, memory):
    """Determine FPC health status."""
    if state.lower() not in ("online",):
        return "critical"
    cpu_val = _int(cpu)
    mem_val = _int(memory)
    if cpu_val > 90 or mem_val > 90:
        return "critical"
    if cpu_val > 75 or mem_val > 75:
        return "warning"
    return "ok"
