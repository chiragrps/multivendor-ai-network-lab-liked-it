#!/usr/bin/env python3
"""
DCN Network Tool - Backend API
Netmiko/NAPALM SSH tool for Enterprise Network infrastructure.
Supports Junos (SRX firewalls, EX/QFX switches, MX routers) and Arista EOS.

SECURITY NOTES (read these before using outside a lab):
  * Read-only by design — every SSH path that accepts user-supplied commands
    funnels through is_command_blocked(); CMD_BLOCKED_PREFIXES /
    CMD_BLOCKED_CONTAINS are the single source of truth for the blocklist.
    No `configure`, `set`, `delete`, `commit`, `rollback`, `request system`,
    `clear`, `restart`, `file copy/delete` etc. is ever forwarded.
  * SSH host-key + SSL verification are env-var gated (Phase-1 hardening):
        DCN_SSH_STRICT_HOST_KEY=true  →  paramiko.RejectPolicy()
        DCN_SSH_STRICT_HOST_KEY=false →  paramiko.AutoAddPolicy() (lab default)
        DCN_VERIFY_SSL=true           →  requests verify=True
        DCN_VERIFY_SSL=false          →  requests verify=False (lab default)
    Both default to permissive so a developer-laptop lab boot works out of
    the box (FRR containers rebuild with fresh host keys; LibreNMS/NetPortal
    reach private corporate URLs on internal CAs). Set both to true in any
    deployment beyond a laptop. Stderr emits a [WARNING] line on every boot
    when running in permissive mode so it shows up in service logs.
    Single source of truth: apply_ssh_policy() helper at line 208.
  * No secrets in this file. Anthropic key, NetBox token, LibreNMS tokens,
    YubiKey PIN, FRR lab password, CLI proxy password all load from env
    (.env via python-dotenv). CLI_PROXY_PASSWORD and FRR_DEFAULT_PASSWORD
    fail closed when unset; LibreNMS tokens default to empty (calls error
    out cleanly rather than authenticating with a placeholder).
  * Bounded in-memory state — _napalm_jobs, _PENDING_CHANGES, _pyez_cache,
    _PYATS_SNAPSHOTS use _bounded_insert() with FIFO eviction so a load test
    or fuzzer can't OOM the process. _OBSERVER_EVENTS and _GLOBAL_AGENT_LOG
    have inline cap logic with the same intent.
  * Single-worker deployment assumption — in-memory job/cache state lives in
    process locals. The Werkzeug dev server and `gunicorn -w 1` work as-is;
    multi-worker setups need a shared backing store (Redis, etc.) before any
    of the job-poll endpoints (`/api/napalm/jobs/*`, `/api/config-change/*`)
    are usable.
"""

import os
import urllib.parse
from dotenv import load_dotenv
load_dotenv()
import csv
import json
import math
import re
import shutil
import subprocess
import threading
import time
# Prefer defusedxml (safe against XXE / billion-laughs); fall back to stdlib
# so existing checkouts without the dependency don't break. The .drawio files
# we parse are operator-authored local files, but defusedxml is the right
# default for any ElementTree use.
try:
    import defusedxml.ElementTree as ET  # type: ignore[import-not-found]
except ImportError:
    import xml.etree.ElementTree as ET  # nosec: B405 — defusedxml preferred via requirements.txt
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import paramiko
import requests as _requests
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

app = Flask(__name__)
CORS(app)

# ── NAPALM Integration ────────────────────────────────────────────────────────
try:
    import napalm
    NAPALM_AVAILABLE = True
except ImportError:
    NAPALM_AVAILABLE = False

import ipaddress

NAPALM_SITES = {}  # Auto-populated from DEVICES inventory after load

_napalm_jobs = {}
_napalm_jobs_lock = threading.Lock()
_napalm_snapshots_dir = os.path.join(os.path.dirname(__file__), "..", "napalm_network", "output", "snapshots")
os.makedirs(_napalm_snapshots_dir, exist_ok=True)
_napalm_output_dir = os.path.join(os.path.dirname(__file__), "..", "napalm_network", "output")
os.makedirs(_napalm_output_dir, exist_ok=True)

# ── SSH Config ─────────────────────────────────────────────────────────────────
# SSH_MODE: "pkcs11" = YubiKey ECDSA via PyKCS11 + paramiko (default for local dev)
#           "key"    = service account key file via paramiko (export/Docker deployment)
SSH_MODE     = os.environ.get("DCN_SSH_MODE",    "pkcs11")
SSH_KEY_PATH = os.environ.get("DCN_SSH_KEY",     os.path.expanduser("~/Downloads/05_Networking/netlab_admin"))
SSH_USER     = os.environ.get("DCN_SSH_USER",    "netadmin1" if SSH_MODE == "pkcs11" else "netadmin")
SSH_TIMEOUT  = int(os.environ.get("DCN_SSH_TIMEOUT", "30"))
# FRR lab SSH — always key-based with lab_key, independent of production SSH mode.
# Resolve relative to src/ layout (../../../) OR flat layout (../../) OR env override.
_HERE = os.path.dirname(os.path.abspath(__file__))
_FRR_SSH_KEY = os.environ.get("DCN_FRR_SSH_KEY") or next(
    (p for p in (
        os.path.normpath(os.path.join(_HERE, "../../../network-lab/ssh-keys/lab_key")),
        os.path.normpath(os.path.join(_HERE, "../../network-lab/ssh-keys/lab_key")),
    ) if os.path.exists(p)),
    os.path.normpath(os.path.join(_HERE, "../../network-lab/ssh-keys/lab_key"))
)
_FRR_SSH_USER = "root"
# PKCS#11 config (YubiKey)
PKCS11_LIB   = os.environ.get("DCN_PKCS11_LIB",  "/usr/local/lib/libykcs11.dylib")
PKCS11_PIN   = os.environ.get("DCN_PKCS11_PIN",   "750100")

# ── PKCS#11 YubiKey key (singleton, initialised on first use) ─────────────────
_pkcs11_pkey = None   # PKCS11ECDSAKey instance
_pkcs11_session = None

def _pkcs11_init():
    """Initialise the PKCS#11 session and build a paramiko-compatible PKey.
    Uses PyKCS11 to sign SSH challenges on the YubiKey — same as SecureCRT.
    """
    global _pkcs11_pkey, _pkcs11_session
    if _pkcs11_pkey is not None:
        return _pkcs11_pkey
    import PyKCS11
    from PyKCS11 import CKA_CLASS, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKA_KEY_TYPE, CKA_EC_POINT, CKM_ECDSA, CKK_EC
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP256R1
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.backends import default_backend
    import hashlib as _hl

    lib = PyKCS11.PyKCS11Lib()
    lib.load(PKCS11_LIB)
    slots = lib.getSlotList(tokenPresent=True)
    if not slots:
        raise RuntimeError("No YubiKey PKCS#11 token found")
    _pkcs11_session = lib.openSession(slots[0], PyKCS11.CKF_SERIAL_SESSION)
    _pkcs11_session.login(PKCS11_PIN)

    # Extract EC public key
    ec_pubs = _pkcs11_session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_KEY_TYPE, CKK_EC)])
    if not ec_pubs:
        raise RuntimeError("No EC public key on YubiKey")
    ec_point_raw = bytes(_pkcs11_session.getAttributeValue(ec_pubs[0], [CKA_EC_POINT])[0])
    ec_point = ec_point_raw[2:] if len(ec_point_raw) == 67 else ec_point_raw
    x = int.from_bytes(ec_point[1:33], 'big')
    y = int.from_bytes(ec_point[33:65], 'big')
    crypto_pubkey = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key(default_backend())

    # Get private key handle (for signing — key never leaves the YubiKey)
    ec_privs = _pkcs11_session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_EC)])
    if not ec_privs:
        raise RuntimeError("No EC private key on YubiKey")
    privkey_handle = ec_privs[0]

    # Get ecdsa_curve from a dummy key (paramiko internal)
    _dummy = paramiko.ECDSAKey.generate(bits=256)
    _curve = _dummy.ecdsa_curve

    class PKCS11ECDSAKey(paramiko.PKey):
        """Paramiko PKey backed by YubiKey PKCS#11 ECDSA signing."""
        def __init__(self, pubkey, sess, priv, curve):
            super().__init__()
            self.verifying_key = pubkey
            self.public_blob = None
            self._sess = sess
            self._priv = priv
            self.ecdsa_curve = curve
        def asbytes(self):
            pt = self.verifying_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            m = paramiko.message.Message()
            m.add_string(self.ecdsa_curve.key_format_identifier)
            m.add_string(self.ecdsa_curve.nist_name)
            m.add_string(pt)
            return m.asbytes()
        def can_sign(self):
            return True
        def sign_ssh_data(self, data, algorithm=None):
            digest = _hl.sha256(data).digest()
            sig_raw = bytes(self._sess.sign(self._priv, digest, PyKCS11.Mechanism(CKM_ECDSA)))
            r = int.from_bytes(sig_raw[:32], 'big')
            s = int.from_bytes(sig_raw[32:], 'big')
            inner = paramiko.message.Message()
            inner.add_mpint(r)
            inner.add_mpint(s)
            m = paramiko.message.Message()
            m.add_string(self.ecdsa_curve.key_format_identifier)
            m.add_string(inner.asbytes())
            return m
        def get_name(self):
            return self.ecdsa_curve.key_format_identifier
        def get_bits(self):
            return 256

    _pkcs11_pkey = PKCS11ECDSAKey(crypto_pubkey, _pkcs11_session, privkey_handle, _curve)
    print(f"[SSH] PKCS#11 YubiKey ECDSA key loaded — {_pkcs11_pkey.get_name()}")
    return _pkcs11_pkey

if SSH_MODE == "pkcs11":
    try:
        _pkcs11_init()
    except Exception as _e:
        print(f"[SSH] PKCS#11 init failed: {_e} — falling back to key mode")
        SSH_MODE = "key"
        SSH_USER = "netadmin"

DCN_SSH_STRICT_HOST_KEY = os.environ.get("DCN_SSH_STRICT_HOST_KEY", "False").lower() == "true"
DCN_VERIFY_SSL = os.environ.get("DCN_VERIFY_SSL", "False").lower() == "true"
import sys
if not DCN_SSH_STRICT_HOST_KEY:
    print("[WARNING] DCN_SSH_STRICT_HOST_KEY is False. Using paramiko.AutoAddPolicy() - permissive mode.", file=sys.stderr)
if not DCN_VERIFY_SSL:
    print("[WARNING] DCN_VERIFY_SSL is False. SSL certificate validation is disabled for external calls.", file=sys.stderr)

def apply_ssh_policy(client):
    """Apply Strict or AutoAdd policy based on DCN_SSH_STRICT_HOST_KEY."""
    if DCN_SSH_STRICT_HOST_KEY:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507 - gated by DCN_SSH_STRICT_HOST_KEY

print(f"[SSH] mode={SSH_MODE}  user={SSH_USER}  pkcs11={'yes' if SSH_MODE=='pkcs11' else 'no'}")

def _ssh_connect(client, ip, port=22):
    """Connect a paramiko SSHClient using the configured SSH_MODE.
    pkcs11 mode: uses PKCS11ECDSAKey (YubiKey signs challenges natively).
    key mode:    service account private key file.
    Sets keepalive so the device drops idle sessions automatically.
    """
    if SSH_MODE == "pkcs11":
        pkey = _pkcs11_init()
        client.connect(ip, port=port, username=SSH_USER, pkey=pkey,
                       timeout=SSH_TIMEOUT, look_for_keys=False, allow_agent=False)
    else:
        client.connect(ip, port=port, username=SSH_USER, key_filename=SSH_KEY_PATH,
                       timeout=SSH_TIMEOUT, look_for_keys=False, allow_agent=False)
    # Keepalive: send probe every 15s; after 2 missed replies the transport dies.
    # This prevents stale sessions lingering on devices for days/months.
    transport = client.get_transport()
    if transport:
        transport.set_keepalive(15)

def _ssh_run_cmd(ip, command, port=22, timeout=None):
    """Run a single SSH command via paramiko exec_command.
    Works for both pkcs11 and key modes — uses _ssh_connect() internally.
    Always closes the connection in a finally block to prevent stale sessions.
    Returns (stdout_str, stderr_str, returncode).
    """
    _timeout = timeout or SSH_TIMEOUT + 10
    client = paramiko.SSHClient()
    apply_ssh_policy(client)
    try:
        _ssh_connect(client, ip, port=port)
        stdin, stdout, stderr = client.exec_command(command, timeout=_timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        rc = stdout.channel.recv_exit_status()
        return out, err, rc
    except Exception as e:
        return "", str(e), 1
    finally:
        try:
            client.close()
        except Exception:
            pass

def _ssh_run_commands(ip, commands_dict, port=22, dtype="junos"):
    """Run multiple SSH commands on a device. Returns {key: output_str}.
    commands_dict: {key: command_str} or list of (command_str, key) tuples.
    """
    results = {}
    if isinstance(commands_dict, list):
        items = commands_dict  # list of (cmd, key) tuples
    else:
        items = [(v, k) for k, v in commands_dict.items()]
    for cmd, key in items:
        stdout, stderr, rc = _ssh_run_cmd(ip, cmd, port=port)
        results[key] = stdout.strip() if rc == 0 else ""
    return results

# ── Local LLM — OpenAI-compatible API ────────────────────────────────────────
# Primary:  Ollama on :11434  (gemma4, qwen2.5-coder, llama3.2, …)
# Fallback: Docker Model Runner on :12434  (ai/qwen3)
# Override via env: MODEL_RUNNER_URL, LLM_MODEL, LLM_BACKEND
OLLAMA_URL        = os.environ.get("OLLAMA_URL",        "http://localhost:11434")
MODEL_RUNNER_URL  = os.environ.get("MODEL_RUNNER_URL",  "http://localhost:12434")
LLM_MODEL         = os.environ.get("LLM_MODEL",         "gemma4:latest")   # Ollama model
LLM_MODEL_RUNNER  = os.environ.get("LLM_MODEL_RUNNER",  "ai/qwen3:latest") # Docker Model Runner fallback
LLM_ENABLED       = os.environ.get("LLM_ENABLED",       "true").lower() == "true"
LLM_TIMEOUT       = int(os.environ.get("LLM_TIMEOUT",   "60"))
# Provider order: "local" = Ollama → ModelRunner → Claude (default, current behavior).
#                 "claude" = Claude first, local fallback.
#                 "claude-only" = Claude only (skip local). Recommended when ANTHROPIC_API_KEY is set.
LLM_PROVIDER      = os.environ.get("LLM_PROVIDER",      "local").lower()
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL   = "claude-haiku-4-5-20251001"

# ── Junos MCP Server (read-only sidecar) ─────────────────────────────────────
JMCP_URL         = os.environ.get("JMCP_URL",         "http://localhost:30030")
JMCP_ENABLED     = os.environ.get("JMCP_ENABLED",     "true").lower() == "true"

# ── Device Inventory ───────────────────────────────────────────────────────────
SECURECRT_CSV = os.environ.get("DCN_SECURECRT_CSV",
    os.path.expanduser("~/Downloads/03_Documents/Text/securecrt_sessions 2.csv"))

NETBOX_IP_CSV = os.environ.get("DCN_NETBOX_CSV",
    os.path.normpath(os.path.join(os.path.dirname(__file__),
        "../../05_Raw_Data/CSV_Reports/dcn_tool_full_inventory.csv")))

# Retired / decommissioned / old CyberNet-i3dnet sites — confirmed unreachable
_RETIRED_SITES = {
    "atl1", "cgn1", "fra2", "fra3", "fra20", "ion1", "jfk1", "lax1",
    "los1", "mia1", "mty1", "ord1", "pbh1", "sea1", "sjc1", "slc1",
    "stl1", "sxb1", "tll2",
}

def _site_from_hostname(hostname):
    m = re.match(r"([a-z]+\d+)", hostname.lower().split(".")[0])
    return m.group(1) if m else ""

def _normalize_hostname(h):
    """Strip VC member suffix (trailing a/b) for dedup: uk-lon-dist-01a -> uk-lon-dist-01"""
    base = h.lower().split(".")[0]
    # Strip trailing a/b only after a digit (VC member indicator)
    return re.sub(r"(\d)[ab]$", r"\1", base)

def load_devices():
    devices = []
    seen_hostnames = set()
    seen_ips = set()
    retired_skipped = 0

    # ── Primary source: SecureCRT CSV ─────────────────────────────────────
    try:
        with open(SECURECRT_CSV, newline='') as f:
            for row in csv.reader(f):
                if len(row) >= 3:
                    site, ip, hostname = row[0].strip(), row[1].strip(), row[2].strip()
                    if _site_from_hostname(hostname) in _RETIRED_SITES:
                        retired_skipped += 1
                        continue
                    dtype = detect_device_type(hostname)
                    port = int(row[3].strip()) if len(row) >= 4 and row[3].strip().isdigit() else 22
                    # 5th column: explicit type override (e.g. "frr" for lab devices)
                    if len(row) >= 5 and row[4].strip():
                        dtype = row[4].strip().lower()
                    devices.append({
                        "site": site,
                        "ip": ip,
                        "hostname": hostname,
                        "type": dtype,
                        "role": detect_role(hostname),
                        "port": port,
                    })
                    seen_hostnames.add(hostname.lower().split(".")[0])
                    seen_hostnames.add(_normalize_hostname(hostname))
                    seen_ips.add(ip)
    except Exception as e:
        print(f"Warning: Could not load SecureCRT CSV: {e}")

    # ── Secondary source: NetBox device inventory CSV ──────────────────────
    # Pre-processed from NetBox API: site,ip,hostname (includes VC b-members)
    # Fills gaps for devices/sites not in SecureCRT
    netbox_added = 0
    try:
        with open(NETBOX_IP_CSV, newline='') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 3:
                    continue
                site, ip, hostname = row[0].strip(), row[1].strip(), row[2].strip()
                if not ip or not hostname:
                    continue
                # Dedup: check exact hostname, normalized hostname, and IP
                hlow = hostname.lower().split(".")[0]
                if hlow in seen_hostnames:
                    continue
                if _normalize_hostname(hostname) in seen_hostnames:
                    continue
                if ip in seen_ips:
                    continue
                # Skip retired/decommissioned sites
                if _site_from_hostname(hostname) in _RETIRED_SITES:
                    retired_skipped += 1
                    continue
                if not site:
                    site_match = re.match(r"([a-z]+\d+)", hlow)
                    site = site_match.group(1).upper() if site_match else ""
                dtype = detect_device_type(hostname)
                devices.append({
                    "site": site,
                    "ip": ip,
                    "hostname": hostname,
                    "type": dtype,
                    "role": detect_role(hostname),
                    "port": 22,
                })
                seen_hostnames.add(hlow)
                seen_hostnames.add(_normalize_hostname(hostname))
                seen_ips.add(ip)
                netbox_added += 1
    except Exception as e:
        print(f"Warning: Could not load NetBox inventory CSV: {e}")

    if netbox_added:
        print(f"NetBox CSV: added {netbox_added} devices not in SecureCRT")
    if retired_skipped:
        print(f"Skipped {retired_skipped} devices from retired sites: {', '.join(sorted(_RETIRED_SITES))}")
    return devices

# Build EOS device set from actual config files on disk (ground truth)
_EOS_CONFIG_DIR = os.environ.get("DCN_EOS_CONFIG_DIR",
    os.path.normpath(os.path.join(os.path.dirname(__file__), "../../01_Device_Configurations/eos")))
_EOS_HOSTNAMES = set()
try:
    for f in os.listdir(_EOS_CONFIG_DIR):
        if f.endswith(".txt"):
            _EOS_HOSTNAMES.add(f[:-4].lower())
except Exception:
    pass
print(f"EOS devices loaded from config files: {len(_EOS_HOSTNAMES)}")

def detect_device_type(hostname):
    h = hostname.lower()
    # Strip trailing domain if present (e.g. .corp.internal)
    base = h.split(".")[0]
    # Ground truth: if config exists in eos/ directory, it's Arista EOS
    if base in _EOS_HOSTNAMES:
        return "eos"
    # Everything else is Junos (SRX, MX, EX, QFX)
    return "junos"

def detect_role(hostname):
    h = hostname.lower()
    if "-fw-" in h:   return "firewall"
    if "-rt-" in h:   return "router"
    if "-sw-" in h:   return "switch"
    return "unknown"

DEVICES = load_devices()

# ── FRR Docker Lab Devices (10 containers, always present) ───────────────────
_FRR_LAB_DEVICES = [
    {"site": "DE-FRA", "ip": "10.200.0.11", "hostname": "de-fra-core-01", "type": "frr", "role": "core", "port": 2201},
    {"site": "DE-FRA", "ip": "10.200.0.12", "hostname": "de-fra-core-02", "type": "frr", "role": "core", "port": 2202},
    {"site": "DE-FRA", "ip": "10.200.0.21", "hostname": "de-fra-edge-01", "type": "frr", "role": "edge", "port": 2205},
    {"site": "DE-FRA", "ip": "10.200.0.33", "hostname": "de-fra-dist-01", "type": "frr", "role": "dist", "port": 2210},
    {"site": "UK-LON", "ip": "10.200.0.13", "hostname": "uk-lon-core-01", "type": "frr", "role": "core", "port": 2203},
    {"site": "UK-LON", "ip": "10.200.0.22", "hostname": "uk-lon-edge-01", "type": "frr", "role": "edge", "port": 2208},
    {"site": "UK-LON", "ip": "10.200.0.31", "hostname": "uk-lon-dist-01", "type": "frr", "role": "dist", "port": 2206},
    {"site": "NL-AMS", "ip": "10.200.0.14", "hostname": "nl-ams-core-01", "type": "frr", "role": "core", "port": 2204},
    {"site": "NL-AMS", "ip": "10.200.0.23", "hostname": "nl-ams-edge-01", "type": "frr", "role": "edge", "port": 2209},
    {"site": "US-NYC", "ip": "10.200.0.15", "hostname": "us-nyc-core-01", "type": "frr", "role": "core", "port": 2207},
    # ── Containerlab Clos EVPN Fabric (clab-clos-evpn-*) ──────────────────
    {"site": "CLAB-DC1", "ip": "172.20.20.11", "hostname": "spine1", "type": "frr", "role": "spine", "port": 22, "vendor": "Nokia", "model": "SRL-IXR-D3L", "as_number": 65100, "fabric": "clos-evpn"},
    {"site": "CLAB-DC1", "ip": "172.20.20.12", "hostname": "spine2", "type": "frr", "role": "spine", "port": 22, "vendor": "Arista", "model": "cEOS-4.33.1F", "as_number": 65100, "fabric": "clos-evpn"},
    {"site": "CLAB-DC1", "ip": "172.20.20.13", "hostname": "spine3", "type": "frr", "role": "spine", "port": 22, "vendor": "FRR", "model": "FRR-v8.4", "as_number": 65100, "fabric": "clos-evpn"},
    {"site": "CLAB-DC1", "ip": "172.20.20.21", "hostname": "leaf1", "type": "frr", "role": "leaf", "port": 22, "vendor": "Arista", "model": "cEOS-4.33.1F", "as_number": 65001, "fabric": "clos-evpn"},
    {"site": "CLAB-DC1", "ip": "172.20.20.22", "hostname": "leaf2", "type": "frr", "role": "leaf", "port": 22, "vendor": "Nokia", "model": "SRL-IXR-D3L", "as_number": 65002, "fabric": "clos-evpn"},
    {"site": "CLAB-DC1", "ip": "172.20.20.23", "hostname": "leaf3", "type": "frr", "role": "leaf", "port": 22, "vendor": "FRR", "model": "FRR-v8.4", "as_number": 65003, "fabric": "clos-evpn"},
    {"site": "CLAB-DC1", "ip": "172.20.20.24", "hostname": "leaf4", "type": "frr", "role": "leaf", "port": 22, "vendor": "Arista", "model": "cEOS-4.33.1F", "as_number": 65004, "fabric": "clos-evpn"},
    {"site": "CLAB-DC1", "ip": "172.20.20.25", "hostname": "leaf5", "type": "frr", "role": "leaf", "port": 22, "vendor": "Nokia", "model": "SRL-IXR-D3L", "as_number": 65005, "fabric": "clos-evpn"},
    {"site": "CLAB-DC1", "ip": "172.20.20.26", "hostname": "leaf6", "type": "frr", "role": "leaf", "port": 22, "vendor": "FRR", "model": "FRR-v8.4", "as_number": 65006, "fabric": "clos-evpn"},
    # ── Containerlab Clos EVPN Hosts (test endpoints, no CLI) ─────────────
    {"site": "CLAB-DC1", "ip": "172.20.20.31", "hostname": "host1", "type": "linux", "role": "host", "port": 22, "vendor": "Linux", "model": "network-multitool", "vlan": 10, "rack": "rack-1", "fabric": "clos-evpn", "connected_leaf": "leaf1"},
    {"site": "CLAB-DC1", "ip": "172.20.20.32", "hostname": "host2", "type": "linux", "role": "host", "port": 22, "vendor": "Linux", "model": "network-multitool", "vlan": 10, "rack": "rack-1", "fabric": "clos-evpn", "connected_leaf": "leaf2"},
    {"site": "CLAB-DC1", "ip": "172.20.20.33", "hostname": "host3", "type": "linux", "role": "host", "port": 22, "vendor": "Linux", "model": "network-multitool", "vlan": 20, "rack": "rack-2", "fabric": "clos-evpn", "connected_leaf": "leaf3"},
    {"site": "CLAB-DC1", "ip": "172.20.20.34", "hostname": "host4", "type": "linux", "role": "host", "port": 22, "vendor": "Linux", "model": "network-multitool", "vlan": 20, "rack": "rack-2", "fabric": "clos-evpn", "connected_leaf": "leaf4"},
    {"site": "CLAB-DC1", "ip": "172.20.20.35", "hostname": "host5", "type": "linux", "role": "host", "port": 22, "vendor": "Linux", "model": "network-multitool", "vlan": 30, "rack": "rack-3", "fabric": "clos-evpn", "connected_leaf": "leaf5"},
    {"site": "CLAB-DC1", "ip": "172.20.20.36", "hostname": "host6", "type": "linux", "role": "host", "port": 22, "vendor": "Linux", "model": "network-multitool", "vlan": 30, "rack": "rack-3", "fabric": "clos-evpn", "connected_leaf": "leaf6"},
]
# Derive container names + normalized vendor for the clab fabric — health-all,
# AI command, and any other docker-exec aware endpoint discover clab nodes by
# the presence of d["container"].
_VENDOR_NORMAL = {
    "Nokia": "nokia-srl", "Arista": "arista-eos", "FRR": "frr", "Linux": "linux",
}
for _d in _FRR_LAB_DEVICES:
    if _d.get("fabric") == "clos-evpn":
        _d.setdefault("container", f"clab-clos-evpn-{_d['hostname']}")
        _norm = _VENDOR_NORMAL.get(_d.get("vendor", ""))
        if _norm:
            _d.setdefault("vendor_canonical", _norm)
            _d["vendor"] = _norm  # endpoints branch on lower-case canonical name
    elif _d.get("type") == "frr" and _d.get("hostname"):
        # DCN-lab FRR routers run as docker containers with the hostname as name.
        # Populating .container lets NAPALM use docker exec vtysh rather than
        # SSHing on port 2201+ (which the .frr fallback path doesn't use right).
        _d.setdefault("container", _d["hostname"])

# Prepend so FRR devices are matched first (production CSV may have collisions)
_lab_hostnames = {d["hostname"] for d in _FRR_LAB_DEVICES}
DEVICES = _FRR_LAB_DEVICES + [d for d in DEVICES if d["hostname"] not in _lab_hostnames]
print(f"Lab FRR devices: {len(_FRR_LAB_DEVICES)} prepended to inventory (total {len(DEVICES)})")

# O(1) device lookup indexes — populated once after DEVICES is finalized.
# Use case-insensitive hostname keys; IP keys are exact match.
_DEVICE_BY_HOSTNAME = {d["hostname"].lower(): d for d in DEVICES}
_DEVICE_BY_IP = {d["ip"]: d for d in DEVICES if d.get("ip")}

def get_device_by_hostname(hostname):
    """O(1) hostname → device dict lookup. Returns None if unknown."""
    if not hostname:
        return None
    return _DEVICE_BY_HOSTNAME.get(hostname.lower().split(".")[0])

def get_device_by_ip(ip):
    """O(1) IP → device dict lookup. Returns None if unknown."""
    return _DEVICE_BY_IP.get(ip) if ip else None


# ── Pre-compiled regex patterns used in hot parsing loops ───────────────────
# Compiling these once at module load avoids redundant work inside ARP, MAC,
# interface, and topology parsing routines that may iterate over thousands of
# lines per device collection pass.
_IPV4_RE       = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
_IPV4_ANY_RE   = re.compile(r"\d+\.\d+\.\d+\.\d+")
_MAC_COLON_RE  = re.compile(r"^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}", re.I)
_MAC_DOT_RE    = re.compile(r"^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$", re.I)
_JUNOS_PHYS_RE = re.compile(r"^(xe|et|ge|xle|fte)-")
# EOS / Arista interface names — used by port-capacity and MTU parsers
_EOS_IFACE_RE      = re.compile(r"^(Ethernet\S+|Et\S+|Vlan\S+|Port-Channel\S+)")
_EOS_IFACE_NAME_RE = re.compile(r"^(Ethernet\S+|Et\S+)\s*$")
_EOS_IFACE_MTU_RE  = re.compile(r"^(Ethernet\S+|Et\S+|Vlan\S+|Port-Channel\S+).*MTU\s+(\d+)", re.I)

# ── Auto-populate NAPALM_SITES from inventory ─────────────────────────────────
# Driver selection rules:
#   - .type == "eos"   → eos driver (paramiko SSH eAPI fallback)
#   - .type == "frr"   → frr driver (docker exec vtysh — see _frr_collect)
#   - .type == "linux" → SKIPPED (hosts have no network CLI)
#   - .vendor_canonical in {nokia-srl, arista-eos} on a clab fabric node
#                      → corresponding clab-* driver routed through docker exec
#   - default          → junos driver
# This is what makes NAPALM endpoints work against the FRR DCN lab + clab fabric.
# Previously every non-EOS device got driver=junos, so NAPALM SSH+NETCONF hung.
for _d in DEVICES:
    _site = _d["site"].lower()
    _host = _d["hostname"].split(".")[0]
    _t = _d.get("type", "")
    _vc = (_d.get("vendor_canonical") or _d.get("vendor") or "").lower()
    if _t == "linux":
        continue   # test hosts — no network CLI to collect from
    # IMPORTANT: clab inventory tags every node with type=frr as a shorthand
    # for "lab container". Vendor-specific drivers (SRL via sr_cli · cEOS
    # via Cli) must be checked FIRST — otherwise every clab node falls into
    # the vtysh-only branch and NAPALM returns empty data for SRL/cEOS.
    if _vc == "nokia-srl" and _d.get("container"):
        _driver = "clab-srl"
    elif _vc == "arista-eos" and _d.get("container"):
        _driver = "clab-eos"
    elif _t == "frr":
        _driver = "frr"
    elif _t == "eos":
        _driver = "eos"
    else:
        _driver = "junos"
    if _site not in NAPALM_SITES:
        NAPALM_SITES[_site] = {}
    NAPALM_SITES[_site][_host] = {
        "ip":        _d["ip"],
        "driver":    _driver,
        "container": _d.get("container"),  # populated for clab nodes
        "port":      _d.get("port", 22),
    }
print(f"NAPALM sites: {len(NAPALM_SITES)} sites, "
      f"{sum(len(v) for v in NAPALM_SITES.values())} devices")


def _resolve_napalm_site(data: dict):
    """Resolve a NAPALM site from the request body, accepting site/hostname/host/device.

    Returns (site, error_response). On success, error_response is None.
    On failure, returns (None, jsonify(...)) suitable to ``return`` directly.

    Why: every napalm endpoint used to demand a `site` and returned the opaque
    ``"Unknown site: "`` error if the caller sent `hostname` instead. Now we
    accept any common key shape and surface the actual accepted values when
    the lookup fails — so a 400 tells the user how to fix it.
    """
    site = (data.get("site") or "").lower().strip()
    if site and site in NAPALM_SITES:
        return site, None

    # Try to resolve from a hostname/device-style key
    candidate = (data.get("hostname") or data.get("host") or data.get("device") or "").strip()
    if candidate:
        host_lower = candidate.split(".")[0].lower()
        for s, devs in NAPALM_SITES.items():
            if host_lower in {h.lower() for h in devs.keys()}:
                return s, None

    return None, (jsonify({
        "error": f"Unknown site: {site!r}" if site else "site (or hostname/host/device) is required",
        "accepted_keys": ["site", "hostname", "host", "device"],
        "valid_sites": sorted(NAPALM_SITES.keys()),
        "got_keys": list(data.keys()),
    }), 400)

# ── Command Templates ──────────────────────────────────────────────────────────
COMMANDS = {
    "junos": {
        "arp":           "show arp",
        "route":         "show route summary",
        "route_table":   "show route",
        "bgp":           "show bgp summary",
        "bgp_detail":    "show bgp neighbor",
        "interfaces":    "show interfaces terse",
        "interfaces_detail": "show interfaces detail",
        "version":       "show version",
        "chassis":       "show chassis hardware",
        "logs":          "show log | no-more | last 100",
        "logs_error":    "show log | match \"error|Error|ERROR\" | no-more | last 50",
        "config_ifaces": "show configuration interfaces",
        "config_bgp":    "show configuration protocols bgp",
        "config_routing":"show configuration routing-options",
        "config_full":   "show configuration | display set",
        "lldp":          "show lldp neighbors",
        "spanning_tree": "show spanning-tree bridge",
        "lacp":          "show lacp interfaces",
        "vlans":         "show vlans",
        "mac_table":     "show ethernet-switching table",
        "isis":          "show isis adjacency",
        "ospf":          "show ospf neighbor",
        "mpls":          "show mpls lsp",
        "firewall":      "show firewall",
        "nat":           "show security nat source summary",
        "ike":           "show security ike sa",
        "ipsec":         "show security ipsec sa",
        "traffic":       "show interfaces | match \"Physical|bps|pps\"",
        "uptime":        "show system uptime",
        "alarms":        "show chassis alarms",
        "pfe":           "show pfe statistics traffic",
        "ports_up":      "show interfaces terse | match \"xe-|et-|ge-\" | except \"\\.\" | match up | count",
        "ports_all":     "show interfaces terse | match \"xe-|et-|ge-\" | except \"\\.\"",
        "ports_count":   "show interfaces terse | match \"xe-|et-|ge-\" | except \"\\.\" | count",
        "ports_hw":      "show chassis hardware | match \"XE|ET|GE|SFP|QSFP\"",
        "ports_errors":  "show interfaces | match \"Physical|error|drop\" | except \"0 errors|0 drops\"",
        "isp_ifaces":    "show interfaces descriptions | match isp",
        "isp_optics":    "show interfaces diagnostics optics",
        "mtu":           "show interfaces | match \"Physical|MTU|mtu\"",
    },
    "eos": {
        "arp":           "show arp",
        "route":         "show ip route summary",
        "route_table":   "show ip route",
        "bgp":           "show bgp summary",
        "bgp_detail":    "show bgp neighbors | head 100",
        "interfaces":    "show interfaces status",
        "interfaces_detail": "show interfaces",
        "version":       "show version",
        "logs":          "show logging last 100",
        "logs_error":    "show logging | grep -i error | tail -50",
        "config_ifaces": "show running-config section interface",
        "config_bgp":    "show running-config section router bgp",
        "config_routing":"show running-config section ip route",
        "config_full":   "show running-config",
        "lldp":          "show lldp neighbors",
        "spanning_tree": "show spanning-tree",
        "lacp":          "show lacp neighbor",
        "vlans":         "show vlan",
        "mac_table":     "show mac address-table",
        "isis":          "show isis neighbors",
        "ospf":          "show ip ospf neighbor",
        "traffic":       "show interfaces counters rates",
        "uptime":        "show version | grep uptime",
        "alarms":        "show system environment",
        "mlag":          "show mlag",
        "tcam":          "show platform trident tcam",
        "cpu":           "show processes top",
        "ports_up":      "show interfaces status | grep connected | grep -E 'Et|Ma' | wc -l",
        "ports_all":     "show interfaces status | grep -E '^Et'",
        "ports_count":   "show interfaces status | grep -E '^Et' | wc -l",
        "ports_hw":      "show inventory | grep -E 'SFP|QSFP|XCVR|Port'",
        "ports_capacity": "show interfaces status",
        "ports_errors":  "show interfaces counters errors | grep -v ' 0 ' | head 40",
        "dom":           "show interfaces transceiver",
        "isp_ifaces":    "show interfaces description | grep -i isp",
        "isp_optics":    "show interfaces transceiver",
        "mtu":           "show interfaces | grep -E 'Ethernet|Vlan|Port-Channel|Loopback' | grep -i mtu",
    },
    # FRR (vtysh) — lab containers. run_command_on_device() wraps these in
    # `vtysh -c '<cmd>'` when dtype == "frr"; keep strings bare here.
    "frr": {
        "version":          "show version",
        "uptime":           "show version",
        "interfaces":       "show interface brief",
        "interfaces_detail":"show interface",
        "arp":              "show ip arp",
        "route":            "show ip route summary",
        "route_table":      "show ip route",
        "bgp":              "show ip bgp summary",
        "bgp_detail":       "show ip bgp neighbors",
        "ospf":             "show ip ospf neighbor",
        "ospf_database":    "show ip ospf database",
        "isis":             "show isis neighbor",
        "lldp":             "show lldp neighbors",
        "logs":             "show logging",
        "alarms":           "show logging | include -i error",
        "config_full":      "show running-config",
        "config_bgp":       "show running-config bgpd",
        "config_routing":   "show running-config zebra",
        "mtu":              "show interface | include MTU",
        "memory":           "show memory summary",
        "cpu":              "show processes cpu",
    },
}

# ── Read-only safety: single source of truth for blocked write commands ─────
# Used by every endpoint that proxies user-supplied commands to a device.
CMD_BLOCKED_PREFIXES = (
    "configure", "edit", "set ", "delete ", "deactivate ", "activate ",
    "rollback", "commit", "load ", "save ",
    "request system reboot", "request system halt", "request system zeroize",
    "request system power", "request system software",
    "clear ", "restart ", "file delete", "file copy",
)
CMD_BLOCKED_CONTAINS = ("| save", "cli -c")

def is_command_blocked(cmd: str) -> bool:
    """Return True if `cmd` is a write/destructive command that must not run."""
    if not cmd:
        return False
    c = cmd.strip().lower()
    return (any(c.startswith(p) for p in CMD_BLOCKED_PREFIXES) or
            any(s in c for s in CMD_BLOCKED_CONTAINS))


def _bounded_insert(d: dict, key, value, max_size: int) -> None:
    """Insert into d with FIFO eviction once len(d) exceeds max_size.

    Relies on Python 3.7+ dict insertion-order guarantee. Updating an
    existing key refreshes its position via re-insertion so frequently-
    touched entries aren't first to evict. Used for in-memory job/cache
    state to bound memory under load tests or fuzzing.
    """
    if key in d:
        del d[key]
    d[key] = value
    while len(d) > max_size:
        try:
            d.pop(next(iter(d)), None)
        except StopIteration:
            break


def get_device_type_netmiko(dtype):
    return "juniper_junos" if dtype == "junos" else "arista_eos"

def ssh_connect(ip, dtype):
    conn_params = {
        "device_type":      get_device_type_netmiko(dtype),
        "host":             ip,
        "username":         SSH_USER,
        "use_keys":         True,
        "timeout":          SSH_TIMEOUT,
        "auth_timeout":     SSH_TIMEOUT,
        "banner_timeout":   SSH_TIMEOUT,
        "conn_timeout":     SSH_TIMEOUT,
        "fast_cli":         False,
        "global_cmd_verify": False,   # don't verify echoed command — avoids Width set to mismatches
        "session_log":      None,
    }
    if SSH_MODE == "pkcs11":
        conn_params["pkey"] = _pkcs11_init()
        conn_params["use_keys"] = False
        conn_params["allow_agent"] = False
    else:
        conn_params["key_file"] = SSH_KEY_PATH
        conn_params["allow_auto_change"] = False
    # For EOS: Netmiko's session_preparation sends 'terminal width 511' and expects
    # 'Width set to' pattern — some EOS devices/versions don't return that, causing
    # a ReadException. We skip Netmiko's session_preparation entirely and do it ourselves.
    if dtype == "eos":
        conn_params["device_type"] = "arista_eos"
        # Monkey-patch session_preparation on the class to avoid terminal width issue
        from netmiko.arista.arista import AristaSSH
        _orig_prep = AristaSSH.session_preparation
        def _safe_session_preparation(self):
            self.ansi_escape_codes = True
            self._test_channel_read(pattern=self.prompt_pattern)
            # Skip set_terminal_width — we do it ourselves below via write_channel
            try:
                self.disable_paging(cmd_verify=False, pattern=r"Pagination disabled")
            except Exception:
                pass
            self.set_base_prompt()
        AristaSSH.session_preparation = _safe_session_preparation
        try:
            conn = ConnectHandler(**conn_params)
        finally:
            AristaSSH.session_preparation = _orig_prep   # restore original
        # Do terminal setup ourselves — raw write avoids pattern matching
        conn.write_channel("terminal length 0\n")
        time.sleep(0.5)
        conn.read_channel()
        conn.write_channel("terminal width 32767\n")
        time.sleep(0.5)
        conn.read_channel()
    else:
        conn = ConnectHandler(**conn_params)
    return conn

# Commands known to produce large output — need higher read_timeout
_HEAVY_CMDS = (
    "ping ", "ping6 ", "traceroute ",
    "show bgp neighbor", "show route", "show running-config",
    "show configuration | display set", "show configuration interfaces",
    "show logging", "show log messages", "show log |", "show log\n", "show interfaces detail",
    "show ip route", "show bgp ipv",
    "show interfaces terse", "show interfaces status",
    "show chassis hardware", "show inventory", "show interfaces transceiver",
    "show interfaces counters",
)

def _read_timeout(command):
    """Return appropriate read_timeout for a command."""
    cmd = command.strip().lower()
    if any(h in cmd for h in _HEAVY_CMDS):
        return 120
    return 60

# expect_string patterns for long-running commands — matched against end-of-output
# so send_command knows when to stop reading without timing out on prompt detection
_EXPECT = {
    # Junos
    "junos": {
        "monitor traffic": r"--",          # Ctrl-C termination string
        "bash ":       r"\$",
    },
    # Arista EOS
    "eos": {
        "bash ":       r"\$",
    },
}

def _get_expect(command, dtype):
    """Return expect_string for long-running commands, or None for normal ones."""
    cmd = command.strip().lower()
    patterns = _EXPECT.get(dtype, {})
    for prefix, pattern in patterns.items():
        if cmd.startswith(prefix):
            return pattern
    return None

def _flush(conn):
    """Flush any buffered data (e.g. 'Width set to' messages) from the channel."""
    try:
        conn.read_channel()
    except Exception:
        pass

def _clean_prompt(raw_prompt):
    """Extract just the last line of the prompt (handles chassis cluster prefix like '(primary:node0)')."""
    if not raw_prompt:
        return None
    last = raw_prompt.strip().splitlines()[-1].strip()
    return re.escape(last) if last else None

def _clab_exec_for_command(ip: str, command: str) -> dict | None:
    """If ``ip`` belongs to a clab fabric node (has a ``container`` field in
    inventory), run ``command`` via ``docker exec`` and return the result dict.
    Returns ``None`` if the IP isn't a clab node — caller falls through to SSH.
    """
    # _DEVICE_BY_IP is populated after DEVICES is finalized.
    dev = _DEVICE_BY_IP.get(ip) if "_DEVICE_BY_IP" in globals() else None
    if not dev or not dev.get("container") or not shutil.which("docker"):
        return None

    container = dev["container"]
    # DCN FRR lab routers don't have a vendor tag — use type as the fallback.
    # Without this, the shim returns "unsupported vendor ''" and the Nornir
    # worker fails for every de-fra-* / uk-lon-* / nl-ams-* / us-nyc-* host.
    vendor = (dev.get("vendor") or dev.get("type") or "").lower()
    cmd_lower = command.lower().strip()

    if vendor in ("frr",):
        argv = ["docker", "exec", container, "vtysh", "-c", command]
    elif vendor in ("arista-eos", "arista", "eos"):
        # Arista accepts the command verbatim; "show ip bgp summary" works as-is.
        argv = ["docker", "exec", container, "Cli", "-p", "15", "-c", command]
    elif vendor in ("nokia-srl", "nokia", "srl"):
        # SR Linux doesn't grok "show ip bgp" — translate the common verbs.
        srl_cmd = command
        if "bgp" in cmd_lower:
            srl_cmd = "show network-instance default protocols bgp neighbor"
        elif "ospf" in cmd_lower:
            srl_cmd = "show network-instance default protocols ospf neighbor"
        elif "interface" in cmd_lower or "intf" in cmd_lower:
            srl_cmd = "show interface"
        argv = ["docker", "exec", container, "sr_cli", "-d", srl_cmd]
    elif vendor in ("linux",):
        argv = ["docker", "exec", container, "sh", "-c", command]
    else:
        return {"success": False, "output": "", "error": f"unsupported vendor {vendor!r}", "command": command}

    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return {"success": False, "output": "", "error": "docker exec timed out", "command": command}
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "output": "", "error": f"docker exec failed: {exc}", "command": command}
    if proc.returncode != 0:
        return {"success": False, "output": proc.stdout, "error": (proc.stderr or "").strip()[:300], "command": command}
    return {"success": True, "output": proc.stdout.strip(), "command": command, "via": "docker-exec", "vendor": vendor, "container": container}


def run_command_on_device(ip, dtype, command, port=22):
    """Execute a single command on a device via paramiko interactive shell.
    Works for both pkcs11 (YubiKey) and key (netadmin) modes.
    FRR devices use exec_command + vtysh -c instead of an interactive shell.
    Containerlab fabric nodes (any vendor) are dispatched through docker exec.
    """
    # clab fabric short-circuit — no SSH needed.
    clab = _clab_exec_for_command(ip, command)
    if clab is not None:
        return clab

    client = paramiko.SSHClient()
    apply_ssh_policy(client)
    try:
        # FRR lab devices: use lab_key/root + localhost port mapping (not internal Docker IP)
        if dtype == "frr":
            import shlex
            # Docker containers are port-mapped to localhost; internal IPs (10.200.x.x) unreachable from host
            frr_host = "127.0.0.1"
            client.connect(frr_host, port=port, username=_FRR_SSH_USER,
                           key_filename=_FRR_SSH_KEY, timeout=10,
                           look_for_keys=False, allow_agent=False)
            vtysh_cmd = f"vtysh -c {shlex.quote(command)}"
            _, stdout, stderr = client.exec_command(vtysh_cmd, timeout=10)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            client.close()
            output = (out or err).strip()
            return {"success": True, "output": output, "command": command}

        # Non-FRR devices: connect with production credentials then open interactive shell
        _ssh_connect(client, ip, port=port)
        shell = client.invoke_shell(width=300, height=1000)
        shell.settimeout(SSH_TIMEOUT)
        # Fully drain banner/prompt — keep reading until channel is silent
        banner = ""
        for _ in range(20):
            time.sleep(0.3)
            if shell.recv_ready():
                banner += shell.recv(65535).decode("utf-8", errors="replace")
            else:
                # One more check after a pause
                time.sleep(0.5)
                if shell.recv_ready():
                    banner += shell.recv(65535).decode("utf-8", errors="replace")
                else:
                    break
        # Disable paging for EOS
        if dtype == "eos":
            shell.sendall(b"terminal length 0\n")
            time.sleep(0.5)
            while shell.recv_ready():
                shell.recv(65535)
            shell.sendall(b"terminal width 32767\n")
            time.sleep(0.5)
            while shell.recv_ready():
                shell.recv(65535)
        # Junos: disable CLI auto-complete to prevent space-triggered completion
        if dtype == "junos":
            shell.sendall(b"set cli complete-on-space off\n")
            time.sleep(0.5)
            while shell.recv_ready():
                shell.recv(65535)
        # Send the actual command as one atomic write
        shell.sendall((command + "\n").encode("utf-8"))
        # Collect output until idle
        timeout = _read_timeout(command)
        output = ""
        idle_count = 0
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(0.5)
            if shell.recv_ready():
                chunk = shell.recv(65535).decode("utf-8", errors="replace")
                output += chunk
                idle_count = 0
            else:
                idle_count += 1
                if idle_count >= 4:  # 2 seconds of no data = done
                    break
        shell.close()
        # Clean up output
        lines = output.splitlines()
        # Remove echoed command line and any "complete-on-space" echo
        cleaned = []
        cmd_found = False
        for line in lines:
            if not cmd_found and command.strip() in line:
                cmd_found = True
                continue
            if cmd_found:
                cleaned.append(line)
        if not cleaned:
            cleaned = lines  # fallback: return everything
        # Remove trailing prompt lines
        while cleaned:
            last = cleaned[-1].strip()
            if not last:
                cleaned.pop(); continue
            if last.startswith("{primary") or last.startswith("{secondary"):
                cleaned.pop(); continue
            if re.match(r'^[\w.-]+@[\w.-]+[>#]\s*$', last):
                cleaned.pop(); continue
            break
        output = "\n".join(cleaned).strip()
        return {"success": True, "output": output, "command": command}
    except Exception as e:
        return {"success": False, "error": str(e), "command": command}
    finally:
        try:
            client.close()
        except Exception:
            pass

def run_commands_on_device(ip, dtype, commands):
    """Execute multiple commands on a device via Netmiko.
    Works for both pkcs11 (YubiKey) and key (netadmin) modes.
    """
    conn = None
    try:
        conn = ssh_connect(ip, dtype)
        _flush(conn)
        # Capture the real prompt once — use it as expect_string for every command
        # so Netmiko never misidentifies ARP/route output as a prompt
        try:
            prompt = _clean_prompt(conn.find_prompt())
        except Exception:
            prompt = None
        results = {}
        for cmd_key, cmd in commands.items():
            try:
                _flush(conn)
                special_expect = _get_expect(cmd, dtype)
                if special_expect:
                    results[cmd_key] = conn.send_command(
                        cmd, expect_string=special_expect, read_timeout=90,
                        strip_prompt=True, strip_command=True, cmd_verify=False)
                elif prompt:
                    results[cmd_key] = conn.send_command(
                        cmd, expect_string=prompt,
                        read_timeout=_read_timeout(cmd),
                        strip_prompt=True, strip_command=True, cmd_verify=False)
                else:
                    results[cmd_key] = conn.send_command(
                        cmd, read_timeout=_read_timeout(cmd), cmd_verify=False)
            except Exception as e:
                results[cmd_key] = f"ERROR: {e}"
        return {"success": True, "results": results}
    except NetmikoTimeoutException:
        return {"success": False, "error": f"Connection timeout to {ip}"}
    except NetmikoAuthenticationException:
        return {"success": False, "error": f"Authentication failed for {ip}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        try:
            if conn:
                conn.disconnect()
        except Exception:
            pass

# ── Static File Serving ────────────────────────────────────────────────────────
_STATIC_DIR = os.path.dirname(os.path.abspath(__file__))
_DEMO_DIR   = os.path.normpath(os.path.join(_STATIC_DIR, "../../demo"))

@app.route("/")
def serve_index():
    return send_from_directory(_STATIC_DIR, "index.html")

@app.route("/demo/")
@app.route("/demo/index.html")
def serve_demo_index():
    return send_from_directory(_DEMO_DIR, "index.html")

@app.route("/demo/<path:filename>")
def serve_demo(filename):
    return send_from_directory(_DEMO_DIR, filename)

@app.route("/<path:filename>")
def serve_static(filename):
    return send_from_directory(_STATIC_DIR, filename)

# ── API Routes ─────────────────────────────────────────────────────────────────

@app.route("/api/devices", methods=["GET"])
def get_devices():
    """Return all devices, optionally filtered by site."""
    site = request.args.get("site", "").upper()
    search = request.args.get("search", "").lower()
    role = request.args.get("role", "")

    result = DEVICES
    if site:
        result = [d for d in result if d["site"] == site]
    if search:
        result = [d for d in result if search in d["hostname"].lower() or search in d["ip"]]
    if role:
        result = [d for d in result if d["role"] == role]
    return jsonify(result)

@app.route("/api/sites", methods=["GET"])
def get_sites():
    """Return all unique sites."""
    sites = sorted(set(d["site"] for d in DEVICES))
    return jsonify(sites)

@app.route("/api/commands/<dtype>", methods=["GET"])
def get_commands(dtype):
    """Return available commands for a device type."""
    cmds = COMMANDS.get(dtype, COMMANDS["junos"])
    return jsonify(cmds)


@app.route("/api/health/<hostname>", methods=["GET"])
def get_device_health(hostname):
    """Single-device operational snapshot — version, BGP, OSPF, interfaces, routes, mem, CPU.

    Runs a parallel fan-out of vendor-specific show commands (typically <2s on the lab)
    and returns one normalized JSON document. See src/health.py for the schema.

    Inspired by scottpeterman/what_a_NOS_could_be — no agents, no SNMP, just show commands.
    """
    dev = get_device_by_hostname(hostname)
    if not dev:
        return jsonify({"success": False, "error": f"Unknown hostname: {hostname}"}), 404

    from health import collect_health  # local import — keeps cold-start cheap

    snapshot = collect_health(
        hostname=dev["hostname"],
        ip=dev.get("ip") or "127.0.0.1",
        dtype=dev.get("type", "frr"),
        port=int(dev.get("port") or 22),
        runner=run_command_on_device,
    )
    return jsonify(snapshot)

@app.route("/api/run", methods=["POST"])
def run_command():
    """
    Run a named command or raw command on a device.
    Body: { "ip": "10.1.9.1", "dtype": "junos", "cmd_key": "arp" }
       or { "ip": "10.1.9.1", "dtype": "junos", "raw": "show version" }
       or { "hostname": "de-fra-core-01", "raw": "show bgp summary" }
    Optional: "port": 2201  — override SSH port (auto-detected from inventory)
    """
    data = request.json
    hostname = data.get("hostname", "")
    ip    = data.get("ip")
    dtype = data.get("dtype", "junos")
    raw   = data.get("raw")
    cmd_key = data.get("cmd_key")

    # Resolve hostname → ip + port + dtype from loaded inventory.
    # Fall back to IP lookup so clients that send {ip, dtype, cmd_key} (no hostname)
    # still pick up the inventory's port mapping — critical for FRR lab containers
    # where port 22 is mapped to localhost:220x and the bare default would fail.
    port = int(data.get("port") or 0)
    dev = get_device_by_hostname(hostname) if hostname else None
    if not dev and ip:
        dev = get_device_by_ip(ip)
    if dev:
        ip    = ip or dev["ip"]
        port  = port or int(dev.get("port") or 22)
        dtype = data.get("dtype") or dev.get("type", "junos")
    elif hostname:
        return jsonify({"success": False, "error": f"Unknown hostname: {hostname}"}), 400
    if not port:
        port = 22

    if not ip:
        return jsonify({"success": False, "error": "Missing ip"}), 400

    # Safety: block write/destructive commands (read-only mode)
    if raw:
        if is_command_blocked(raw):
            return jsonify({"success": False, "error": "BLOCKED: write/destructive commands not allowed (read-only mode)"}), 403
        command = raw
    elif cmd_key:
        command = COMMANDS.get(dtype, {}).get(cmd_key)
        if not command:
            return jsonify({"success": False, "error": f"Unknown command key: {cmd_key}"}), 400
    else:
        return jsonify({"success": False, "error": "Provide cmd_key or raw"}), 400

    result = run_command_on_device(ip, dtype, command, port=port)
    result["timestamp"] = datetime.now().isoformat()
    return jsonify(result)

@app.route("/api/session-audit", methods=["POST"])
def session_audit():
    """Audit SSH sessions on a device or site. Returns active sessions with idle time.
    Body: { "ip": "10.1.15.101", "dtype": "junos" }
      or: { "site": "UK-LON" }
    Optional: "kill_stale": true  — logout our own sessions idle > threshold (default 60 min).
              "idle_threshold_min": 60  — minutes of idle before considering stale.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    data = request.json or {}
    ip = data.get("ip")
    dtype = data.get("dtype", "junos")
    site = data.get("site", "").upper()
    kill_stale = data.get("kill_stale", False)
    idle_threshold_min = int(data.get("idle_threshold_min", 60))

    def _parse_idle(idle_str):
        """Parse idle time string to minutes.
        Junos IDLE examples: '-' (active), '19days', '79days', '3:15', '45', '2d3h'.
        Ignore anything with AM/PM (that's LOGIN@ not IDLE).
        """
        idle_str = idle_str.strip().lower()
        if not idle_str or idle_str == "-":
            return 0
        # Skip login timestamps like '2:34pm', '11:43am'
        if "am" in idle_str or "pm" in idle_str:
            return 0
        if "day" in idle_str:
            m = re.search(r"(\d+)", idle_str)
            return int(m.group(1)) * 1440 if m else 0
        if "d" in idle_str and "h" in idle_str:
            m = re.match(r"(\d+)d(\d+)h", idle_str)
            return (int(m.group(1)) * 1440 + int(m.group(2)) * 60) if m else 0
        if ":" in idle_str:
            parts = idle_str.split(":")
            try:
                return int(parts[0]) * 60 + int(parts[1])
            except (ValueError, IndexError):
                return 0
        try:
            return int(idle_str)
        except ValueError:
            return 0

    def _audit_device(dev_ip, dev_dtype, dev_hostname=""):
        """Run show system users on a single device, parse output, optionally kill stale."""
        cmd = "show system users | no-more" if dev_dtype == "junos" else "show users"
        stdout, stderr, rc = _ssh_run_cmd(dev_ip, cmd)
        sessions = []
        killed = []
        if not stdout:
            return {"hostname": dev_hostname, "ip": dev_ip, "sessions": [], "killed": [], "error": stderr or "No output"}
        # Junos output format (fixed-width columns):
        #  USER     TTY      FROM              LOGIN@  IDLE WHAT
        #  netadmin1 p0      192.168.144.138      2:34PM   -   -cli (cli)
        #  netadmin6 p1     192.168.144.2        17Feb26 19days -
        lines = stdout.splitlines()
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("USER") or "load average" in stripped.lower():
                continue
            if stripped.startswith("fpc") or stripped.startswith("{") or re.match(r'^\d+:\d+\w+\s+up\s', stripped):
                continue
            parts = stripped.split()
            if len(parts) < 4:
                continue
            user = parts[0]
            tty = parts[1]
            # Find IDLE: scan from the right — IDLE is the field before WHAT (which is the last field(s))
            # In Junos: fields are USER TTY FROM LOGIN@ IDLE WHAT
            # IDLE is typically parts[4] if FROM is present, but sometimes FROM is missing
            # Strategy: try each token from index 3 onward; the IDLE field matches day/time patterns
            idle_str = "-"
            for idx in range(3, min(len(parts), 6)):
                p = parts[idx]
                p_lower = p.lower()
                # Skip IP addresses and login timestamps
                if _IPV4_RE.match(p):
                    continue
                if "am" in p_lower or "pm" in p_lower:
                    continue
                if re.match(r'^\d{1,2}\w{3}\d{2}$', p):  # date like 17Feb26
                    continue
                # Match idle patterns: '-', 'Ndays', 'H:MM', digits
                if p == "-" or "day" in p_lower or re.match(r'^\d+:\d+$', p) or re.match(r'^\d+$', p):
                    idle_str = p
                    break
            idle_min = _parse_idle(idle_str)
            sessions.append({
                "user": user, "tty": tty, "idle_str": idle_str,
                "idle_minutes": idle_min, "stale": idle_min >= idle_threshold_min,
                "raw": stripped
            })
        # Kill stale sessions — ONLY our own user, and only if explicitly requested
        if kill_stale and dev_dtype == "junos":
            for s in sessions:
                if s["stale"] and s["user"] == SSH_USER:
                    kill_cmd = f"request system logout terminal {s['tty']} | no-more"
                    _ssh_run_cmd(dev_ip, kill_cmd)
                    killed.append(s)
        return {"hostname": dev_hostname, "ip": dev_ip, "sessions": sessions, "killed": killed, "error": None}

    # Single device mode
    if ip:
        result = _audit_device(ip, dtype, ip)
        return jsonify(result)

    # Site mode — audit all devices in parallel
    if site:
        site_devs = [d for d in DEVICES if d["site"] == site]
        if not site_devs:
            return jsonify({"error": f"No devices found for site {site}"}), 404
        results = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = {ex.submit(_audit_device, d["ip"], d.get("dtype", "junos"), d["hostname"]): d for d in site_devs}
            for fut in as_completed(futs):
                try:
                    results.append(fut.result())
                except Exception as e:
                    d = futs[fut]
                    results.append({"hostname": d["hostname"], "ip": d["ip"], "sessions": [], "killed": [], "error": str(e)})
        # Sort: devices with stale sessions first
        results.sort(key=lambda r: -sum(1 for s in r["sessions"] if s["stale"]))
        total_sessions = sum(len(r["sessions"]) for r in results)
        total_stale = sum(sum(1 for s in r["sessions"] if s["stale"]) for r in results)
        total_killed = sum(len(r["killed"]) for r in results)
        return jsonify({
            "site": site, "devices_audited": len(results),
            "total_sessions": total_sessions, "total_stale": total_stale,
            "total_killed": total_killed, "results": results
        })

    return jsonify({"error": "Provide 'ip' or 'site'"}), 400

@app.route("/api/snapshot", methods=["POST"])
def device_snapshot():
    """
    Collect a full snapshot of a device (version, interfaces, bgp, arp, route, logs).
    Body: { "ip": "10.1.9.1", "dtype": "junos" }
    """
    data  = request.json
    ip    = data.get("ip")
    dtype = data.get("dtype", "junos")

    if not ip:
        return jsonify({"success": False, "error": "Missing ip"}), 400

    snapshot_cmds_junos = {
        "version":    COMMANDS["junos"]["version"],
        "uptime":     COMMANDS["junos"]["uptime"],
        "interfaces": COMMANDS["junos"]["interfaces"],
        "arp":        COMMANDS["junos"]["arp"],
        "route":      COMMANDS["junos"]["route"],
        "bgp":        COMMANDS["junos"]["bgp"],
        "alarms":     COMMANDS["junos"]["alarms"],
        "logs":       COMMANDS["junos"]["logs_error"],
    }
    snapshot_cmds_eos = {
        "version":    COMMANDS["eos"]["version"],
        "interfaces": COMMANDS["eos"]["interfaces"],
        "arp":        COMMANDS["eos"]["arp"],
        "route":      COMMANDS["eos"]["route"],
        "bgp":        COMMANDS["eos"]["bgp"],
        "alarms":     COMMANDS["eos"]["alarms"],
        "logs":       COMMANDS["eos"]["logs_error"],
    }

    cmds = snapshot_cmds_junos if dtype == "junos" else snapshot_cmds_eos
    result = run_commands_on_device(ip, dtype, cmds)
    result["timestamp"] = datetime.now().isoformat()
    result["ip"] = ip
    result["dtype"] = dtype
    return jsonify(result)


@app.route("/api/incident", methods=["POST"])
def incident_investigation():
    """
    Incident investigation: collect logs, alarms, BGP/IKE/IPsec status.
    Body: { "ip": "10.1.9.1", "dtype": "junos" }
    """
    data  = request.json
    ip    = data.get("ip")
    dtype = data.get("dtype", "junos")

    if not ip:
        return jsonify({"success": False, "error": "Missing ip"}), 400

    if dtype == "junos":
        cmds = {
            "alarms":    COMMANDS["junos"]["alarms"],
            "logs":      COMMANDS["junos"]["logs"],
            "logs_err":  COMMANDS["junos"]["logs_error"],
            "bgp":       COMMANDS["junos"]["bgp"],
            "interfaces":COMMANDS["junos"]["interfaces"],
            "ike":       COMMANDS["junos"]["ike"],
            "ipsec":     COMMANDS["junos"]["ipsec"],
            "firewall":  COMMANDS["junos"]["firewall"],
            "isp_ifaces":COMMANDS["junos"]["isp_ifaces"],
            "isp_optics":COMMANDS["junos"]["isp_optics"],
            "mtu":       COMMANDS["junos"]["mtu"],
        }
    else:
        cmds = {
            "alarms":    COMMANDS["eos"]["alarms"],
            "logs":      COMMANDS["eos"]["logs"],
            "bgp":       COMMANDS["eos"]["bgp"],
            "interfaces":COMMANDS["eos"]["interfaces"],
            "lacp":      COMMANDS["eos"]["lacp"],
            "isp_ifaces":COMMANDS["eos"]["isp_ifaces"],
            "isp_optics":COMMANDS["eos"]["isp_optics"],
            "mtu":       COMMANDS["eos"]["mtu"],
        }

    result = run_commands_on_device(ip, dtype, cmds)
    result["timestamp"] = datetime.now().isoformat()
    return jsonify(result)

@app.route("/api/ports", methods=["POST"])
def port_capacity():
    """
    Port capacity summary: runs port commands, parses output, returns
    structured breakdown of total/up/down(free)/optics per interface type.
    Body: { "ip": "...", "dtype": "junos" }
    """
    data  = request.json
    ip    = data.get("ip")
    dtype = data.get("dtype", "junos")

    if not ip:
        return jsonify({"success": False, "error": "Missing ip"}), 400

    if dtype == "junos":
        # Run each command in its own SSH session — running multiple commands
        # in one session causes 'show interfaces terse' to intermittently
        # return empty due to prompt/output contention in Netmiko.
        ver_raw = run_command_on_device(ip, dtype, COMMANDS["junos"]["version"])
        if not ver_raw["success"]:
            return jsonify(ver_raw)
        terse_raw = run_command_on_device(ip, dtype, "show interfaces terse")
        hw_raw    = run_command_on_device(ip, dtype, "show chassis hardware")
        results = {
            "version":    ver_raw.get("output", ""),
            "ports_all":  terse_raw.get("output", "") if terse_raw["success"] else "",
            "chassis_hw": hw_raw.get("output", "") if hw_raw["success"] else "",
        }
    else:
        ver_raw = run_command_on_device(ip, dtype, COMMANDS["eos"]["version"])
        if not ver_raw["success"]:
            return jsonify(ver_raw)
        raw = run_commands_on_device(ip, dtype, {
            "ports_capacity": COMMANDS["eos"]["ports_capacity"],
            "ports_hw":       COMMANDS["eos"]["ports_hw"],
        })
        if not raw["success"]:
            return jsonify(raw)
        results = raw["results"]
        results["version"] = ver_raw.get("output", "")
    summary = _parse_port_capacity(dtype, results)
    summary["timestamp"] = datetime.now().isoformat()
    summary["raw"] = results
    return jsonify({"success": True, **summary})


def _parse_port_capacity(dtype, results):
    """Parse raw command output into a structured port capacity summary."""
    summary = {
        "total": 0, "up": 0, "down": 0, "disabled": 0,
        "free": 0,
        "optics_installed": 0,
        "by_speed": {},    # {"100G": {"total":N,"up":N,"down":N}, "25G":..., "10G":...}
        "by_type": {},     # kept for backward compat
        "platform": "",
        "model": "",
        "ports_detail": [],
        "breakout_count": 0,   # number of physical slots used for breakout
        "logical_ports": 0,    # total logical interfaces (after breakout expansion)
    }

    if dtype == "junos":
        # ── Parse version for platform/model ──────────────────────────────────
        ver = results.get("version", "")
        for line in ver.splitlines():
            if "Model:" in line:
                summary["model"] = line.split("Model:")[-1].strip()
            if "Junos:" in line or "JUNOS" in line:
                summary["platform"] = "Junos " + (line.split()[-1] if line.split() else "")

        # ── Parse chassis hardware for total physical port slots + optics ─────
        hw_out = results.get("chassis_hw", "")
        chassis_total_slots = 0
        optics = 0
        for line in hw_out.splitlines():
            l_stripped = line.strip()
            l_upper = l_stripped.upper()
            # Count transceivers (Xcvr lines = optics installed)
            if l_stripped.startswith("Xcvr") or "XCVR" in l_upper:
                if any(x in l_upper for x in ("SFP", "QSFP", "XFP", "CFP", "CWDM", "LR", "SR", "ER", "AOC")):
                    optics += 1
            # Parse PIC lines for total physical port slot count
            # e.g. "PIC 0    BUILTIN  BUILTIN  32X40G/32X100G-QSFP"
            # e.g. "PIC 0    BUILTIN  BUILTIN  48x 10G SFP+"
            # e.g. "PIC 0    BUILTIN  BUILTIN  24x10/100/1000 Base-T"
            if re.match(r'PIC\s+\d+', l_stripped):
                full_desc = " ".join(l_stripped.split()[4:])
                # Match port counts: "24x10G", "4x10G", "24x10/100/1000", "32X100G"
                # Use the FIRST NxSPEED group — for dual-speed PICs like
                # "32X40G/32X100G" both use the same 32 physical slots
                port_matches = re.findall(r'(\d+)\s*[xX]\s*\d+', full_desc)
                if port_matches:
                    # Take the max count (dual-speed PICs share physical slots)
                    chassis_total_slots += max(int(p) for p in port_matches)
        summary["optics_installed"] = optics

        # ── Parse interfaces terse for actual logical ports ───────────────────
        # Channelized ports: et-0/0/0:0 through :3 = 1 physical QSFP → 4x25G
        # Non-channelized: et-0/0/0 = 1 physical QSFP = 1x100G
        ports_out = results.get("ports_all", "")
        by_speed = {}
        detail = []
        channelized_parents = set()   # physical slots that are broken out
        non_channelized = set()       # physical slots used as-is (no breakout)

        for line in ports_out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if not parts:
                continue
            iface = parts[0]
            # Skip subinterfaces (xe-0/0/0.0) but keep channelized (et-0/0/0:0)
            if "." in iface:
                continue
            m = re.match(r'^(xe|et|ge|xle|fte)-', iface)
            if not m:
                continue
            itype = m.group(1)
            admin = parts[1] if len(parts) > 1 else "unknown"
            link  = parts[2] if len(parts) > 2 else ""

            # Detect channelized vs non-channelized
            is_channelized = ":" in iface
            if is_channelized:
                # et-0/0/0:0 → parent = et-0/0/0
                parent = iface.split(":")[0]
                channelized_parents.add(parent)
                # Channelized 100G → 4x25G typically
                speed = "25G"
            else:
                non_channelized.add(iface)
                if itype in ("et",):   speed = "100G"
                elif itype in ("xe",): speed = "10G"
                elif itype in ("ge",): speed = "1G"
                else:                  speed = "other"

            if speed not in by_speed:
                by_speed[speed] = {"total": 0, "up": 0, "down": 0, "disabled": 0}
            by_speed[speed]["total"] += 1

            if admin.lower() == "up" and link.lower() == "up":
                by_speed[speed]["up"] += 1
            elif admin.lower() == "up" and link.lower() == "down":
                by_speed[speed]["down"] += 1       # up/down = empty slot
            elif admin.lower() == "down":
                by_speed[speed]["disabled"] += 1   # admin disabled
            else:
                by_speed[speed]["down"] += 1

            detail.append({
                "iface": iface, "status": admin, "link": link,
                "speed": speed, "channelized": is_channelized
            })

        summary["by_speed"] = by_speed
        summary["by_type"] = by_speed   # backward compat
        summary["ports_detail"] = detail
        summary["breakout_count"] = len(channelized_parents)

        # ── Totals ────────────────────────────────────────────────────────────
        logical_total = sum(v["total"] for v in by_speed.values())
        up    = sum(v["up"]       for v in by_speed.values())
        dis   = sum(v["disabled"] for v in by_speed.values())
        down  = sum(v["down"]     for v in by_speed.values())

        # Total = chassis hardware slots if available and >= logical count
        total_physical = max(chassis_total_slots, logical_total)
        summary["total"]          = total_physical
        summary["logical_ports"]  = logical_total
        summary["up"]             = up
        summary["disabled"]       = dis
        summary["down"]           = down
        summary["breakout_count"] = len(channelized_parents)
        # Free = total slots - in_use - admin_disabled  (matches reference system)
        summary["free"]           = max(0, total_physical - up - dis)

    else:
        # ── EOS: parse show interfaces status ────────────────────────────────
        ver = results.get("version", "")
        for line in ver.splitlines():
            if "cEOS" in line or "DCS-" in line or "vEOS" in line or "Arista" in line:
                summary["model"] = line.strip()
                break
        summary["platform"] = "Arista EOS"

        ports_out = results.get("ports_capacity", "")
        by_type = {}
        detail = []
        for line in ports_out.splitlines():
            line = line.strip()
            # Header lines or blank
            if not line or line.startswith("Port") or line.startswith("---"):
                continue
            parts = line.split()
            if not parts:
                continue
            iface = parts[0]
            # Only physical Ethernet ports
            if not re.match(r'^Ethernet', iface, re.IGNORECASE):
                continue

            # EOS show interfaces status columns:
            # Port    Name    Status    Vlan    Duplex    Speed    Type
            # Determine type by speed or interface name
            status_col = parts[2] if len(parts) > 2 else "notconnect"
            speed_col  = parts[5] if len(parts) > 5 else ""
            type_col   = parts[6] if len(parts) > 6 else ""

            if "100G" in speed_col or "100G" in type_col:
                itype = "100G"
            elif "40G" in speed_col or "40G" in type_col:
                itype = "40G"
            elif "25G" in speed_col or "25G" in type_col:
                itype = "25G"
            elif "10G" in speed_col or "10G" in type_col:
                itype = "10G"
            elif "1G" in speed_col or "1000" in speed_col:
                itype = "1G"
            else:
                itype = "other"

            if itype not in by_type:
                by_type[itype] = {"total": 0, "up": 0, "down": 0, "disabled": 0}
            by_type[itype]["total"] += 1

            status_norm = status_col.lower()
            if status_norm == "connected":
                by_type[itype]["up"] += 1
            elif status_norm == "disabled" or status_norm == "errdisabled":
                by_type[itype]["disabled"] += 1
            else:
                by_type[itype]["down"] += 1

            detail.append({"iface": iface, "status": status_col,
                           "speed": speed_col, "type": type_col})

        summary["by_type"] = by_type
        summary["ports_detail"] = detail

        # ── Optics from show inventory ────────────────────────────────────────
        hw_out = results.get("ports_hw", "")
        optics = 0
        for line in hw_out.splitlines():
            l = line.upper()
            if any(x in l for x in ("SFP", "QSFP", "XFP", "XCVR")):
                optics += 1
        summary["optics_installed"] = optics

        total = sum(v["total"]    for v in by_type.values())
        up    = sum(v["up"]       for v in by_type.values())
        dis   = sum(v["disabled"] for v in by_type.values())
        down  = sum(v["down"]     for v in by_type.values())
        summary["total"]    = total
        summary["up"]       = up
        summary["disabled"] = dis
        summary["down"]     = down
        summary["free"]     = down + dis

    return summary


@app.route("/api/analyze", methods=["POST"])
def analyze_output():
    """
    AI-style analysis: pattern-match output for known issues and best practices.
    Body: { "hostname": "...", "dtype": "junos", "data": { "cmd": "output" } }
    """
    data     = request.json
    hostname = data.get("hostname", "")
    dtype    = data.get("dtype", "junos")
    cmd_data = data.get("data", {})

    findings  = []
    warnings  = []
    best_practices = []

    for cmd_key, output in cmd_data.items():
        if not isinstance(output, str):
            continue
        out = output.lower()

        # ── BGP Analysis ──────────────────────────────────────────────────────
        if "bgp" in cmd_key:
            if "established" not in out and "active" in out:
                warnings.append(f"[BGP] Session in ACTIVE state (not established) — check neighbor reachability")
            if "idle" in out:
                warnings.append(f"[BGP] BGP session IDLE — possible auth or routing issue")
            if "connect" in out and "established" not in out:
                warnings.append(f"[BGP] BGP session stuck in CONNECT — TCP connectivity issue")
            if "0/0/0/0" in out:
                warnings.append(f"[BGP] BGP neighbor with 0 prefixes received — check prefix policy")
            if "established" in out:
                findings.append(f"[BGP] Sessions established ✓")
            best_practices.append("[BGP] Ensure BFD is enabled on all BGP sessions for fast failover")
            best_practices.append("[BGP] Verify route policies (import/export) are filtering correctly")

        # ── Interface Analysis ───────────────────────────────────────────────
        if "interface" in cmd_key or "traffic" in cmd_key:
            if "down" in out:
                # Count downs
                down_count = out.count(" down")
                if down_count > 0:
                    warnings.append(f"[INTERFACES] {down_count} interface(s) detected as DOWN")
            if "error" in out:
                findings.append(f"[INTERFACES] Interface errors detected — check for duplex/cabling issues")
            if "gbps" in out or "mbps" in out:
                findings.append(f"[TRAFFIC] Traffic data collected — review for capacity thresholds")
            best_practices.append("[INTERFACES] Interfaces running >80% utilization should be reviewed for upgrades")
            best_practices.append("[INTERFACES] Check for input/output errors — may indicate physical layer issues")

        # ── Alarm Analysis ───────────────────────────────────────────────────
        if "alarm" in cmd_key:
            if "no alarms" not in out and len(output.strip()) > 10:
                warnings.append(f"[ALARMS] Active alarms detected on device — review immediately")
            else:
                findings.append(f"[ALARMS] No active alarms ✓")

        # ── Log Analysis ─────────────────────────────────────────────────────
        if "log" in cmd_key:
            if "rpd_bgp" in out:
                warnings.append(f"[LOGS] BGP routing daemon events found in logs")
            if "chassisd" in out or "fpc" in out:
                warnings.append(f"[LOGS] Chassis/FPC events in logs — possible hardware issue")
            if "lacpd" in out or "lacp" in out:
                warnings.append(f"[LOGS] LACP events in logs — LAG instability possible")
            if "license" in out:
                warnings.append(f"[LOGS] License-related events in logs — check expiry")
            if "authentication" in out or "login" in out:
                findings.append(f"[LOGS] Authentication events present — review for security")
            if "rpd" in out:
                warnings.append(f"[LOGS] Routing protocol daemon (rpd) events — review BGP/OSPF/ISIS state")

        # ── IKE/IPsec Analysis ───────────────────────────────────────────────
        if "ike" in cmd_key or "ipsec" in cmd_key:
            if "up" not in out and len(output.strip()) > 10:
                warnings.append(f"[VPN] IKE/IPsec tunnels may be down — check ADVPN connectivity")
            else:
                findings.append(f"[VPN] IKE/IPsec tunnels appear active ✓")

        # ── Route Analysis ───────────────────────────────────────────────────
        if "route" in cmd_key:
            if "0.0.0.0" in out:
                findings.append(f"[ROUTING] Default route present ✓")
            best_practices.append("[ROUTING] Verify static routes have proper next-hops and are not stale")
            best_practices.append("[ROUTING] BGP routes should have appropriate local-preference and MED values")

        # ── Version/Uptime ───────────────────────────────────────────────────
        if "version" in cmd_key or "uptime" in cmd_key:
            if dtype == "junos":
                if "19." in out or "18." in out or "17." in out:
                    warnings.append(f"[VERSION] Junos version may be EOL — consider upgrading to 22.x/23.x")
            elif dtype == "eos":
                if "4.2" in out or "4.19" in out or "4.20" in out:
                    warnings.append(f"[VERSION] EOS version may be outdated — consider upgrading to 4.30+")

        # ── MTU Analysis ──────────────────────────────────────────────────────
        if cmd_key == "mtu":
            mtu_map = {}       # {iface: mtu_value}
            current_iface = None
            for line in output.splitlines():
                line_s = line.strip()
                if not line_s:
                    continue
                # Junos: "Physical interface: xe-0/0/0, ..." then "Link-level type: ..., MTU: 9192, ..."
                m_phys = re.match(r'Physical interface:\s+(\S+)', line_s)
                if m_phys:
                    current_iface = m_phys.group(1).rstrip(",")
                    continue
                # Junos MTU in same block
                if current_iface and dtype == "junos":
                    m_mtu = re.search(r'MTU:\s*(\d+)', line_s)
                    if m_mtu:
                        mtu_map[current_iface] = int(m_mtu.group(1))
                        current_iface = None
                        continue
                # EOS: "Ethernet1 is up ... MTU 9214 bytes" or inline
                if dtype == "eos":
                    m_eos = _EOS_IFACE_RE.match(line_s)
                    if m_eos:
                        iface = m_eos.group(1)
                        m_mtu = re.search(r'MTU\s+(\d+)', line_s, re.IGNORECASE)
                        if m_mtu:
                            mtu_map[iface] = int(m_mtu.group(1))

            if mtu_map:
                mtu_values = set(mtu_map.values())
                mtu_counts = {}
                for v in mtu_map.values():
                    mtu_counts[v] = mtu_counts.get(v, 0) + 1

                findings.append(f"[MTU] Collected MTU for {len(mtu_map)} interfaces")

                # Flag MTU mismatches — multiple different MTU values on same device
                if len(mtu_values) > 1:
                    mtu_summary = ", ".join(f"{v} ({c} ports)" for v, c in sorted(mtu_counts.items()))
                    warnings.append(f"[MTU] ⚠️ MIXED MTU VALUES detected: {mtu_summary} — verify consistency across paths")

                # Flag non-jumbo MTU on physical interfaces (< 9000)
                small_mtu = [f"{iface} (MTU:{mtu})" for iface, mtu in mtu_map.items()
                             if mtu < 9000 and not iface.lower().startswith(("lo", "fxp", "em", "me", "vme", "management"))]
                if small_mtu and len(small_mtu) <= 20:
                    warnings.append(f"[MTU] Non-jumbo MTU (<9000) on: {', '.join(small_mtu)}")
                elif small_mtu:
                    warnings.append(f"[MTU] {len(small_mtu)} interfaces with non-jumbo MTU (<9000) — may cause fragmentation")

                # Flag 1500 MTU specifically (default, often a misconfiguration in DC fabrics)
                default_mtu = [iface for iface, mtu in mtu_map.items() if mtu == 1500
                               and not iface.lower().startswith(("lo", "fxp", "em", "me", "vme", "management"))]
                if default_mtu:
                    warnings.append(f"[MTU] 🔴 DEFAULT MTU (1500) on {len(default_mtu)} interface(s) — likely needs jumbo frames for DC traffic")

                best_practices.append("[MTU] DC fabric should use consistent jumbo MTU (9192-9214) on all physical + VLAN interfaces")
                best_practices.append("[MTU] MTU mismatch between neighbors causes silent packet drops — verify end-to-end path MTU")

        # ── ISP Interface Status ──────────────────────────────────────────────
        if cmd_key == "isp_ifaces":
            isp_down = []
            isp_up = []
            for line in output.splitlines():
                line_s = line.strip()
                if not line_s:
                    continue
                parts = line_s.split()
                if len(parts) >= 3:
                    iface = parts[0]
                    admin = parts[1]
                    link  = parts[2]
                    desc  = " ".join(parts[3:]) if len(parts) > 3 else ""
                    if admin == "up" and link == "down":
                        isp_down.append(f"{iface} ({desc})" if desc else iface)
                    elif admin == "up" and link == "up":
                        isp_up.append(f"{iface} ({desc})" if desc else iface)
            if isp_down:
                warnings.append(f"[ISP] 🔴 ISP link DOWN on: {', '.join(isp_down)} — check fiber/SFP with ISP")
            if isp_up:
                findings.append(f"[ISP] ISP interfaces UP: {', '.join(isp_up)} ✓")
            if not isp_down and not isp_up and len(output.strip()) < 5:
                findings.append(f"[ISP] No ISP-facing interfaces found (no descriptions matching 'isp')")

        # ── SFP / Optics Diagnostics (Tx/Rx Power Analysis) ──────────────────
        if cmd_key == "isp_optics" or cmd_key == "dom":
            current_iface = None
            sfp_data = {}   # {iface: {rx_dbm, tx_dbm, temp, bias}}

            for line in output.splitlines():
                line_s = line.strip()
                ll = line_s.lower()

                # Skip header/separator lines
                if not line_s or line_s.startswith("---") or "port" in ll and "temp" in ll:
                    continue

                # ── Junos: "Physical interface: xe-1/0/23" ───────────────
                m_junos = re.match(r'Physical interface:\s+(\S+)', line_s)
                if m_junos:
                    current_iface = m_junos.group(1)
                    sfp_data.setdefault(current_iface, {})
                    continue

                # ── EOS table row ─────────────────────────────────────────
                # Format: "Et1  32.5  3.30  6.200  -2.3  -3.1"
                # or:     "Ethernet1  32.5  3.30  6.200  -2.3  -3.1"
                # Columns: Port  Temp(C)  Voltage(V)  Bias(mA)  TxPower(dBm)  RxPower(dBm)
                if dtype == "eos":
                    m_eos_row = re.match(r'^(Et\S+|Ethernet\S+)\s+(.+)', line_s)
                    if m_eos_row:
                        iface_name = m_eos_row.group(1)
                        rest = m_eos_row.group(2)
                        # Skip lines with only N/A
                        if "N/A" in rest:
                            # Extract any numeric values that aren't N/A
                            vals = rest.split()
                            nums = [v for v in vals if v != "N/A" and re.match(r'^[-+]?\d+\.?\d*$', v)]
                        else:
                            nums = re.findall(r'[-+]?\d+\.?\d*', rest)
                        if len(nums) >= 4:
                            sfp_data.setdefault(iface_name, {})
                            try:
                                sfp_data[iface_name]["temp"] = float(nums[0])
                                sfp_data[iface_name]["tx_dbm"] = float(nums[-2])
                                sfp_data[iface_name]["rx_dbm"] = float(nums[-1])
                            except (ValueError, IndexError):
                                pass
                        elif len(nums) >= 2:
                            # Partial data — at least Tx and Rx
                            sfp_data.setdefault(iface_name, {})
                            try:
                                sfp_data[iface_name]["tx_dbm"] = float(nums[-2])
                                sfp_data[iface_name]["rx_dbm"] = float(nums[-1])
                            except (ValueError, IndexError):
                                pass
                        continue

                # ── EOS detail format: "Ethernet1" on line by itself ──────
                if dtype == "eos":
                    m_eos_det = _EOS_IFACE_NAME_RE.match(line_s)
                    if m_eos_det:
                        current_iface = m_eos_det.group(1)
                        sfp_data.setdefault(current_iface, {})
                        continue

                # ── Per-field parsing (Junos labeled lines & EOS detail) ──
                if not current_iface:
                    continue

                # Rx power
                if "receiver power" in ll or "rx power" in ll:
                    dbm = re.search(r'([-+]?\d+\.?\d*)\s*dBm', line_s)
                    mw  = re.search(r'([\d.]+)\s*mW', line_s)
                    if dbm:
                        sfp_data[current_iface]["rx_dbm"] = float(dbm.group(1))
                    elif mw:
                        mw_val = float(mw.group(1))
                        if mw_val > 0:
                            sfp_data[current_iface]["rx_dbm"] = round(10 * math.log10(mw_val), 2)
                # Tx power
                elif "output power" in ll or "tx power" in ll:
                    dbm = re.search(r'([-+]?\d+\.?\d*)\s*dBm', line_s)
                    mw  = re.search(r'([\d.]+)\s*mW', line_s)
                    if dbm:
                        sfp_data[current_iface]["tx_dbm"] = float(dbm.group(1))
                    elif mw:
                        mw_val = float(mw.group(1))
                        if mw_val > 0:
                            sfp_data[current_iface]["tx_dbm"] = round(10 * math.log10(mw_val), 2)
                # Temperature
                elif "temperature" in ll:
                    t = re.search(r'([\d.]+)\s*(?:degrees?\s*)?C', line_s)
                    if t:
                        sfp_data[current_iface]["temp"] = float(t.group(1))
                # Bias current
                elif "bias" in ll:
                    b = re.search(r'([\d.]+)\s*mA', line_s)
                    if b:
                        sfp_data[current_iface]["bias"] = float(b.group(1))

            # Analyze parsed SFP data
            no_rx_light = []
            low_rx = []
            low_tx = []
            high_temp = []
            healthy = []

            for iface, data in sfp_data.items():
                rx = data.get("rx_dbm")
                tx = data.get("tx_dbm")
                temp = data.get("temp")

                if rx is not None:
                    if rx <= -30:
                        no_rx_light.append(f"{iface} (Rx: {rx} dBm — NO LIGHT)")
                    elif rx < -10:
                        low_rx.append(f"{iface} (Rx: {rx} dBm)")
                    elif tx is not None:
                        healthy.append(iface)

                if tx is not None and tx < -8:
                    low_tx.append(f"{iface} (Tx: {tx} dBm)")

                if temp is not None and temp > 70:
                    high_temp.append(f"{iface} ({temp}°C)")

            if no_rx_light:
                warnings.append(f"[SFP] 🔴 NO RX LIGHT on: {', '.join(no_rx_light)} — fiber cut or remote SFP failure")
            if low_rx:
                warnings.append(f"[SFP] ⚠️ LOW RX POWER on: {', '.join(low_rx)} — degraded signal, check fiber/patch")
            if low_tx:
                warnings.append(f"[SFP] ⚠️ LOW TX POWER on: {', '.join(low_tx)} — local SFP may be failing")
            if high_temp:
                warnings.append(f"[SFP] 🌡️ HIGH TEMPERATURE on: {', '.join(high_temp)} — check airflow/environment")
            if healthy:
                findings.append(f"[SFP] {len(healthy)} optics with healthy Tx/Rx levels ✓")
            if sfp_data:
                findings.append(f"[SFP] Analyzed {len(sfp_data)} transceiver(s) total")
                best_practices.append("[SFP] Normal Rx range: -1 to -10 dBm | Below -10 dBm = degraded | -40 dBm = no light")
                best_practices.append("[SFP] Monitor optics proactively — gradual Rx degradation often precedes link failure")

    # Deduplicate
    findings       = list(dict.fromkeys(findings))
    warnings       = list(dict.fromkeys(warnings))
    best_practices = list(dict.fromkeys(best_practices))[:8]

    severity = "OK"
    if len(warnings) > 3:
        severity = "CRITICAL"
    elif len(warnings) > 0:
        severity = "WARNING"

    return jsonify({
        "hostname":      hostname,
        "severity":      severity,
        "findings":      findings,
        "warnings":      warnings,
        "best_practices": best_practices,
        "summary":       f"{len(findings)} findings, {len(warnings)} warnings detected",
        "timestamp":     datetime.now().isoformat()
    })

# ── Recommendation Engine ──────────────────────────────────────────────────────

# Commands to collect for recommendation analysis
_RECO_CMDS_JUNOS = {
    "version":       "show version",
    "config_set":    "show configuration | display set | no-more",
    "interfaces":    "show interfaces terse",
    "bgp":           "show bgp summary",
    "alarms":        "show chassis alarms",
    "security_zones":"show security zones",
    "ntp":           "show ntp associations",
    "snmp":          "show snmp statistics",
    "stp":           "show spanning-tree bridge",
    "lacp":          "show lacp interfaces",
    "uptime":        "show system uptime",
    "routing":       "show route summary",
}

_RECO_CMDS_EOS = {
    "version":       "show version",
    "config":        "show running-config",
    "interfaces":    "show interfaces status",
    "bgp":           "show bgp summary",
    "ntp":           "show ntp associations",
    "stp":           "show spanning-tree",
    "lacp":          "show lacp neighbor",
    "uptime":        "show uptime",
    "routing":       "show ip route summary",
    "logging":       "show logging | tail 20",
}


def _generate_recommendations(hostname, dtype, results):
    """Analyze collected config/state and return categorized recommendations."""
    recs = {
        "security":    [],
        "performance": [],
        "resilience":  [],
        "optimization":[],
        "compliance":  [],
    }
    config = results.get("config_set", "") or results.get("config", "")
    config_lower = config.lower()
    version_out = results.get("version", "").lower()
    bgp_out = results.get("bgp", "").lower()
    ifaces_out = results.get("interfaces", "").lower()
    alarms_out = results.get("alarms", "").lower()
    ntp_out = results.get("ntp", "").lower()
    stp_out = results.get("stp", "").lower()
    lacp_out = results.get("lacp", "").lower()
    uptime_out = results.get("uptime", "").lower()
    routing_out = results.get("routing", "").lower()
    zones_out = results.get("security_zones", "").lower()

    # ── SECURITY ──────────────────────────────────────────────────────────
    if dtype == "junos":
        if "set system login" in config_lower and "ssh-rsa" not in config_lower and "ssh-ed25519" not in config_lower:
            recs["security"].append({
                "title": "Enable SSH Key Authentication",
                "detail": "Only password-based authentication detected. Configure SSH public keys for all admin users.",
                "severity": "high",
                "command": "set system login user <user> authentication ssh-rsa \"<public-key>\""
            })
        if "set system services ssh root-login" in config_lower and "deny" not in config_lower:
            recs["security"].append({
                "title": "Disable Root SSH Login",
                "detail": "Root login via SSH should be disabled. Use named accounts with proper RBAC.",
                "severity": "high",
                "command": "set system services ssh root-login deny"
            })
        if "set system services ssh protocol-version v2" not in config_lower and "set system services ssh" in config_lower:
            recs["security"].append({
                "title": "Enforce SSH Protocol v2",
                "detail": "Ensure only SSHv2 is allowed. SSHv1 has known vulnerabilities.",
                "severity": "medium",
                "command": "set system services ssh protocol-version v2"
            })
        if "set system syslog" not in config_lower:
            recs["security"].append({
                "title": "Configure Remote Syslog",
                "detail": "No syslog configuration detected. Send logs to a centralized SIEM for audit compliance.",
                "severity": "high",
                "command": "set system syslog host <syslog-ip> any warning"
            })
        if "set system login" in config_lower and "class" not in config_lower:
            recs["security"].append({
                "title": "Implement RBAC Login Classes",
                "detail": "Users should be assigned login classes with appropriate permission levels.",
                "severity": "medium",
                "command": "set system login class <class-name> permissions <permissions>"
            })
        if "set security screen" not in config_lower and "set security" in config_lower:
            recs["security"].append({
                "title": "Enable IDS/IPS Screen Policies",
                "detail": "Security screens protect against common attacks (SYN flood, ICMP flood, port scan).",
                "severity": "medium",
                "command": "set security screen ids-option <name> icmp ping-death\nset security screen ids-option <name> tcp syn-flood"
            })
        if "set system services web-management" in config_lower:
            recs["security"].append({
                "title": "Disable Web Management (J-Web)",
                "detail": "Web management interface should be disabled unless actively needed. Use CLI/Netconf.",
                "severity": "low",
                "command": "delete system services web-management"
            })
    elif dtype == "eos":
        if "aaa authorization" not in config_lower:
            recs["security"].append({
                "title": "Configure AAA Authorization",
                "detail": "AAA authorization ensures commands are checked against TACACS+/RADIUS policy.",
                "severity": "high",
                "command": "aaa authorization exec default local"
            })
        if "ip access-list" not in config_lower:
            recs["security"].append({
                "title": "Apply Control-Plane ACLs",
                "detail": "Protect management plane with ACLs to restrict SSH/SNMP/NTP access.",
                "severity": "medium",
                "command": "ip access-list MGMT-ACL\n  permit tcp <mgmt-subnet> any eq ssh"
            })
        if "logging host" not in config_lower:
            recs["security"].append({
                "title": "Configure Remote Syslog",
                "detail": "No remote syslog host configured. Send logs to centralized SIEM.",
                "severity": "high",
                "command": "logging host <syslog-ip>"
            })

    # ── PERFORMANCE ───────────────────────────────────────────────────────
    if dtype == "junos":
        if "set forwarding-options storm-control" not in config_lower:
            recs["performance"].append({
                "title": "Enable Storm Control",
                "detail": "Storm control prevents broadcast/multicast storms from consuming bandwidth.",
                "severity": "medium",
                "command": "set forwarding-options storm-control-profiles <name> all bandwidth-percentage 5"
            })
        if "set class-of-service" not in config_lower:
            recs["performance"].append({
                "title": "Configure QoS / Class of Service",
                "detail": "CoS ensures critical traffic (BGP, management) is prioritized during congestion.",
                "severity": "low",
                "command": "set class-of-service forwarding-classes ..."
            })
        # Check for jumbo frames on data interfaces
        if "mtu 9" not in config_lower and "mtu 1" in config_lower:
            recs["performance"].append({
                "title": "Consider Jumbo Frames on Data Interfaces",
                "detail": "DC fabric interfaces typically benefit from MTU 9192+ to reduce overhead.",
                "severity": "low",
                "command": "set interfaces <iface> mtu 9192"
            })
    elif dtype == "eos":
        if "mlag" in config_lower and "mlag configuration" not in config_lower:
            recs["performance"].append({
                "title": "Verify MLAG Configuration",
                "detail": "MLAG detected but may need full configuration review for proper redundancy.",
                "severity": "medium",
                "command": "show mlag detail"
            })

    # ── RESILIENCE ────────────────────────────────────────────────────────
    # NTP
    if not ntp_out.strip() or "no association" in ntp_out or "error" in ntp_out:
        recs["resilience"].append({
            "title": "Configure NTP Time Synchronization",
            "detail": "NTP is critical for log correlation, certificate validation, and troubleshooting.",
            "severity": "high",
            "command": "set system ntp server <ntp-server>" if dtype == "junos" else "ntp server <ntp-server>"
        })
    elif ntp_out.strip() and "reject" in ntp_out:
        recs["resilience"].append({
            "title": "Fix NTP Server Reachability",
            "detail": "NTP server(s) unreachable (reject status). Verify routing and firewall rules.",
            "severity": "high",
            "command": "show ntp associations"
        })

    # BGP BFD
    if "bgp" in config_lower and "bfd" not in config_lower:
        recs["resilience"].append({
            "title": "Enable BFD for BGP Sessions",
            "detail": "BFD provides sub-second failover detection. Without it, BGP hold-timer (90s) is used.",
            "severity": "high",
            "command": "set protocols bgp group <group> bfd-liveness-detection minimum-interval 300" if dtype == "junos"
                       else "router bgp <asn>\n  neighbor <ip> bfd"
        })

    # Redundant routing protocols
    if bgp_out.strip() and "established" in bgp_out:
        # Count established sessions
        est_count = bgp_out.count("established") + bgp_out.count("establ")
        if est_count < 2:
            recs["resilience"].append({
                "title": "Add Redundant BGP Sessions",
                "detail": f"Only ~{est_count} BGP session(s) established. Consider dual-homing for resilience.",
                "severity": "medium",
                "command": "N/A — design decision"
            })

    # LACP
    if lacp_out.strip() and ("detached" in lacp_out or "defaulted" in lacp_out):
        recs["resilience"].append({
            "title": "Fix LACP Detached/Defaulted Members",
            "detail": "LACP members in detached/defaulted state reduce aggregate bandwidth and resilience.",
            "severity": "high",
            "command": "show lacp interfaces"
        })

    # Alarms
    if alarms_out and "no alarms" not in alarms_out and len(alarms_out.strip()) > 10:
        recs["resilience"].append({
            "title": "Resolve Active Chassis Alarms",
            "detail": "Active alarms can indicate hardware degradation. Review and resolve promptly.",
            "severity": "high",
            "command": "show chassis alarms"
        })

    # VRRP / Gateway redundancy
    if dtype == "junos":
        if "set interfaces" in config_lower and "vrrp" not in config_lower and "virtual-gateway" not in config_lower:
            recs["resilience"].append({
                "title": "Consider VRRP/VGARP for Gateway Redundancy",
                "detail": "No VRRP or virtual-gateway detected. First-hop redundancy is critical for availability.",
                "severity": "medium",
                "command": "set interfaces <iface> unit <unit> family inet address <ip>/24 vrrp-group <id> virtual-address <vip>"
            })

    # ── OPTIMIZATION ──────────────────────────────────────────────────────
    if dtype == "junos":
        if "set system commit synchronize" not in config_lower:
            recs["optimization"].append({
                "title": "Enable Commit Synchronize (HA)",
                "detail": "On dual-RE or chassis cluster, commit synchronize keeps both nodes in sync.",
                "severity": "medium",
                "command": "set system commit synchronize"
            })
        if "set system auto-snapshot" not in config_lower:
            recs["optimization"].append({
                "title": "Enable Auto-Snapshot for Rollback",
                "detail": "Auto-snapshot saves config before upgrades, enabling quick rollback.",
                "severity": "low",
                "command": "set system auto-snapshot"
            })
        if "set system configuration rescue" not in config_lower and "rescue" not in config_lower:
            recs["optimization"].append({
                "title": "Save Rescue Configuration",
                "detail": "A rescue config provides a known-good fallback for recovery scenarios.",
                "severity": "medium",
                "command": "request system configuration rescue save"
            })
        # LLDP
        if "set protocols lldp" not in config_lower:
            recs["optimization"].append({
                "title": "Enable LLDP Protocol",
                "detail": "LLDP aids in topology discovery and helps verify physical cabling.",
                "severity": "low",
                "command": "set protocols lldp interface all"
            })
    elif dtype == "eos":
        if "lldp" not in config_lower:
            recs["optimization"].append({
                "title": "Enable LLDP Protocol",
                "detail": "LLDP aids in topology discovery and cable verification.",
                "severity": "low",
                "command": "lldp run"
            })
        if "errdisable recovery" not in config_lower:
            recs["optimization"].append({
                "title": "Enable Error-Disable Recovery",
                "detail": "Automatically recover err-disabled ports after a timeout to reduce manual intervention.",
                "severity": "low",
                "command": "errdisable recovery interval 300"
            })

    # ── COMPLIANCE ────────────────────────────────────────────────────────
    # Version checks
    if dtype == "junos":
        for old_ver in ("17.", "18.", "19.", "20.1", "20.2", "20.3"):
            if old_ver in version_out:
                recs["compliance"].append({
                    "title": "Upgrade Junos to Supported Version",
                    "detail": f"Running Junos {old_ver}x which may be end-of-life. Target 22.x or 23.x for security patches.",
                    "severity": "high",
                    "command": "request system software add <image> no-validate reboot"
                })
                break
    elif dtype == "eos":
        for old_ver in ("4.19", "4.20", "4.21", "4.22", "4.23", "4.24"):
            if old_ver in version_out:
                recs["compliance"].append({
                    "title": "Upgrade EOS to Supported Version",
                    "detail": f"Running EOS {old_ver}.x which may be outdated. Target 4.30+ for latest features and fixes.",
                    "severity": "high",
                    "command": "N/A — follow Arista upgrade procedure"
                })
                break

    # SNMP v3
    if dtype == "junos":
        if "set snmp community" in config_lower and "set snmp v3" not in config_lower:
            recs["compliance"].append({
                "title": "Migrate to SNMPv3",
                "detail": "SNMPv2c communities are sent in cleartext. SNMPv3 provides authentication and encryption.",
                "severity": "medium",
                "command": "set snmp v3 usm local-engine user <user> authentication-sha ..."
            })
    elif dtype == "eos":
        if "snmp-server community" in config_lower and "snmp-server user" not in config_lower:
            recs["compliance"].append({
                "title": "Migrate to SNMPv3",
                "detail": "SNMPv2c communities are cleartext. Use SNMPv3 for security compliance.",
                "severity": "medium",
                "command": "snmp-server user <user> <group> v3 auth sha <pass> priv aes <pass>"
            })

    # Banner — check for actual banner config, not generic "login" keyword
    has_banner = False
    if dtype == "junos" and "set system login message" in config_lower:
        has_banner = True
    elif dtype == "eos" and "banner login" in config_lower:
        has_banner = True
    if not has_banner:
        recs["compliance"].append({
            "title": "Configure Login Banner",
            "detail": "A legal warning banner is required for compliance in most organizations.",
            "severity": "low",
            "command": "set system login message \"Authorized use only. All activity is monitored.\"" if dtype == "junos"
                       else "banner login\nAuthorized use only. All activity is monitored.\nEOF"
        })

    # Count totals
    total = sum(len(v) for v in recs.values())
    high_count = sum(1 for cat in recs.values() for r in cat if r["severity"] == "high")
    med_count = sum(1 for cat in recs.values() for r in cat if r["severity"] == "medium")

    return {
        "hostname": hostname,
        "dtype": dtype,
        "recommendations": recs,
        "total": total,
        "high_count": high_count,
        "medium_count": med_count,
        "timestamp": datetime.now().isoformat(),
    }


@app.route("/api/recommendations", methods=["POST"])
def get_recommendations():
    """Collect device config and generate best-practice recommendations."""
    data  = request.json
    ip    = data.get("ip")
    dtype = data.get("dtype", "junos")
    hostname = data.get("hostname", ip)

    if not ip:
        return jsonify({"success": False, "error": "Missing ip"}), 400

    cmds = _RECO_CMDS_JUNOS if dtype == "junos" else _RECO_CMDS_EOS
    result = run_commands_on_device(ip, dtype, cmds)

    if not result["success"]:
        return jsonify({"success": False, "error": result.get("error", "SSH failed")})

    recs = _generate_recommendations(hostname, dtype, result["results"])
    recs["success"] = True
    return jsonify(recs)


# ── AI Agent Deep Analysis ─────────────────────────────────────────────────────

_DEEP_CMDS_JUNOS = {
    "version":        "show version | no-more",
    "uptime":         "show system uptime | no-more",
    "alarms":         "show chassis alarms",
    "chassis":        "show chassis hardware | no-more",
    "config_set":     "show configuration | display set | no-more",
    "bgp":            "show bgp summary",
    "bgp_detail":     "show bgp neighbor",
    "interfaces":     "show interfaces terse",
    "optics":         "show interfaces diagnostics optics",
    "mtu":            "show interfaces | match \"Physical|MTU|mtu\"",
    "traffic":        "show interfaces | match \"Physical|bps|pps\"",
    "ports_all":      "show interfaces terse | match \"xe-|et-|ge-\" | except \"\\.\"",
    "lldp":           "show lldp neighbors",
    "lacp":           "show lacp interfaces",
    "routing":        "show route summary",
    "logs":           "show log | no-more | last 100",
    "ntp":            "show ntp associations",
    "ike":            "show security ike sa",
    "ipsec":          "show security ipsec sa",
    "firewall":       "show firewall",
    "vlans":          "show vlans",
    "stp":            "show spanning-tree bridge",
    "errors":         "show interfaces | match \"Physical|error|drop\" | except \"0 errors|0 drops\"",
}

_DEEP_CMDS_EOS = {
    "version":        "show version",
    "uptime":         "show uptime",
    "alarms":         "show system environment",
    "config":         "show running-config",
    "bgp":            "show bgp summary",
    "bgp_detail":     "show bgp neighbors | head 100",
    "interfaces":     "show interfaces status",
    "optics":         "show interfaces transceiver",
    "mtu":            "show interfaces | grep -E 'Ethernet|Vlan|Port-Channel|Loopback' | grep -i mtu",
    "traffic":        "show interfaces counters rates",
    "ports_all":      "show interfaces status | grep -E '^Et'",
    "lldp":           "show lldp neighbors",
    "lacp":           "show lacp neighbor",
    "routing":        "show ip route summary",
    "logs":           "show logging last 100",
    "ntp":            "show ntp associations",
    "mlag":           "show mlag",
    "vlans":          "show vlan",
    "stp":            "show spanning-tree",
    "errors":         "show interfaces counters errors | grep -v ' 0 ' | head 40",
}


def _deep_analyze(hostname, dtype, results):
    """Cross-correlate ALL collected data into a comprehensive health report."""

    # ── Helper to safely get output ───────────────────────────────────────
    def g(key):
        v = results.get(key, "")
        return v if isinstance(v, str) else ""

    config   = g("config_set") or g("config")
    cfg_low  = config.lower()
    ver_out  = g("version").lower()
    bgp_out  = g("bgp").lower()
    bgp_det  = g("bgp_detail").lower()
    ifaces   = g("interfaces").lower()
    optics   = g("optics")
    mtu_out  = g("mtu")
    traffic  = g("traffic").lower()
    lldp_out = g("lldp").lower()
    lacp_out = g("lacp").lower()
    logs_out = g("logs").lower()
    ntp_out  = g("ntp").lower()
    alarms   = g("alarms").lower()
    routing  = g("routing").lower()
    stp_out  = g("stp").lower()
    errors   = g("errors")
    ports    = g("ports_all")

    # Score starts at 100, deductions applied for issues
    score = 100
    categories = {
        "infrastructure": {"icon": "🏗️", "title": "Infrastructure & Hardware", "items": []},
        "security":       {"icon": "🔒", "title": "Security Posture", "items": []},
        "performance":    {"icon": "⚡", "title": "Performance & Capacity", "items": []},
        "reliability":    {"icon": "🛡️", "title": "Reliability & Resilience", "items": []},
        "monitoring":     {"icon": "📡", "title": "Monitoring & Observability", "items": []},
        "risks":          {"icon": "⚠️", "title": "Identified Risks", "items": []},
    }

    def add(cat, severity, title, detail, remediation=""):
        categories[cat]["items"].append({
            "severity": severity,
            "title": title,
            "detail": detail,
            "remediation": remediation,
        })

    # ═══════════════════════════════════════════════════════════════════════
    # 1. INFRASTRUCTURE & HARDWARE
    # ═══════════════════════════════════════════════════════════════════════

    # ── Version / Model ───────────────────────────────────────────────────
    model = "Unknown"
    version = "Unknown"
    ver_raw = g("version")
    chassis_raw = g("chassis")
    if dtype == "junos":
        # ── Model extraction (ordered by reliability) ─────────────────
        # 1) 'show version' → "Model: ex4600-40f"
        m = re.search(r'Model:\s*(\S+)', ver_raw)
        if m:
            model = m.group(1)
        else:
            # 2) 'show chassis hardware' → FPC or Routing Engine description
            #    e.g. "FPC 0  REV 23  650-064288  TC3720180004  EX4600-40F"
            #    e.g. "Routing Engine 0  BUILTIN  BUILTIN  EX4600-40F"
            m = re.search(r'(?:FPC|Routing Engine)\s+\d+\s+.*?((?:EX|QFX|SRX|MX|ACX|PTX|NFX)\d+\S*)', chassis_raw, re.IGNORECASE)
            if m:
                model = m.group(1)
            else:
                # 3) Any EX/QFX/SRX/MX line in chassis (skip "Virtual Chassis")
                m = re.search(r'((?:EX|QFX|SRX|MX|ACX|PTX|NFX)\d+\S*)', chassis_raw)
                if m:
                    model = m.group(1)
                else:
                    # 4) Last resort: infer from hostname
                    h = hostname.lower()
                    if "-fw-" in h:   model = "SRX (from hostname)"
                    elif "-sw-" in h: model = "EX/QFX (from hostname)"
                    elif "-rt-" in h: model = "MX (from hostname)"

        # ── Version extraction (ordered by reliability) ───────────────
        cfg_raw = g("config_set") or g("config")
        # 1) 'show version' → "Junos: 21.4R3-S9.5"
        m = re.search(r'Junos:\s*(\S+)', ver_raw)
        # 2) 'show version' → "JUNOS Base OS boot [21.4R3-S9.5]"
        if not m: m = re.search(r'JUNOS\s+\S+\s+\[(\S+)\]', ver_raw)
        # 3) 'show configuration | display set' → "set version 21.4R3-S9.5"
        if not m: m = re.search(r'set\s+version\s+(\S+)', cfg_raw)
        # 4) 'show chassis hardware' JUNOS entries → [21.4R3-S9.5]
        if not m: m = re.search(r'JUNOS\s+\S+\s+\[(\S+)\]', chassis_raw)
        # 5) Look for version pattern anywhere in version output
        if not m: m = re.search(r'(\d+\.\d+R\d+\S*)', ver_raw)
        # 6) Look for version pattern in chassis output
        if not m: m = re.search(r'(\d+\.\d+R\d+\S*)', chassis_raw)
        # 7) Look for version pattern in config
        if not m: m = re.search(r'(\d+\.\d+R\d+\S*)', cfg_raw)
        if m: version = m.group(1)

        # Check for outdated Junos (use whichever source has data)
        ver_check = ver_out if ver_out.strip() else chassis_raw.lower()
        for old in ("17.", "18.", "19.", "20.1", "20.2", "20.3"):
            if old in ver_check:
                score -= 6
                add("infrastructure", "high", "Outdated Junos Version",
                    f"Running Junos {version} — may be end-of-life. Security vulnerabilities not patched.",
                    "Upgrade to Junos 22.x or 23.x following JTAC recommended releases")
                break
    else:
        # ── EOS Model extraction ──────────────────────────────────────
        eos_ver_raw = g("version")
        m = re.search(r'Arista\s+(DCS-\S+|CCS-\S+|\S+)', eos_ver_raw)
        if not m: m = re.search(r'(DCS-\S+|CCS-\S+|7\d{3,4}\S*)', eos_ver_raw)
        if m: model = m.group(1)
        # ── EOS Version extraction ────────────────────────────────────
        m = re.search(r'Software image version:\s*(\S+)', eos_ver_raw)
        if not m: m = re.search(r'(?:EOS|internal)\s+version\s+(\S+)', eos_ver_raw, re.IGNORECASE)
        if not m: m = re.search(r'(4\.\d+\.\d+\S*)', ver_out)
        if m: version = m.group(1)
        for old in ("4.19", "4.20", "4.21", "4.22", "4.23", "4.24"):
            if old in ver_out:
                score -= 6
                add("infrastructure", "high", "Outdated EOS Version",
                    f"Running EOS {version} — consider upgrading for security and feature support.",
                    "Upgrade to EOS 4.30+ following Arista upgrade procedures")
                break

    add("infrastructure", "info", "Device Identity",
        f"Model: {model} | Version: {version} | Type: {dtype.upper()}", "")

    # ── Uptime ────────────────────────────────────────────────────────────
    uptime_str = g("uptime").lower()
    if uptime_str:
        # Check for very long uptime (might mean missed patching window)
        year_m = re.search(r'(\d+)\s+year', uptime_str)
        if year_m and int(year_m.group(1)) >= 1:
            score -= 3
            add("infrastructure", "medium", "Extended Uptime",
                f"Device has been running for {year_m.group(1)}+ years without reboot — may have missed critical patches.",
                "Schedule maintenance window for firmware upgrade")

    # ── Alarms ────────────────────────────────────────────────────────────
    if alarms.strip() and "no alarms" not in alarms and "no active" not in alarms and len(alarms.strip()) > 10:
        score -= 10
        add("infrastructure", "critical", "Active Hardware Alarms",
            "Chassis alarms detected — possible hardware degradation (PSU, fan, temperature).",
            "Run 'show chassis alarms' and check hardware status immediately")
    else:
        add("infrastructure", "ok", "No Active Alarms", "Chassis hardware healthy — no active alarms.", "")

    # ── Chassis / Hardware ────────────────────────────────────────────────
    chassis_out = g("chassis").lower()
    if "failed" in chassis_out or "absent" in chassis_out:
        score -= 8
        add("infrastructure", "high", "Hardware Component Issue",
            "Failed or absent component detected in chassis hardware inventory.",
            "Check 'show chassis hardware' for failed FPC/PIC/PSU/Fan modules")

    # ═══════════════════════════════════════════════════════════════════════
    # 2. SECURITY POSTURE
    # ═══════════════════════════════════════════════════════════════════════

    if dtype == "junos":
        if "ssh-rsa" not in cfg_low and "ssh-ed25519" not in cfg_low and "set system login" in cfg_low:
            score -= 4
            add("security", "high", "No SSH Key Authentication",
                "Only password-based auth detected. SSH keys are more secure and auditable.",
                "set system login user <user> authentication ssh-rsa \"<key>\"")
        if "set system services ssh root-login" in cfg_low and "deny" not in cfg_low:
            score -= 3
            add("security", "high", "Root SSH Login Allowed",
                "Root can log in via SSH — violates principle of least privilege.",
                "set system services ssh root-login deny")
        if "set system syslog" not in cfg_low:
            score -= 5
            add("security", "high", "No Remote Syslog",
                "Logs are not sent to a centralized SIEM — incidents may go undetected.",
                "set system syslog host <syslog-ip> any warning")
        if "set security screen" not in cfg_low and "set security" in cfg_low:
            score -= 3
            add("security", "medium", "No IDS/IPS Screens",
                "Security screens (SYN flood, port scan protection) not configured on firewall.",
                "set security screen ids-option <name> icmp ping-death")
        if "set system services web-management" in cfg_low:
            score -= 2
            add("security", "low", "Web Management (J-Web) Enabled",
                "Web UI should be disabled unless actively needed — increases attack surface.",
                "delete system services web-management")
    else:
        if "aaa authorization" not in cfg_low:
            score -= 3
            add("security", "medium", "No AAA Authorization",
                "Commands not checked against TACACS+/RADIUS policy.",
                "aaa authorization exec default local")
        if "ip access-list" not in cfg_low:
            score -= 3
            add("security", "medium", "No Control-Plane ACLs",
                "Management plane unprotected — SSH/SNMP/NTP open to any source.",
                "ip access-list MGMT-ACL\n  permit tcp <mgmt-subnet> any eq ssh")
        if "logging host" not in cfg_low:
            score -= 5
            add("security", "high", "No Remote Syslog",
                "No remote syslog host configured. Incidents may go undetected.",
                "logging host <syslog-ip>")

    # SNMP
    if dtype == "junos":
        if "set snmp community" in cfg_low and "set snmp v3" not in cfg_low:
            score -= 2
            add("security", "medium", "Using SNMPv2c (Cleartext)",
                "SNMP community strings sent in cleartext — use SNMPv3 for encryption.",
                "set snmp v3 usm local-engine user <user> authentication-sha ...")
    else:
        if "snmp-server community" in cfg_low and "snmp-server user" not in cfg_low:
            score -= 2
            add("security", "medium", "Using SNMPv2c (Cleartext)",
                "SNMP community strings in cleartext. Migrate to SNMPv3.",
                "snmp-server user <user> <group> v3 auth sha <pass> priv aes <pass>")

    # Security score bonus for good practices
    sec_items = [i for i in categories["security"]["items"] if i["severity"] in ("high","critical")]
    if not sec_items:
        add("security", "ok", "Security Baseline Met",
            "No critical security issues detected in configuration.", "")

    # ═══════════════════════════════════════════════════════════════════════
    # 3. PERFORMANCE & CAPACITY
    # ═══════════════════════════════════════════════════════════════════════

    # ── Port Capacity ─────────────────────────────────────────────────────
    port_lines = [l for l in ports.splitlines() if l.strip()]
    total_ports = len(port_lines)
    up_ports = sum(1 for l in port_lines if " up " in l.lower() or "connected" in l.lower())
    if total_ports > 0:
        pct_used = round((up_ports / total_ports) * 100)
        add("performance", "info", "Port Utilization",
            f"{up_ports}/{total_ports} ports in use ({pct_used}%)", "")
        if pct_used >= 90:
            score -= 5
            add("performance", "high", "Critical Port Capacity",
                f"Port utilization at {pct_used}% — nearly exhausted. Plan for expansion.",
                "Review traffic engineering or add line cards/switches")
        elif pct_used >= 75:
            score -= 2
            add("performance", "medium", "High Port Utilization",
                f"Port utilization at {pct_used}% — approaching capacity.",
                "Track port usage trends and plan for capacity")

    # ── MTU Analysis ──────────────────────────────────────────────────────
    mtu_map = {}
    current_iface = None
    for line in mtu_out.splitlines():
        ls = line.strip()
        if not ls: continue
        if dtype == "junos":
            m = re.match(r'Physical interface:\s+(\S+)', ls)
            if m: current_iface = m.group(1).rstrip(","); continue
            if current_iface:
                m2 = re.search(r'MTU:\s*(\d+)', ls)
                if m2: mtu_map[current_iface] = int(m2.group(1)); current_iface = None
        else:
            m = _EOS_IFACE_MTU_RE.match(ls)
            if m: mtu_map[m.group(1)] = int(m.group(2))

    if mtu_map:
        mtu_values = set(mtu_map.values())
        non_jumbo = [f for f, v in mtu_map.items()
                     if v < 9000 and not f.lower().startswith(("lo","fxp","em","me","vme","management"))]
        default_1500 = [f for f, v in mtu_map.items()
                        if v == 1500 and not f.lower().startswith(("lo","fxp","em","me","vme","management"))]

        add("performance", "info", "MTU Overview",
            f"{len(mtu_map)} interfaces analyzed — {len(mtu_values)} unique MTU value(s): {sorted(mtu_values)}", "")

        if len(mtu_values) > 1:
            score -= 3
            add("performance", "medium", "Mixed MTU Values",
                f"Multiple MTU sizes detected on same device — can cause fragmentation and silent drops.",
                "Standardize MTU across all fabric interfaces (recommend 9192-9214)")
        if default_1500:
            score -= 3
            add("performance", "high", f"Default MTU (1500) on {len(default_1500)} Interface(s)",
                "Default MTU in DC fabric causes fragmentation. Examples: " + ", ".join(default_1500[:5]),
                "Configure jumbo MTU (9192+) on all DC fabric interfaces")

    # ── SFP / Optics Health ───────────────────────────────────────────────
    sfp_issues = []
    sfp_ok = 0
    if optics.strip():
        current_iface = None
        for line in optics.splitlines():
            ls = line.strip()
            ll = ls.lower()
            if not ls or ls.startswith("---") or ("port" in ll and "temp" in ll):
                continue

            # Junos interface header
            m = re.match(r'Physical interface:\s+(\S+)', ls)
            if m: current_iface = m.group(1); continue

            # EOS table row
            if dtype == "eos":
                m = re.match(r'^(Et\S+|Ethernet\S+)\s+(.+)', ls)
                if m:
                    iface = m.group(1)
                    rest = m.group(2)
                    nums = [v for v in rest.split() if v != "N/A" and re.match(r'^[-+]?\d+\.?\d*$', v)]
                    if len(nums) >= 2:
                        try:
                            rx = float(nums[-1])
                            if rx <= -30:
                                sfp_issues.append(f"{iface}: NO Rx light ({rx} dBm)")
                            elif rx < -10:
                                sfp_issues.append(f"{iface}: Low Rx ({rx} dBm)")
                            else:
                                sfp_ok += 1
                        except ValueError:
                            pass
                    continue

            # Junos Rx power
            if current_iface and ("receiver power" in ll or "rx power" in ll):
                dbm = re.search(r'([-+]?\d+\.?\d*)\s*dBm', ls)
                if dbm:
                    rx = float(dbm.group(1))
                    if rx <= -30:
                        sfp_issues.append(f"{current_iface}: NO Rx light ({rx} dBm)")
                    elif rx < -10:
                        sfp_issues.append(f"{current_iface}: Low Rx ({rx} dBm)")
                    else:
                        sfp_ok += 1
                else:
                    mw = re.search(r'([\d.]+)\s*mW', ls)
                    if mw:
                        mw_val = float(mw.group(1))
                        if mw_val > 0:
                            rx = round(10 * math.log10(mw_val), 2)
                            if rx <= -30:
                                sfp_issues.append(f"{current_iface}: NO Rx light ({rx} dBm)")
                            elif rx < -10:
                                sfp_issues.append(f"{current_iface}: Low Rx ({rx} dBm)")
                            else:
                                sfp_ok += 1

    if sfp_issues:
        score -= min(len(sfp_issues) * 2, 8)
        add("performance", "high" if any("NO Rx" in s for s in sfp_issues) else "medium",
            f"SFP/Optics Issues ({len(sfp_issues)})",
            "Degraded or failed optics: " + "; ".join(sfp_issues[:10]),
            "Replace failed SFPs, clean fiber connectors, verify fiber patch integrity")
    if sfp_ok > 0:
        add("performance", "ok", f"{sfp_ok} SFP Module(s) Healthy",
            "Tx/Rx power levels within normal range.", "")

    # ── Interface Errors ──────────────────────────────────────────────────
    if errors.strip():
        err_lines = [l for l in errors.splitlines() if l.strip() and "physical" not in l.lower()]
        if err_lines:
            score -= min(len(err_lines), 5)
            add("performance", "medium", f"Interface Errors/Drops ({len(err_lines)} lines)",
                "Active error counters on interfaces — may indicate CRC errors, duplex mismatch, or congestion.",
                "Check 'show interfaces extensive' for affected ports")

    # ═══════════════════════════════════════════════════════════════════════
    # 4. RELIABILITY & RESILIENCE
    # ═══════════════════════════════════════════════════════════════════════

    # ── BGP Analysis ──────────────────────────────────────────────────────
    bgp_established = bgp_out.count("established") + bgp_out.count("establ")
    bgp_active = bgp_out.count("active") if "established" not in bgp_out else 0
    bgp_idle = bgp_out.count("idle")
    bgp_connect = bgp_out.count("connect") if "established" not in bgp_out else 0

    if bgp_established > 0:
        add("reliability", "ok", f"BGP: {bgp_established} Session(s) Established",
            "BGP peering operational.", "")
    if bgp_idle > 0:
        score -= 5
        add("reliability", "high", f"BGP: {bgp_idle} Session(s) IDLE",
            "BGP session idle — possible authentication failure, misconfiguration, or route filtering.",
            "Check 'show bgp neighbor <ip>' for detailed error")
    if bgp_active > 0:
        score -= 3
        add("reliability", "medium", f"BGP: {bgp_active} Session(s) ACTIVE (not established)",
            "BGP trying to connect — check neighbor reachability and TCP port 179.",
            "Verify routing to neighbor IP and firewall rules")

    # BFD
    if bgp_established > 0 and "bfd" not in cfg_low:
        score -= 3
        add("reliability", "high", "No BFD for BGP",
            "BGP sessions rely on 90s hold-timer for failure detection. BFD provides sub-second failover.",
            "set protocols bgp group <group> bfd-liveness-detection minimum-interval 300" if dtype == "junos"
            else "router bgp <asn>\n  neighbor <ip> bfd")

    # ── NTP ───────────────────────────────────────────────────────────────
    if not ntp_out.strip() or "no association" in ntp_out or "error" in ntp_out:
        score -= 5
        add("reliability", "high", "NTP Not Configured",
            "Time synchronization is critical for log correlation, certificates, and troubleshooting.",
            "set system ntp server <ntp-server>" if dtype == "junos" else "ntp server <ntp-server>")
    elif "reject" in ntp_out:
        score -= 3
        add("reliability", "medium", "NTP Unreachable",
            "NTP server(s) show reject status — time may drift, affecting log accuracy.",
            "Verify routing to NTP servers and firewall rules")
    else:
        add("reliability", "ok", "NTP Synchronized", "Time synchronization operational.", "")

    # ── LACP ──────────────────────────────────────────────────────────────
    if lacp_out.strip():
        if "detached" in lacp_out or "defaulted" in lacp_out:
            score -= 6
            add("reliability", "high", "LACP Members Degraded",
                "LAG members in detached/defaulted state — reduced bandwidth and no redundancy on affected LAGs.",
                "Check physical cabling and remote switch LACP config")
        else:
            add("reliability", "ok", "LACP/LAG Healthy", "All LAG members operational.", "")

    # ── VPN (Junos only) ──────────────────────────────────────────────────
    ike_out = g("ike").lower()
    ipsec_out = g("ipsec").lower()
    if ike_out.strip() or ipsec_out.strip():
        if "up" in ike_out or "up" in ipsec_out:
            add("reliability", "ok", "VPN Tunnels Active", "IKE/IPsec tunnels are up.", "")
        elif len(ike_out.strip()) > 10 or len(ipsec_out.strip()) > 10:
            score -= 5
            add("reliability", "high", "VPN Tunnels Down",
                "IKE/IPsec tunnels not in UP state — remote site connectivity may be impacted.",
                "Check IKE Phase 1/2 with 'show security ike sa detail'")

    # ── Spanning Tree ─────────────────────────────────────────────────────
    if "topology change" in stp_out:
        score -= 2
        add("reliability", "medium", "STP Topology Changes Detected",
            "Spanning tree topology changes indicate network instability.",
            "Identify flapping ports causing STP reconvergence")

    # ── Redundancy ────────────────────────────────────────────────────────
    if dtype == "junos" and "vrrp" not in cfg_low and "virtual-gateway" not in cfg_low and "irb" in cfg_low:
        score -= 2
        add("reliability", "medium", "No Gateway Redundancy (VRRP)",
            "L3 gateway interfaces without VRRP/virtual-gateway — single point of failure.",
            "set interfaces <iface> unit <unit> family inet address <ip> vrrp-group <id> virtual-address <vip>")
    if dtype == "eos" and "mlag" not in cfg_low and "vlan" in cfg_low:
        add("reliability", "info", "No MLAG Configured",
            "Consider MLAG for switch-level redundancy in DC fabric.", "")

    # ═══════════════════════════════════════════════════════════════════════
    # 5. MONITORING & OBSERVABILITY
    # ═══════════════════════════════════════════════════════════════════════

    # SNMP
    has_snmp = "snmp" in cfg_low
    if has_snmp:
        add("monitoring", "ok", "SNMP Configured", "SNMP monitoring enabled for NMS integration.", "")
    else:
        score -= 2
        add("monitoring", "medium", "No SNMP Configuration",
            "Device not monitored via SNMP — missing from NMS dashboards.",
            "Configure SNMPv3 for monitoring integration")

    # LLDP
    if "lldp" in cfg_low or lldp_out.strip():
        lldp_neighbors = len([l for l in g("lldp").splitlines() if l.strip() and "lldp" not in l.lower() and "device" not in l.lower() and "---" not in l])
        add("monitoring", "ok", f"LLDP Active ({max(lldp_neighbors-1,0)} neighbors)",
            "Topology discovery enabled.", "")
    else:
        score -= 1
        add("monitoring", "low", "LLDP Not Configured",
            "LLDP aids in topology discovery and cable verification.",
            "set protocols lldp interface all" if dtype == "junos" else "lldp run")

    # Login banner
    has_banner = False
    if dtype == "junos" and "set system login message" in cfg_low: has_banner = True
    elif dtype == "eos" and "banner login" in cfg_low: has_banner = True
    if not has_banner:
        score -= 1
        add("monitoring", "low", "No Login Banner",
            "Legal warning banner required for compliance.",
            'set system login message "Authorized use only."' if dtype == "junos"
            else 'banner login\nAuthorized use only.\nEOF')

    # ═══════════════════════════════════════════════════════════════════════
    # 6. LOG ANALYSIS — RISK IDENTIFICATION
    # ═══════════════════════════════════════════════════════════════════════

    if logs_out:
        if "rpd_bgp" in logs_out or "bgp_io" in logs_out:
            add("risks", "medium", "BGP Events in Logs",
                "Routing daemon BGP events detected — possible session flaps or policy changes.", "")
        if "chassisd" in logs_out or "fpc" in logs_out:
            score -= 3
            add("risks", "high", "Chassis/FPC Errors in Logs",
                "Hardware-related log events — possible line card or hardware degradation.",
                "Investigate 'show chassis fpc' and 'show log messages | match fpc'")
        if "lacpd" in logs_out or "lag_bundle" in logs_out:
            add("risks", "medium", "LACP Events in Logs",
                "LAG instability events detected — member flaps or negotiation issues.", "")
        if "license" in logs_out:
            score -= 2
            add("risks", "medium", "License Events in Logs",
                "License-related events — possible expired or missing feature licenses.",
                "Check 'show system license' for expiry dates")
        if "kernel" in logs_out or "panic" in logs_out:
            score -= 8
            add("risks", "critical", "Kernel/Panic Events in Logs",
                "Critical system events detected — device stability at risk.",
                "Collect RSI and open TAC case immediately")
        if "snmp_trap_link" in logs_out or "link_down" in logs_out or "snmp_trap" in logs_out:
            add("risks", "medium", "Interface Flap Events",
                "SNMP trap link events suggest interface instability.", "")

    # ═══════════════════════════════════════════════════════════════════════
    # Final scoring
    # ═══════════════════════════════════════════════════════════════════════
    score = max(score, 0)

    if score >= 90:
        grade, grade_label = "A", "Excellent"
    elif score >= 75:
        grade, grade_label = "B", "Good"
    elif score >= 60:
        grade, grade_label = "C", "Fair"
    elif score >= 40:
        grade, grade_label = "D", "Poor"
    else:
        grade, grade_label = "F", "Critical"

    # Count severities
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "ok": 0}
    for cat in categories.values():
        for item in cat["items"]:
            sev_counts[item["severity"]] = sev_counts.get(item["severity"], 0) + 1

    return {
        "success": True,
        "hostname": hostname,
        "dtype": dtype,
        "model": model,
        "version": version,
        "score": score,
        "grade": grade,
        "grade_label": grade_label,
        "categories": categories,
        "severity_counts": sev_counts,
        "total_findings": sum(sev_counts.values()),
        "raw_data": {k: v[:200] + "..." if isinstance(v, str) and len(v) > 200 else v
                     for k, v in results.items()},
        "timestamp": datetime.now().isoformat(),
    }


@app.route("/api/deep-analysis", methods=["POST"])
def deep_analysis():
    """AI Agent: Collect ALL data and produce comprehensive cross-correlated health report.
    Combines SSH live data with LibreNMS historical bandwidth + 6-month forecast."""
    data     = request.json
    ip       = data.get("ip")
    dtype    = data.get("dtype", "junos")
    hostname = data.get("hostname", ip)

    if not ip:
        return jsonify({"success": False, "error": "Missing ip"}), 400

    cmds = _DEEP_CMDS_JUNOS if dtype == "junos" else _DEEP_CMDS_EOS
    result = run_commands_on_device(ip, dtype, cmds)

    if not result["success"]:
        return jsonify({"success": False, "error": result.get("error", "SSH failed")})

    report = _deep_analyze(hostname, dtype, result["results"])

    # ── Enrich with PyEZ NETCONF data (Junos only) ──────────────────────
    report["pyez_enriched"] = False
    if dtype == "junos":
        try:
            from pyez_collector import collect_all as pyez_collect_all
            # Try cached data first (from a previous Hardware button click)
            pyez = None
            cache_key = hostname.lower()
            if cache_key in _pyez_cache:
                cached = _pyez_cache[cache_key]
                if time.time() - cached["timestamp"] < _pyez_cache_ttl:
                    pyez = cached["result"]
            if pyez is None:
                pyez = pyez_collect_all(
                    ip,
                    ssh_mode=os.environ.get("DCN_SSH_MODE", "key"),
                    ssh_user=os.environ.get("DCN_SSH_USER", "netadmin"),
                    ssh_key_path=os.environ.get("DCN_SSH_KEY", os.path.expanduser("~/Downloads/05_Networking/netlab_admin")),
                    ssh_timeout=20,
                )
                # Cache the fresh result for reuse — entries also TTL-checked at read time
                if pyez.get("netconf_available"):
                    _bounded_insert(_pyez_cache, cache_key,
                                    {"result": pyez, "timestamp": time.time()},
                                    max_size=50)
            if pyez.get("netconf_available"):
                report["pyez_enriched"] = True
                cats = report.get("categories", {})
                infra = cats.get("infrastructure", {"icon": "🏗️", "title": "Infrastructure & Hardware", "items": []})
                perf = cats.get("performance", {"icon": "⚡", "title": "Performance & Capacity", "items": []})
                score_adj = 0

                # ── FPC Health ────────────────────────────────────────
                fpc_data = pyez.get("fpc_health", {}).get("data", [])
                if fpc_data:
                    fpc_critical = [f for f in fpc_data if f.get("status") == "critical"]
                    fpc_warning = [f for f in fpc_data if f.get("status") == "warning"]
                    fpc_online = [f for f in fpc_data if f.get("state", "").lower() == "online"]
                    fpc_offline = [f for f in fpc_data if f.get("state", "").lower() not in ("online", "empty", "unknown")]

                    if fpc_offline:
                        score_adj -= 12
                        detail = ", ".join(f"FPC {f['slot']}: {f['state']}" for f in fpc_offline)
                        infra["items"].append({
                            "severity": "critical",
                            "title": f"🔬 FPC Offline ({len(fpc_offline)} slot(s)) [PyEZ/NETCONF]",
                            "detail": f"Line card(s) not online: {detail}. Traffic on these slots is black-holed.",
                            "remediation": "Check 'show chassis fpc' and reseat or RMA failed FPC modules",
                        })

                    if fpc_critical:
                        for f in fpc_critical:
                            if f.get("state", "").lower() == "online":
                                score_adj -= 5
                                infra["items"].append({
                                    "severity": "high",
                                    "title": f"🔬 FPC {f['slot']} High Resource Usage [PyEZ]",
                                    "detail": f"CPU: {f['cpu_percent']}%, Memory: {f['memory_percent']}% — approaching system limits.",
                                    "remediation": "Investigate running processes; possible memory leak or route table overflow",
                                })

                    if fpc_warning:
                        for f in fpc_warning:
                            score_adj -= 2
                            infra["items"].append({
                                "severity": "medium",
                                "title": f"🔬 FPC {f['slot']} Elevated Resources [PyEZ]",
                                "detail": f"CPU: {f['cpu_percent']}%, Memory: {f['memory_percent']}% — monitor closely.",
                                "remediation": "Track resource trend; consider maintenance window if climbing",
                            })

                    if fpc_online and not fpc_critical and not fpc_warning and not fpc_offline:
                        infra["items"].append({
                            "severity": "ok",
                            "title": f"🔬 All {len(fpc_online)} FPC(s) Healthy [PyEZ/NETCONF]",
                            "detail": "All line cards online with normal CPU/memory utilization.",
                            "remediation": "",
                        })

                # ── Optic Diagnostics (PyEZ — more structured than CLI) ─
                optics_data = pyez.get("optics", {}).get("data", [])
                if optics_data:
                    optics_crit = [o for o in optics_data if o.get("status") == "critical"]
                    optics_warn = [o for o in optics_data if o.get("status") == "warning"]
                    if optics_crit:
                        score_adj -= min(len(optics_crit) * 3, 10)
                        detail = "; ".join(f"{o['name']}: RX={o.get('rx_power_dbm','?')}dBm TX={o.get('tx_power_dbm','?')}dBm" for o in optics_crit[:5])
                        perf["items"].append({
                            "severity": "critical",
                            "title": f"🔬 {len(optics_crit)} Optic(s) Critical [PyEZ/NETCONF]",
                            "detail": f"SFP modules failing or no light: {detail}",
                            "remediation": "Replace SFPs, clean fiber, check patch panel",
                        })
                    if optics_warn:
                        score_adj -= min(len(optics_warn), 4)
                        detail = "; ".join(f"{o['name']}: RX={o.get('rx_power_dbm','?')}dBm" for o in optics_warn[:5])
                        perf["items"].append({
                            "severity": "medium",
                            "title": f"🔬 {len(optics_warn)} Optic(s) Warning [PyEZ]",
                            "detail": f"Degraded optical power: {detail}",
                            "remediation": "Monitor trend; schedule SFP replacement during maintenance window",
                        })

                # ── Error Type Breakdown (PyEZ — granular counters) ────
                err_data = pyez.get("port_errors", {}).get("data", [])
                if err_data:
                    ports_with_errors = [e for e in err_data if e.get("has_errors")]
                    if ports_with_errors:
                        # Categorize error types across all ports
                        err_types = {
                            "CRC/Frame": sum(e.get("rx_frame_errors", 0) for e in ports_with_errors),
                            "Input Errors": sum(e.get("rx_errors", 0) for e in ports_with_errors),
                            "Input Drops": sum(e.get("rx_drops", 0) for e in ports_with_errors),
                            "Output Errors": sum(e.get("tx_errors", 0) for e in ports_with_errors),
                            "Output Drops": sum(e.get("tx_drops", 0) for e in ports_with_errors),
                            "Runts": sum(e.get("rx_runts", 0) for e in ports_with_errors),
                            "FIFO": sum(e.get("rx_fifo_errors", 0) + e.get("tx_fifo_errors", 0) for e in ports_with_errors),
                            "Carrier Transitions": sum(e.get("tx_carrier_transitions", 0) for e in ports_with_errors),
                            "Collisions": sum(e.get("tx_collisions", 0) for e in ports_with_errors),
                        }
                        active = {k: v for k, v in err_types.items() if v > 0}

                        if active:
                            # Determine worst error type
                            top3 = sorted(active.items(), key=lambda x: x[1], reverse=True)[:3]
                            breakdown = " | ".join(f"{k}: {v:,}" for k, v in top3)
                            top_ports = sorted(ports_with_errors, key=lambda e: e["total_errors"], reverse=True)[:3]
                            top_ports_str = ", ".join(f"{p['name']} ({p['total_errors']:,})" for p in top_ports)

                            sev = "high" if err_types.get("CRC/Frame", 0) > 0 or err_types.get("Runts", 0) > 0 else "medium"
                            if sev == "high":
                                score_adj -= 4
                            else:
                                score_adj -= 2

                            perf["items"].append({
                                "severity": sev,
                                "title": f"🔬 Error Breakdown: {len(ports_with_errors)} port(s) [PyEZ/NETCONF]",
                                "detail": f"Top error types: {breakdown}. Worst ports: {top_ports_str}",
                                "remediation": "CRC/Frame errors → check cabling/SFP. Drops → congestion or CoS. Carrier transitions → link flaps.",
                            })

                # ── Storage (PyEZ — structured) ───────────────────────
                stor_data = pyez.get("storage", {}).get("data", [])
                if stor_data:
                    # Filter actionable (same logic as frontend)
                    import re as _re
                    actionable = [s for s in stor_data
                                  if s.get("mounted_on")
                                  and not _re.match(r'^(devfs|procfs)$', s.get("filesystem", ""))
                                  and "/packages/mnt/" not in s.get("mounted_on", "")
                                  and s.get("mounted_on") not in ("/dev", "/proc")]
                    # Deduplicate
                    seen_mounts = set()
                    deduped = []
                    for s in actionable:
                        if s["mounted_on"] not in seen_mounts:
                            seen_mounts.add(s["mounted_on"])
                            deduped.append(s)

                    stor_crit = [s for s in deduped if s.get("used_percent", 0) >= 90]
                    stor_warn = [s for s in deduped if 75 <= s.get("used_percent", 0) < 90]

                    if stor_crit:
                        score_adj -= min(len(stor_crit) * 5, 15)
                        detail = ", ".join(f"{s['mounted_on']}: {s['used_percent']}%" for s in stor_crit)
                        infra["items"].append({
                            "severity": "critical",
                            "title": f"🔬 Filesystem Critical ({len(stor_crit)}) [PyEZ]",
                            "detail": f"Near-full filesystems: {detail}. May cause log loss or commit failures.",
                            "remediation": "request system storage cleanup / delete old core-dumps and log archives",
                        })
                    if stor_warn:
                        score_adj -= min(len(stor_warn) * 2, 6)
                        detail = ", ".join(f"{s['mounted_on']}: {s['used_percent']}%" for s in stor_warn)
                        infra["items"].append({
                            "severity": "high",
                            "title": f"🔬 Filesystem Warning ({len(stor_warn)}) [PyEZ]",
                            "detail": f"Filling filesystems: {detail}",
                            "remediation": "Schedule cleanup; check for large core files or excessive logs",
                        })

                # ── Apply score adjustment ─────────────────────────────
                if score_adj != 0:
                    new_score = max(0, report.get("score", 100) + score_adj)
                    report["score"] = new_score
                    if new_score >= 90:   report["grade"], report["grade_label"] = "A", "Excellent"
                    elif new_score >= 75: report["grade"], report["grade_label"] = "B", "Good"
                    elif new_score >= 60: report["grade"], report["grade_label"] = "C", "Fair"
                    elif new_score >= 40: report["grade"], report["grade_label"] = "D", "Poor"
                    else:                 report["grade"], report["grade_label"] = "F", "Critical"

                # ── Recount severities after PyEZ findings ─────────────
                sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "ok": 0}
                for cat in cats.values():
                    for item in cat.get("items", []):
                        sev_counts[item["severity"]] = sev_counts.get(item["severity"], 0) + 1
                report["severity_counts"] = sev_counts
                report["total_findings"] = sum(sev_counts.values())
        except ImportError:
            pass  # junos-eznc not installed — skip PyEZ enrichment
        except Exception:
            pass  # PyEZ enrichment is best-effort; SSH report always returned

    # ── Enrich with LibreNMS bandwidth forecast ──────────────────────────
    report["bandwidth_forecast"] = None
    try:
        region = _lnms_region_for_host(hostname)
        dev, region = _lnms_find_device(hostname, region)
        if dev:
            device_id = dev.get("device_id")
            hw = (dev.get("hardware") or "").lower()
            sysname = hostname.lower()

            if any(x in hw for x in ("srx", "firewall", "palo")) or "-fw-" in sysname:
                role, mg = "firewall", 3.0
            elif any(x in hw for x in ("mx", "router", "7280")) or "-rt-" in sysname:
                role, mg = "router", 5.0
            else:
                role, mg = "switch", 4.0

            pdata = _lnms_api(region, f"/devices/{device_id}/ports",
                              params={"columns": "ifName,ifAlias,ifSpeed,ifOperStatus,"
                                      "ifInOctets_rate,ifOutOctets_rate"})
            ports = pdata.get("ports", [])

            total_cap = 0
            total_used = 0
            crit_ports = []
            warn_ports = []
            risk_ports = []
            top_util = []

            for p in ports:
                ifname = p.get("ifName", "")
                if not ifname or ifname.startswith(("lo", "irb", "vlan", "vtep", "vme", "jsrv", "pip", "bme")):
                    continue
                if ifname in ("fxp0", "Management1", "em0"):
                    continue
                if ".0" in ifname:
                    continue
                if p.get("ifOperStatus") != "up":
                    continue
                speed = p.get("ifSpeed") or 0
                if speed < 1_000_000_000:
                    continue

                in_bps = (p.get("ifInOctets_rate") or 0) * 8
                out_bps = (p.get("ifOutOctets_rate") or 0) * 8
                peak = max(in_bps, out_bps)
                cur_util = (peak / speed * 100) if speed else 0
                total_cap += speed
                total_used += peak

                # 6-month projection
                proj6 = peak * ((1 + mg / 100) ** 6)
                proj6_util = (proj6 / speed * 100) if speed else 0

                entry = {"ifName": ifname, "ifAlias": p.get("ifAlias", ""),
                         "speed_gbps": round(speed / 1e9, 1),
                         "current_mbps": round(peak / 1e6, 1),
                         "current_util_pct": round(cur_util, 1),
                         "month6_util_pct": round(proj6_util, 1)}

                top_util.append(entry)
                if proj6_util >= 100:
                    crit_ports.append(entry)
                elif proj6_util >= 80:
                    warn_ports.append(entry)
                elif cur_util > 60:
                    risk_ports.append(entry)

            top_util.sort(key=lambda x: x["current_util_pct"], reverse=True)
            overall_util = round(total_used / total_cap * 100, 1) if total_cap else 0
            overall_6mo = round(total_used * ((1 + mg / 100) ** 6) / total_cap * 100, 1) if total_cap else 0

            # Inject findings into the report's performance category
            cats = report.get("categories", {})
            perf = cats.get("performance", {"items": []})
            score_adj = 0

            perf["items"].append({
                "severity": "info",
                "title": "📊 LibreNMS Bandwidth Overview",
                "detail": (f"Total capacity: {round(total_cap/1e9,1)} Gbps | "
                           f"Current usage: {round(total_used/1e9,1)} Gbps ({overall_util}%) | "
                           f"6-month projection: {overall_6mo}% @ {mg}%/mo growth"),
                "remediation": "",
            })

            if top_util[:5]:
                top5 = " | ".join(f"{p['ifName']} ({p['ifAlias']}): {p['current_util_pct']}%"
                                  for p in top_util[:5])
                perf["items"].append({
                    "severity": "info",
                    "title": "Top 5 Busiest Ports (LibreNMS)",
                    "detail": top5,
                    "remediation": "",
                })

            if crit_ports:
                score_adj -= 15
                detail = ", ".join(f"{p['ifName']} ({p['ifAlias']}): {p['current_util_pct']}% → {p['month6_util_pct']}%"
                                  for p in crit_ports[:5])
                perf["items"].append({
                    "severity": "critical",
                    "title": f"🔴 {len(crit_ports)} Port(s) Will Exceed 100% in 6 Months",
                    "detail": detail,
                    "remediation": "Upgrade port speed or add LAG members immediately. Order hardware if needed.",
                })

            if warn_ports:
                score_adj -= 8
                detail = ", ".join(f"{p['ifName']} ({p['ifAlias']}): {p['current_util_pct']}% → {p['month6_util_pct']}%"
                                  for p in warn_ports[:5])
                perf["items"].append({
                    "severity": "high",
                    "title": f"🟠 {len(warn_ports)} Port(s) Will Exceed 80% in 6 Months",
                    "detail": detail,
                    "remediation": "Plan capacity upgrade. Evaluate traffic engineering or load balancing.",
                })

            if risk_ports:
                score_adj -= 3
                detail = ", ".join(f"{p['ifName']} @ {p['current_util_pct']}%" for p in risk_ports[:5])
                perf["items"].append({
                    "severity": "medium",
                    "title": f"🟡 {len(risk_ports)} Port(s) Above 60% Utilization",
                    "detail": detail,
                    "remediation": "Monitor closely. Add to capacity planning review.",
                })

            # Only adjust score if LibreNMS found actual bandwidth issues
            if score_adj != 0:
                new_score = max(0, report.get("score", 100) + score_adj)
                report["score"] = new_score
                if new_score >= 90:   report["grade"], report["grade_label"] = "A", "Excellent"
                elif new_score >= 75: report["grade"], report["grade_label"] = "B", "Good"
                elif new_score >= 60: report["grade"], report["grade_label"] = "C", "Fair"
                elif new_score >= 40: report["grade"], report["grade_label"] = "D", "Poor"
                else:                 report["grade"], report["grade_label"] = "F", "Critical"

            # Recount severities (always — we added info items)
            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "ok": 0}
            for cat in cats.values():
                for item in cat.get("items", []):
                    sev_counts[item["severity"]] = sev_counts.get(item["severity"], 0) + 1
            report["severity_counts"] = sev_counts
            report["total_findings"] = sum(sev_counts.values())

            # Add forecast summary to response
            report["bandwidth_forecast"] = {
                "source": "LibreNMS",
                "region": region,
                "hardware": dev.get("hardware"),
                "librenms_version": dev.get("version"),
                "monthly_growth_pct": mg,
                "total_capacity_gbps": round(total_cap / 1e9, 1),
                "total_used_gbps": round(total_used / 1e9, 1),
                "current_util_pct": overall_util,
                "projected_6month_util_pct": overall_6mo,
                "critical_ports": len(crit_ports),
                "warning_ports": len(warn_ports),
                "at_risk_ports": len(risk_ports),
                "top_ports": top_util[:10],
            }
    except Exception:
        pass  # LibreNMS enrichment is best-effort; SSH report is always returned

    # ── LLM-powered executive narrative (DISABLED — structured findings sufficient) ──
    report["llm_narrative"] = None
    report["llm_powered"] = False

    return jsonify(report)


# ── AI Log Intelligence ───────────────────────────────────────────────────────

_LOG_CMDS_JUNOS = {
    "logs":     "show log messages | last 1000 | no-more",
    "logs_alt": "show log default-log-messages | last 1000 | no-more",
    "logs0":    "show log messages.0 | last 500 | no-more",
}
_LOG_CMDS_EOS = {
    "logs": "show logging last 1000",
}

# Pattern definitions: (regex, severity, category, action, description)
_LOG_PATTERNS = [
    # ── CRITICAL ──
    (r"kernel\s*panic|core\s*dump|watchdog.*reset",            "critical", "system",     "Escalate immediately",          "Kernel panic / core dump — hardware or OS failure"),
    (r"fpc\d+.*offline|fpc\d+.*error|fpc\d+.*power.?off",     "critical", "hardware",   "Check line card / FPC health",  "FPC/Line card offline or error"),
    (r"chassis.*alarm|major\s+alarm|minor\s+alarm",            "critical", "hardware",   "Investigate chassis alarms",    "Chassis alarm triggered"),
    (r"power\s*supply.*fail|psu.*fail|fan.*fail",              "critical", "hardware",   "Replace failed PSU/fan",        "Power supply or fan failure"),
    (r"memory.*full|out\s+of\s+memory|heap.*exhaust",          "critical", "system",     "Investigate memory leak",       "Memory exhaustion detected"),
    (r"disk.*full|storage.*full|no\s+space",                   "critical", "system",     "Clean up storage",              "Disk/storage full"),

    # ── HIGH ──
    (r"bgp.*(?:down|cease|notification|hold.?timer.*expired)", "high",     "routing",    "Check BGP peer status",         "BGP peer down / session reset"),
    (r"ospf.*(?:neighbor.*down|adj.*change|dead.*timer)",      "high",     "routing",    "Check OSPF adjacency",          "OSPF neighbor state change"),
    (r"bfd.*(?:down|session.*removed)",                        "high",     "routing",    "Check BFD session & link",      "BFD session down"),
    (r"license.*expir|license.*invalid|license.*warning",      "high",     "compliance", "Renew license",                 "License expiration or issue"),
    (r"ike.*fail|ipsec.*fail|vpn.*down|tunnel.*down",          "high",     "vpn",        "Check VPN tunnel status",       "VPN/IPsec tunnel failure"),
    (r"lacp.*timeout|lacp.*expired|lag.*down|ae\d+.*down",     "high",     "lag",        "Check LAG member links",        "LACP/LAG member down or timeout"),
    (r"mlag.*fail|mlag.*inconsist|mlag.*disabled",             "high",     "lag",        "Check MLAG state",              "MLAG failure or inconsistency"),
    (r"snmp_trap_link_down|link\s+down|carrier.*down",         "high",     "interface",  "Check physical link",           "Interface link down event"),
    (r"err-disabled|errdisable|shutdown.*error",               "high",     "interface",  "Check err-disable reason",      "Interface error-disabled"),
    (r"authentication.*fail|login.*fail|sshd.*fail",           "high",     "security",   "Review auth logs",              "Authentication failure"),
    (r"rpd_bgp_neighbor_state_changed.*idle",                  "high",     "routing",    "Check BGP peer & config",       "BGP peer transitioned to Idle"),
    (r"vrrp.*master.*change|vrrp.*backup|failover",            "high",     "redundancy", "Verify VRRP/failover state",    "VRRP/failover state change"),

    # ── MEDIUM ──
    (r"snmp_trap_link_up|link\s+up|carrier.*up",               "medium",   "interface",  "Verify link stability",         "Interface link up event"),
    (r"rpd_bgp_neighbor_state_changed.*estab",                 "medium",   "routing",    "Monitor — BGP established",     "BGP peer established"),
    (r"ntp.*(?:unreachable|stratum.*16|no.*server)",           "medium",   "ntp",        "Check NTP configuration",       "NTP server unreachable"),
    (r"stp.*(?:tcn|topology.*change|root.*change)",            "medium",   "stp",        "Investigate STP changes",       "STP topology change detected"),
    (r"interface.*flap|flapping",                              "medium",   "interface",  "Check cable/SFP on interface",  "Interface flapping"),
    (r"pfe.*discard|packet.*drop|policer.*drop",               "medium",   "performance","Check traffic policing",        "Packet drops / policer discard"),
    (r"temperature.*warning|temp.*high|thermal",               "medium",   "hardware",   "Check environment cooling",     "Temperature warning"),
    (r"snmp.*community|snmp.*trap",                            "medium",   "monitoring", "Review SNMP config",            "SNMP activity"),
    (r"acl.*deny|firewall.*deny|filter.*block",               "medium",   "security",   "Review ACL/firewall hits",      "Firewall/ACL deny event"),
    (r"ddos|flood|storm",                                      "medium",   "security",   "Check for traffic anomalies",   "Potential DDoS/storm detected"),

    # ── LOW ──
    (r"user.*login|sshd.*accepted|session.*opened",            "low",      "auth",       "Informational — user login",    "User login event"),
    (r"user.*logout|session.*closed",                          "low",      "auth",       "Informational — user logout",   "User logout event"),
    (r"commit.*confirmed|configuration.*changed|commit",       "low",      "config",     "Audit trail — config change",   "Configuration change committed"),
    (r"snmpd|agentx",                                          "low",      "monitoring", "Normal SNMP activity",          "SNMP daemon activity"),
    (r"cron|scheduled|periodic",                               "low",      "system",     "Informational — scheduled task", "Scheduled task execution"),
    (r"transfer.*complete|backup.*complete|archive",           "low",      "system",     "Informational — backup/archive","File transfer or backup"),
    (r"lldp.*neighbor|lldp.*add|lldp.*delete",                "low",      "discovery",  "Informational — neighbor change","LLDP neighbor change"),
]


def _analyze_logs(hostname, dtype, raw_logs):
    """Classify each syslog line by severity, category, and required action."""

    lines = [l.strip() for l in raw_logs.splitlines() if l.strip()]
    # Skip header lines (e.g., "show logging..." echo, dashes, empty)
    filtered = []
    for l in lines:
        ll = l.lower()
        if ll.startswith("show ") or ll.startswith("---") or ll.startswith("==="):
            continue
        if len(l) < 10:
            continue
        filtered.append(l)

    classified = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    category_counts = {}

    for line in filtered:
        ll = line.lower()
        matched = False
        for pattern, sev, cat, action, desc in _LOG_PATTERNS:
            if re.search(pattern, ll):
                classified.append({
                    "line": line,
                    "severity": sev,
                    "category": cat,
                    "action": action,
                    "description": desc,
                })
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                category_counts[cat] = category_counts.get(cat, 0) + 1
                matched = True
                break
        if not matched:
            classified.append({
                "line": line,
                "severity": "info",
                "category": "other",
                "action": "No action needed",
                "description": "Unclassified log message",
            })
            severity_counts["info"] += 1
            category_counts["other"] = category_counts.get("other", 0) + 1

    # Sort: critical first, then high, medium, low, info
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    classified.sort(key=lambda x: sev_order.get(x["severity"], 5))

    # Build top issues summary
    top_issues = [m for m in classified if m["severity"] in ("critical", "high")]

    # Action items — deduplicated by (severity, description)
    seen_actions = set()
    action_items = []
    for m in classified:
        if m["severity"] in ("critical", "high", "medium"):
            key = (m["severity"], m["description"])
            if key not in seen_actions:
                seen_actions.add(key)
                action_items.append({
                    "severity": m["severity"],
                    "category": m["category"],
                    "action": m["action"],
                    "description": m["description"],
                    "count": sum(1 for x in classified if x["description"] == m["description"]),
                })

    action_items.sort(key=lambda x: (sev_order.get(x["severity"], 5), -x["count"]))

    return {
        "success": True,
        "hostname": hostname,
        "dtype": dtype,
        "total_messages": len(filtered),
        "classified": len([m for m in classified if m["severity"] != "info"]),
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "action_items": action_items,
        "top_issues": top_issues[:30],
        "messages": classified,
        "timestamp": datetime.now().isoformat(),
    }


@app.route("/api/log-analysis", methods=["POST"])
def log_analysis():
    """AI Log Intelligence: Collect last ~1000 syslog messages and classify each."""
    data     = request.json
    ip       = data.get("ip")
    dtype    = data.get("dtype", "junos")
    hostname = data.get("hostname", ip)

    if not ip:
        return jsonify({"success": False, "error": "Missing ip"}), 400

    cmds = _LOG_CMDS_JUNOS if dtype == "junos" else _LOG_CMDS_EOS
    result = run_commands_on_device(ip, dtype, cmds)

    if not result["success"]:
        return jsonify({"success": False, "error": result.get("error", "SSH failed")})

    # Merge all log sources (Junos may have multiple: messages, default-log-messages, messages.0)
    raw_parts = []
    for key in ("logs", "logs_alt", "logs0"):
        part = result["results"].get(key, "")
        if part and "could not open" not in part and "No such file" not in part and "could not resolve" not in part:
            raw_parts.append(part)
    raw_logs = "\n".join(raw_parts)
    report = _analyze_logs(hostname, dtype, raw_logs)

    # ── LLM-powered log narrative (DISABLED — structured findings sufficient) ──
    report["llm_narrative"] = None
    report["llm_powered"] = False

    return jsonify(report)


# ══════════════════════════════════════════════════════════════════════════════
# ── 🔮 CONFIG DRIFT & COMPLIANCE AUDITOR ─────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_JUNOS_CONFIG_DIR = os.environ.get("DCN_JUNOS_CONFIG_DIR",
    os.path.normpath(os.path.join(os.path.dirname(__file__), "../../01_Device_Configurations/junos")))

_DRIFT_CMDS_JUNOS = {
    "config_set": "show configuration | display set",
    "version":    "show version | no-more",
    "ntp":        "show configuration system ntp | display set",
    "snmp":       "show configuration snmp | display set",
    "syslog":     "show configuration system syslog | display set",
    "aaa":        "show configuration system login | display set",
    "security":   "show configuration security | display set",
    "bgp_cfg":    "show configuration protocols bgp | display set",
    "firewall":   "show configuration firewall | display set",
    "lldp_cfg":   "show configuration protocols lldp | display set",
    "banner":     "show configuration system login message | display set",
    "services":   "show configuration system services | display set",
}
_DRIFT_CMDS_EOS = {
    "config_set": "show running-config",
    "version":    "show version",
    "ntp":        "show running-config section ntp",
    "snmp":       "show running-config section snmp",
    "syslog":     "show running-config section logging",
    "aaa":        "show running-config section aaa",
    "bgp_cfg":    "show running-config section router bgp",
    "lldp_cfg":   "show running-config section lldp",
    "banner":     "show running-config section banner",
    "services":   "show running-config section management",
}

_COMPLIANCE_CHECKS = [
    # (id, title, severity, check_fn_name, remediation_junos, remediation_eos)
    ("ntp_configured",   "NTP Servers Configured",    "high",     "check_ntp"),
    ("ntp_auth",         "NTP Authentication",         "medium",   "check_ntp_auth"),
    ("snmp_v3",          "SNMPv3 Preferred over v2c",  "high",     "check_snmpv3"),
    ("snmp_community",   "SNMP Community Not Default",  "critical", "check_snmp_default"),
    ("syslog_remote",    "Remote Syslog Configured",   "high",     "check_syslog_remote"),
    ("aaa_tacacs",       "TACACS+/RADIUS AAA",         "high",     "check_aaa"),
    ("login_banner",     "Login Banner Present",       "medium",   "check_banner"),
    ("ssh_v2_only",      "SSH v2 Only",                "high",     "check_sshv2"),
    ("root_login",       "Root Login Restricted",      "critical", "check_root_login"),
    ("password_policy",  "Password Complexity/Retry",  "medium",   "check_password"),
    ("lldp_enabled",     "LLDP Enabled",               "low",      "check_lldp"),
    ("bgp_auth",         "BGP MD5/TCP-AO Auth",        "high",     "check_bgp_auth"),
    ("firewall_filter",  "Loopback Filter / ACL",      "high",     "check_loopback_filter"),
    ("idle_timeout",     "Session Idle Timeout",       "medium",   "check_idle_timeout"),
    ("rescue_config",    "Rescue Configuration Saved", "medium",   "check_rescue"),
    ("console_security", "Console Port Security",      "medium",   "check_console"),
    ("dns_configured",   "DNS Name Servers Set",       "low",      "check_dns"),
    ("logging_level",    "Appropriate Logging Level",  "low",      "check_log_level"),
]


def _run_compliance(hostname, dtype, results):
    """Run all compliance checks and compute drift + compliance report."""
    cfg = (results.get("config_set") or "").lower()
    checks = []
    score = 100
    passed = 0
    failed = 0
    warnings = 0

    sev_penalty = {"critical": 12, "high": 7, "medium": 4, "low": 1}

    for check_id, title, severity, fn_name in _COMPLIANCE_CHECKS:
        status, detail, remediation = _compliance_check(fn_name, dtype, cfg, results)
        item = {
            "id": check_id,
            "title": title,
            "severity": severity,
            "status": status,  # "pass", "fail", "warn"
            "detail": detail,
            "remediation": remediation,
        }
        checks.append(item)
        if status == "pass":
            passed += 1
        elif status == "fail":
            failed += 1
            score -= sev_penalty.get(severity, 3)
        else:
            warnings += 1
            score -= sev_penalty.get(severity, 3) // 2

    score = max(0, min(100, score))
    grade = "A+" if score >= 95 else "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"

    # ── Config drift detection ────────────────────────────────────────────
    drift_items = []
    live_config = results.get("config_set", "")
    saved_path = None
    saved_config = ""

    base_hostname = hostname.lower().split(".")[0]
    # Try to find saved config
    if dtype == "eos":
        p = os.path.join(_EOS_CONFIG_DIR, f"{base_hostname}.txt")
        if os.path.isfile(p):
            saved_path = p
    else:
        p = os.path.join(_JUNOS_CONFIG_DIR, f"{base_hostname}.txt")
        if os.path.isfile(p):
            saved_path = p

    if saved_path:
        try:
            with open(saved_path, "r") as f:
                saved_config = f.read()
        except Exception:
            pass

    if saved_config and live_config:
        if dtype == "eos":
            drift_items = _diff_eos_configs(saved_config, live_config)
        else:
            drift_items = _diff_junos_configs(saved_config, live_config)

    return {
        "success": True,
        "hostname": hostname,
        "dtype": dtype,
        "compliance_score": score,
        "grade": grade,
        "total_checks": len(checks),
        "passed": passed,
        "failed": failed,
        "warnings": warnings,
        "checks": checks,
        "drift_detected": len(drift_items) > 0,
        "drift_count": len(drift_items),
        "drift_items": drift_items[:100],
        "saved_config_found": saved_path is not None,
        "saved_config_path": os.path.basename(saved_path) if saved_path else None,
        "timestamp": datetime.now().isoformat(),
    }


def _compliance_check(fn_name, dtype, cfg, results):
    """Run a single compliance check. Returns (status, detail, remediation)."""
    ntp_cfg = (results.get("ntp") or "").lower()
    snmp_cfg = (results.get("snmp") or "").lower()
    syslog_cfg = (results.get("syslog") or "").lower()
    aaa_cfg = (results.get("aaa") or "").lower()
    banner_cfg = (results.get("banner") or "").lower()
    bgp_cfg_out = (results.get("bgp_cfg") or "").lower()
    fw_cfg = (results.get("firewall") or "").lower()
    services_cfg = (results.get("services") or "").lower()
    lldp_cfg = (results.get("lldp_cfg") or "").lower()

    if fn_name == "check_ntp":
        if dtype == "junos":
            if "set system ntp server" in ntp_cfg or "ntp server" in cfg:
                servers = [l for l in ntp_cfg.splitlines() if "server" in l]
                return ("pass", f"NTP configured with {len(servers)} server(s)", "")
            return ("fail", "No NTP servers configured", "set system ntp server 10.0.0.1")
        else:
            if "ntp server" in cfg:
                servers = [l for l in cfg.splitlines() if "ntp server" in l]
                return ("pass", f"NTP configured with {len(servers)} server(s)", "")
            return ("fail", "No NTP servers configured", "ntp server 10.0.0.1")

    if fn_name == "check_ntp_auth":
        if "authentication-key" in ntp_cfg or "ntp authentication" in cfg:
            return ("pass", "NTP authentication enabled", "")
        return ("warn", "NTP authentication not configured", "set system ntp authentication-key ..." if dtype == "junos" else "ntp authenticate")

    if fn_name == "check_snmpv3":
        if "v3" in snmp_cfg or "snmp-server view" in cfg:
            return ("pass", "SNMPv3 configured", "")
        if "community" in snmp_cfg or "snmp-server community" in cfg:
            return ("warn", "Only SNMPv2c community strings found — SNMPv3 recommended", "set snmp v3 ..." if dtype == "junos" else "snmp-server view ...")
        return ("fail", "No SNMP configured", "Configure SNMPv3 for monitoring")

    if fn_name == "check_snmp_default":
        defaults = ["public", "private", "community"]
        for d in defaults:
            if f'community {d}' in snmp_cfg or f'community {d}' in cfg:
                return ("fail", f"Default SNMP community '{d}' detected — change immediately", "set snmp community <secure-string>" if dtype == "junos" else "snmp-server community <secure>")
        if "community" in snmp_cfg or "community" in cfg:
            return ("pass", "Non-default SNMP community strings", "")
        return ("pass", "No community strings configured (OK if using v3)", "")

    if fn_name == "check_syslog_remote":
        if dtype == "junos":
            if "host" in syslog_cfg and ("10." in syslog_cfg or "172." in syslog_cfg or "192." in syslog_cfg):
                hosts = [l for l in syslog_cfg.splitlines() if "host" in l]
                return ("pass", f"Remote syslog configured ({len(hosts)} target(s))", "")
            return ("fail", "No remote syslog targets", "set system syslog host 10.x.x.x any any")
        else:
            if "logging host" in cfg:
                return ("pass", "Remote syslog configured", "")
            return ("fail", "No remote syslog targets", "logging host 10.x.x.x")

    if fn_name == "check_aaa":
        if "tacplus" in cfg or "tacacs" in cfg or "radius" in cfg:
            return ("pass", "AAA (TACACS+/RADIUS) configured", "")
        return ("warn", "No TACACS+/RADIUS — using local auth only", "set system tacplus-server ..." if dtype == "junos" else "aaa group server tacacs+ ...")

    if fn_name == "check_banner":
        if banner_cfg.strip() and len(banner_cfg.strip()) > 10:
            return ("pass", "Login banner configured", "")
        if "banner" in cfg and "authorized" in cfg:
            return ("pass", "Login banner present", "")
        return ("fail", "No login banner — required for legal compliance", "set system login message \"Authorized use only\"" if dtype == "junos" else "banner login \"Authorized use only\"")

    if fn_name == "check_sshv2":
        if dtype == "junos":
            if "protocol-version v2" in services_cfg or "ssh" in services_cfg:
                return ("pass", "SSH enabled (Junos defaults to v2)", "")
            return ("warn", "SSH version not explicitly set to v2", "set system services ssh protocol-version v2")
        else:
            if "ssh" in cfg:
                return ("pass", "SSH enabled", "")
            return ("fail", "SSH not found in config", "management ssh / ip ssh version 2")

    if fn_name == "check_root_login":
        if dtype == "junos":
            if "root-login deny" in cfg or "root-login allow-configuration" in cfg:
                return ("pass", "Root login restricted", "")
            return ("fail", "Root login not restricted", "set system root-login deny")
        else:
            if "no username admin" in cfg or "aaa root" in cfg:
                return ("pass", "Root/admin access controlled", "")
            return ("warn", "Verify root/admin login is restricted", "")

    if fn_name == "check_password":
        if "retry-options" in cfg or "tries-before-disconnect" in cfg or "aaa authentication" in cfg:
            return ("pass", "Password/login retry policy configured", "")
        return ("warn", "No login retry/lockout policy detected", "set system login retry-options tries-before-disconnect 3" if dtype == "junos" else "aaa authentication attempts max-fail 3")

    if fn_name == "check_lldp":
        if lldp_cfg.strip() or "lldp run" in cfg or "lldp interface" in cfg:
            return ("pass", "LLDP enabled", "")
        return ("fail", "LLDP not configured", "set protocols lldp interface all" if dtype == "junos" else "lldp run")

    if fn_name == "check_bgp_auth":
        if "authentication-key" in bgp_cfg_out or "password" in bgp_cfg_out:
            return ("pass", "BGP session authentication configured", "")
        if "neighbor" in bgp_cfg_out or "group" in bgp_cfg_out:
            return ("warn", "BGP sessions without MD5/TCP-AO authentication", "set protocols bgp group <g> neighbor <ip> authentication-key <key>" if dtype == "junos" else "neighbor <ip> password <key>")
        return ("pass", "No BGP configured (N/A)", "")

    if fn_name == "check_loopback_filter":
        if dtype == "junos":
            if "lo0" in fw_cfg or "protect-re" in fw_cfg or "filter" in fw_cfg:
                return ("pass", "Loopback/RE protection filter found", "")
            return ("fail", "No loopback protection filter — RE exposed", "set firewall family inet filter protect-re ...")
        else:
            if "access-list" in cfg or "ip access-group" in cfg or "control-plane" in cfg:
                return ("pass", "ACLs / control-plane protection found", "")
            return ("warn", "No explicit control-plane ACL detected", "ip access-list ...")

    if fn_name == "check_idle_timeout":
        if "idle-timeout" in cfg or "exec-timeout" in cfg:
            return ("pass", "Session idle timeout configured", "")
        return ("warn", "No idle timeout — sessions may persist indefinitely", "set system login idle-timeout 15" if dtype == "junos" else "line vty 0 15 / exec-timeout 15")

    if fn_name == "check_rescue":
        if dtype == "junos":
            if "rescue" in cfg:
                return ("pass", "Rescue configuration referenced", "")
            return ("warn", "No rescue configuration saved", "request system configuration rescue save")
        return ("pass", "N/A for EOS (startup-config is persistent)", "")

    if fn_name == "check_console":
        if "console" in cfg and ("insecure" not in cfg):
            return ("pass", "Console port configured", "")
        if "insecure" in cfg:
            return ("fail", "Console marked insecure", "set system ports console type vt100")
        return ("warn", "Console security not explicitly configured", "")

    if fn_name == "check_dns":
        if "name-server" in cfg or "ip name-server" in cfg:
            return ("pass", "DNS name servers configured", "")
        return ("warn", "No DNS name servers", "set system name-server 8.8.8.8" if dtype == "junos" else "ip name-server 8.8.8.8")

    if fn_name == "check_log_level":
        if "severity" in syslog_cfg or "logging level" in cfg or "any any" in syslog_cfg:
            return ("pass", "Logging severity level set", "")
        return ("warn", "Logging severity not explicitly configured", "")

    return ("pass", "Check not implemented", "")


def _diff_eos_configs(saved, live):
    """Diff two EOS running-config outputs line by line, ignoring comments/timestamps."""
    def clean(text):
        lines = []
        for l in text.splitlines():
            s = l.rstrip()
            if not s or s.startswith("!") or s.startswith("Building configuration") or "Last configuration" in s:
                continue
            if s.startswith("! "):
                continue
            lines.append(s)
        return lines

    saved_lines = set(clean(saved))
    live_lines = set(clean(live))
    added = sorted(live_lines - saved_lines)
    removed = sorted(saved_lines - live_lines)

    items = []
    for l in removed:
        items.append({"type": "removed", "line": l})
    for l in added:
        items.append({"type": "added", "line": l})
    return items


def _diff_junos_configs(saved_hier, live_set):
    """Compare Junos hierarchical saved config with live 'display set' config.
    Extract key config sections from saved and compare semantically."""
    items = []
    # Extract key values from saved hierarchical config
    saved_lower = saved_hier.lower()
    live_lower = live_set.lower()

    # Check for key config elements that may have changed
    # Hostname check
    import re as _re
    saved_hostname = ""
    m = _re.search(r"host-name\s+(\S+)", saved_hier)
    if m:
        saved_hostname = m.group(1).rstrip(";")
    live_hostname = ""
    m = _re.search(r"set system host-name\s+(\S+)", live_set)
    if m:
        live_hostname = m.group(1)
    if saved_hostname and live_hostname and saved_hostname.lower() != live_hostname.lower():
        items.append({"type": "changed", "line": f"Hostname changed: {saved_hostname} → {live_hostname}"})

    # Compare set-style lines from live config to look for new/changed sections
    live_set_lines = set()
    for l in live_set.splitlines():
        s = l.strip()
        if s.startswith("set "):
            live_set_lines.add(s.lower())

    # Key sections to look for drift
    drift_sections = [
        ("system ntp", "NTP"),
        ("system syslog", "Syslog"),
        ("system login", "Login/AAA"),
        ("snmp", "SNMP"),
        ("protocols bgp", "BGP"),
        ("protocols lldp", "LLDP"),
        ("security zones", "Security Zones"),
        ("security policies", "Security Policies"),
        ("firewall", "Firewall Filters"),
        ("system services", "System Services"),
    ]

    # Check if saved config mentions sections not in live (rough check)
    for section_key, section_name in drift_sections:
        saved_has = section_key.replace(" ", "") in saved_lower.replace(" ", "").replace("\n", "")
        live_lines_section = [l for l in live_set_lines if section_key in l]
        if saved_has and not live_lines_section:
            items.append({"type": "removed", "line": f"Section '{section_name}' present in saved config but missing from live"})
        elif not saved_has and live_lines_section:
            items.append({"type": "added", "line": f"Section '{section_name}' added in live config ({len(live_lines_section)} lines)"})

    # Version drift
    saved_ver = ""
    m = _re.search(r"version\s+([\d.A-Za-z\-]+)", saved_hier[:500])
    if m:
        saved_ver = m.group(1).rstrip(";")
    live_ver = ""
    m = _re.search(r"set version\s+(\S+)", live_set)
    if m:
        live_ver = m.group(1)
    if saved_ver and live_ver and saved_ver != live_ver:
        items.append({"type": "changed", "line": f"OS version changed: {saved_ver} → {live_ver}"})

    # User changes
    saved_users = set(_re.findall(r"user\s+(\S+)\s+{", saved_hier))
    live_users = set()
    for l in live_set.splitlines():
        m = _re.match(r"set system login user\s+(\S+)", l)
        if m:
            live_users.add(m.group(1))
    for u in live_users - saved_users:
        items.append({"type": "added", "line": f"New user added: {u}"})
    for u in saved_users - live_users:
        items.append({"type": "removed", "line": f"User removed: {u}"})

    if not items and saved_hier.strip():
        items.append({"type": "info", "line": "No significant drift detected between saved and live config"})

    return items


@app.route("/api/config-drift", methods=["POST"])
def config_drift():
    """Config Drift & Compliance Auditor."""
    data     = request.json
    ip       = data.get("ip")
    dtype    = data.get("dtype", "junos")
    hostname = data.get("hostname", ip)

    if not ip:
        return jsonify({"success": False, "error": "Missing ip"}), 400

    cmds = _DRIFT_CMDS_JUNOS if dtype == "junos" else _DRIFT_CMDS_EOS
    result = run_commands_on_device(ip, dtype, cmds)

    if not result["success"]:
        return jsonify({"success": False, "error": result.get("error", "SSH failed")})

    report = _run_compliance(hostname, dtype, result["results"])
    return jsonify(report)


# ══════════════════════════════════════════════════════════════════════════════
# ── 🌐 TOPOLOGY DISCOVERY ────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_TOPO_CMDS_JUNOS = {
    "lldp":          "show lldp neighbors",
    "lldp_detail":   "show lldp neighbors detail",
    "interfaces":    "show interfaces descriptions",
    "arp":           "show arp | no-more",
    "mac_table":     "show ethernet-switching table | no-more",
    "route":         "show route summary",
    "bgp":           "show bgp summary",
    "ospf":          "show ospf neighbor",
    "isis":          "show isis adjacency",
    "lacp":          "show lacp interfaces",
    "chassis":       "show chassis hardware | match model",
}
_TOPO_CMDS_EOS = {
    "lldp":          "show lldp neighbors",
    "lldp_detail":   "show lldp neighbors detail",
    "interfaces":    "show interfaces description",
    "arp":           "show arp",
    "mac_table":     "show mac address-table",
    "route":         "show ip route summary",
    "bgp":           "show bgp summary",
    "ospf":          "show ip ospf neighbor",
    "lacp":          "show lacp neighbor",
    "mlag":          "show mlag",
    "version":       "show version | grep -i model",
}


def _analyze_topology(hostname, dtype, results):
    """Build neighbor/topology map from LLDP, interface descriptions, ARP, routing protocols."""
    neighbors = []
    seen = set()
    g = lambda k: results.get(k, "") or ""

    # ── LLDP Neighbors ────────────────────────────────────────────────────
    lldp_raw = g("lldp")
    lldp_detail = g("lldp_detail")
    if lldp_raw.strip() and "lldp" not in lldp_raw.lower().split('\n')[0].strip().replace("show lldp",""):
        for line in lldp_raw.splitlines():
            line = line.strip()
            if not line or "local" in line.lower()[:15] or "---" in line or "device" in line.lower()[:10] or "port" in line.lower()[:10]:
                continue
            parts = line.split()
            if len(parts) >= 2:
                local_port = parts[0]
                remote_system = parts[-1] if len(parts) >= 3 else parts[1]
                # Clean up remote system name
                remote_system = remote_system.split(".")[0]  # strip FQDN
                key = f"lldp:{local_port}:{remote_system}"
                if key not in seen:
                    seen.add(key)
                    neighbors.append({
                        "source": "lldp",
                        "local_port": local_port,
                        "remote_device": remote_system,
                        "remote_port": parts[1] if len(parts) >= 4 else "",
                        "detail": "",
                    })

    # ── Parse LLDP detail for extra info ──────────────────────────────────
    if lldp_detail.strip():
        current = {}
        for line in lldp_detail.splitlines():
            l = line.strip().lower()
            if "local interface" in l or "local port" in l:
                if current.get("local_port") and current.get("remote_device"):
                    key = f"lldp_d:{current['local_port']}:{current['remote_device']}"
                    if key not in seen:
                        seen.add(key)
                        neighbors.append({
                            "source": "lldp",
                            "local_port": current.get("local_port", ""),
                            "remote_device": current.get("remote_device", ""),
                            "remote_port": current.get("remote_port", ""),
                            "detail": current.get("description", ""),
                        })
                current = {}
                parts = line.split(":")
                if len(parts) >= 2:
                    current["local_port"] = parts[-1].strip().split(",")[0]
            elif "system name" in l:
                parts = line.split(":")
                if len(parts) >= 2:
                    current["remote_device"] = parts[-1].strip().split(".")[0]
            elif "port id" in l or "port description" in l:
                parts = line.split(":")
                if len(parts) >= 2:
                    current["remote_port"] = parts[-1].strip()
            elif "system description" in l:
                parts = line.split(":")
                if len(parts) >= 2:
                    current["description"] = parts[-1].strip()[:80]
        # Last entry
        if current.get("local_port") and current.get("remote_device"):
            key = f"lldp_d:{current['local_port']}:{current['remote_device']}"
            if key not in seen:
                seen.add(key)
                neighbors.append({
                    "source": "lldp",
                    "local_port": current.get("local_port", ""),
                    "remote_device": current.get("remote_device", ""),
                    "remote_port": current.get("remote_port", ""),
                    "detail": current.get("description", ""),
                })

    # ── Interface descriptions (common way to document connections) ────────
    iface_raw = g("interfaces")
    for line in iface_raw.splitlines():
        line = line.strip()
        if not line or "interface" in line.lower()[:12] and "name" in line.lower():
            continue
        parts = line.split()
        if len(parts) >= 3:
            port = parts[0]
            # Look for description that mentions another device
            desc_parts = parts[2:] if len(parts) > 2 else []
            desc = " ".join(desc_parts)
            # Detect device-like patterns in description (e.g., uk-lon-dist-01, de-fra-core-01)
            import re as _re
            dev_match = _re.findall(r"[a-z]{2,5}\d+-(?:sw|rt|fw)-\d+[a-z]?", desc.lower())
            for dm in dev_match:
                key = f"desc:{port}:{dm}"
                if key not in seen:
                    seen.add(key)
                    neighbors.append({
                        "source": "description",
                        "local_port": port,
                        "remote_device": dm,
                        "remote_port": "",
                        "detail": desc[:100],
                    })

    # ── BGP Neighbors ─────────────────────────────────────────────────────
    bgp_raw = g("bgp")
    for line in bgp_raw.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            ip_candidate = parts[0]
            if re.match(r"\d+\.\d+\.\d+\.\d+", ip_candidate):
                asn = parts[1] if parts[1].isdigit() else parts[2] if len(parts) > 2 and parts[2].isdigit() else ""
                state = parts[-1] if parts else ""
                key = f"bgp:{ip_candidate}"
                if key not in seen:
                    seen.add(key)
                    neighbors.append({
                        "source": "bgp",
                        "local_port": "BGP",
                        "remote_device": ip_candidate,
                        "remote_port": f"AS{asn}" if asn else "",
                        "detail": f"State: {state}",
                    })

    # ── OSPF Neighbors ────────────────────────────────────────────────────
    ospf_raw = g("ospf")
    for line in ospf_raw.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
            key = f"ospf:{parts[0]}"
            if key not in seen:
                seen.add(key)
                iface = parts[-1] if len(parts) >= 4 else ""
                state = ""
                for p in parts:
                    if p.lower() in ("full", "2way", "init", "down", "exstart", "exchange", "loading"):
                        state = p
                neighbors.append({
                    "source": "ospf",
                    "local_port": iface,
                    "remote_device": parts[0],
                    "remote_port": f"Router-ID",
                    "detail": f"State: {state}" if state else "",
                })

    # ── ISIS Adjacency ────────────────────────────────────────────────────
    isis_raw = g("isis")
    for line in isis_raw.splitlines():
        parts = line.split()
        if len(parts) >= 3 and "-" in parts[0]:
            key = f"isis:{parts[0]}"
            if key not in seen:
                seen.add(key)
                iface = parts[1] if len(parts) > 1 else ""
                state = parts[2] if len(parts) > 2 else ""
                neighbors.append({
                    "source": "isis",
                    "local_port": iface,
                    "remote_device": parts[0].split(".")[0],
                    "remote_port": "",
                    "detail": f"State: {state}",
                })

    # ── LACP ──────────────────────────────────────────────────────────────
    lacp_raw = g("lacp")
    for line in lacp_raw.splitlines():
        line = line.strip()
        parts = line.split()
        if len(parts) >= 2:
            # Look for system-id or partner patterns
            mac_match = re.search(r"([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})", line.lower())
            if mac_match:
                key = f"lacp:{mac_match.group(1)}"
                if key not in seen:
                    seen.add(key)
                    neighbors.append({
                        "source": "lacp",
                        "local_port": parts[0] if parts else "",
                        "remote_device": f"Partner MAC {mac_match.group(1)}",
                        "remote_port": "",
                        "detail": "LAG partner",
                    })

    # ── MLAG (EOS only) ───────────────────────────────────────────────────
    mlag_raw = g("mlag")
    if mlag_raw.strip():
        peer_match = re.search(r"peer-address\s*:\s*(\S+)", mlag_raw, re.IGNORECASE)
        state_match = re.search(r"state\s*:\s*(\S+)", mlag_raw, re.IGNORECASE)
        if peer_match:
            key = f"mlag:{peer_match.group(1)}"
            if key not in seen:
                seen.add(key)
                neighbors.append({
                    "source": "mlag",
                    "local_port": "MLAG",
                    "remote_device": peer_match.group(1),
                    "remote_port": "MLAG Peer",
                    "detail": f"State: {state_match.group(1)}" if state_match else "",
                })

    # ── Summary stats ─────────────────────────────────────────────────────
    source_counts = {}
    for n in neighbors:
        src = n["source"]
        source_counts[src] = source_counts.get(src, 0) + 1

    # Unique remote devices
    remote_devices = set()
    for n in neighbors:
        rd = n["remote_device"].lower().split(".")[0]
        if rd and not _IPV4_RE.match(rd):
            remote_devices.add(rd)

    return {
        "success": True,
        "hostname": hostname,
        "dtype": dtype,
        "total_neighbors": len(neighbors),
        "unique_devices": len(remote_devices),
        "source_counts": source_counts,
        "neighbors": neighbors,
        "remote_devices": sorted(remote_devices),
        "timestamp": datetime.now().isoformat(),
    }


@app.route("/api/topology", methods=["POST"])
def topology_discovery():
    """Topology Discovery: Map neighbors via LLDP, descriptions, routing protocols."""
    data     = request.json
    ip       = data.get("ip")
    dtype    = data.get("dtype", "junos")
    hostname = data.get("hostname", ip)

    if not ip:
        return jsonify({"success": False, "error": "Missing ip"}), 400

    cmds = _TOPO_CMDS_JUNOS if dtype == "junos" else _TOPO_CMDS_EOS
    result = run_commands_on_device(ip, dtype, cmds)

    if not result["success"]:
        return jsonify({"success": False, "error": result.get("error", "SSH failed")})

    report = _analyze_topology(hostname, dtype, result["results"])
    return jsonify(report)


# ══════════════════════════════════════════════════════════════════════════════
# ── 📊 CAPACITY FORECASTING ──────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_CAP_CMDS_JUNOS = {
    "interfaces":     "show interfaces terse",
    "iface_detail":   "show interfaces detail",
}
_CAP_CMDS_EOS = {
    "interfaces":     "show interfaces status",
    "iface_detail":   "show interfaces",
}


def _analyze_capacity(hostname, dtype, results):
    """Analyze interface utilization and port capacity from live device."""
    g = lambda k: results.get(k, "") or ""
    findings = []
    port_stats = {"total": 0, "up": 0, "down": 0, "admin_down": 0}
    speed_breakdown = {}
    high_util_ports = []
    util_data = []

    iface_terse = g("interfaces")
    iface_detail = g("iface_detail")

    # ── JUNOS: parse terse-style data ─────────────────────────────────────
    # Format: xe-0/0/0    up    up
    #         xe-0/0/0.0  up    up   inet     10.x.x.x/30
    # We want physical interfaces only (no sub-units with ".")
    # Try both outputs — some devices return terse in either command
    if dtype == "junos":
        _JUNOS_PHYS = re.compile(
            r"^(xe-|et-|ge-|ae\d|reth\d|fxp\d|irb|lo0|st0)")
        _TERSE_LINE = re.compile(
            r"^(\S+)\s+(up|down)\s+(up|down)", re.I)

        # Use whichever output has terse-style lines
        terse_src = iface_terse
        terse_lines = [l for l in terse_src.splitlines() if _TERSE_LINE.match(l.strip())]
        if len(terse_lines) < 2:
            # Fallback: try iface_detail which may contain terse output
            alt_lines = [l for l in iface_detail.splitlines() if _TERSE_LINE.match(l.strip())]
            if len(alt_lines) > len(terse_lines):
                terse_lines = alt_lines

        for line in terse_lines:
            line = line.strip()
            parts = line.split()
            if len(parts) < 3:
                continue
            iface = parts[0]
            if "." in iface:
                continue
            if not _JUNOS_PHYS.match(iface):
                continue
            port_stats["total"] += 1
            admin_status = parts[1].lower()
            oper_status = parts[2].lower()
            if admin_status == "up" and oper_status == "up":
                port_stats["up"] += 1
            elif admin_status == "up" and oper_status == "down":
                port_stats["down"] += 1
            else:
                port_stats["admin_down"] += 1

        # Parse "show interfaces detail" for speed + bps on Junos
        # Format:
        #   Physical interface: xe-0/0/0, Enabled, Physical link is Up
        #     Link-level type: Ethernet, ..., Speed: 10Gbps, ...
        #   Traffic statistics:
        #     Input  bytes  :     1207846119480260            202387000 bps
        #     Output bytes  :     1611871251747616             45605888 bps
        cur_port = ""
        cur_speed = 0
        cur_in = 0
        cur_out = 0
        _in_seen = False  # only take first Input bytes line per interface
        _out_seen = False
        _PHYS_LINE = re.compile(r"Physical interface:\s*(\S+)")
        # Speed: 10Gbps  OR  Speed: 40000mbps  OR  Speed: 1000mbps
        _SPEED_RE = re.compile(r"Speed:\s*(\d+)\s*([GgMm])bps", re.I)
        # Input  bytes  :  <cumulative>  <rate> bps
        _IN_BYTES = re.compile(r"^\s*Input\s+bytes\s*:\s+\d+\s+(\d+)\s+bps", re.I)
        _OUT_BYTES = re.compile(r"^\s*Output\s+bytes\s*:\s+\d+\s+(\d+)\s+bps", re.I)
        # Fallback: Input rate : 123456 bps
        _IN_RATE = re.compile(r"Input\s+rate\s*:\s*([\d,]+)\s*bps", re.I)
        _OUT_RATE = re.compile(r"Output\s+rate\s*:\s*([\d,]+)\s*bps", re.I)

        def _save_junos():
            nonlocal cur_port, cur_speed, cur_in, cur_out
            if cur_port and cur_speed > 0:
                in_pct = cur_in / cur_speed * 100
                out_pct = cur_out / cur_speed * 100
                mx = max(in_pct, out_pct)
                util_data.append({"port": cur_port, "speed_bps": cur_speed,
                    "in_bps": cur_in, "out_bps": cur_out,
                    "in_pct": round(in_pct,1), "out_pct": round(out_pct,1),
                    "max_pct": round(mx,1)})
                if mx > 70:
                    high_util_ports.append({"port": cur_port,
                        "utilization": round(mx,1),
                        "direction": "IN" if in_pct > out_pct else "OUT",
                        "speed": cur_speed})
                # Speed breakdown
                if cur_speed >= 100_000_000_000:
                    speed_breakdown["100G"] = speed_breakdown.get("100G",0)+1
                elif cur_speed >= 40_000_000_000:
                    speed_breakdown["40G"] = speed_breakdown.get("40G",0)+1
                elif cur_speed >= 25_000_000_000:
                    speed_breakdown["25G"] = speed_breakdown.get("25G",0)+1
                elif cur_speed >= 10_000_000_000:
                    speed_breakdown["10G"] = speed_breakdown.get("10G",0)+1
                elif cur_speed >= 1_000_000_000:
                    speed_breakdown["1G"] = speed_breakdown.get("1G",0)+1
                elif cur_speed >= 100_000_000:
                    speed_breakdown["100M"] = speed_breakdown.get("100M",0)+1

        for line in iface_detail.splitlines():
            m = _PHYS_LINE.search(line)
            if m:
                _save_junos()
                cur_port = m.group(1).rstrip(",")
                cur_speed = 0; cur_in = 0; cur_out = 0
                _in_seen = False; _out_seen = False
                continue
            m = _SPEED_RE.search(line)
            if m:
                num = int(m.group(1))
                unit = m.group(2).lower()
                # Handle both "10Gbps" and "40000mbps" / "1000mbps"
                cur_speed = num * (1_000_000_000 if unit == "g" else 1_000_000)
                continue
            # Primary: "Input  bytes  :  <total>  <rate> bps"
            if not _in_seen:
                m = _IN_BYTES.search(line)
                if m:
                    cur_in = int(m.group(1))
                    _in_seen = True
                    continue
            if not _out_seen:
                m = _OUT_BYTES.search(line)
                if m:
                    cur_out = int(m.group(1))
                    _out_seen = True
                    continue
            # Fallback: "Input rate : 123456 bps"
            m = _IN_RATE.search(line)
            if m and not _in_seen:
                cur_in = int(m.group(1).replace(",",""))
                _in_seen = True
                continue
            m = _OUT_RATE.search(line)
            if m and not _out_seen:
                cur_out = int(m.group(1).replace(",",""))
                _out_seen = True
                continue
        _save_junos()  # last interface

    # ── EOS: parse "show interfaces status" ───────────────────────────────
    # Format: Et1    Description    connected  trunk  full  10G   10GBASE-SR
    elif dtype == "eos":
        _EOS_IFACE = re.compile(r"^(Et\S+|Po\d+|Vl\d+|Lo\d+)\s+")
        _EOS_SPEED = re.compile(r"\b(\d+[GM])\b", re.I)
        for line in iface_terse.splitlines():
            line = line.strip()
            m = _EOS_IFACE.match(line)
            if not m:
                continue
            port_stats["total"] += 1
            ll = line.lower()
            if "connected" in ll or "up" in ll:
                port_stats["up"] += 1
            elif "notconnect" in ll or "disabled" in ll or "errdisabled" in ll:
                if "disabled" in ll or "errdisabled" in ll:
                    port_stats["admin_down"] += 1
                else:
                    port_stats["down"] += 1
            else:
                port_stats["down"] += 1
            # Speed from status line
            sm = _EOS_SPEED.search(line)
            if sm:
                spd = sm.group(1).upper()
                speed_breakdown[spd] = speed_breakdown.get(spd, 0) + 1

        # Parse "show interfaces" for bps on EOS
        # Format:
        #   Ethernet1 is up, line protocol is up (connected)
        #     5 minutes input rate 1234 bps, ...
        #     5 minutes output rate 5678 bps, ...
        #     Bandwidth 10G
        cur_port = ""
        cur_speed = 0
        cur_in = 0
        cur_out = 0
        _EOS_PHYS = re.compile(r"^(Ethernet\S+|Port-Channel\d+)\s+is\s+(up|down|administratively)", re.I)
        _EOS_BW = re.compile(r"BW\s+(\d+)\s*(Gbit|Mbit|Kbit)", re.I)
        _EOS_IN = re.compile(r"input rate\s+([\d.]+)\s*(bps|Kbps|Mbps|Gbps)", re.I)
        _EOS_OUT = re.compile(r"output rate\s+([\d.]+)\s*(bps|Kbps|Mbps|Gbps)", re.I)

        def _to_bps(val_str, unit):
            v = float(val_str)
            u = unit.lower()
            if u == "gbps": return int(v * 1e9)
            if u == "mbps": return int(v * 1e6)
            if u == "kbps": return int(v * 1e3)
            return int(v)

        def _save_eos():
            nonlocal cur_port, cur_speed, cur_in, cur_out
            if cur_port and cur_speed > 0:
                in_pct = cur_in / cur_speed * 100
                out_pct = cur_out / cur_speed * 100
                mx = max(in_pct, out_pct)
                util_data.append({"port": cur_port, "speed_bps": cur_speed,
                    "in_bps": cur_in, "out_bps": cur_out,
                    "in_pct": round(in_pct,1), "out_pct": round(out_pct,1),
                    "max_pct": round(mx,1)})
                if mx > 70:
                    high_util_ports.append({"port": cur_port,
                        "utilization": round(mx,1),
                        "direction": "IN" if in_pct > out_pct else "OUT",
                        "speed": cur_speed})

        for line in iface_detail.splitlines():
            m = _EOS_PHYS.match(line.strip())
            if m:
                _save_eos()
                cur_port = m.group(1)
                cur_speed = 0; cur_in = 0; cur_out = 0
                continue
            m = _EOS_BW.search(line)
            if m:
                num = int(m.group(1))
                u = m.group(2).lower()
                cur_speed = num * (1_000_000_000 if "gbit" in u else 1_000_000 if "mbit" in u else 1_000)
                continue
            m = _EOS_IN.search(line)
            if m:
                cur_in = _to_bps(m.group(1), m.group(2))
                continue
            m = _EOS_OUT.search(line)
            if m:
                cur_out = _to_bps(m.group(1), m.group(2))
                continue
        _save_eos()

    # ── Generate findings ─────────────────────────────────────────────────
    total = port_stats["total"] or 1
    used_pct = round(port_stats["up"] / total * 100, 1)

    if used_pct > 90:
        findings.append({"severity": "critical", "category": "capacity", "title": f"Port Capacity Critical: {used_pct}% used",
            "detail": f"{port_stats['up']}/{total} ports active — nearly out of physical ports", "metric": used_pct})
    elif used_pct > 75:
        findings.append({"severity": "high", "category": "capacity", "title": f"Port Capacity Warning: {used_pct}% used",
            "detail": f"{port_stats['up']}/{total} ports active — plan expansion", "metric": used_pct})
    elif used_pct > 50:
        findings.append({"severity": "medium", "category": "capacity", "title": f"Port Capacity Moderate: {used_pct}% used",
            "detail": f"{port_stats['up']}/{total} ports active", "metric": used_pct})
    else:
        findings.append({"severity": "ok", "category": "capacity", "title": f"Port Capacity Healthy: {used_pct}% used",
            "detail": f"{port_stats['up']}/{total} ports active — plenty of room", "metric": used_pct})

    if port_stats["down"] > 5:
        findings.append({"severity": "medium", "category": "health", "title": f"{port_stats['down']} Ports Down (not admin-disabled)",
            "detail": "These ports may have cabling issues or failed optics", "metric": port_stats["down"]})

    # High utilization findings
    crit_util = [p for p in high_util_ports if p["utilization"] > 90]
    high_util = [p for p in high_util_ports if 80 < p["utilization"] <= 90]
    warn_util = [p for p in high_util_ports if 70 < p["utilization"] <= 80]

    if crit_util:
        findings.append({"severity": "critical", "category": "bandwidth", "title": f"{len(crit_util)} Port(s) >90% Utilization",
            "detail": ", ".join(f"{p['port']} ({p['utilization']}% {p['direction']})" for p in crit_util[:5]),
            "metric": max(p["utilization"] for p in crit_util)})
    if high_util:
        findings.append({"severity": "high", "category": "bandwidth", "title": f"{len(high_util)} Port(s) 80-90% Utilization",
            "detail": ", ".join(f"{p['port']} ({p['utilization']}% {p['direction']})" for p in high_util[:5]),
            "metric": max(p["utilization"] for p in high_util)})
    if warn_util:
        findings.append({"severity": "medium", "category": "bandwidth", "title": f"{len(warn_util)} Port(s) 70-80% Utilization",
            "detail": ", ".join(f"{p['port']} ({p['utilization']}% {p['direction']})" for p in warn_util[:5]),
            "metric": max(p["utilization"] for p in warn_util)})

    if not high_util_ports and util_data:
        findings.append({"severity": "ok", "category": "bandwidth", "title": "All Ports Below 70% Utilization",
            "detail": f"Analyzed {len(util_data)} active ports — no congestion detected", "metric": 0})

    # Sort utilization data by max_pct descending
    util_data.sort(key=lambda x: x["max_pct"], reverse=True)

    # Forecast: simple projection
    forecasts = []
    for p in util_data[:20]:
        if p["max_pct"] > 40:
            quarters_to_80 = max(0, (80 - p["max_pct"]) / 5)
            quarters_to_100 = max(0, (100 - p["max_pct"]) / 5)
            forecasts.append({
                "port": p["port"],
                "current_pct": p["max_pct"],
                "est_quarters_to_80": round(quarters_to_80, 1),
                "est_quarters_to_100": round(quarters_to_100, 1),
                "recommendation": "Upgrade soon" if quarters_to_80 < 2 else "Monitor" if quarters_to_80 < 4 else "OK",
            })

    return {
        "success": True,
        "hostname": hostname,
        "dtype": dtype,
        "port_stats": port_stats,
        "used_pct": used_pct,
        "speed_breakdown": speed_breakdown,
        "findings": findings,
        "high_util_ports": sorted(high_util_ports, key=lambda x: -x["utilization"]),
        "utilization_top20": util_data[:20],
        "forecasts": forecasts,
        "total_analyzed": len(util_data),
        "timestamp": datetime.now().isoformat(),
    }


@app.route("/api/capacity", methods=["POST"])
def capacity_forecast():
    """Capacity Forecasting: Analyze interface utilization and predict congestion."""
    data     = request.json
    ip       = data.get("ip")
    dtype    = data.get("dtype", "junos")
    hostname = data.get("hostname", ip)

    if not ip:
        return jsonify({"success": False, "error": "Missing ip"}), 400

    cmds = _CAP_CMDS_JUNOS if dtype == "junos" else _CAP_CMDS_EOS
    result = run_commands_on_device(ip, dtype, cmds)

    if not result["success"]:
        return jsonify({"success": False, "error": result.get("error", "SSH failed")})

    report = _analyze_capacity(hostname, dtype, result["results"])
    return jsonify(report)


# ══════════════════════════════════════════════════════════════════════════════
# ── 🔐 SECURITY POSTURE AUDIT ────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_SEC_CMDS_JUNOS = {
    "config":         "show configuration | display set",
    "version":        "show version",
    "users":          "show configuration system login | display set",
    "services":       "show configuration system services | display set",
    "snmp":           "show configuration snmp | display set",
    "firewall":       "show configuration firewall | display set",
    "security":       "show configuration security | display set",
    "ntp":            "show configuration system ntp | display set",
    "syslog":         "show configuration system syslog | display set",
    "interfaces":     "show interfaces terse",
    "bgp":            "show bgp summary",
    "ike":            "show security ike sa",
    "ipsec":          "show security ipsec sa",
    "alarms":         "show chassis alarms",
    "routing_engine": "show chassis routing-engine",
}
_SEC_CMDS_EOS = {
    "config":         "show running-config",
    "version":        "show version",
    "users":          "show running-config section username",
    "services":       "show running-config section management",
    "snmp":           "show running-config section snmp",
    "syslog":         "show running-config section logging",
    "ntp":            "show running-config section ntp",
    "interfaces":     "show interfaces status",
    "bgp":            "show bgp summary",
    "alarms":         "show system environment",
    "aaa":            "show running-config section aaa",
}


def _security_audit(hostname, dtype, results):
    """Deep security posture audit with CVE-awareness, cipher checks, access control analysis."""
    g = lambda k: (results.get(k) or "").lower()
    cfg = g("config")
    findings = []
    score = 100

    sev_pen = {"critical": 15, "high": 8, "medium": 4, "low": 2}

    def add(sev, cat, title, detail, remediation=""):
        nonlocal score
        score -= sev_pen.get(sev, 0)
        findings.append({"severity": sev, "category": cat, "title": title, "detail": detail, "remediation": remediation})

    # ── 1. Firmware / CVE Check ───────────────────────────────────────────
    version_raw = g("version")
    version_str = ""
    ver_match = re.search(r"(\d+\.\d+[A-Za-z]\d+[\-S\.0-9]*)", version_raw)
    if not ver_match:
        ver_match = re.search(r"(4\.\d+\.\d+[A-Z]*)", version_raw)
    if ver_match:
        version_str = ver_match.group(1)

    if version_str:
        # Known vulnerable versions (simplified CVE awareness)
        vuln_patterns = [
            (r"21\.2R[12][\.\-]", "CVE-2023-36844/36845 — Junos J-Web RCE (21.2R1-R2)", "critical"),
            (r"21\.4R1[\.\-]",    "CVE-2023-36844 — Junos J-Web RCE (21.4R1)", "critical"),
            (r"22\.1R1[\.\-]",    "CVE-2023-44194 — Junos Unauthorized Access", "high"),
            (r"4\.25\.",          "EOS 4.25.x — Multiple advisories, recommend upgrade", "medium"),
            (r"4\.26\.[01]",     "EOS 4.26.0-1 — Known BGP vulnerabilities", "medium"),
            (r"20\.[1-3]",       "Junos 20.x — End of support, multiple CVEs", "high"),
            (r"19\.",            "Junos 19.x — End of life, critical CVEs unpatched", "critical"),
            (r"18\.",            "Junos 18.x — End of life", "critical"),
            (r"4\.23\.",         "EOS 4.23.x — End of support", "high"),
            (r"4\.24\.",         "EOS 4.24.x — Near end of support", "medium"),
        ]
        found_vuln = False
        for pattern, desc, sev in vuln_patterns:
            if re.search(pattern, version_str):
                add(sev, "firmware", f"Vulnerable Firmware: {version_str}", desc, "Upgrade to latest supported version")
                found_vuln = True
                break
        if not found_vuln:
            findings.append({"severity": "ok", "category": "firmware", "title": f"Firmware: {version_str}", "detail": "No known critical CVEs for this version", "remediation": ""})

    # ── 2. SSH / Crypto ───────────────────────────────────────────────────
    if dtype == "junos":
        services = g("services")
        if "ssh" in services:
            if "protocol-version v1" in services:
                add("critical", "crypto", "SSHv1 Enabled", "SSHv1 is broken — disable immediately", "set system services ssh protocol-version v2")
            else:
                findings.append({"severity": "ok", "category": "crypto", "title": "SSH v2", "detail": "SSH enabled (Junos defaults v2)", "remediation": ""})
            # Check for weak ciphers
            if "hmac-md5" in services or "hmac-sha1 " in services:
                add("medium", "crypto", "Weak SSH MACs", "MD5/SHA1 MACs detected in SSH config", "Remove weak MACs from ssh config")
            if "arcfour" in services or "3des" in services or "blowfish" in services:
                add("high", "crypto", "Weak SSH Ciphers", "Insecure ciphers (3DES/arcfour/blowfish)", "set system services ssh ciphers aes256-ctr,aes128-ctr")
        else:
            add("high", "crypto", "SSH Not Configured", "No SSH service in config", "set system services ssh")
    else:
        if "ip ssh version 2" in cfg or "management ssh" in cfg:
            findings.append({"severity": "ok", "category": "crypto", "title": "SSH v2", "detail": "SSH v2 enabled", "remediation": ""})
        elif "ssh" in cfg:
            findings.append({"severity": "ok", "category": "crypto", "title": "SSH Enabled", "detail": "SSH active", "remediation": ""})

    # ── 3. User Account Audit ─────────────────────────────────────────────
    users_cfg = g("users")
    if dtype == "junos":
        users = list(dict.fromkeys(re.findall(r"set system login user\s+(\S+)", users_cfg)))
    else:
        users = list(dict.fromkeys(re.findall(r"username\s+(\S+)", users_cfg)))

    if users:
        findings.append({"severity": "ok" if len(users) <= 10 else "medium", "category": "access",
            "title": f"{len(users)} User Accounts", "detail": ", ".join(users[:15]),
            "remediation": "Audit user accounts — remove stale accounts" if len(users) > 10 else ""})

        # Check for known default/test accounts
        suspicious = [u for u in users if u.lower() in ("test", "admin", "default", "temp", "guest", "lab")]
        if suspicious:
            add("high", "access", f"Suspicious Accounts: {', '.join(suspicious)}", "Default/test accounts found", "Remove default/test accounts")

        # Check SSH key auth
        ssh_key_count = len(re.findall(r"ssh-key|ssh-rsa|ecdsa|ed25519", users_cfg))
        if ssh_key_count > 0:
            findings.append({"severity": "ok", "category": "access", "title": f"SSH Key Auth ({ssh_key_count} keys)",
                "detail": "Key-based authentication configured", "remediation": ""})
        else:
            add("medium", "access", "No SSH Keys", "Password-only auth — SSH keys recommended", "Add SSH public keys for all users")
    else:
        add("high", "access", "No User Accounts Found", "Could not parse user configuration", "")

    # ── 4. SNMP Security ──────────────────────────────────────────────────
    snmp = g("snmp")
    if "community public" in snmp or "community private" in snmp:
        add("critical", "snmp", "Default SNMP Community", "public/private community string — change immediately", "Change SNMP community strings")
    if "v3" in snmp:
        findings.append({"severity": "ok", "category": "snmp", "title": "SNMPv3 Configured", "detail": "Encrypted SNMP in use", "remediation": ""})
    elif "community" in snmp:
        add("medium", "snmp", "SNMPv2c Only", "Cleartext community strings — upgrade to SNMPv3", "Configure SNMPv3")

    # ── 5. Firewall / ACL ─────────────────────────────────────────────────
    fw = g("firewall") if dtype == "junos" else cfg
    if dtype == "junos":
        if "filter" in fw:
            filter_count = len(re.findall(r"set firewall.*filter\s+(\S+)", fw))
            findings.append({"severity": "ok", "category": "firewall", "title": f"Firewall Filters ({filter_count})",
                "detail": "Packet filtering configured", "remediation": ""})
            if "lo0" not in fw and "protect" not in fw:
                add("high", "firewall", "No RE Protection Filter", "Loopback/RE not protected by firewall filter",
                    "set interfaces lo0 unit 0 family inet filter input protect-re")
        else:
            add("high", "firewall", "No Firewall Filters", "No packet filtering configured", "Configure firewall filters")
    else:
        if "access-list" in cfg or "ip access-group" in cfg:
            findings.append({"severity": "ok", "category": "firewall", "title": "ACLs Configured", "detail": "Access control lists found", "remediation": ""})
        else:
            add("medium", "firewall", "No ACLs Detected", "No access-list configuration found", "Consider adding control-plane ACLs")

    # ── 6. Management Plane Security ──────────────────────────────────────
    if "telnet" in cfg and "no telnet" not in cfg and "disable" not in cfg:
        add("critical", "management", "Telnet Enabled", "Telnet transmits credentials in cleartext", "Disable telnet; use SSH only")
    if "http" in cfg and "https" not in cfg:
        if "no http" not in cfg and "disable" not in cfg:
            add("high", "management", "HTTP (non-HTTPS) Enabled", "Unencrypted web management", "Disable HTTP; use HTTPS only")

    # ── 7. Logging & Monitoring ───────────────────────────────────────────
    syslog = g("syslog")
    if dtype == "junos":
        remote_log = bool(re.search(r"host\s+\d+\.\d+", syslog))
    else:
        remote_log = "logging host" in cfg
    if remote_log:
        findings.append({"severity": "ok", "category": "logging", "title": "Remote Syslog", "detail": "Logs forwarded to external collector", "remediation": ""})
    else:
        add("high", "logging", "No Remote Syslog", "Logs only stored locally — send to SIEM", "Configure remote syslog target")

    # ── 8. NTP ────────────────────────────────────────────────────────────
    ntp = g("ntp")
    if "server" in ntp:
        findings.append({"severity": "ok", "category": "ntp", "title": "NTP Configured", "detail": "Time synchronization active", "remediation": ""})
    else:
        add("medium", "ntp", "No NTP", "Clock not synced — affects logging and certificates", "Configure NTP servers")

    # ── 9. BGP Security ───────────────────────────────────────────────────
    bgp = g("bgp")
    if "neighbor" in cfg or "group" in cfg:
        if "authentication" in cfg or "password" in cfg:
            findings.append({"severity": "ok", "category": "routing", "title": "BGP Authentication", "detail": "BGP MD5/TCP-AO auth configured", "remediation": ""})
        else:
            add("high", "routing", "BGP Without Authentication", "BGP sessions lack MD5/TCP-AO — vulnerable to hijacking",
                "Add authentication-key to BGP peers")
        if "maximum-prefix" in cfg or "maximum-routes" in cfg:
            findings.append({"severity": "ok", "category": "routing", "title": "BGP Prefix Limits", "detail": "Maximum prefix limits set", "remediation": ""})
        else:
            add("medium", "routing", "No BGP Prefix Limits", "Unbounded prefix acceptance — risk of route table overflow",
                "Set maximum-prefix on BGP peers")

    # ── 10. VPN / IPsec ──────────────────────────────────────────────────
    ike_out = g("ike")
    ipsec_out = g("ipsec")
    if ike_out.strip() and "no entries" not in ike_out:
        ike_count = len([l for l in ike_out.splitlines() if re.match(r"\d+\.\d+", l.strip())])
        findings.append({"severity": "ok", "category": "vpn", "title": f"IKE Tunnels Active ({max(ike_count,1)})",
            "detail": "IPsec VPN tunnels established", "remediation": ""})
        if "sha1" in ike_out or "3des" in ike_out or "des-cbc" in ike_out:
            add("high", "vpn", "Weak VPN Ciphers", "SHA1/3DES/DES detected in IKE SAs", "Upgrade to AES-256-GCM + SHA-256")

    # ── Final scoring ─────────────────────────────────────────────────────
    score = max(0, min(100, score))
    grade = "A+" if score >= 95 else "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"

    # Risk level
    crit_count = sum(1 for f in findings if f["severity"] == "critical")
    high_count = sum(1 for f in findings if f["severity"] == "high")
    risk = "CRITICAL" if crit_count >= 2 else "HIGH" if crit_count >= 1 or high_count >= 3 else "MEDIUM" if high_count >= 1 else "LOW"

    # Category summary
    cat_summary = {}
    for f in findings:
        cat = f["category"]
        cat_summary.setdefault(cat, {"pass": 0, "fail": 0})
        if f["severity"] == "ok":
            cat_summary[cat]["pass"] += 1
        else:
            cat_summary[cat]["fail"] += 1

    return {
        "success": True,
        "hostname": hostname,
        "dtype": dtype,
        "security_score": score,
        "grade": grade,
        "risk_level": risk,
        "total_checks": len(findings),
        "critical": crit_count,
        "high": high_count,
        "medium": sum(1 for f in findings if f["severity"] == "medium"),
        "low": sum(1 for f in findings if f["severity"] == "low"),
        "passed": sum(1 for f in findings if f["severity"] == "ok"),
        "findings": findings,
        "category_summary": cat_summary,
        "firmware_version": version_str,
        "timestamp": datetime.now().isoformat(),
    }


@app.route("/api/security-audit", methods=["POST"])
def security_audit():
    """Security Posture Audit: Deep security scan with CVE awareness."""
    data     = request.json
    ip       = data.get("ip")
    dtype    = data.get("dtype", "junos")
    hostname = data.get("hostname", ip)

    if not ip:
        return jsonify({"success": False, "error": "Missing ip"}), 400

    cmds = _SEC_CMDS_JUNOS if dtype == "junos" else _SEC_CMDS_EOS
    result = run_commands_on_device(ip, dtype, cmds)

    if not result["success"]:
        return jsonify({"success": False, "error": result.get("error", "SSH failed")})

    report = _security_audit(hostname, dtype, result["results"])

    # ── LLM-powered security narrative (DISABLED — structured findings sufficient) ──
    report["llm_narrative"] = None
    report["llm_powered"] = False

    return jsonify(report)


@app.route("/api/ping", methods=["POST"])
def ping_device():
    """Quick reachability test via SSH."""
    data  = request.json
    ip    = data.get("ip")
    dtype = data.get("dtype", "junos")

    if not ip:
        return jsonify({"success": False, "error": "Missing ip"}), 400

    result = run_command_on_device(ip, dtype, "show version | head 3" if dtype == "junos" else "show version | head 3")
    result["ip"] = ip
    result["reachable"] = result["success"]
    return jsonify(result)

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "devices_loaded": len(DEVICES), "timestamp": datetime.now().isoformat()})


# ══════════════════════════════════════════════════════════════════════════════
# ── 📊 LIBRENMS INTEGRATION — Historical Bandwidth & Device Health ────────────
# ══════════════════════════════════════════════════════════════════════════════

_LIBRENMS_INSTANCES = {
    "emea": {
        "url":   os.environ.get("LIBRENMS_EMEA_URL",   "https://librenms.emea.example.com"),
        "token": os.environ.get("LIBRENMS_EMEA_TOKEN", ""),
    },
    "amer": {
        "url":   os.environ.get("LIBRENMS_AMER_URL",   "https://librenms.amer.example.com"),
        "token": os.environ.get("LIBRENMS_AMER_TOKEN", ""),
    },
    "apac": {
        "url":   os.environ.get("LIBRENMS_APAC_URL",   "https://librenms.apac.example.com"),
        "token": os.environ.get("LIBRENMS_APAC_TOKEN", ""),
    },
}
_LIBRENMS_ZTASID = os.environ.get("LIBRENMS_ZTASID", "")

# Site → region mapping for auto-routing to the right LibreNMS instance
_SITE_REGION = {}
_EMEA_SITES = {"de-fra","uk-lon","nl-ams","fr-par","de-ber","de-muc","ch-zur",
               "se-sto","pl-waw","cz-prg","at-vie","ie-dub","it-mil",
               "es-mad","pt-lis","ro-buh","hu-bud","fi-hel","no-osl"}
_AMER_SITES = {"us-nyc","us-lax","us-chi","us-dfw","us-sea","us-mia",
               "ca-tor","ca-van","br-sao","mx-mex","us-phx","us-iad"}
_APAC_SITES = {"sg-sin","au-syd","jp-tyo","hk-hkg","in-bom","in-del",
               "kr-icn","au-mel","my-kul","id-jkt","tw-tpe"}
for _s in _EMEA_SITES: _SITE_REGION[_s] = "emea"
for _s in _AMER_SITES: _SITE_REGION[_s] = "amer"
for _s in _APAC_SITES: _SITE_REGION[_s] = "apac"


def _lnms_region_for_host(hostname):
    """Determine LibreNMS region from hostname (e.g. de-fra-dist-01 → emea)."""
    site = hostname.split("-")[0].lower() if hostname else ""
    return _SITE_REGION.get(site, "emea")


def _lnms_api(region, path, params=None, timeout=15):
    """Call LibreNMS API. Returns parsed JSON or error dict."""
    inst = _LIBRENMS_INSTANCES.get(region, _LIBRENMS_INSTANCES["emea"])
    url = f"{inst['url']}/api/v0{path}"
    headers = {"X-Auth-Token": inst["token"]}
    cookies = {}
    ztasid = _LIBRENMS_ZTASID
    if ztasid:
        cookies["ztasid"] = ztasid
    try:
        r = _requests.get(url, headers=headers, cookies=cookies, params=params,
                          timeout=timeout, verify=DCN_VERIFY_SSL)
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}", "detail": r.text[:300]}
    except Exception as e:
        return {"error": str(e)}


def _lnms_find_device(hostname, region=None):
    """Find a device in LibreNMS by hostname. Returns (device_dict, region) or (None, region).
    Tries expected region first, then falls back to all 3 regions."""
    if not region:
        region = _lnms_region_for_host(hostname)

    def _try_region(r):
        for query in [f"{hostname}.corp.internal", hostname]:
            data = _lnms_api(r, f"/devices/{query}")
            if "devices" in data and data["devices"]:
                return data["devices"][0]
            if "hostname" in data and "device_id" in data:
                return data
        data = _lnms_api(r, "/devices", params={"type": "keyword", "query": hostname})
        for d in data.get("devices", []):
            if hostname.lower() in d.get("hostname", "").lower():
                return d
        return None

    # Try expected region first
    dev = _try_region(region)
    if dev:
        return dev, region

    # Fallback: try other regions
    for fallback in ("emea", "amer", "apac"):
        if fallback == region:
            continue
        dev = _try_region(fallback)
        if dev:
            return dev, fallback

    return None, region


@app.route("/api/librenms/device/<hostname>", methods=["GET"])
def lnms_device(hostname):
    """Get device info from LibreNMS — model, uptime, OS version, location."""
    region = request.args.get("region") or _lnms_region_for_host(hostname)
    dev, region = _lnms_find_device(hostname, region)
    if not dev:
        return jsonify({"success": False, "error": f"Device {hostname} not found in LibreNMS {region.upper()}"})
    return jsonify({
        "success": True, "region": region,
        "device_id": dev.get("device_id"),
        "hostname": dev.get("hostname"),
        "sysName": dev.get("sysName"),
        "os": dev.get("os"),
        "version": dev.get("version"),
        "hardware": dev.get("hardware"),
        "serial": dev.get("serial"),
        "uptime": dev.get("uptime"),
        "uptime_text": dev.get("uptime_long") or dev.get("uptime_short"),
        "location": dev.get("location"),
        "status": dev.get("status"),
        "status_reason": dev.get("status_reason"),
        "last_polled": dev.get("last_polled"),
    })


@app.route("/api/librenms/ports/<hostname>", methods=["GET"])
def lnms_ports(hostname):
    """Get all port traffic rates from LibreNMS — current IN/OUT bps, utilization, errors."""
    region = request.args.get("region") or _lnms_region_for_host(hostname)
    dev, region = _lnms_find_device(hostname, region)
    if not dev:
        return jsonify({"success": False, "error": f"Device {hostname} not found in LibreNMS {region.upper()}"})

    device_id = dev.get("device_id")
    data = _lnms_api(region, f"/devices/{device_id}/ports", params={"columns": "ifName,ifAlias,ifSpeed,ifOperStatus,ifInOctets_rate,ifOutOctets_rate,ifInErrors,ifOutErrors"})
    ports = data.get("ports", [])

    result = []
    for p in ports:
        ifname = p.get("ifName", "")
        if not ifname or ifname.startswith("lo") or ifname == "fxp0":
            continue
        speed = p.get("ifSpeed") or 0
        in_bps = (p.get("ifInOctets_rate") or 0) * 8
        out_bps = (p.get("ifOutOctets_rate") or 0) * 8
        util_in = round(in_bps / speed * 100, 1) if speed else 0
        util_out = round(out_bps / speed * 100, 1) if speed else 0
        result.append({
            "ifName": ifname,
            "ifAlias": p.get("ifAlias", ""),
            "speed_gbps": round(speed / 1e9, 1) if speed else 0,
            "status": p.get("ifOperStatus", ""),
            "in_bps": round(in_bps),
            "out_bps": round(out_bps),
            "in_mbps": round(in_bps / 1e6, 2),
            "out_mbps": round(out_bps / 1e6, 2),
            "util_in_pct": util_in,
            "util_out_pct": util_out,
            "in_errors": p.get("ifInErrors", 0),
            "out_errors": p.get("ifOutErrors", 0),
        })
    result.sort(key=lambda x: max(x["in_bps"], x["out_bps"]), reverse=True)
    return jsonify({
        "success": True, "hostname": hostname, "region": region,
        "device_id": device_id, "total_ports": len(result),
        "ports": result,
    })


@app.route("/api/librenms/bandwidth/<hostname>/<path:ifname>", methods=["GET"])
def lnms_bandwidth(hostname, ifname):
    """Get bandwidth graph data for a specific port from LibreNMS.
    Query param: period=6h|24h|7d|30d|90d|1y (default 24h)"""
    region = request.args.get("region") or _lnms_region_for_host(hostname)
    period = request.args.get("period", "24h")
    dev, region = _lnms_find_device(hostname, region)
    if not dev:
        return jsonify({"success": False, "error": f"Device {hostname} not found in LibreNMS {region.upper()}"})

    device_id = dev.get("device_id")
    # Find port_id for the interface
    ports_data = _lnms_api(region, f"/devices/{device_id}/ports", params={"columns": "port_id,ifName,ifAlias,ifSpeed"})
    port_id = None
    port_info = {}
    for p in ports_data.get("ports", []):
        if p.get("ifName", "").lower() == ifname.lower():
            port_id = p.get("port_id")
            port_info = p
            break
    if not port_id:
        return jsonify({"success": False, "error": f"Interface {ifname} not found on {hostname}"})

    # Map period to LibreNMS time ranges
    period_map = {"1h": "-1h", "6h": "-6h", "24h": "-24h", "7d": "-7d",
                  "30d": "-30d", "90d": "-90d", "1y": "-1y", "365d": "-365d"}
    from_time = period_map.get(period, "-24h")

    # Get bill/graph data via RRD
    graph_data = _lnms_api(region, f"/ports/{port_id}/bill",
                           params={"from": from_time, "to": "now"}, timeout=30)
    # Also get the port stats
    port_stats = _lnms_api(region, f"/ports/{port_id}")

    return jsonify({
        "success": True, "hostname": hostname, "region": region,
        "ifName": ifname,
        "ifAlias": port_info.get("ifAlias", ""),
        "speed_gbps": round((port_info.get("ifSpeed") or 0) / 1e9, 1),
        "period": period,
        "port_id": port_id,
        "stats": port_stats if "error" not in port_stats else {},
        "graph_url": f"{_LIBRENMS_INSTANCES[region]['url']}/graphs/port/{port_id}/port_bits/from={from_time}/",
    })


@app.route("/api/librenms/top-ports", methods=["GET"])
def lnms_top_ports():
    """Get busiest ports across a site or all devices. Query: site=DE-FRA&limit=20&region=emea"""
    site = request.args.get("site", "").upper()
    limit = int(request.args.get("limit", "20"))
    region = request.args.get("region") or (_lnms_region_for_host(site.lower() + "-x") if site else "emea")

    # Get all ports sorted by traffic
    params = {"columns": "port_id,ifName,ifAlias,ifSpeed,ifOperStatus,ifInOctets_rate,ifOutOctets_rate,device_id"}
    if site:
        # Get devices for site first, then ports for each
        devs_data = _lnms_api(region, "/devices", params={"type": "keyword", "query": site.lower()})
        all_ports = []
        for dev in devs_data.get("devices", [])[:50]:
            did = dev.get("device_id")
            hostname = dev.get("hostname", "")
            if site.lower() not in hostname.lower():
                continue
            pdata = _lnms_api(region, f"/devices/{did}/ports", params=params)
            for p in pdata.get("ports", []):
                p["_hostname"] = hostname.split(".")[0]
            all_ports.extend(pdata.get("ports", []))
    else:
        return jsonify({"success": False, "error": "Provide site parameter (e.g. site=DE-FRA)"})

    # Filter and sort
    result = []
    for p in all_ports:
        ifname = p.get("ifName", "")
        if not ifname or ifname.startswith("lo") or ifname in ("fxp0", "Management1"):
            continue
        if p.get("ifOperStatus") != "up":
            continue
        in_bps = (p.get("ifInOctets_rate") or 0) * 8
        out_bps = (p.get("ifOutOctets_rate") or 0) * 8
        speed = p.get("ifSpeed") or 0
        total_bps = in_bps + out_bps
        if total_bps < 1000:
            continue
        result.append({
            "hostname": p.get("_hostname", ""),
            "ifName": ifname,
            "ifAlias": p.get("ifAlias", ""),
            "speed_gbps": round(speed / 1e9, 1) if speed else 0,
            "in_mbps": round(in_bps / 1e6, 2),
            "out_mbps": round(out_bps / 1e6, 2),
            "total_mbps": round(total_bps / 1e6, 2),
            "util_pct": round(max(in_bps, out_bps) / speed * 100, 1) if speed else 0,
        })
    result.sort(key=lambda x: x["total_mbps"], reverse=True)

    return jsonify({
        "success": True, "site": site, "region": region,
        "total_ports": len(result), "limit": limit,
        "ports": result[:limit],
    })


@app.route("/api/librenms/alerts", methods=["GET"])
def lnms_alerts():
    """Get active LibreNMS alerts. Query: site=DE-FRA&region=emea"""
    site = request.args.get("site", "").upper()
    region = request.args.get("region") or (_lnms_region_for_host(site.lower() + "-x") if site else "emea")

    data = _lnms_api(region, "/alerts", params={"state": "1"})  # state=1 = active
    alerts = data.get("alerts", [])

    if site:
        alerts = [a for a in alerts if site.lower() in (a.get("hostname") or "").lower()]

    result = []
    for a in alerts:
        result.append({
            "id": a.get("id"),
            "hostname": (a.get("hostname") or "").split(".")[0],
            "rule": a.get("rule"),
            "severity": a.get("severity"),
            "state": a.get("state"),
            "timestamp": a.get("timestamp"),
            "alerted": a.get("alerted"),
        })

    return jsonify({
        "success": True, "site": site or "ALL", "region": region,
        "total_alerts": len(result),
        "alerts": result,
    })


@app.route("/api/librenms/health/<hostname>", methods=["GET"])
def lnms_health(hostname):
    """Get device health from LibreNMS — CPU, memory, temperature, fans, PSU."""
    region = request.args.get("region") or _lnms_region_for_host(hostname)
    dev, region = _lnms_find_device(hostname, region)
    if not dev:
        return jsonify({"success": False, "error": f"Device {hostname} not found in LibreNMS {region.upper()}"})

    device_id = dev.get("device_id")
    health_types = ["device_processor", "device_mempool", "device_temperature", "device_fan", "device_voltage", "device_power"]
    health = {}
    for htype in health_types:
        data = _lnms_api(region, f"/devices/{device_id}/health/{htype}")
        entries = data.get("graphs", data.get("data", []))
        if entries:
            health[htype.replace("device_", "")] = entries

    return jsonify({
        "success": True, "hostname": hostname, "region": region,
        "device_id": device_id,
        "hardware": dev.get("hardware"),
        "version": dev.get("version"),
        "uptime_text": dev.get("uptime_long") or dev.get("uptime_short"),
        "health": health,
    })


@app.route("/api/librenms/forecast/<hostname>", methods=["GET"])
def lnms_forecast(hostname):
    """Bandwidth capacity forecast: current utilization + 6-month projection.
    Uses LibreNMS live port rates, applies monthly growth rates, and identifies
    ports that will hit 80%/90%/100% capacity within 6 months.
    Query: growth=10 (monthly growth % override, default auto-detect by role)"""
    region = request.args.get("region") or _lnms_region_for_host(hostname)
    growth_override = request.args.get("growth")  # monthly % override

    dev, region = _lnms_find_device(hostname, region)
    if not dev:
        return jsonify({"success": False, "error": f"Device {hostname} not found in LibreNMS {region.upper()}"})

    device_id = dev.get("device_id")
    hw = (dev.get("hardware") or "").lower()
    sysname = (dev.get("sysName") or hostname).lower()

    # Determine device role & default monthly growth rate
    if any(x in hw for x in ("srx", "firewall", "palo")) or "-fw-" in sysname:
        role, default_growth = "firewall", 3.0
    elif any(x in hw for x in ("mx", "router", "7280")) or "-rt-" in sysname:
        role, default_growth = "router", 5.0
    else:
        role, default_growth = "switch", 4.0

    monthly_growth = float(growth_override) if growth_override else default_growth

    # Fetch all ports
    data = _lnms_api(region, f"/devices/{device_id}/ports",
                     params={"columns": "port_id,ifName,ifAlias,ifSpeed,ifOperStatus,"
                             "ifInOctets_rate,ifOutOctets_rate,ifInErrors,ifOutErrors"})
    ports = data.get("ports", [])

    # Analyze each port
    forecast_ports = []
    total_capacity_bps = 0
    total_used_bps = 0
    critical_ports = []   # will hit 100% in 6 months
    warning_ports = []    # will hit 80% in 6 months
    at_risk_ports = []    # currently > 60%

    for p in ports:
        ifname = p.get("ifName", "")
        if not ifname or ifname.startswith("lo") or ifname in ("fxp0", "Management1", "em0"):
            continue
        # Skip logical/virtual interfaces — only physical ports matter for capacity
        if ifname.startswith(("irb", "vlan", "vtep", "vme", "jsrv", "pip", "bme")):
            continue
        if ".0" in ifname or "." in ifname.split("/")[-1] if "/" in ifname else False:
            continue  # skip sub-interfaces like et-0/0/30.0
        if p.get("ifOperStatus") != "up":
            continue
        speed = p.get("ifSpeed") or 0
        if speed < 1_000_000_000:  # skip sub-1Gbps (mgmt, console, etc.)
            continue

        in_bps = (p.get("ifInOctets_rate") or 0) * 8
        out_bps = (p.get("ifOutOctets_rate") or 0) * 8
        peak_bps = max(in_bps, out_bps)
        current_util = (peak_bps / speed * 100) if speed else 0

        total_capacity_bps += speed
        total_used_bps += peak_bps

        # Project 6 months forward (compound monthly growth)
        projections = []
        months_to_80 = None
        months_to_90 = None
        months_to_100 = None

        for month in range(1, 7):
            projected = peak_bps * ((1 + monthly_growth / 100) ** month)
            proj_util = (projected / speed * 100) if speed else 0
            projections.append({
                "month": month,
                "projected_mbps": round(projected / 1e6, 1),
                "projected_util_pct": round(proj_util, 1),
            })
            if proj_util >= 80 and months_to_80 is None:
                months_to_80 = month
            if proj_util >= 90 and months_to_90 is None:
                months_to_90 = month
            if proj_util >= 100 and months_to_100 is None:
                months_to_100 = month

        port_entry = {
            "ifName": ifname,
            "ifAlias": p.get("ifAlias", ""),
            "speed_gbps": round(speed / 1e9, 1),
            "current_in_mbps": round(in_bps / 1e6, 1),
            "current_out_mbps": round(out_bps / 1e6, 1),
            "current_peak_mbps": round(peak_bps / 1e6, 1),
            "current_util_pct": round(current_util, 1),
            "month6_projected_mbps": projections[-1]["projected_mbps"],
            "month6_projected_util_pct": projections[-1]["projected_util_pct"],
            "months_to_80pct": months_to_80,
            "months_to_90pct": months_to_90,
            "months_to_100pct": months_to_100,
            "risk": "critical" if months_to_100 else ("warning" if months_to_80 else ("watch" if current_util > 60 else "ok")),
            "projections": projections,
        }
        forecast_ports.append(port_entry)

        if months_to_100:
            critical_ports.append(port_entry)
        elif months_to_80:
            warning_ports.append(port_entry)
        elif current_util > 60:
            at_risk_ports.append(port_entry)

    # Sort by current utilization descending
    forecast_ports.sort(key=lambda x: x["current_util_pct"], reverse=True)
    critical_ports.sort(key=lambda x: x.get("months_to_100pct") or 99)
    warning_ports.sort(key=lambda x: x.get("months_to_80pct") or 99)

    # Overall device capacity
    overall_util = round(total_used_bps / total_capacity_bps * 100, 1) if total_capacity_bps else 0
    overall_month6 = round(total_used_bps * ((1 + monthly_growth / 100) ** 6) / total_capacity_bps * 100, 1) if total_capacity_bps else 0

    # Generate recommendations
    recommendations = []
    if critical_ports:
        recommendations.append({
            "severity": "critical",
            "action": f"{len(critical_ports)} port(s) will exceed 100% capacity within 6 months",
            "detail": ", ".join(f"{p['ifName']} ({p['ifAlias']})" for p in critical_ports[:5]),
            "remediation": "Upgrade port speed or add LAG members immediately. Order hardware if needed."
        })
    if warning_ports:
        recommendations.append({
            "severity": "high",
            "action": f"{len(warning_ports)} port(s) will exceed 80% capacity within 6 months",
            "detail": ", ".join(f"{p['ifName']} ({p['ifAlias']})" for p in warning_ports[:5]),
            "remediation": "Plan capacity upgrade. Evaluate traffic engineering or load balancing options."
        })
    if at_risk_ports:
        recommendations.append({
            "severity": "medium",
            "action": f"{len(at_risk_ports)} port(s) currently above 60% utilization",
            "detail": ", ".join(f"{p['ifName']} @ {p['current_util_pct']}%" for p in at_risk_ports[:5]),
            "remediation": "Monitor closely. Add to capacity planning review."
        })
    if not critical_ports and not warning_ports and not at_risk_ports:
        recommendations.append({
            "severity": "info",
            "action": "All ports within comfortable capacity margins",
            "detail": f"Overall utilization: {overall_util}%",
            "remediation": "Continue standard monitoring. Next review in 3 months."
        })

    return jsonify({
        "success": True,
        "hostname": hostname,
        "region": region,
        "hardware": dev.get("hardware"),
        "version": dev.get("version"),
        "role": role,
        "monthly_growth_pct": monthly_growth,
        "analysis_date": datetime.now().isoformat(),
        "summary": {
            "total_ports_analyzed": len(forecast_ports),
            "total_capacity_gbps": round(total_capacity_bps / 1e9, 1),
            "total_used_gbps": round(total_used_bps / 1e9, 1),
            "current_overall_util_pct": overall_util,
            "projected_6month_util_pct": overall_month6,
            "critical_ports": len(critical_ports),
            "warning_ports": len(warning_ports),
            "at_risk_ports": len(at_risk_ports),
        },
        "recommendations": recommendations,
        "critical_ports": critical_ports,
        "warning_ports": warning_ports,
        "at_risk_ports": at_risk_ports,
        "all_ports": forecast_ports[:50],  # top 50 by utilization
    })


@app.route("/api/librenms/forecast-site", methods=["GET"])
def lnms_forecast_site():
    """Site-wide bandwidth capacity forecast: all devices at a site with 6-month projection.
    Query: site=DE-FRA&growth=5&limit=30"""
    site = request.args.get("site", "").upper()
    if not site:
        return jsonify({"success": False, "error": "Provide site parameter (e.g. site=DE-FRA)"})
    growth_override = request.args.get("growth")
    limit = int(request.args.get("limit", "30"))
    region = request.args.get("region") or _lnms_region_for_host(site.lower() + "-x")

    # Get all devices at the site
    devs_data = _lnms_api(region, "/devices", params={"type": "keyword", "query": site.lower()})
    devices = [d for d in devs_data.get("devices", []) if site.lower() in d.get("hostname", "").lower()]

    all_critical = []
    all_warning = []
    all_at_risk = []
    device_summaries = []
    total_cap = 0
    total_used = 0

    for dev in devices[:50]:
        hostname = dev.get("hostname", "").split(".")[0]
        hw = (dev.get("hardware") or "").lower()
        sysname = hostname.lower()

        if any(x in hw for x in ("srx", "firewall", "palo")) or "-fw-" in sysname:
            role, default_growth = "firewall", 3.0
        elif any(x in hw for x in ("mx", "router", "7280")) or "-rt-" in sysname:
            role, default_growth = "router", 5.0
        else:
            role, default_growth = "switch", 4.0

        mg = float(growth_override) if growth_override else default_growth
        did = dev.get("device_id")
        pdata = _lnms_api(region, f"/devices/{did}/ports",
                          params={"columns": "ifName,ifAlias,ifSpeed,ifOperStatus,ifInOctets_rate,ifOutOctets_rate"})

        dev_cap = 0
        dev_used = 0
        dev_crit = 0
        dev_warn = 0
        dev_risk = 0

        for p in pdata.get("ports", []):
            ifname = p.get("ifName", "")
            if not ifname or ifname.startswith("lo") or ifname in ("fxp0", "Management1", "em0"):
                continue
            if ifname.startswith(("irb", "vlan", "vtep", "vme", "jsrv", "pip", "bme")):
                continue
            if ".0" in ifname or "." in ifname.split("/")[-1] if "/" in ifname else False:
                continue
            if p.get("ifOperStatus") != "up":
                continue
            speed = p.get("ifSpeed") or 0
            if speed < 1_000_000_000:
                continue
            in_bps = (p.get("ifInOctets_rate") or 0) * 8
            out_bps = (p.get("ifOutOctets_rate") or 0) * 8
            peak = max(in_bps, out_bps)
            cur_util = (peak / speed * 100) if speed else 0
            dev_cap += speed
            dev_used += peak

            # Check 6-month projection
            proj6 = peak * ((1 + mg / 100) ** 6)
            proj6_util = (proj6 / speed * 100) if speed else 0

            entry = {
                "hostname": hostname, "ifName": ifname,
                "ifAlias": p.get("ifAlias", ""),
                "speed_gbps": round(speed / 1e9, 1),
                "current_peak_mbps": round(peak / 1e6, 1),
                "current_util_pct": round(cur_util, 1),
                "month6_util_pct": round(proj6_util, 1),
            }

            if proj6_util >= 100:
                dev_crit += 1
                all_critical.append(entry)
            elif proj6_util >= 80:
                dev_warn += 1
                all_warning.append(entry)
            elif cur_util > 60:
                dev_risk += 1
                all_at_risk.append(entry)

        total_cap += dev_cap
        total_used += dev_used

        device_summaries.append({
            "hostname": hostname,
            "hardware": dev.get("hardware"),
            "role": role,
            "capacity_gbps": round(dev_cap / 1e9, 1),
            "used_gbps": round(dev_used / 1e9, 1),
            "util_pct": round(dev_used / dev_cap * 100, 1) if dev_cap else 0,
            "critical": dev_crit,
            "warning": dev_warn,
            "at_risk": dev_risk,
        })

    device_summaries.sort(key=lambda x: x["util_pct"], reverse=True)
    all_critical.sort(key=lambda x: x["month6_util_pct"], reverse=True)
    all_warning.sort(key=lambda x: x["month6_util_pct"], reverse=True)

    overall_util = round(total_used / total_cap * 100, 1) if total_cap else 0

    return jsonify({
        "success": True,
        "site": site,
        "region": region,
        "analysis_date": datetime.now().isoformat(),
        "summary": {
            "devices_analyzed": len(device_summaries),
            "total_capacity_tbps": round(total_cap / 1e12, 2),
            "total_used_gbps": round(total_used / 1e9, 1),
            "current_overall_util_pct": overall_util,
            "critical_ports": len(all_critical),
            "warning_ports": len(all_warning),
            "at_risk_ports": len(all_at_risk),
        },
        "devices": device_summaries,
        "critical_ports": all_critical[:limit],
        "warning_ports": all_warning[:limit],
        "at_risk_ports": all_at_risk[:limit],
    })


# ── ISP Links Health Check ─────────────────────────────────────────────────────

# Primary pattern: description contains "-ISP-" (the standard naming convention)
# Secondary: known ISP/transit provider names as fallback
_ISP_PROVIDERS = [
    "lumen", "centurylink", "level3", "zayo", "cogent", "ntt-", "gtt-", "pccw",
    "telia", "arelion", "colt-", "hurricane", "leaseweb", "i3dnet", "i3d-",
    "webwerks", "megaport", "telstra", "singtel", "airtel", "tata-", "claro",
    "embratel", "telefonica", "swisscom", "init7", "edgeuno", "latitude",
    "internexa", "ufinet", "retn", "seacom", "teraco",
]
# Explicit exclusion patterns (PDU, console, management, internal)
_ISP_EXCLUDE = ["pdu", "console", "mgmt", "management", "oob", "monitor", "idrac", "ilo", "bmc"]

def _is_isp_port(alias):
    """Check if an interface description matches ISP link patterns."""
    if not alias:
        return False
    a = alias.lower()
    # Exclude non-ISP ports
    if any(ex in a for ex in _ISP_EXCLUDE):
        return False
    # Primary: standard "-ISP-" naming convention
    if "-isp-" in a or a.startswith("isp-") or "isp " in a:
        return True
    # Secondary: transit/upstream/peering keywords
    if any(kw in a for kw in ("transit", "upstream", "peering")):
        return True
    # Tertiary: known provider names
    return any(prov in a for prov in _ISP_PROVIDERS)


@app.route("/api/isp-links", methods=["GET"])
def isp_links_check():
    """Check all ISP links across the entire network in one call.
    Scans routers, switches, and firewalls in all 3 LibreNMS regions.
    Returns ISP link utilization, 6-month forecast, and risk status.
    Query: growth=5 (override monthly growth %, default 5%)"""
    import concurrent.futures

    growth = float(request.args.get("growth", "5"))
    results = []
    errors = []
    devices_checked = 0

    def _scan_region(region):
        """Fetch all devices in a region and extract ISP ports."""
        nonlocal devices_checked
        region_results = []
        try:
            data = _lnms_api(region, "/devices", timeout=30)
            devices = data.get("devices", [])
        except Exception as e:
            errors.append({"region": region, "error": str(e)})
            return region_results

        for dev in devices:
            sysname = (dev.get("sysName") or dev.get("hostname") or "").lower()
            hostname_short = sysname.split(".")[0]
            # Only check routers, switches, and firewalls (skip consoles, monitors, etc.)
            if not any(t in hostname_short for t in ("-rt-", "-sw-", "-fw-")):
                continue

            device_id = dev.get("device_id")
            if not device_id:
                continue

            try:
                pdata = _lnms_api(region, f"/devices/{device_id}/ports",
                                  params={"columns": "ifName,ifAlias,ifSpeed,ifOperStatus,"
                                          "ifInOctets_rate,ifOutOctets_rate,ifInErrors,ifOutErrors"})
            except Exception:
                continue

            devices_checked += 1
            for p in pdata.get("ports", []):
                alias = p.get("ifAlias") or ""
                if not _is_isp_port(alias):
                    continue
                ifname = p.get("ifName", "")
                if not ifname:
                    continue

                speed = p.get("ifSpeed") or 0
                in_bps = (p.get("ifInOctets_rate") or 0) * 8
                out_bps = (p.get("ifOutOctets_rate") or 0) * 8
                peak_bps = max(in_bps, out_bps)
                cur_util = round((peak_bps / speed * 100), 1) if speed else 0
                # 6-month projection
                proj6_bps = peak_bps * ((1 + growth / 100) ** 6)
                proj6_util = round((proj6_bps / speed * 100), 1) if speed else 0

                status = p.get("ifOperStatus", "unknown")
                in_err = p.get("ifInErrors") or 0
                out_err = p.get("ifOutErrors") or 0

                # Risk assessment
                if status != "up":
                    risk = "down"
                elif proj6_util >= 100:
                    risk = "critical"
                elif proj6_util >= 80:
                    risk = "warning"
                elif cur_util >= 60:
                    risk = "watch"
                else:
                    risk = "ok"

                # Extract site and provider from description
                site = hostname_short.split("-")[0].upper()
                # Parse provider: typically "{site}-ISP-{Provider}" or "{site}-{Provider}"
                provider = alias
                if "-ISP-" in alias.upper():
                    provider = alias.upper().split("-ISP-", 1)[1].split("-")[0]
                elif "-isp-" in alias.lower():
                    provider = alias.lower().split("-isp-", 1)[1].split("-")[0]

                region_results.append({
                    "site": site,
                    "hostname": hostname_short,
                    "ifName": ifname,
                    "description": alias,
                    "provider": provider,
                    "speed_gbps": round(speed / 1e9, 1) if speed else 0,
                    "status": status,
                    "in_mbps": round(in_bps / 1e6, 1),
                    "out_mbps": round(out_bps / 1e6, 1),
                    "peak_mbps": round(peak_bps / 1e6, 1),
                    "current_util_pct": cur_util,
                    "projected_6mo_util_pct": proj6_util,
                    "in_errors": in_err,
                    "out_errors": out_err,
                    "risk": risk,
                    "region": region,
                    "hardware": dev.get("hardware", ""),
                })
        return region_results

    # Query all 3 regions in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(_scan_region, r): r for r in ("emea", "amer", "apac")}
        for f in concurrent.futures.as_completed(futures):
            try:
                results.extend(f.result())
            except Exception as e:
                errors.append({"region": futures[f], "error": str(e)})

    # Sort: down links first, then by utilization descending
    risk_order = {"down": 0, "critical": 1, "warning": 2, "watch": 3, "ok": 4}
    results.sort(key=lambda x: (risk_order.get(x["risk"], 5), -x["current_util_pct"]))

    # Summary stats
    total = len(results)
    up_links = [r for r in results if r["status"] == "up"]
    down_links = [r for r in results if r["status"] != "up"]
    critical = [r for r in results if r["risk"] == "critical"]
    warning = [r for r in results if r["risk"] == "warning"]
    watch = [r for r in results if r["risk"] == "watch"]
    total_cap = sum(r["speed_gbps"] for r in up_links)
    total_used = sum(r["peak_mbps"] for r in up_links) / 1000
    avg_util = round(sum(r["current_util_pct"] for r in up_links) / len(up_links), 1) if up_links else 0

    # Group by site
    site_summary = {}
    for r in results:
        s = r["site"]
        if s not in site_summary:
            site_summary[s] = {"site": s, "links": 0, "down": 0, "critical": 0,
                               "warning": 0, "avg_util": 0, "_utils": []}
        site_summary[s]["links"] += 1
        if r["status"] != "up":
            site_summary[s]["down"] += 1
        if r["risk"] == "critical":
            site_summary[s]["critical"] += 1
        elif r["risk"] == "warning":
            site_summary[s]["warning"] += 1
        if r["status"] == "up":
            site_summary[s]["_utils"].append(r["current_util_pct"])

    for s in site_summary.values():
        s["avg_util"] = round(sum(s["_utils"]) / len(s["_utils"]), 1) if s["_utils"] else 0
        del s["_utils"]

    sites_sorted = sorted(site_summary.values(), key=lambda x: (-x["down"], -x["critical"], -x["avg_util"]))

    # ── LLM-powered ISP executive narrative (DISABLED — structured findings sufficient) ──
    llm_narrative = None
    llm_powered = False

    return jsonify({
        "success": True,
        "analysis_date": datetime.now().isoformat(),
        "monthly_growth_pct": growth,
        "llm_narrative": llm_narrative,
        "llm_powered": llm_powered,
        "summary": {
            "total_isp_links": total,
            "links_up": len(up_links),
            "links_down": len(down_links),
            "critical_6mo": len(critical),
            "warning_6mo": len(warning),
            "watch": len(watch),
            "total_capacity_gbps": round(total_cap, 1),
            "total_used_gbps": round(total_used, 1),
            "avg_utilization_pct": avg_util,
            "devices_scanned": devices_checked,
            "regions_scanned": 3,
        },
        "sites": sites_sorted,
        "links": results,
        "errors": errors,
    })


# ── Network-Wide Port Capacity Report ──────────────────────────────────────────

@app.route("/api/report/ports", methods=["GET"])
def report_all_ports():
    """Network-wide port capacity report via LibreNMS.
    Scans all routers, switches, firewalls across all 3 regions.
    Returns per-site and per-device port usage summary."""
    import concurrent.futures

    results = []
    errors = []

    def _scan_region(region):
        region_results = []
        try:
            data = _lnms_api(region, "/devices", timeout=30)
            devices = data.get("devices", [])
        except Exception as e:
            errors.append({"region": region, "error": str(e)})
            return region_results

        for dev in devices:
            sysname = (dev.get("sysName") or dev.get("hostname") or "").lower()
            hostname_short = sysname.split(".")[0]
            if not any(t in hostname_short for t in ("-rt-", "-sw-", "-fw-")):
                continue
            device_id = dev.get("device_id")
            if not device_id:
                continue
            try:
                pdata = _lnms_api(region, f"/devices/{device_id}/ports",
                                  params={"columns": "ifName,ifAlias,ifSpeed,ifOperStatus,ifAdminStatus,ifType"})
            except Exception:
                continue

            total = up = down = disabled = 0
            by_speed = {}
            ports_detail = []
            for p in pdata.get("ports", []):
                ifname = p.get("ifName") or ""
                # Skip logical/virtual interfaces
                if any(ifname.lower().startswith(x) for x in (
                    "lo", "irb", "vlan", "vtep", "vme", "bme", "jsrv", "pip",
                    "lsi", "gre", "ipip", "tap", "em", "fxp", "me0", "vcp",
                    "dsc", "pime", "pimd", "pfh", "cbp", "demux", "esi",
                    "gr-", "ip-", "lt-", "mt-", "sp-", "st0", "pp0", "ppd", "lc-",
                )):
                    continue
                if "." in ifname:  # sub-interfaces
                    continue
                if ifname.startswith("ae") and not any(c.isdigit() and int(c) < 200 for c in re.findall(r'\d+', ifname)):
                    pass  # keep ae interfaces

                speed = p.get("ifSpeed") or 0
                oper = p.get("ifOperStatus", "")
                admin = p.get("ifAdminStatus", "")
                alias = (p.get("ifAlias") or "").strip()
                # Clear description if it just echoes the interface name
                if alias.lower() == ifname.lower():
                    alias = ""

                total += 1
                if admin == "down":
                    disabled += 1
                    status = "disabled"
                elif oper == "up":
                    up += 1
                    status = "up"
                else:
                    down += 1
                    status = "down"

                # Bucket by speed
                if speed >= 100e9:
                    bucket = "100G"
                elif speed >= 40e9:
                    bucket = "40G"
                elif speed >= 25e9:
                    bucket = "25G"
                elif speed >= 10e9:
                    bucket = "10G"
                elif speed >= 1e9:
                    bucket = "1G"
                elif speed > 0:
                    bucket = "<1G"
                else:
                    bucket = "unknown"

                if bucket not in by_speed:
                    by_speed[bucket] = {"total": 0, "up": 0, "down": 0, "disabled": 0}
                by_speed[bucket]["total"] += 1
                if status == "disabled":
                    by_speed[bucket]["disabled"] += 1
                elif status == "up":
                    by_speed[bucket]["up"] += 1
                else:
                    by_speed[bucket]["down"] += 1

                ports_detail.append({
                    "ifName": ifname,
                    "description": alias,
                    "speed": bucket,
                    "status": status,
                })

            if total == 0:
                continue

            site = hostname_short.split("-")[0].upper()
            dtype = "router" if "-rt-" in hostname_short else "firewall" if "-fw-" in hostname_short else "switch"
            util_pct = round(up / total * 100, 1) if total else 0

            region_results.append({
                "site": site,
                "hostname": hostname_short,
                "device_type": dtype,
                "total": total, "up": up, "down": down, "disabled": disabled,
                "free": down,
                "utilization_pct": util_pct,
                "by_speed": by_speed,
                "ports_detail": ports_detail,
                "hardware": dev.get("hardware", ""),
                "region": region,
            })
        return region_results

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(_scan_region, r): r for r in ("emea", "amer", "apac")}
        for f in concurrent.futures.as_completed(futures):
            try:
                results.extend(f.result())
            except Exception as e:
                errors.append({"region": futures[f], "error": str(e)})

    # Site aggregation
    site_summary = {}
    for d in results:
        s = d["site"]
        if s not in site_summary:
            site_summary[s] = {"site": s, "devices": 0, "total": 0, "up": 0, "down": 0,
                               "disabled": 0, "utilization_pct": 0, "_utils": []}
        site_summary[s]["devices"] += 1
        site_summary[s]["total"] += d["total"]
        site_summary[s]["up"] += d["up"]
        site_summary[s]["down"] += d["down"]
        site_summary[s]["disabled"] += d["disabled"]
        site_summary[s]["_utils"].append(d["utilization_pct"])

    for ss in site_summary.values():
        ss["utilization_pct"] = round(sum(ss["_utils"]) / len(ss["_utils"]), 1) if ss["_utils"] else 0
        del ss["_utils"]

    sites_sorted = sorted(site_summary.values(), key=lambda x: (-x["total"], x["site"]))
    results.sort(key=lambda x: (x["site"], x["hostname"]))

    grand = {"total": sum(d["total"] for d in results),
             "up": sum(d["up"] for d in results),
             "down": sum(d["down"] for d in results),
             "disabled": sum(d["disabled"] for d in results)}
    grand["utilization_pct"] = round(grand["up"] / grand["total"] * 100, 1) if grand["total"] else 0

    return jsonify({
        "success": True,
        "analysis_date": datetime.now().isoformat(),
        "summary": {
            "total_devices": len(results),
            "total_sites": len(site_summary),
            "total_ports": grand["total"],
            "ports_up": grand["up"],
            "ports_down": grand["down"],
            "ports_disabled": grand["disabled"],
            "avg_utilization_pct": grand["utilization_pct"],
        },
        "sites": sites_sorted,
        "devices": results,
        "errors": errors,
    })


# ── Network-Wide BGP Summary Report ───────────────────────────────────────────

_AS_NAMES = {
    577: "Bell Canada", 680: "DFN", 786: "JANET (UK)", 852: "TIWS (Taiwan)",
    1221: "Telstra", 1267: "WIND Tre (IT)", 1299: "Arelion (Telia)", 1680: "CellCom (IL)",
    1836: "Green Mountain Access", 2856: "BT (UK)", 2914: "NTT", 3303: "Swisscom",
    3356: "Lumen (CenturyLink)", 4226: "EGIHosting", 4637: "Telstra Global",
    5410: "Bouygues Telecom", 5413: "Daisy (UK)", 5430: "Freenet (DE)",
    5459: "LINX", 5607: "BSkyB (UK)", 5645: "TekSavvy", 5650: "Frontier",
    5769: "Videotron", 6128: "Cablevision", 6204: "SRIT (DE)", 6315: "Xplornet",
    6695: "DE-CIX", 6777: "AMS-IX", 6805: "Telefonica (DE)", 6908: "DATEV",
    6939: "Hurricane Electric", 7029: "Windstream", 7195: "EdgeConneX",
    7606: "InfoRelay", 7843: "Charter", 7922: "Comcast",
    8075: "Microsoft", 8220: "Colt", 8309: "SIPARTECH (FR)", 8365: "ManSE (DE)",
    8426: "Claranet", 8447: "A1 Telekom (AT)", 8455: "SCHUBERG (NL)",
    8473: "Bahnhof (SE)", 8551: "Bezeq (IL)", 8657: "Polkomtel (PL)",
    8714: "Linx Telecom", 8781: "Telia Lietuva", 8966: "Etisalat",
    9009: "M247", 9286: "IIPL (IN)",
    11260: "EastLink", 11670: "Equinix Connect",
    12083: "MiSP (PL)", 12189: "Leaseweb", 12713: "OTEGLOBE (GR)",
    12874: "Fastweb (IT)", 12956: "Telefonica Global", 13030: "Init7 (CH)",
    13037: "Zen Internet (UK)", 13150: "Cato Networks", 13335: "Cloudflare",
    13727: "Cyxtera", 13760: "Unitas Global",
    15169: "Google", 15600: "Quickline (CH)", 15692: "GCI (DE)",
    15802: "DU (UAE)", 16082: "Splio (FR)",
    16509: "Amazon AWS", 16735: "Algar Telecom (BR)",
    20115: "Charter", 20121: "Comcast Business", 20746: "Telecom Italia Sparkle",
    20940: "Akamai", 21056: "SolidSpeed", 21574: "Redsys (ES)",
    22652: "Fibrenoire (CA)", 24115: "Equinix IX", 24940: "Hetzner",
    25180: "Exponential-e (UK)", 25375: "KW Datacenter",
    26162: "Solarwinds", 28126: "DAISY (UK)", 28166: "ITSHOSTED (NL)",
    28173: "I.C.Sys (RO)", 28343: "Siemens Healthineers",
    29222: "Infomaniak (CH)", 30600: "Cygate (SE)", 30781: "Jaguar (FR)",
    30937: "Kaypu (US)", 31655: "Gamtel (GM)", 31898: "Oracle Cloud",
    32277: "Amazon (US-West)", 33108: "Google Edge",
    34307: "NL-IX", 34309: "Link11 (DE)", 34555: "Liberty Global",
    35793: "S-NET (DE)", 40519: "Tivit (BR)", 40838: "DataCamp",
    42184: "IVU (DE)", 42476: "SwissIX", 46450: "Fundacao de Amparo",
    48185: "REGIO.Digital (DE)", 48635: "Packet Clearing House",
    49544: "i3D.net", 50263: "Verizon Digital",
    50316: "IPERCAST (DE)", 51392: "Windcloud (DE)", 51706: "CorpNet",
    52965: "Localiza (BR)", 53107: "Netilion (US)",
    53405: "SERVERIUS (NL)", 53427: "TWTELECOM", 53991: "Uniti Fiber",
    55256: "Loxone (AU)", 59253: "JasTel (TH)", 61525: "Zayo",
    62887: "Cyrusone", 63997: "Netflix", 64234: "Equinix Metal",
    64510: "CorpNet Private", 65111: "CorpNet Private",
    65131: "CorpNet Private", 65517: "CorpNet Private",
    133296: "Broadband (AU)", 136988: "Symbio (AU)",
    206238: "Freedom Internet (NL)", 206446: "Cloudeo (DE)",
    262287: "Sengi (BR)", 262740: "GGNet (BR)", 263998: "Claro (BR)",
    264525: "V.tal (BR)", 267629: "Globenet (BR)", 272394: "Desktop (BR)",
}


def _as_name(asn):
    """Resolve AS number to name. Handles CorpNet private 42xxxxx ASNs."""
    asn = int(asn) if asn else 0
    if asn in _AS_NAMES:
        return _AS_NAMES[asn]
    if 4200000000 <= asn <= 4294967295:
        return "CorpNet Private"
    if 64512 <= asn <= 65534:
        return "Private ASN"
    if 4200000000 <= asn <= 4294967294:
        return "Private ASN (4-byte)"
    return ""


@app.route("/api/report/bgp", methods=["GET"])
def report_all_bgp():
    """Network-wide BGP session health via LibreNMS.
    Scans all routers (and switches with BGP) across all 3 regions.
    Returns per-device BGP neighbor summary with session states."""
    import concurrent.futures

    results = []
    errors = []

    def _scan_region(region):
        region_results = []
        # Build device lookup map: device_id → {hostname, hardware}
        try:
            dev_data = _lnms_api(region, "/devices", timeout=30)
            devices = dev_data.get("devices", [])
        except Exception as e:
            errors.append({"region": region, "error": str(e)})
            return region_results

        dev_map = {}
        for dev in devices:
            did = dev.get("device_id")
            if not did:
                continue
            sysname = (dev.get("sysName") or dev.get("hostname") or "").lower()
            hostname_short = sysname.split(".")[0]
            if any(t in hostname_short for t in ("-rt-", "-sw-", "-fw-")):
                dev_map[str(did)] = {"hostname": hostname_short, "hardware": dev.get("hardware", "")}

        # Use global /bgp endpoint — one call gets ALL BGP sessions in the region
        try:
            bgp_data = _lnms_api(region, "/bgp", timeout=30)
        except Exception as e:
            errors.append({"region": region, "error": f"BGP API: {e}"})
            return region_results

        # Try different response keys (LibreNMS versions vary)
        neighbours = bgp_data.get("bgp_sessions", bgp_data.get("bgp", []))
        if not isinstance(neighbours, list):
            neighbours = []

        for n in neighbours:
            did = str(n.get("device_id", ""))
            dev_info = dev_map.get(did)
            if not dev_info:
                continue  # skip non-network devices

            hostname_short = dev_info["hostname"]
            site = hostname_short.split("-")[0].upper()
            peer_ip = n.get("bgpPeerIdentifier") or n.get("bgpPeerRemoteAddr") or ""
            state = (n.get("bgpPeerState") or "unknown").lower()
            remote_as = n.get("bgpPeerRemoteAs") or 0
            local_as = n.get("bgpLocalAs") or n.get("bgpPeerLocalAs") or 0
            pfx_accepted = n.get("bgpPeerAcceptedPrefixes") or 0

            if str(remote_as) == str(local_as):
                session_type = "iBGP"
            else:
                session_type = "eBGP"

            if state == "established":
                risk = "ok"
            elif state in ("active", "connect", "opensent", "openconfirm"):
                risk = "warning"
            elif state == "idle":
                risk = "critical"
            else:
                risk = "unknown"

            region_results.append({
                "site": site,
                "hostname": hostname_short,
                "peer_ip": peer_ip,
                "remote_as": remote_as,
                "as_name": _as_name(remote_as),
                "local_as": local_as,
                "session_type": session_type,
                "state": state,
                "prefixes_accepted": pfx_accepted,
                "risk": risk,
                "region": region,
                "hardware": dev_info["hardware"],
            })
        return region_results

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(_scan_region, r): r for r in ("emea", "amer", "apac")}
        for f in concurrent.futures.as_completed(futures):
            try:
                results.extend(f.result())
            except Exception as e:
                errors.append({"region": futures[f], "error": str(e)})

    # Sort: non-established first
    state_order = {"idle": 0, "active": 1, "connect": 2, "opensent": 3,
                   "openconfirm": 4, "unknown": 5, "established": 6}
    results.sort(key=lambda x: (state_order.get(x["state"], 5), x["site"], x["hostname"]))

    # Summary stats
    total = len(results)
    established = [r for r in results if r["state"] == "established"]
    not_established = [r for r in results if r["state"] != "established"]
    idle_sessions = [r for r in results if r["state"] == "idle"]
    active_sessions = [r for r in results if r["state"] in ("active", "connect")]
    ebgp = [r for r in results if r["session_type"] == "eBGP"]
    ibgp = [r for r in results if r["session_type"] == "iBGP"]
    unique_devices = set(r["hostname"] for r in results)
    unique_sites = set(r["site"] for r in results)

    # Site aggregation
    site_summary = {}
    for r in results:
        s = r["site"]
        if s not in site_summary:
            site_summary[s] = {"site": s, "total": 0, "established": 0,
                               "not_established": 0, "idle": 0, "ebgp": 0, "ibgp": 0}
        site_summary[s]["total"] += 1
        if r["state"] == "established":
            site_summary[s]["established"] += 1
        else:
            site_summary[s]["not_established"] += 1
        if r["state"] == "idle":
            site_summary[s]["idle"] += 1
        if r["session_type"] == "eBGP":
            site_summary[s]["ebgp"] += 1
        else:
            site_summary[s]["ibgp"] += 1

    sites_sorted = sorted(site_summary.values(),
                          key=lambda x: (-x["not_established"], -x["idle"], x["site"]))

    return jsonify({
        "success": True,
        "analysis_date": datetime.now().isoformat(),
        "summary": {
            "total_sessions": total,
            "established": len(established),
            "not_established": len(not_established),
            "idle": len(idle_sessions),
            "active_connect": len(active_sessions),
            "ebgp_sessions": len(ebgp),
            "ibgp_sessions": len(ibgp),
            "devices_with_bgp": len(unique_devices),
            "sites_with_bgp": len(unique_sites),
        },
        "sites": sites_sorted,
        "sessions": results,
        "errors": errors,
    })


# ── Subnet / IP Exhaustion Analysis ───────────────────────────────────────────

def _parse_subnets_junos(iface_output):
    """Parse JunOS 'show interfaces terse | match inet' to extract interface→subnet mapping."""
    import ipaddress
    subnets = {}
    current_iface = None
    for line in iface_output.splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        parts = line.split()
        # Lines starting with interface name (not indented)
        if not line.startswith(" ") and len(parts) >= 3:
            current_iface = parts[0]
            # Find inet address in this line
            for p in parts:
                if "/" in p and not p.startswith("fe80") and not p.startswith("::"):
                    try:
                        iface_net = ipaddress.ip_interface(p)
                        if iface_net.version == 4:
                            net = iface_net.network
                            if net.prefixlen <= 31 and not net.is_loopback:
                                subnets[str(net)] = {"interface": current_iface, "gateway": str(iface_net.ip), "prefix": net.prefixlen}
                    except (ValueError, TypeError):
                        pass
        elif line.startswith(" ") and current_iface:
            # Continuation line with inet address
            for p in parts:
                if "/" in p and not p.startswith("fe80") and not p.startswith("::"):
                    try:
                        iface_net = ipaddress.ip_interface(p)
                        if iface_net.version == 4:
                            net = iface_net.network
                            if net.prefixlen <= 31 and not net.is_loopback:
                                subnets[str(net)] = {"interface": current_iface, "gateway": str(iface_net.ip), "prefix": net.prefixlen}
                    except (ValueError, TypeError):
                        pass
    return subnets

def _parse_subnets_eos(iface_output):
    """Parse EOS 'show ip interface brief' to extract interface→subnet mapping."""
    import ipaddress
    subnets = {}
    for line in iface_output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        iface = parts[0]
        for p in parts[1:]:
            if "/" in p:
                try:
                    iface_net = ipaddress.ip_interface(p)
                    if iface_net.version == 4:
                        net = iface_net.network
                        if net.prefixlen <= 31 and not net.is_loopback:
                            subnets[str(net)] = {"interface": iface, "gateway": str(iface_net.ip), "prefix": net.prefixlen}
                except (ValueError, TypeError):
                    pass
    return subnets

def _parse_arp_junos(arp_output):
    """Parse JunOS 'show arp' or 'show arp no-resolve'.
    With resolve:    MAC IP Name Interface Flags   (5+ cols)
    Without resolve: MAC IP Interface Flags        (4 cols)
    """
    entries = []
    for line in arp_output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        mac = parts[0]
        if not _MAC_COLON_RE.match(mac):
            continue
        ip_addr = parts[1]
        # Detect format: if parts[2] looks like an interface (contains . or /) it's no-resolve
        if len(parts) == 4 or (len(parts) >= 4 and ("." in parts[2] or "/" in parts[2])):
            # no-resolve: MAC IP Interface Flags
            iface = parts[2]
            name = ""
        else:
            # resolve: MAC IP Name Interface Flags
            name = parts[2]
            iface = parts[-2]
        entries.append({"mac": mac, "ip": ip_addr, "name": name, "interface": iface})
    return entries

def _parse_arp_eos(arp_output):
    """Parse EOS 'show arp' → list of {mac, ip, name, interface}."""
    entries = []
    for line in arp_output.splitlines():
        # Address         Age (sec)  Hardware Addr   Interface
        parts = line.split()
        if len(parts) < 4:
            continue
        ip_addr = parts[0]
        if not _IPV4_RE.match(ip_addr):
            continue
        mac = parts[2]
        iface = parts[3] if len(parts) > 3 else ""
        entries.append({"mac": mac, "ip": ip_addr, "name": "", "interface": iface})
    return entries


def _parse_iface_descriptions_junos(desc_output):
    """Parse JunOS 'show interfaces descriptions' → {interface_base: description}."""
    descs = {}
    for line in desc_output.splitlines():
        parts = line.split(None, 3)
        if len(parts) >= 4 and parts[1] in ("up", "down"):
            # Interface  Admin  Link  Description
            descs[parts[0]] = parts[3]
        elif len(parts) == 3 and parts[1] in ("up", "down"):
            descs[parts[0]] = ""
    return descs

def _parse_iface_descriptions_eos(desc_output):
    """Parse EOS 'show interfaces description' → {interface: description}."""
    descs = {}
    for line in desc_output.splitlines():
        parts = line.split(None, 3)
        if len(parts) >= 4 and parts[1] in ("up", "down", "admin"):
            descs[parts[0]] = parts[3] if len(parts) > 3 else ""
        elif len(parts) >= 3 and parts[1] in ("up", "down"):
            descs[parts[0]] = parts[3] if len(parts) > 3 else ""
    return descs

def _parse_mac_per_vlan_junos(mac_output):
    """Parse JunOS ethernet-switching table → {vlan_name: count_of_unique_macs}."""
    vlan_macs = {}
    for line in mac_output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        mac = parts[1] if len(parts) >= 6 else ""
        if not _MAC_COLON_RE.match(mac):
            continue
        vlan = parts[0]
        vlan_macs.setdefault(vlan, set()).add(mac.lower())
    return {v: len(macs) for v, macs in vlan_macs.items()}

def _parse_mac_per_vlan_eos(mac_output):
    """Parse EOS mac address-table → {vlan_id: count_of_unique_macs}."""
    vlan_macs = {}
    for line in mac_output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        # Try to find VLAN ID and MAC
        vlan = None
        mac = None
        for p in parts:
            if p.isdigit() and vlan is None:
                vlan = p
            if re.match(r'^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$', p, re.I):
                mac = p
        if vlan and mac:
            vlan_macs.setdefault(vlan, set()).add(mac.lower())
    return {v: len(macs) for v, macs in vlan_macs.items()}


@app.route("/api/subnet-analysis", methods=["POST"])
def subnet_analysis():
    """
    Analyze subnet IP exhaustion for a device.
    Collects ARP, interface IPs, MAC table, and interface descriptions.
    Cross-references ARP (L3 active hosts) with MAC table (L2 devices).
    Body: { "ip": "10.1.15.1", "dtype": "junos", "hostname": "uk-lon-fw-20a" }
    Returns per-subnet breakdown with utilization %, active hosts, free IPs,
    MAC-only devices, interface descriptions, and exhaustion status.
    """
    import ipaddress

    data = request.json or {}
    ip       = data.get("ip")
    dtype    = data.get("dtype", "junos")
    hostname = data.get("hostname", ip or "")

    if not ip:
        return jsonify({"success": False, "error": "Missing ip"}), 400

    # Collect data from device — individual SSH calls (Paramiko)
    # run_command_on_device is more reliable than Netmiko batch across device types
    if dtype == "junos":
        cmd_map = {
            "arp":          "show arp | no-more",
            "interfaces":   "show interfaces terse | match inet | no-more",
            "mac_table":    "show ethernet-switching table | no-more",
            "descriptions": "show interfaces descriptions | no-more",
        }
    else:
        cmd_map = {
            "arp":          "show arp",
            "interfaces":   "show ip interface brief",
            "mac_table":    "show mac address-table",
            "descriptions": "show interfaces description",
        }

    outputs = {}
    for key, cmd in cmd_map.items():
        r = run_command_on_device(ip, dtype, cmd)
        if key in ("arp", "interfaces") and not r.get("success"):
            return jsonify({"success": False, "error": r.get("error", f"SSH failed for {key}")}), 500
        outputs[key] = r.get("output", "") if r.get("success") else ""

    arp_raw   = outputs.get("arp", "")
    iface_raw = outputs.get("interfaces", "")
    mac_raw   = outputs.get("mac_table", "")
    desc_raw  = outputs.get("descriptions", "")

    # Parse subnets from interfaces
    if dtype == "junos":
        subnets = _parse_subnets_junos(iface_raw)
        arp_entries = _parse_arp_junos(arp_raw)
        iface_descs = _parse_iface_descriptions_junos(desc_raw)
        mac_per_vlan = _parse_mac_per_vlan_junos(mac_raw)
    else:
        subnets = _parse_subnets_eos(iface_raw)
        arp_entries = _parse_arp_eos(arp_raw)
        iface_descs = _parse_iface_descriptions_eos(desc_raw)
        mac_per_vlan = _parse_mac_per_vlan_eos(mac_raw)

    # Build a set of all ARP MACs for cross-reference
    arp_macs = set()
    for entry in arp_entries:
        arp_macs.add(entry["mac"].lower())

    # Skip truly internal/uninteresting subnets
    skip_prefixes = ("128.0.", "169.254.")
    filtered_subnets = {}
    for net_str, info in subnets.items():
        iface_lower = info["interface"].lower()
        # Skip internal fabric/chassis interfaces (but keep fxp0 management)
        if any(iface_lower.startswith(x) for x in ("fab", "bme", "jsrv", "pfh", "pfe")):
            continue
        if iface_lower.startswith("em") and "32768" not in info["interface"]:
            # Skip em2/em3/em4 internal but keep em2.32768 (management on some routers)
            if not iface_lower.startswith("em0"):
                continue
        if any(net_str.startswith(x) for x in skip_prefixes):
            continue
        # Skip /32 host routes only
        if info["prefix"] >= 32:
            continue
        # Skip 30.x.x.x fabric interconnects
        if net_str.startswith("30."):
            continue
        filtered_subnets[net_str] = info

    # Look up description for each interface
    for net_str, info in filtered_subnets.items():
        iface = info["interface"]
        # Try exact match first, then base name (reth1.0 → reth1)
        desc = iface_descs.get(iface, "")
        if not desc:
            base = iface.split(".")[0]
            desc = iface_descs.get(base, "")
        info["description"] = desc

    # Map ARP entries to subnets
    subnet_results = []
    for net_str, info in sorted(filtered_subnets.items()):
        try:
            network = ipaddress.ip_network(net_str)
        except ValueError:
            continue

        # /31 P2P links have 2 usable IPs per RFC 3021 (no net/bcast)
        if network.prefixlen == 31:
            total_ips = 2
        else:
            total_ips = network.num_addresses - 2  # exclude network + broadcast
        if total_ips <= 0:
            continue

        # Find ARP entries in this subnet
        hosts_in_subnet = []
        seen_ips = set()
        seen_macs = set()
        for entry in arp_entries:
            try:
                host_ip = ipaddress.ip_address(entry["ip"])
            except (ValueError, TypeError):
                continue
            if host_ip in network and entry["ip"] not in seen_ips:
                seen_ips.add(entry["ip"])
                seen_macs.add(entry["mac"].lower())
                hosts_in_subnet.append({
                    "ip": entry["ip"],
                    "mac": entry["mac"],
                    "name": entry.get("name", ""),
                    "interface": entry.get("interface", ""),
                    "source": "arp",
                })

        active_count = len(hosts_in_subnet)
        free_count = total_ips - active_count
        utilization = round((active_count / total_ips) * 100, 1) if total_ips > 0 else 0

        # Try to find MAC-only count for this subnet's VLAN
        # JunOS: interface reth1.0 might map to vlan name "vlan10" or similar
        # This is a best-effort match
        mac_only_count = 0
        matched_vlan = ""
        iface_base = info["interface"].split(".")[0]
        for vlan_name, mcount in mac_per_vlan.items():
            # Simple heuristic: if vlan name contains the interface unit number
            unit = info["interface"].split(".")[-1] if "." in info["interface"] else ""
            if unit and unit in vlan_name:
                mac_only_count = max(0, mcount - active_count)
                matched_vlan = vlan_name
                break

        # Determine status
        if utilization >= 90:
            status = "critical"
        elif utilization >= 75:
            status = "warning"
        elif utilization >= 50:
            status = "moderate"
        else:
            status = "healthy"

        subnet_results.append({
            "subnet": net_str,
            "interface": info["interface"],
            "gateway": info["gateway"],
            "prefix": info["prefix"],
            "description": info.get("description", ""),
            "total_ips": total_ips,
            "active_hosts": active_count,
            "free_ips": free_count,
            "utilization_pct": utilization,
            "status": status,
            "mac_only": mac_only_count,
            "vlan": matched_vlan,
            "hosts": sorted(hosts_in_subnet, key=lambda h: [int(x) for x in h["ip"].split(".")]),
        })

    # Sort: critical first, then by utilization descending
    status_order = {"critical": 0, "warning": 1, "moderate": 2, "healthy": 3}
    subnet_results.sort(key=lambda s: (status_order.get(s["status"], 9), -s["utilization_pct"]))

    # Summary stats
    total_subnets = len(subnet_results)
    total_all_ips = sum(s["total_ips"] for s in subnet_results)
    total_active = sum(s["active_hosts"] for s in subnet_results)
    total_free = sum(s["free_ips"] for s in subnet_results)
    total_mac_only = sum(s["mac_only"] for s in subnet_results)
    critical_count = sum(1 for s in subnet_results if s["status"] == "critical")
    warning_count = sum(1 for s in subnet_results if s["status"] == "warning")

    # Count total MAC entries
    mac_count = 0
    for line in mac_raw.splitlines():
        if re.search(r'[0-9a-f]{2}[:\-][0-9a-f]{2}[:\-][0-9a-f]{2}', line, re.I):
            mac_count += 1

    return jsonify({
        "success": True,
        "hostname": hostname,
        "dtype": dtype,
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_subnets": total_subnets,
            "total_ips": total_all_ips,
            "active_hosts": total_active,
            "free_ips": total_free,
            "overall_utilization": round((total_active / total_all_ips) * 100, 1) if total_all_ips > 0 else 0,
            "critical_subnets": critical_count,
            "warning_subnets": warning_count,
            "mac_entries": mac_count,
            "mac_only_devices": total_mac_only,
        },
        "subnets": subnet_results,
        "mac_per_vlan": mac_per_vlan,
        "raw": {
            "arp_entries": len(arp_entries),
            "mac_entries": mac_count,
        },
    })


# ── PyEZ Structured Statistics (NETCONF) ─────────────────────────────────────

_PYEZ_AVAILABLE = False
try:
    from pyez_collector import collect_all as _pyez_collect_all
    _PYEZ_AVAILABLE = True
except ImportError:
    pass

_pyez_cache = {}       # hostname -> {result, timestamp}
_pyez_cache_ttl = 120  # seconds

@app.route("/api/device/pyez-stats/<hostname>", methods=["GET"])
def pyez_stats(hostname):
    """
    Collect structured Junos statistics via PyEZ NETCONF.
    Returns: port stats (bps/pps), optic diagnostics, FPC health,
             detailed error counters, and filesystem storage.
    Only works for Junos devices with NETCONF enabled.
    Query params: ?refresh=1 to bypass cache.
    """
    if not _PYEZ_AVAILABLE:
        return jsonify({"success": False, "error": "PyEZ (junos-eznc) not installed"}), 500

    # Look up device
    dev = None
    hn_lower = hostname.lower()
    for d in DEVICES:
        if d["hostname"].lower() == hn_lower:
            dev = d
            break
    if not dev:
        return jsonify({"success": False, "error": f"Device '{hostname}' not found"}), 404
    if dev["type"] != "junos":
        return jsonify({"success": False, "error": f"PyEZ only supports Junos devices ('{hostname}' is {dev['type']})"}), 400

    # Cache check
    refresh = request.args.get("refresh", "0") == "1"
    cache_key = hn_lower
    if not refresh and cache_key in _pyez_cache:
        cached = _pyez_cache[cache_key]
        if time.time() - cached["timestamp"] < _pyez_cache_ttl:
            cached["result"]["from_cache"] = True
            return jsonify({"success": True, **cached["result"]})

    # Collect via PyEZ NETCONF
    result = _pyez_collect_all(
        ip=dev["ip"],
        ssh_mode=SSH_MODE,
        ssh_user="netadmin" if SSH_MODE != "pkcs11" else SSH_USER,
        ssh_key_path=SSH_KEY_PATH,
        ssh_timeout=SSH_TIMEOUT,
        pkcs11_pkey=_pkcs11_pkey if SSH_MODE == "pkcs11" else None,
    )

    if result.get("error") and not result.get("netconf_available"):
        return jsonify({"success": False, "error": result["error"],
                        "hint": "NETCONF may not be enabled on this device (set system services netconf ssh)"}), 502

    # Cache the result
    _bounded_insert(_pyez_cache, cache_key,
                    {"result": result, "timestamp": time.time()},
                    max_size=50)
    result["from_cache"] = False

    return jsonify({"success": True, **result})


@app.route("/api/device/pyez-stats", methods=["GET"])
def pyez_status():
    """Check if PyEZ is available and return status."""
    return jsonify({
        "pyez_available": _PYEZ_AVAILABLE,
        "ssh_mode": SSH_MODE,
        "cached_devices": list(_pyez_cache.keys()),
    })


# ── Network-Wide IP Exhaustion Report ─────────────────────────────────────────

def _analyze_device_subnets(dev):
    """Analyze subnets on a single device via SSH. Returns dict with subnet info or error."""
    import ipaddress
    ip = dev["ip"]
    dtype = dev["type"]
    hostname = dev["hostname"]
    site = dev.get("site", _site_from_hostname(hostname))

    if dtype == "junos":
        cmd_map = {
            "arp":          "show arp | no-more",
            "interfaces":   "show interfaces terse | match inet | no-more",
            "mac_table":    "show ethernet-switching table | no-more",
            "descriptions": "show interfaces descriptions | no-more",
        }
    else:
        cmd_map = {
            "arp":          "show arp",
            "interfaces":   "show ip interface brief",
            "mac_table":    "show mac address-table",
            "descriptions": "show interfaces description",
        }

    outputs = {}
    for key, cmd in cmd_map.items():
        r = run_command_on_device(ip, dtype, cmd)
        if key in ("arp", "interfaces") and not r.get("success"):
            return {"hostname": hostname, "site": site, "dtype": dtype, "error": r.get("error", "SSH failed"), "subnets": []}
        outputs[key] = r.get("output", "") if r.get("success") else ""

    arp_raw   = outputs.get("arp", "")
    iface_raw = outputs.get("interfaces", "")
    mac_raw   = outputs.get("mac_table", "")
    desc_raw  = outputs.get("descriptions", "")

    if dtype == "junos":
        subnets = _parse_subnets_junos(iface_raw)
        arp_entries = _parse_arp_junos(arp_raw)
        iface_descs = _parse_iface_descriptions_junos(desc_raw)
        mac_per_vlan = _parse_mac_per_vlan_junos(mac_raw)
    else:
        subnets = _parse_subnets_eos(iface_raw)
        arp_entries = _parse_arp_eos(arp_raw)
        iface_descs = _parse_iface_descriptions_eos(desc_raw)
        mac_per_vlan = _parse_mac_per_vlan_eos(mac_raw)

    arp_macs = {e["mac"].lower() for e in arp_entries}

    # Filter subnets — skip infra/mgmt/tunnel/internal and very large blocks
    skip_prefixes = ("128.0.", "169.254.", "192.168.", "30.")
    skip_iface_prefixes = ("fab", "bme", "jsrv", "pfh", "pfe", "st0", "lo0")
    # Skip management / VPN / internal blocks (10.1.x is typically mgmt/tunnel)
    skip_net_prefixes = ("10.1.",)
    filtered = {}
    for net_str, info in subnets.items():
        iface_lower = info["interface"].lower()
        if any(iface_lower.startswith(x) for x in skip_iface_prefixes):
            continue
        if iface_lower.startswith("em") and "32768" not in info["interface"]:
            if not iface_lower.startswith("em0"):
                continue
        if any(net_str.startswith(x) for x in skip_prefixes):
            continue
        if any(net_str.startswith(x) for x in skip_net_prefixes):
            continue
        if info["prefix"] >= 32:
            continue
        # Skip overly large blocks (/16 and bigger) — usually fabric/overlay
        if info["prefix"] <= 16:
            continue
        # Look up description
        iface = info["interface"]
        desc = iface_descs.get(iface, "")
        if not desc:
            base = iface.split(".")[0]
            desc = iface_descs.get(base, "")
        info["description"] = desc
        filtered[net_str] = info

    subnet_results = []
    for net_str, info in sorted(filtered.items()):
        try:
            network = ipaddress.ip_network(net_str)
        except ValueError:
            continue
        total_ips = 2 if network.prefixlen == 31 else network.num_addresses - 2
        if total_ips <= 0:
            continue
        seen_ips = set()
        for entry in arp_entries:
            try:
                host_ip = ipaddress.ip_address(entry["ip"])
            except (ValueError, TypeError):
                continue
            if host_ip in network and entry["ip"] not in seen_ips:
                seen_ips.add(entry["ip"])
        active = len(seen_ips)
        free = total_ips - active
        util = round((active / total_ips) * 100, 1) if total_ips > 0 else 0
        status = "critical" if util >= 90 else "warning" if util >= 75 else "moderate" if util >= 50 else "healthy"
        subnet_results.append({
            "subnet": net_str, "interface": info["interface"], "description": info.get("description", ""),
            "prefix": info["prefix"], "gateway": info["gateway"],
            "total_ips": total_ips, "active_hosts": active, "free_ips": free,
            "utilization_pct": util, "status": status,
        })

    # Sort: critical first
    status_order = {"critical": 0, "warning": 1, "moderate": 2, "healthy": 3}
    subnet_results.sort(key=lambda s: (status_order.get(s["status"], 9), -s["utilization_pct"]))

    return {
        "hostname": hostname, "site": site, "dtype": dtype, "error": None,
        "subnets": subnet_results,
        "total_subnets": len(subnet_results),
        "total_ips": sum(s["total_ips"] for s in subnet_results),
        "active_hosts": sum(s["active_hosts"] for s in subnet_results),
        "free_ips": sum(s["free_ips"] for s in subnet_results),
        "critical": sum(1 for s in subnet_results if s["status"] == "critical"),
        "warning": sum(1 for s in subnet_results if s["status"] == "warning"),
        "utilization_pct": round(
            sum(s["active_hosts"] for s in subnet_results) / max(sum(s["total_ips"] for s in subnet_results), 1) * 100, 1
        ),
        "arp_count": len(arp_entries),
    }


@app.route("/api/report/ip-exhaustion", methods=["GET"])
def report_ip_exhaustion():
    """Network-wide IP exhaustion report.
    Scans firewalls, routers, and switches via SSH to collect ARP/MAC/interface data.
    Query: site=UK-LON (scan one site) or omit for all sites.
    Returns per-site summary + per-device subnet breakdown."""
    import concurrent.futures

    target_site = request.args.get("site", "").strip().lower()
    # Filter devices to scan: firewalls and routers have L3 subnets
    candidates = []
    seen = set()
    for dev in DEVICES:
        h = dev["hostname"].lower().split(".")[0]
        norm = _normalize_hostname(dev["hostname"])
        if norm in seen:
            continue
        site = _site_from_hostname(h)
        if target_site and site != target_site:
            continue
        # Only scan devices with L3 interfaces (firewalls, routers, L3 switches)
        role = dev.get("role", "")
        if not any(t in h for t in ("-fw-", "-rt-", "-sw-")):
            continue
        seen.add(norm)
        candidates.append(dev)

    errors = []
    device_results = []
    lock = threading.Lock()

    def _scan_device(dev):
        try:
            result = _analyze_device_subnets(dev)
            with lock:
                if result.get("error"):
                    errors.append({"hostname": dev["hostname"], "error": result["error"]})
                if result.get("subnets"):
                    device_results.append(result)
        except Exception as e:
            with lock:
                errors.append({"hostname": dev["hostname"], "error": str(e)})

    # Run with thread pool — limit concurrency to avoid SSH overload
    max_workers = 8 if not target_site else 4
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        pool.map(_scan_device, candidates)

    # Aggregate by site — with subnet deduplication across devices
    import ipaddress as _ipa
    site_map = {}
    for dr in device_results:
        site = dr["site"]
        if site not in site_map:
            site_map[site] = {"site": site, "devices": [], "_subnet_dedup": {}}
        site_map[site]["devices"].append(dr)
        # Merge subnets: same subnet on multiple devices → combine ARP hosts
        for sn in dr.get("subnets", []):
            key = sn["subnet"]
            if key not in site_map[site]["_subnet_dedup"]:
                site_map[site]["_subnet_dedup"][key] = {
                    "subnet": key, "prefix": sn["prefix"], "total_ips": sn["total_ips"],
                    "arp_ips": set(), "interfaces": [], "description": sn.get("description", ""),
                    "gateway": sn.get("gateway", ""),
                }
            entry = site_map[site]["_subnet_dedup"][key]
            # Collect unique ARP IPs across devices for this subnet
            # We need to re-derive from arp_entries but we only have counts;
            # approximate: use the max active count from any single device
            # (since the same host appears in ARP on multiple L3 devices)
            entry["arp_ips"] |= {sn["subnet"] + ":" + str(i) for i in range(sn["active_hosts"])}
            entry["interfaces"].append({"device": dr["hostname"], "interface": sn["interface"]})
            # Keep the best (non-empty) description
            if sn.get("description") and not entry["description"]:
                entry["description"] = sn["description"]

    # Now recalculate site-level stats from deduplicated subnets
    for site_code, sm in site_map.items():
        deduped = sm.pop("_subnet_dedup")
        # For deduplication: use MAX active hosts from any single device
        # (same ARP entries appear on multiple L3 gateways)
        deduped_subnets = []
        for key, entry in sorted(deduped.items()):
            # Pick the max active_hosts from the devices that reported this subnet
            max_active = 0
            best_iface = ""
            for dv in sm["devices"]:
                for sn in dv.get("subnets", []):
                    if sn["subnet"] == key:
                        if sn["active_hosts"] > max_active:
                            max_active = sn["active_hosts"]
                            best_iface = sn["interface"]
            total_ips = entry["total_ips"]
            free = total_ips - max_active
            util = round((max_active / max(total_ips, 1)) * 100, 1)
            status = "critical" if util >= 90 else "warning" if util >= 75 else "moderate" if util >= 50 else "healthy"
            devices_str = ", ".join(d["device"] for d in entry["interfaces"])
            deduped_subnets.append({
                "subnet": key, "interface": best_iface, "description": entry.get("description", ""),
                "prefix": entry["prefix"], "gateway": entry.get("gateway", ""),
                "total_ips": total_ips, "active_hosts": max_active, "free_ips": free,
                "utilization_pct": util, "status": status, "seen_on": devices_str,
            })
        sm["deduped_subnets"] = deduped_subnets
        sm["total_subnets"] = len(deduped_subnets)
        sm["total_ips"] = sum(s["total_ips"] for s in deduped_subnets)
        sm["active_hosts"] = sum(s["active_hosts"] for s in deduped_subnets)
        sm["free_ips"] = sum(s["free_ips"] for s in deduped_subnets)
        sm["critical"] = sum(1 for s in deduped_subnets if s["status"] == "critical")
        sm["warning"] = sum(1 for s in deduped_subnets if s["status"] == "warning")

    # Calculate per-site utilization and sort devices within each site
    sites = []
    for site_code, sm in sorted(site_map.items()):
        sm["utilization_pct"] = round(sm["active_hosts"] / max(sm["total_ips"], 1) * 100, 1)
        sm["device_count"] = len(sm["devices"])
        status = "critical" if sm["critical"] > 0 else "warning" if sm["warning"] > 0 else "healthy"
        sm["status"] = status
        sites.append(sm)

    # Sort sites: critical first, then by utilization descending
    sites.sort(key=lambda s: (0 if s["status"] == "critical" else 1 if s["status"] == "warning" else 2, -s["utilization_pct"]))

    # Global summary
    total_subnets = sum(s["total_subnets"] for s in sites)
    total_ips = sum(s["total_ips"] for s in sites)
    total_active = sum(s["active_hosts"] for s in sites)
    total_free = sum(s["free_ips"] for s in sites)
    total_critical = sum(s["critical"] for s in sites)
    total_warning = sum(s["warning"] for s in sites)
    total_devices = sum(s["device_count"] for s in sites)

    return jsonify({
        "success": True,
        "analysis_date": datetime.now().isoformat(),
        "target_site": target_site or "ALL",
        "summary": {
            "total_sites": len(sites),
            "total_devices": total_devices,
            "devices_scanned": len(candidates),
            "total_subnets": total_subnets,
            "total_ips": total_ips,
            "active_hosts": total_active,
            "free_ips": total_free,
            "overall_utilization": round(total_active / max(total_ips, 1) * 100, 1),
            "critical_subnets": total_critical,
            "warning_subnets": total_warning,
        },
        "sites": sites,
        "errors": errors,
    })


# ── NetPortal Capacity API Integration ─────────────────────────────────────────
_NETPORTAL_BASE = os.environ.get("NETPORTAL_URL", "https://netportal.lab.local")

def _netportal_api(path, timeout=30):
    """Call NetPortal Capacity API (private IP, no auth needed)."""
    url = f"{_NETPORTAL_BASE}/capacity/api{path}"
    try:
        r = _requests.get(url, timeout=timeout, verify=DCN_VERIFY_SSL)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

@app.route("/api/netportal/reports", methods=["GET"])
def netportal_reports():
    """List available NetPortal capacity reports."""
    return jsonify(_netportal_api("/reports/"))

@app.route("/api/netportal/site/<site_code>", methods=["GET"])
def netportal_site(site_code):
    """Get full capacity data for a site from NetPortal (ports, IPs, ISP, racks)."""
    data = _netportal_api(f"/reports/site/{site_code.upper()}/", timeout=60)
    if "error" in data and isinstance(data["error"], str):
        return jsonify(data), 502
    return jsonify(data)

@app.route("/api/netportal/download/<int:report_id>", methods=["GET"])
def netportal_download(report_id):
    """Download a full NetPortal report by ID."""
    data = _netportal_api(f"/reports/{report_id}/download/", timeout=120)
    if "error" in data and isinstance(data["error"], str):
        return jsonify(data), 502
    return jsonify(data)

@app.route("/api/netportal/summary", methods=["GET"])
def netportal_summary():
    """Get a summary of all sites from the latest NetPortal report."""
    rpt = _netportal_api("/reports/")
    if "error" in rpt:
        return jsonify(rpt), 502
    reports = rpt.get("reports", [])
    if not reports:
        return jsonify({"error": "No reports available"}), 404
    latest_id = reports[0]["id"]
    full = _netportal_api(f"/reports/{latest_id}/download/", timeout=120)
    if "error" in full and isinstance(full["error"], str):
        return jsonify(full), 502
    # Build compact summary per site
    sites = []
    raw_sites = full.get("sites", [])
    if isinstance(raw_sites, dict):
        raw_sites = [{"site_code": k, **v} for k, v in raw_sites.items()]
    for site_data in raw_sites:
        site_code = site_data.get("site_code", "?")
        s = site_data.get("summary", {})
        ports = s.get("ports", {}).get("effective_ports", {})
        racks = s.get("racks", {})
        ips = s.get("ip_prefixes", {})
        sites.append({
            "site": site_code,
            "switches": s.get("ports", {}).get("switches", 0),
            "ports_total": ports.get("total", 0),
            "ports_used": ports.get("used", 0),
            "ports_free": ports.get("free", 0),
            "ports_util_pct": ports.get("utilization_pct", 0),
            "racks_total": racks.get("total_racks", 0),
            "rack_u_total": racks.get("total_u", 0),
            "rack_u_used": racks.get("used_u", 0),
            "rack_util_pct": racks.get("utilization_pct", 0),
            "ip_prefixes": ips.get("total_prefixes", 0),
            "ip_usable": ips.get("total_usable_ips", 0),
            "ip_consumed": ips.get("consumed_ips", 0),
            "ip_consumed_pct": ips.get("consumed_pct", 0),
            "ip_arp_active": ips.get("arp_active", 0),
            "ip_undocumented": ips.get("undocumented_ip_count", 0),
            "warnings": len(site_data.get("warnings", [])),
            "isp_links": len(site_data.get("isp_links", [])),
        })
    sites.sort(key=lambda x: x["site"])
    return jsonify({
        "report_id": latest_id,
        "generated_at": reports[0].get("generated_at", ""),
        "site_count": len(sites),
        "sites": sites,
    })


# ── Junos MCP Server (Read-Only) Integration ──────────────────────────────────
# Auto-generates devices.json from DCN inventory and proxies MCP tool calls

def _generate_jmcp_devices_json():
    """Generate a JMCP-compatible devices.json from the DCN device inventory.
    Only includes Junos devices (switches, routers, firewalls with -sw-, -rt-, -fw- in hostname).
    Returns dict mapping device_name -> {ip, port, username, auth}."""
    jmcp_devices = {}
    for dev in DEVICES:
        hostname = dev.get("hostname", "")
        ip = dev.get("ip", "")
        dtype = dev.get("type", "").lower()
        if not hostname or not ip:
            continue
        # Only Junos devices (skip EOS/Arista)
        if dtype == "eos":
            continue
        # Only network devices
        hn = hostname.lower()
        if not any(r in hn for r in ("-sw-", "-rt-", "-fw-")):
            continue
        device_name = hostname.split(".")[0].lower()
        auth_block = ({"type": "ssh_agent"} if SSH_MODE == "agent"
                      else {"type": "ssh_key", "private_key_path": "/data/ssh/netlab_admin"})
        jmcp_devices[device_name] = {
            "ip": ip,
            "port": 22,
            "username": SSH_USER,
            "auth": auth_block,
        }
    return jmcp_devices

def _generate_all_network_devices():
    """Generate a unified device dict for ALL network devices (Junos + EOS).
    Returns dict mapping device_name -> {ip, port, username, dtype, role}."""
    all_devs = {}
    for dev in DEVICES:
        hostname = dev.get("hostname", "")
        ip = dev.get("ip", "")
        dtype = dev.get("type", "").lower()
        if not hostname or not ip:
            continue
        hn = hostname.lower()
        if not any(r in hn for r in ("-sw-", "-rt-", "-fw-")):
            continue
        device_name = hostname.split(".")[0].lower()
        all_devs[device_name] = {
            "ip": ip,
            "port": 22,
            "username": SSH_USER,
            "dtype": dtype,       # "junos" or "eos"
            "role": dev.get("role", "unknown"),
        }
    return all_devs

def _write_jmcp_devices_file():
    """Write devices.json to jmcp/config directory for the JMCP sidecar."""
    jmcp_devices = _generate_jmcp_devices_json()
    # Write to jmcp config dir (for Docker sidecar) and local jmcp/ dir
    for path in [
        os.path.join(os.path.dirname(__file__), "jmcp", "devices.json"),
    ]:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                json.dump(jmcp_devices, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not write JMCP devices to {path}: {e}")
    return len(jmcp_devices)

@app.route("/api/jmcp/status", methods=["GET"])
def jmcp_status():
    """Check JMCP sidecar status and return available tools."""
    if not JMCP_ENABLED:
        return jsonify({"available": False, "reason": "JMCP_ENABLED=false"})
    try:
        # MCP servers expose a streamable-http endpoint at /mcp/
        r = _requests.get(f"{JMCP_URL}/mcp/", timeout=5)
        available = r.status_code < 500
    except Exception:
        available = False
    # Count devices in inventory
    jmcp_devices = _generate_jmcp_devices_json()
    return jsonify({
        "available": available,
        "url": JMCP_URL,
        "junos_devices": len(jmcp_devices),
        "tools": [
            "execute_junos_command",
            "execute_junos_command_batch",
            "get_junos_config",
            "junos_config_diff",
            "gather_device_facts",
            "get_router_list",
        ],
        "mode": "read-only",
    })

@app.route("/api/jmcp/devices", methods=["GET"])
def jmcp_devices():
    """Return ALL network devices (Junos + EOS) for the JMCP tab."""
    all_devs = _generate_all_network_devices()
    safe_devs = {}
    for name, info in all_devs.items():
        safe_devs[name] = {
            "ip": info["ip"],
            "port": info["port"],
            "username": info["username"],
            "dtype": info["dtype"],
            "role": info.get("role", "unknown"),
        }
    junos_count = sum(1 for d in safe_devs.values() if d["dtype"] == "junos")
    eos_count = sum(1 for d in safe_devs.values() if d["dtype"] == "eos")
    return jsonify({
        "device_count": len(safe_devs),
        "junos_count": junos_count,
        "eos_count": eos_count,
        "devices": safe_devs,
    })

@app.route("/api/jmcp/devices/regenerate", methods=["POST"])
def jmcp_devices_regenerate():
    """Regenerate devices.json from current DCN inventory."""
    count = _write_jmcp_devices_file()
    return jsonify({"ok": True, "junos_devices_written": count})

@app.route("/api/jmcp/execute", methods=["POST"])
def jmcp_execute():
    """Proxy: execute a read-only Junos CLI command via JMCP.
    Body: {device: "hostname", command: "show ...", timeout: 60}"""
    if not JMCP_ENABLED:
        return jsonify({"error": "JMCP is disabled (JMCP_ENABLED=false)"}), 503
    body = request.get_json(force=True) or {}
    device = body.get("device", "").strip().lower().split(".")[0]
    command = body.get("command", "").strip()
    timeout = body.get("timeout", 60)
    if not device or not command:
        return jsonify({"error": "device and command are required"}), 400
    # Safety: block write/destructive commands at proxy level (read-only mode)
    if is_command_blocked(command):
        return jsonify({"error": f"BLOCKED: '{command}' is not allowed (read-only mode)"}), 403
    # Use direct SSH (same as deep-analysis) — simpler than MCP protocol proxy
    all_devs = _generate_all_network_devices()
    if device not in all_devs:
        return jsonify({"error": f"Device '{device}' not found in inventory ({len(all_devs)} devices available)"}), 404
    dev_info = all_devs[device]
    try:
        import paramiko
        ssh = paramiko.SSHClient()
        apply_ssh_policy(ssh)
        _ssh_connect(ssh, dev_info["ip"], port=dev_info["port"])
        stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        ssh.close()
        return jsonify({
            "device": device,
            "ip": dev_info["ip"],
            "command": command,
            "output": output,
            "stderr": err if err.strip() else None,
            "dtype": dev_info.get("dtype", "junos"),
            "mode": "read-only",
        })
    except Exception as e:
        return jsonify({"error": f"SSH error on {device} ({dev_info['ip']}): {str(e)}"}), 500

@app.route("/api/jmcp/batch", methods=["POST"])
def jmcp_batch():
    """Proxy: execute a read-only CLI command on multiple devices in parallel (Junos + EOS).
    Body: {devices: ["host1", "host2"], command: "show ...", timeout: 60}"""
    if not JMCP_ENABLED:
        return jsonify({"error": "JMCP is disabled"}), 503
    body = request.get_json(force=True) or {}
    devices_list = body.get("devices", [])
    command = body.get("command", "").strip()
    timeout = body.get("timeout", 60)
    if not devices_list or not command:
        return jsonify({"error": "devices[] and command are required"}), 400
    # Safety check
    if is_command_blocked(command):
        return jsonify({"error": f"BLOCKED: '{command}' is not allowed (read-only mode)"}), 403
    all_devs = _generate_all_network_devices()
    import concurrent.futures, time as _time
    results = []
    def _exec_one(dev_name):
        dev_name = dev_name.strip().lower().split(".")[0]
        if dev_name not in all_devs:
            return {"device": dev_name, "status": "error", "output": f"Not found in device inventory"}
        dev_info = all_devs[dev_name]
        t0 = _time.time()
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            apply_ssh_policy(ssh)
            _ssh_connect(ssh, dev_info["ip"], port=dev_info["port"])
            stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
            output = stdout.read().decode("utf-8", errors="replace")
            ssh.close()
            return {"device": dev_name, "ip": dev_info["ip"], "status": "success",
                    "output": output, "duration": round(_time.time() - t0, 2)}
        except Exception as e:
            return {"device": dev_name, "ip": dev_info.get("ip", "?"), "status": "error",
                    "output": str(e), "duration": round(_time.time() - t0, 2)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(devices_list), 20)) as pool:
        results = list(pool.map(_exec_one, devices_list))
    ok = sum(1 for r in results if r["status"] == "success")
    return jsonify({
        "command": command,
        "total": len(results),
        "successful": ok,
        "failed": len(results) - ok,
        "results": results,
        "mode": "read-only",
    })

@app.route("/api/jmcp/facts", methods=["POST"])
def jmcp_facts():
    """Get device facts (model, version, serial, uptime) for a Junos or EOS device.
    Body: {device: "hostname"}"""
    if not JMCP_ENABLED:
        return jsonify({"error": "JMCP is disabled"}), 503
    body = request.get_json(force=True) or {}
    device = body.get("device", "").strip().lower().split(".")[0]
    if not device:
        return jsonify({"error": "device is required"}), 400
    all_devs = _generate_all_network_devices()
    if device not in all_devs:
        return jsonify({"error": f"Device '{device}' not found in inventory"}), 404
    dev_info = all_devs[device]
    try:
        import paramiko
        ssh = paramiko.SSHClient()
        apply_ssh_policy(ssh)
        _ssh_connect(ssh, dev_info["ip"], port=dev_info["port"])
        # Gather facts via CLI commands — different for Junos vs EOS
        dtype = dev_info.get("dtype", "junos")
        if dtype == "eos":
            fact_cmds = [
                ("show version", "version"),
                ("show version | grep uptime", "uptime"),
                ("show inventory", "hardware"),
            ]
        else:
            fact_cmds = [
                ("show version | no-more", "version"),
                ("show system uptime | no-more", "uptime"),
                ("show chassis hardware | match Chassis | no-more", "hardware"),
            ]
        facts = {}
        for cmd, key in fact_cmds:
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=30)
            facts[key] = stdout.read().decode("utf-8", errors="replace").strip()
        ssh.close()
        return jsonify({"device": device, "ip": dev_info["ip"], "dtype": dtype, "facts": facts, "mode": "read-only"})
    except Exception as e:
        return jsonify({"error": f"SSH error on {device}: {str(e)}"}), 500


@app.route("/api/jmcp/ask", methods=["POST"])
def jmcp_ask():
    """Natural-language query against a Junos device.  Uses the local LLM to
    determine which CLI commands to run, executes them via SSH, then sends the
    output back to the LLM for a human-readable analysis.

    Body: {device: "hostname", question: "Why is BGP down?", history: [...]}
    """
    if not JMCP_ENABLED:
        return jsonify({"error": "JMCP is disabled"}), 503
    if not LLM_ENABLED:
        return jsonify({"error": "LLM is disabled — natural-language mode requires a running LLM (Docker Model Runner)"}), 503

    body = request.get_json(force=True) or {}
    device = body.get("device", "").strip().lower().split(".")[0]
    question = body.get("question", "").strip()
    history = body.get("history", [])  # optional conversation history
    if not device:
        return jsonify({"error": "device is required"}), 400
    if not question:
        return jsonify({"error": "question is required"}), 400

    all_devs = _generate_all_network_devices()
    if device not in all_devs:
        return jsonify({"error": f"Device '{device}' not found in inventory"}), 404
    dev_info = all_devs[device]
    dtype = dev_info.get("dtype", "junos")

    # ── Step 1: Ask LLM which commands to run ────────────────────────────
    if dtype == "eos":
        plan_system = (
            "You convert natural-language questions about Arista EOS network devices "
            "into a JSON array of read-only Arista EOS CLI commands.\n"
            "RULES:\n"
            "1. Output ONLY a JSON array, nothing else. No markdown, no explanation.\n"
            "2. Max 5 commands. These are Arista EOS commands (NOT Junos).\n"
            "3. Only read-only commands (show). NEVER configure/set/delete/commit.\n"
            "4. Example input:  'What is the BGP status?'\n"
            '   Example output: ["show bgp summary", "show bgp neighbors"]\n'
            "5. Example input:  'Are there any alarms?'\n"
            '   Example output: ["show system environment all", "show logging last 50"]\n'
            "6. Example input:  'Show me interface errors'\n"
            '   Example output: ["show interfaces status", "show interfaces counters errors"]'
        )
    else:
        plan_system = (
            "You convert natural-language questions about Juniper/Junos network devices "
            "into a JSON array of read-only Junos CLI commands.\n"
            "RULES:\n"
            "1. Output ONLY a JSON array, nothing else. No markdown, no explanation.\n"
            "2. Max 5 commands. Append ' | no-more' to each command.\n"
            "3. Only read-only commands (show, monitor, ping, traceroute). "
            "NEVER configure/set/delete/commit/rollback.\n"
            "4. Example input:  'What is the BGP status?'\n"
            '   Example output: ["show bgp summary | no-more", "show bgp neighbor | no-more"]\n'
            "5. Example input:  'Are there any alarms?'\n"
            '   Example output: ["show chassis alarms | no-more", "show system alarms | no-more"]\n'
            "6. Example input:  'Show me interface errors'\n"
            '   Example output: ["show interfaces extensive | match error | no-more", "show interfaces terse | no-more"]'
        )
    plan_user = question
    if history:
        ctx = "\n".join(
            f"{'Q' if i%2==0 else 'A'}: {h.get('content','')[:200]}"
            for i, h in enumerate(history[-6:])
        )
        plan_user = f"Context:\n{ctx}\n\nNew question: {question}"

    # Retry up to 3 times — LLM can be slow on first call (cold start)
    import re as _re
    plan_raw = None
    for attempt in range(3):
        plan_raw = _llm_query(plan_system, plan_user, max_tokens=200)
        if plan_raw:
            break
        print(f"[JMCP/ask] LLM attempt {attempt+1} returned None, retrying...")

    if not plan_raw:
        return jsonify({"error": "LLM did not respond after 3 attempts — check Docker Model Runner is running"}), 503

    print(f"[JMCP/ask] LLM plan response: {plan_raw[:300]}")

    # Parse commands from LLM response
    commands = []
    try:
        # Try to extract JSON array from the response
        match = _re.search(r'\[.*?\]', plan_raw, _re.DOTALL)
        if match:
            commands = json.loads(match.group())
        else:
            commands = json.loads(plan_raw)
    except (json.JSONDecodeError, ValueError):
        pass

    # Fallback: extract any 'show ...' commands from prose text
    if not commands:
        for match in _re.finditer(r"['\"`]?(show\s+[^'\"`,\n\]]+)", plan_raw):
            cmd = match.group(1).strip().rstrip("'\"`,.")
            if cmd and cmd not in commands:
                commands.append(cmd)

    # Last resort: use sensible defaults based on keywords in question
    if not commands:
        q_lower = question.lower()
        # Keyword → command mappings (order matters — first match wins)
        _KW_EOS = [
            (("subnet", "prefix", "network", "address"),  ["show ip interface brief"]),
            (("bgp", "peer"),                              ["show bgp summary", "show bgp neighbors"]),
            (("ospf",),                                    ["show ip ospf neighbor", "show ip ospf interface brief"]),
            (("isis",),                                    ["show isis neighbors", "show isis interface brief"]),
            (("interface", "port", "link"),                ["show interfaces status", "show interfaces counters errors"]),
            (("error", "drop", "discard", "crc"),          ["show interfaces counters errors", "show interfaces counters discards"]),
            (("alarm", "health", "status", "environment"), ["show system environment all", "show system environment power"]),
            (("route", "routing", "rib"),                  ["show ip route summary"]),
            (("version", "software", "eos", "upgrade"),    ["show version"]),
            (("arp",),                                     ["show arp"]),
            (("mac", "cam"),                               ["show mac address-table"]),
            (("log", "syslog", "message", "event"),        ["show logging last 50"]),
            (("lldp", "topology", "connected", "cdp"),     ["show lldp neighbors"]),
            (("config", "configuration", "running"),       ["show running-config"]),
            (("mlag", "vpc"),                              ["show mlag", "show mlag detail"]),
            (("vlan",),                                    ["show vlan"]),
            (("vxlan", "vtep", "evpn"),                    ["show vxlan vtep", "show bgp evpn summary"]),
            (("lacp", "lag", "bundle", "port-channel"),    ["show lacp neighbor", "show port-channel summary"]),
            (("spanning", "stp", "rstp"),                  ["show spanning-tree"]),
            (("optic", "sfp", "transceiver", "dom", "light"), ["show interfaces transceiver"]),
            (("hardware", "inventory", "serial", "model"), ["show inventory"]),
            (("uptime", "reboot", "reload"),               ["show uptime", "show reload cause"]),
            (("mtu",),                                     ["show interfaces"]),
            (("firewall", "acl", "access-list"),           ["show ip access-lists"]),
            (("ntp", "clock", "time"),                     ["show ntp status", "show clock"]),
            (("dns",),                                     ["show ip name-server"]),
            (("snmp",),                                    ["show snmp"]),
            (("power", "psu"),                             ["show system environment power"]),
            (("temperature", "temp", "thermal", "fan"),    ["show system environment temperature", "show system environment cooling"]),
            (("memory", "cpu", "utilization", "load"),     ["show processes top once"]),
            (("traffic", "bandwidth", "throughput", "counter"), ["show interfaces counters rates"]),
        ]
        _KW_JUNOS = [
            (("subnet", "prefix", "network", "address"),  ["show configuration interfaces | display set | match address | no-more"]),
            (("bgp", "peer"),                              ["show bgp summary | no-more", "show bgp neighbor | no-more"]),
            (("ospf",),                                    ["show ospf neighbor | no-more", "show ospf interface brief | no-more"]),
            (("isis",),                                    ["show isis adjacency | no-more", "show isis interface | no-more"]),
            (("interface", "port", "link"),                ["show interfaces terse | no-more"]),
            (("error", "drop", "discard", "crc"),          ["show interfaces terse | no-more", "show interfaces extensive | match error | no-more"]),
            (("alarm", "health", "status"),                ["show chassis alarms | no-more", "show system alarms | no-more", "show system uptime | no-more"]),
            (("route", "routing", "rib"),                  ["show route summary | no-more"]),
            (("version", "software", "junos", "upgrade"),  ["show version | no-more"]),
            (("arp",),                                     ["show arp | no-more"]),
            (("mac", "cam", "ethernet-switching"),         ["show ethernet-switching table | no-more"]),
            (("log", "syslog", "message", "event"),        ["show log messages | last 50 | no-more"]),
            (("lldp", "topology", "connected"),            ["show lldp neighbors | no-more"]),
            (("config", "configuration"),                  ["show configuration | display set | no-more"]),
            (("vlan",),                                    ["show vlans | no-more"]),
            (("vxlan", "vtep", "evpn"),                    ["show evpn database | no-more"]),
            (("lacp", "lag", "ae", "bundle"),              ["show lacp interfaces | no-more"]),
            (("spanning", "stp", "rstp"),                  ["show spanning-tree bridge | no-more"]),
            (("optic", "sfp", "transceiver", "dom", "light"), ["show interfaces diagnostics optics | no-more"]),
            (("hardware", "inventory", "serial", "model"), ["show chassis hardware | no-more"]),
            (("uptime", "reboot", "reload"),               ["show system uptime | no-more"]),
            (("mtu",),                                     ["show interfaces | match \"Physical|MTU\" | no-more"]),
            (("firewall", "acl", "filter"),                ["show firewall | no-more"]),
            (("ntp", "clock", "time"),                     ["show ntp associations | no-more", "show system uptime | no-more"]),
            (("dns",),                                     ["show configuration system name-server | display set | no-more"]),
            (("snmp",),                                    ["show snmp statistics | no-more"]),
            (("power", "psu"),                             ["show chassis environment | no-more"]),
            (("temperature", "temp", "thermal", "fan"),    ["show chassis environment | no-more"]),
            (("memory", "cpu", "utilization", "load"),     ["show system processes extensive | no-more"]),
            (("traffic", "bandwidth", "throughput", "counter"), ["show interfaces detail | match \"bytes|bps|Physical\" | no-more"]),
            (("policy", "prefix-list"),                    ["show policy | no-more"]),
            (("dhcp",),                                    ["show dhcp relay binding | no-more"]),
            (("class-of-service", "cos", "qos"),           ["show class-of-service interface | no-more"]),
            (("neighbor",),                                ["show lldp neighbors | no-more", "show bgp neighbor | no-more"]),
            (("security", "ids", "screen"),                ["show security screen statistics | no-more"]),
        ]
        kw_map = _KW_EOS if dtype == "eos" else _KW_JUNOS
        for keywords, cmds in kw_map:
            if any(k in q_lower for k in keywords):
                commands = cmds
                break
        if not commands:
            if dtype == "eos":
                commands = ["show system environment all", "show bgp summary", "show interfaces status"]
            else:
                commands = ["show chassis alarms | no-more", "show system alarms | no-more",
                            "show bgp summary | no-more", "show interfaces terse | no-more"]

    print(f"[JMCP/ask] dtype={dtype} commands: {commands}")

    # Sanitize common LLM mistakes in CLI syntax
    def _sanitize_cmd(cmd):
        cmd = str(cmd).strip()
        if dtype == "eos":
            # EOS doesn't use '| no-more' — it uses terminal length 0 via SSH
            cmd = _re.sub(r'\s*\|\s*no-more', '', cmd)
            cmd = _re.sub(r'\s+', ' ', cmd).strip()
            return cmd
        # Junos sanitization
        # Fix: 'show log messages last 1000' → 'show log messages | last 1000'
        cmd = _re.sub(r'\b(last|match|count|except|find|no-more)\b', r'| \1', cmd)
        # Remove double pipes
        cmd = _re.sub(r'\|\s*\|', '|', cmd)
        # Fix invalid Junos log commands the LLM often generates
        cmd = _re.sub(r'show system messages\b', 'show log messages', cmd)
        cmd = _re.sub(r'show system log\b', 'show log messages', cmd)
        cmd = _re.sub(r'show syslog\b', 'show log messages', cmd)
        # Fix: Junos uses 'show bgp neighbor' (singular), not 'neighbors'
        cmd = _re.sub(r'show bgp neighbors\b', 'show bgp neighbor', cmd)
        # Fix: Junos uses 'show ospf neighbor' (singular)
        cmd = _re.sub(r'show ospf neighbors\b', 'show ospf neighbor', cmd)
        # Ensure '| no-more' at end
        if "| no-more" not in cmd.lower():
            cmd = cmd.rstrip() + " | no-more"
        # Clean up extra spaces
        cmd = _re.sub(r'\s+', ' ', cmd).strip()
        return cmd

    # Safety: filter out any write commands that slipped through
    safe_commands = []
    seen = set()
    for cmd in commands[:5]:
        cmd = _sanitize_cmd(cmd)
        cmd_lower = cmd.lower()
        if is_command_blocked(cmd):
            continue
        if cmd_lower in seen:
            continue
        seen.add(cmd_lower)
        safe_commands.append(cmd)

    if not safe_commands:
        return jsonify({"error": "All suggested commands were blocked (write commands not allowed)"}), 400

    # ── Step 2: Execute commands via SSH ──────────────────────────────────
    import paramiko
    cmd_outputs = {}
    try:
        ssh = paramiko.SSHClient()
        apply_ssh_policy(ssh)
        _ssh_connect(ssh, dev_info["ip"], port=dev_info["port"])
        for cmd in safe_commands:
            try:
                stdin, stdout, stderr = ssh.exec_command(cmd, timeout=30)
                output = stdout.read().decode("utf-8", errors="replace").strip()
                cmd_outputs[cmd] = output[:4000]  # cap per-command output
            except Exception as e:
                cmd_outputs[cmd] = f"(error: {str(e)})"
        ssh.close()
    except Exception as e:
        return jsonify({"error": f"SSH connection failed to {device}: {str(e)}"}), 500

    # ── Step 3: Send outputs to LLM for analysis ─────────────────────────
    output_text = "\n\n".join(
        f"### {cmd}\n{out}" for cmd, out in cmd_outputs.items()
    )
    # Truncate if too large for LLM context
    if len(output_text) > 8000:
        output_text = output_text[:8000] + "\n\n... (output truncated)"

    platform = "Arista EOS" if dtype == "eos" else "Juniper Junos"
    analysis_system = (
        f"You are a senior DCN network engineer. "
        f"The user asked a question about a {platform} device. You ran commands and got the output below. "
        "Reply ONLY with a clear, concise, technical analysis answering the user's question. "
        "Use short bullet points. Be direct. Reference specific values from the output. "
        "If something is wrong, explain the root cause and suggest remediation. "
        "Do not repeat the raw command output — summarize and analyze it."
    )
    analysis_user = (
        f"Device: {device} ({dev_info['ip']}) — {platform}\n"
        f"Question: {question}\n\n"
        f"Command outputs:\n{output_text}"
    )

    analysis = _llm_query(analysis_system, analysis_user, max_tokens=800)

    return jsonify({
        "device": device,
        "ip": dev_info["ip"],
        "dtype": dtype,
        "question": question,
        "commands_run": safe_commands,
        "command_outputs": cmd_outputs,
        "analysis": analysis or "(LLM did not produce an analysis — see raw command outputs above)",
        "mode": "read-only",
        "llm_powered": bool(analysis),
    })


@app.route("/api/jmcp/ask-site", methods=["POST"])
def jmcp_ask_site():
    """Natural-language query against a whole site or list of devices (Junos + EOS).
    Runs the appropriate command(s) per device type, collects output, then LLM analyzes.

    Body: {question: "...", site: "UK-LON"} or {question: "...", devices: ["uk-lon-dist-01a","nl-ams-core-01"]}
    """
    if not JMCP_ENABLED:
        return jsonify({"error": "JMCP is disabled"}), 503
    if not LLM_ENABLED:
        return jsonify({"error": "LLM is disabled"}), 503

    body = request.get_json(force=True) or {}
    question = body.get("question", "").strip()
    site = body.get("site", "").strip().lower()
    device_list = body.get("devices", [])
    if not question:
        return jsonify({"error": "question is required"}), 400
    if not site and not device_list:
        return jsonify({"error": "site or devices[] is required"}), 400

    all_devs = _generate_all_network_devices()

    # Resolve target devices
    if device_list:
        targets = [d.strip().lower().split(".")[0] for d in device_list if d.strip()]
        targets = [t for t in targets if t in all_devs]
    else:
        targets = sorted([n for n in all_devs if n.startswith(site)])

    if not targets:
        return jsonify({"error": f"No devices found for site/devices: {site or device_list}"}), 404
    if len(targets) > 30:
        targets = targets[:30]

    # Count device types
    junos_targets = [t for t in targets if all_devs[t].get("dtype") == "junos"]
    eos_targets = [t for t in targets if all_devs[t].get("dtype") == "eos"]

    # ── Step 1: Determine commands per device type (instant keyword mapping) ─
    # Site queries skip LLM planning for speed — keyword mapping is instant
    import re as _re
    q_lower = question.lower()

    # Keyword → Junos commands mapping (site-wide — max 2 cmds for speed)
    _JUNOS_KW_MAP = [
        (("subnet", "prefix", "network", "address"),  ["show configuration interfaces | display set | match address | no-more"]),
        (("bgp", "peer"),                              ["show bgp summary | no-more"]),
        (("ospf",),                                    ["show ospf neighbor | no-more"]),
        (("isis",),                                    ["show isis adjacency | no-more"]),
        (("interface", "port", "link"),                ["show interfaces terse | no-more"]),
        (("error", "drop", "discard", "crc"),          ["show interfaces extensive | match error | no-more"]),
        (("alarm", "health", "status"),                ["show chassis alarms | no-more", "show system alarms | no-more"]),
        (("route", "routing", "rib"),                  ["show route summary | no-more"]),
        (("version", "software", "junos", "upgrade"),  ["show version | no-more"]),
        (("arp",),                                     ["show arp | no-more"]),
        (("mac", "cam", "ethernet-switching"),         ["show ethernet-switching table | no-more"]),
        (("log", "syslog", "message", "event"),        ["show log messages | last 50 | no-more"]),
        (("lldp", "topology", "connected"),            ["show lldp neighbors | no-more"]),
        (("config", "configuration"),                  ["show configuration | display set | no-more"]),
        (("vlan",),                                    ["show vlans | no-more"]),
        (("vxlan", "vtep", "evpn"),                    ["show evpn database | no-more"]),
        (("lacp", "lag", "ae", "bundle"),              ["show lacp interfaces | no-more"]),
        (("spanning", "stp", "rstp"),                  ["show spanning-tree bridge | no-more"]),
        (("optic", "sfp", "transceiver", "dom", "light"), ["show interfaces diagnostics optics | no-more"]),
        (("hardware", "inventory", "serial", "model"), ["show chassis hardware | no-more"]),
        (("uptime", "reboot", "reload"),               ["show system uptime | no-more"]),
        (("mtu",),                                     ["show interfaces | match \"Physical|MTU\" | no-more"]),
        (("firewall", "acl", "filter"),                ["show firewall | no-more"]),
        (("ntp", "clock", "time"),                     ["show ntp associations | no-more"]),
        (("snmp",),                                    ["show snmp statistics | no-more"]),
        (("power", "psu"),                             ["show chassis environment | no-more"]),
        (("temperature", "temp", "thermal", "fan"),    ["show chassis environment | no-more"]),
        (("memory", "cpu", "utilization", "load"),     ["show system processes extensive | no-more"]),
        (("traffic", "bandwidth", "throughput", "counter"), ["show interfaces detail | match \"bytes|bps|Physical\" | no-more"]),
        (("security", "ids", "screen"),                ["show security screen statistics | no-more"]),
        (("neighbor",),                                ["show lldp neighbors | no-more"]),
        (("ip",),                                      ["show configuration interfaces | display set | match address | no-more"]),
    ]
    # Keyword → EOS commands mapping (site-wide — max 2 cmds for speed)
    _EOS_KW_MAP = [
        (("subnet", "prefix", "network", "address"),  ["show ip interface brief"]),
        (("bgp", "peer"),                              ["show bgp summary"]),
        (("ospf",),                                    ["show ip ospf neighbor"]),
        (("isis",),                                    ["show isis neighbors"]),
        (("interface", "port", "link"),                ["show interfaces status"]),
        (("error", "drop", "discard", "crc"),          ["show interfaces counters errors"]),
        (("alarm", "health", "status", "environment"), ["show system environment all"]),
        (("route", "routing", "rib"),                  ["show ip route summary"]),
        (("version", "software", "eos", "upgrade"),    ["show version"]),
        (("arp",),                                     ["show arp"]),
        (("mac", "cam"),                               ["show mac address-table"]),
        (("log", "syslog", "message", "event"),        ["show logging last 50"]),
        (("lldp", "topology", "connected", "cdp"),     ["show lldp neighbors"]),
        (("config", "configuration", "running"),       ["show running-config"]),
        (("vlan",),                                    ["show vlan"]),
        (("vxlan", "vtep", "evpn"),                    ["show vxlan vtep"]),
        (("mlag", "vpc"),                              ["show mlag"]),
        (("lacp", "lag", "bundle", "port-channel"),    ["show lacp neighbor"]),
        (("spanning", "stp", "rstp"),                  ["show spanning-tree"]),
        (("optic", "sfp", "transceiver", "dom", "light"), ["show interfaces transceiver"]),
        (("hardware", "inventory", "serial", "model"), ["show inventory"]),
        (("uptime", "reboot", "reload"),               ["show uptime"]),
        (("mtu",),                                     ["show interfaces"]),
        (("firewall", "acl", "access-list"),           ["show ip access-lists"]),
        (("ntp", "clock", "time"),                     ["show ntp status"]),
        (("snmp",),                                    ["show snmp"]),
        (("power", "psu"),                             ["show system environment power"]),
        (("temperature", "temp", "thermal", "fan"),    ["show system environment temperature"]),
        (("memory", "cpu", "utilization", "load"),     ["show processes top once"]),
        (("traffic", "bandwidth", "throughput", "counter"), ["show interfaces counters rates"]),
        (("neighbor",),                                ["show lldp neighbors"]),
        (("ip",),                                      ["show ip interface brief"]),
    ]

    def _match_keywords(kw_map, q):
        for keywords, cmds in kw_map:
            if any(k in q for k in keywords):
                return cmds[:3]
        return None

    junos_cmds = []
    if junos_targets:
        junos_cmds = _match_keywords(_JUNOS_KW_MAP, q_lower) or ["show chassis alarms | no-more", "show interfaces terse | no-more"]
    eos_cmds = []
    if eos_targets:
        eos_cmds = _match_keywords(_EOS_KW_MAP, q_lower) or ["show system environment all", "show interfaces status"]

    # Safety blocklist (centralized in is_command_blocked)
    junos_cmds = [c for c in junos_cmds if not is_command_blocked(c)]
    eos_cmds = [c for c in eos_cmds if not is_command_blocked(c)]

    all_cmds_label = junos_cmds + ([f"(EOS) {c}" for c in eos_cmds] if eos_cmds else [])

    # ── Step 2: Execute on all devices in parallel ───────────────────────
    import paramiko
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _run_on_device(dev_name):
        info = all_devs[dev_name]
        dt = info.get("dtype", "junos")
        cmds = eos_cmds if dt == "eos" else junos_cmds
        result = {"device": dev_name, "ip": info["ip"], "dtype": dt, "outputs": {}, "status": "success"}
        try:
            ssh = paramiko.SSHClient()
            apply_ssh_policy(ssh)
            _ssh_connect(ssh, info["ip"], port=info["port"])
            for cmd in cmds:
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=15)
                    result["outputs"][cmd] = stdout.read().decode("utf-8", errors="replace").strip()[:2000]
                except Exception as e:
                    result["outputs"][cmd] = f"(error: {e})"
            ssh.close()
        except Exception as e:
            result["status"] = "error"
            result["outputs"]["_connection"] = str(e)
        return result

    results = []
    with ThreadPoolExecutor(max_workers=min(20, len(targets))) as pool:
        futures = {pool.submit(_run_on_device, t): t for t in targets}
        for f in as_completed(futures):
            results.append(f.result())
    results.sort(key=lambda r: r["device"])

    ok = sum(1 for r in results if r["status"] == "success")
    fail = len(results) - ok

    # ── Step 3: Send combined output to LLM ──────────────────────────────
    output_parts = []
    for r in results:
        plat = "EOS" if r.get("dtype") == "eos" else "Junos"
        header = f"═══ {r['device']} ({r['ip']}) [{plat}] — {r['status']} ═══"
        for cmd, out in r["outputs"].items():
            output_parts.append(f"{header}\n$ {cmd}\n{out[:800]}")
    combined = "\n\n".join(output_parts)
    if len(combined) > 12000:
        combined = combined[:12000] + "\n\n... (truncated)"

    site_label = site.upper() if site else ", ".join(targets[:5])
    platforms = []
    if junos_targets:
        platforms.append(f"{len(junos_targets)} Junos")
    if eos_targets:
        platforms.append(f"{len(eos_targets)} EOS")
    platform_info = " + ".join(platforms)

    analysis_system = (
        "You are a senior DCN network engineer. "
        f"The user asked about {len(results)} devices ({platform_info}) at site {site_label}. "
        "The site has a mix of Juniper Junos and Arista EOS devices. "
        "Command outputs from each device are below. "
        "Reply with a clear, concise SITE-WIDE analysis:\n"
        "- Summarize findings ACROSS devices (don't repeat per-device output)\n"
        "- Highlight any anomalies or inconsistencies between devices\n"
        "- Flag devices that differ from the majority (outliers)\n"
        "- Note any Junos vs EOS differences if relevant\n"
        "- Use bullet points, be direct and technical"
    )
    analysis_user = (
        f"Site: {site_label} ({platform_info}, {ok} ok, {fail} failed)\n"
        f"Question: {question}\n\n{combined}"
    )
    analysis = _llm_query(analysis_system, analysis_user, max_tokens=1000)

    return jsonify({
        "site": site.upper() if site else None,
        "question": question,
        "device_count": len(results),
        "junos_count": len(junos_targets),
        "eos_count": len(eos_targets),
        "successful": ok,
        "failed": fail,
        "commands_run": all_cmds_label,
        "results": results,
        "analysis": analysis or "(LLM did not produce an analysis — see raw device outputs)",
        "mode": "read-only",
        "llm_powered": bool(analysis),
    })


# ── API Documentation ─────────────────────────────────────────────────────────

_API_ENDPOINTS = [
    {
        "method": "GET", "path": "/api/health",
        "title": "Health Check",
        "desc": "Check if the API is running and how many devices are loaded.",
        "params": [],
        "example_curl": "curl http://localhost:5757/api/health",
        "response": '{"status":"ok","devices_loaded":450,"timestamp":"2026-02-27T10:00:00"}',
    },
    {
        "method": "GET", "path": "/api/devices",
        "title": "List Devices",
        "desc": "Return all network devices. Filter by site, hostname search, or role.",
        "params": [
            {"name": "site", "in": "query", "type": "string", "desc": "Filter by site code (e.g. UK-LON, DE-FRA)"},
            {"name": "search", "in": "query", "type": "string", "desc": "Search hostname or IP (partial match)"},
            {"name": "role", "in": "query", "type": "string", "desc": "Filter by role: switch, firewall, router"},
        ],
        "example_curl": 'curl "http://localhost:5757/api/devices?site=UK-LON&role=switch"',
        "response": '[{"hostname":"uk-lon-dist-01a","ip":"10.1.15.101","site":"UK-LON","type":"junos","role":"switch"}]',
    },
    {
        "method": "GET", "path": "/api/sites",
        "title": "List Sites",
        "desc": "Return all unique datacenter site codes.",
        "params": [],
        "example_curl": "curl http://localhost:5757/api/sites",
        "response": '["UK-LON","AKL1","NL-AMS","AUH1","BLL1",...]',
    },
    {
        "method": "GET", "path": "/api/commands/{dtype}",
        "title": "Available Commands",
        "desc": "Return the named command map for a device type (junos or eos).",
        "params": [
            {"name": "dtype", "in": "path", "type": "string", "desc": "Device type: junos or eos"},
        ],
        "example_curl": "curl http://localhost:5757/api/commands/junos",
        "response": '{"version":"show version","interfaces":"show interfaces terse",...}',
    },
    {
        "method": "POST", "path": "/api/run",
        "title": "Run Command",
        "desc": "Execute a single named or raw CLI command on a device via SSH.",
        "params": [
            {"name": "ip", "in": "body", "type": "string", "desc": "Device IP address (required)"},
            {"name": "dtype", "in": "body", "type": "string", "desc": "Device type: junos or eos"},
            {"name": "cmd_key", "in": "body", "type": "string", "desc": "Named command key (e.g. version, bgp, arp)"},
            {"name": "raw", "in": "body", "type": "string", "desc": "Raw CLI command string (alternative to cmd_key)"},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/run -H "Content-Type: application/json" -d '{"ip":"10.1.15.101","dtype":"junos","cmd_key":"version"}'""",
        "response": '{"success":true,"output":"Hostname: uk-lon-dist-01\\nModel: ex4600-40f\\n...","timestamp":"..."}',
    },
    {
        "method": "POST", "path": "/api/ping",
        "title": "Ping / Reachability",
        "desc": "Quick SSH reachability test — checks if device is accessible.",
        "params": [
            {"name": "ip", "in": "body", "type": "string", "desc": "Device IP address"},
            {"name": "dtype", "in": "body", "type": "string", "desc": "Device type: junos or eos"},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/ping -H "Content-Type: application/json" -d '{"ip":"10.1.15.101","dtype":"junos"}'""",
        "response": '{"success":true,"reachable":true,"output":"..."}',
    },
    {
        "method": "POST", "path": "/api/snapshot",
        "title": "Device Snapshot",
        "desc": "Collect a full snapshot: version, uptime, interfaces, ARP, routes, BGP, alarms, logs.",
        "params": [
            {"name": "ip", "in": "body", "type": "string", "desc": "Device IP address"},
            {"name": "dtype", "in": "body", "type": "string", "desc": "Device type: junos or eos"},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/snapshot -H "Content-Type: application/json" -d '{"ip":"10.1.15.101","dtype":"junos"}'""",
        "response": '{"success":true,"results":{"version":"...","interfaces":"...","bgp":"...","arp":"..."},"timestamp":"..."}',
    },
    {
        "method": "POST", "path": "/api/ports",
        "title": "Port Capacity",
        "desc": "Structured port breakdown: total physical slots, in use, empty, admin disabled, optics installed, by-speed table.",
        "params": [
            {"name": "ip", "in": "body", "type": "string", "desc": "Device IP address"},
            {"name": "dtype", "in": "body", "type": "string", "desc": "Device type: junos or eos"},
            {"name": "hostname", "in": "body", "type": "string", "desc": "Hostname for display"},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/ports -H "Content-Type: application/json" -d '{"ip":"10.1.15.101","dtype":"junos","hostname":"uk-lon-dist-01a"}'""",
        "response": '{"success":true,"total":48,"up":27,"free":21,"disabled":0,"optics_installed":31,"model":"ex4600-40f","by_speed":{"10G":{"total":24,"up":24},"1G":{"total":3,"up":3}}}',
    },
    {
        "method": "POST", "path": "/api/capacity",
        "title": "Capacity Forecasting",
        "desc": "Interface utilization analysis: traffic rates, speed breakdown, high-utilization ports, port status summary.",
        "params": [
            {"name": "ip", "in": "body", "type": "string", "desc": "Device IP address"},
            {"name": "dtype", "in": "body", "type": "string", "desc": "Device type: junos or eos"},
            {"name": "hostname", "in": "body", "type": "string", "desc": "Hostname for display"},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/capacity -H "Content-Type: application/json" -d '{"ip":"10.1.15.101","dtype":"junos","hostname":"uk-lon-dist-01a"}'""",
        "response": '{"success":true,"port_stats":{"total":27,"up":27},"speed_breakdown":{"10G":24},"utilization_top20":[...],"high_util_ports":[...]}',
    },
    {
        "method": "POST", "path": "/api/incident",
        "title": "Incident Investigation",
        "desc": "Collect incident-related data: logs, alarms, BGP, IKE/IPsec, interfaces, firewall, ISP optics, MTU.",
        "params": [
            {"name": "ip", "in": "body", "type": "string", "desc": "Device IP address"},
            {"name": "dtype", "in": "body", "type": "string", "desc": "Device type: junos or eos"},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/incident -H "Content-Type: application/json" -d '{"ip":"10.1.15.101","dtype":"junos"}'""",
        "response": '{"success":true,"results":{"alarms":"...","logs":"...","bgp":"...","ike":"...","ipsec":"..."},"timestamp":"..."}',
    },
    {
        "method": "POST", "path": "/api/analyze",
        "title": "AI Analysis",
        "desc": "Pattern-match collected command output for known issues: BGP, interfaces, alarms, logs, VPN, routes, MTU, ISP, SFP optics.",
        "params": [
            {"name": "hostname", "in": "body", "type": "string", "desc": "Hostname for context"},
            {"name": "dtype", "in": "body", "type": "string", "desc": "Device type: junos or eos"},
            {"name": "data", "in": "body", "type": "object", "desc": 'Map of command key → output string, e.g. {"bgp":"...","interfaces":"..."}'},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/analyze -H "Content-Type: application/json" -d '{"hostname":"uk-lon-dist-01a","dtype":"junos","data":{"bgp":"Established...","alarms":"No alarms"}}'""",
        "response": '{"hostname":"...","severity":"WARNING","findings":[...],"warnings":[...],"best_practices":[...]}',
    },
    {
        "method": "POST", "path": "/api/recommendations",
        "title": "Best-Practice Recommendations",
        "desc": "Collect device configuration and generate best-practice recommendations with severity and remediation steps.",
        "params": [
            {"name": "ip", "in": "body", "type": "string", "desc": "Device IP address"},
            {"name": "dtype", "in": "body", "type": "string", "desc": "Device type: junos or eos"},
            {"name": "hostname", "in": "body", "type": "string", "desc": "Hostname for display"},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/recommendations -H "Content-Type: application/json" -d '{"ip":"10.1.15.101","dtype":"junos","hostname":"uk-lon-dist-01a"}'""",
        "response": '{"success":true,"score":85,"grade":"B","recommendations":[{"severity":"high","title":"NTP not configured",...}]}',
    },
    {
        "method": "POST", "path": "/api/deep-analysis",
        "title": "Deep Analysis (AI Agent)",
        "desc": "Comprehensive cross-correlated health report: collects 20+ commands, analyzes BGP, interfaces, optics, MTU, traffic, config, security, and produces a scored report.",
        "params": [
            {"name": "ip", "in": "body", "type": "string", "desc": "Device IP address"},
            {"name": "dtype", "in": "body", "type": "string", "desc": "Device type: junos or eos"},
            {"name": "hostname", "in": "body", "type": "string", "desc": "Hostname for display"},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/deep-analysis -H "Content-Type: application/json" -d '{"ip":"10.1.15.101","dtype":"junos","hostname":"uk-lon-dist-01a"}'""",
        "response": '{"success":true,"hostname":"...","health_score":82,"grade":"B","severity_counts":{...},"categories":{...}}',
    },
    {
        "method": "POST", "path": "/api/log-analysis",
        "title": "Log Intelligence",
        "desc": "Collect last ~1000 syslog messages and classify each by severity (critical/high/medium/low), category, and recommended action.",
        "params": [
            {"name": "ip", "in": "body", "type": "string", "desc": "Device IP address"},
            {"name": "dtype", "in": "body", "type": "string", "desc": "Device type: junos or eos"},
            {"name": "hostname", "in": "body", "type": "string", "desc": "Hostname for display"},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/log-analysis -H "Content-Type: application/json" -d '{"ip":"10.1.15.101","dtype":"junos","hostname":"uk-lon-dist-01a"}'""",
        "response": '{"success":true,"total_messages":1000,"severity_counts":{"high":3,"medium":12,"low":45},"messages":[...],"action_items":[...]}',
    },
    {
        "method": "POST", "path": "/api/config-drift",
        "title": "Config Drift & Compliance",
        "desc": "Run 18 compliance checks (NTP, SNMP, syslog, AAA, BGP, firewall, etc.) and detect config drift against saved baseline.",
        "params": [
            {"name": "ip", "in": "body", "type": "string", "desc": "Device IP address"},
            {"name": "dtype", "in": "body", "type": "string", "desc": "Device type: junos or eos"},
            {"name": "hostname", "in": "body", "type": "string", "desc": "Hostname for display"},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/config-drift -H "Content-Type: application/json" -d '{"ip":"10.1.15.101","dtype":"junos","hostname":"uk-lon-dist-01a"}'""",
        "response": '{"success":true,"compliance_score":92,"grade":"A","passed":16,"failed":2,"drift_detected":false,"checks":[...]}',
    },
    {
        "method": "POST", "path": "/api/topology",
        "title": "Topology Discovery",
        "desc": "Map all neighbor connections via LLDP, interface descriptions, BGP, OSPF, ISIS, LACP, and MLAG.",
        "params": [
            {"name": "ip", "in": "body", "type": "string", "desc": "Device IP address"},
            {"name": "dtype", "in": "body", "type": "string", "desc": "Device type: junos or eos"},
            {"name": "hostname", "in": "body", "type": "string", "desc": "Hostname for display"},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/topology -H "Content-Type: application/json" -d '{"ip":"10.1.15.101","dtype":"junos","hostname":"uk-lon-dist-01a"}'""",
        "response": '{"success":true,"total_neighbors":24,"unique_devices":8,"neighbors":[{"local_port":"xe-0/0/0","remote_device":"uk-lon-fw-20","source":"lldp"},...]}',
    },
    {
        "method": "POST", "path": "/api/security-audit",
        "title": "Security Posture Audit",
        "desc": "Deep security scan: firmware CVE awareness, crypto strength, ACL review, user accounts, SNMP security, BGP auth, VPN status.",
        "params": [
            {"name": "ip", "in": "body", "type": "string", "desc": "Device IP address"},
            {"name": "dtype", "in": "body", "type": "string", "desc": "Device type: junos or eos"},
            {"name": "hostname", "in": "body", "type": "string", "desc": "Hostname for display"},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/security-audit -H "Content-Type: application/json" -d '{"ip":"10.1.15.101","dtype":"junos","hostname":"uk-lon-dist-01a"}'""",
        "response": '{"success":true,"security_score":75,"grade":"C","risk_level":"MEDIUM","findings":[...],"critical":0,"high":3,"medium":5,"passed":12}',
    },
    {
        "method": "POST", "path": "/api/subnet-analysis",
        "title": "Subnet IP Exhaustion",
        "desc": "Per-subnet IP utilization from ARP table. Shows active hosts (IP, MAC, hostname), free IPs, exhaustion status (critical/warning/moderate/healthy).",
        "params": [
            {"name": "ip", "in": "body", "type": "string", "desc": "Device IP address"},
            {"name": "dtype", "in": "body", "type": "string", "desc": "Device type: junos or eos"},
            {"name": "hostname", "in": "body", "type": "string", "desc": "Hostname for display"},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/subnet-analysis -H "Content-Type: application/json" -d '{"ip":"10.1.15.1","dtype":"junos","hostname":"uk-lon-fw-20a"}'""",
        "response": '{"success":true,"summary":{"total_subnets":9,"total_ips":2350,"active_hosts":222,"free_ips":2128,"overall_utilization":9.4},"subnets":[{"subnet":"10.245.48.0/23","utilization_pct":31.4,"status":"healthy","hosts":[...]}]}',
    },
    {
        "method": "GET", "path": "/api/jmcp/status",
        "title": "JMCP Status",
        "desc": "Check Junos MCP Server sidecar status, available tools, and device count.",
        "params": [],
        "example_curl": "curl http://localhost:5757/api/jmcp/status",
        "response": '{"available":true,"junos_devices":384,"tools":["execute_junos_command",...],"mode":"read-only"}',
    },
    {
        "method": "GET", "path": "/api/jmcp/devices",
        "title": "JMCP Device Inventory",
        "desc": "List all Junos devices auto-generated from DCN inventory (auth details stripped).",
        "params": [],
        "example_curl": "curl http://localhost:5757/api/jmcp/devices",
        "response": '{"device_count":384,"devices":{"uk-lon-dist-01":{"ip":"10.1.15.101","port":22,"username":"Georgi.Gaydarov","auth_type":"ssh_agent"},...}}',
    },
    {
        "method": "POST", "path": "/api/jmcp/execute",
        "title": "JMCP Execute Command",
        "desc": "Execute a read-only Junos CLI command on a single device. Write commands are blocked.",
        "params": [
            {"name": "device", "in": "body", "type": "string", "desc": "Device hostname (e.g. uk-lon-dist-01)"},
            {"name": "command", "in": "body", "type": "string", "desc": "Junos CLI command (show/monitor only)"},
            {"name": "timeout", "in": "body", "type": "integer", "desc": "Command timeout in seconds (default: 60)"},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/jmcp/execute -H "Content-Type: application/json" -d '{"device":"uk-lon-dist-01","command":"show bgp summary"}'""",
        "response": '{"device":"uk-lon-dist-01","ip":"10.1.15.101","command":"show bgp summary","output":"...","mode":"read-only"}',
    },
    {
        "method": "POST", "path": "/api/jmcp/batch",
        "title": "JMCP Batch Execute",
        "desc": "Execute a read-only Junos CLI command on multiple devices in parallel (max 20 concurrent).",
        "params": [
            {"name": "devices", "in": "body", "type": "array", "desc": "List of device hostnames"},
            {"name": "command", "in": "body", "type": "string", "desc": "Junos CLI command (show/monitor only)"},
            {"name": "timeout", "in": "body", "type": "integer", "desc": "Per-device timeout (default: 60)"},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/jmcp/batch -H "Content-Type: application/json" -d '{"devices":["uk-lon-dist-01","uk-lon-dist-01"],"command":"show version"}'""",
        "response": '{"command":"show version","total":2,"successful":2,"failed":0,"results":[...],"mode":"read-only"}',
    },
    {
        "method": "POST", "path": "/api/jmcp/facts",
        "title": "JMCP Device Facts",
        "desc": "Gather device facts (version, uptime, chassis hardware) for a Junos device.",
        "params": [
            {"name": "device", "in": "body", "type": "string", "desc": "Device hostname"},
        ],
        "example_curl": """curl -X POST http://localhost:5757/api/jmcp/facts -H "Content-Type: application/json" -d '{"device":"uk-lon-dist-01"}'""",
        "response": '{"device":"uk-lon-dist-01","ip":"10.1.15.101","facts":{"version":"...","uptime":"...","hardware":"..."},"mode":"read-only"}',
    },
]


@app.route("/api/docs", methods=["GET"])
def api_docs_json():
    """Return API documentation as JSON."""
    return jsonify({
        "title": "DCN Network Tool API",
        "version": "1.0",
        "base_url": request.host_url.rstrip("/"),
        "total_endpoints": len(_API_ENDPOINTS),
        "endpoints": _API_ENDPOINTS,
    })


@app.route("/docs")
def api_docs_page():
    """Serve interactive API documentation page."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DCN Network Tool — API Documentation</title>
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#1c2129;--fg:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--border:#30363d;--orange:#f0883e}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--fg);line-height:1.6}
.container{max-width:1100px;margin:0 auto;padding:20px}
h1{font-size:24px;margin-bottom:4px}
.subtitle{color:var(--muted);font-size:14px;margin-bottom:24px}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:3px 10px;border-radius:4px;font-family:Consolas,monospace}
.badge-get{background:#1a3d2a;color:var(--green);border:1px solid #2a5a3a}
.badge-post{background:#1a2d4d;color:var(--accent);border:1px solid #2a4d7d}
.ep{background:var(--bg2);border:1px solid var(--border);border-radius:10px;margin-bottom:12px;overflow:hidden}
.ep-head{padding:14px 18px;cursor:pointer;display:flex;align-items:center;gap:12px;user-select:none}
.ep-head:hover{background:var(--bg3)}
.ep-path{font-family:Consolas,monospace;font-size:14px;font-weight:600;color:var(--fg)}
.ep-title{font-size:13px;color:var(--muted);flex:1}
.ep-arrow{color:var(--muted);font-size:14px;transition:transform .2s}
.ep.open .ep-arrow{transform:rotate(90deg)}
.ep-body{display:none;padding:0 18px 16px;border-top:1px solid var(--border)}
.ep.open .ep-body{display:block}
.ep-desc{color:var(--muted);font-size:13px;margin:12px 0}
table{width:100%;border-collapse:collapse;font-size:12px;margin:10px 0}
th{text-align:left;padding:6px 10px;background:var(--bg3);color:var(--muted);border-bottom:1px solid var(--border)}
td{padding:6px 10px;border-bottom:1px solid var(--border)}
.code{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px;font-family:Consolas,monospace;font-size:12px;overflow-x:auto;white-space:pre-wrap;position:relative;color:var(--green)}
.code-label{font-size:10px;color:var(--muted);margin-bottom:4px;font-weight:600}
.copy-btn{position:absolute;top:6px;right:6px;background:var(--bg3);border:1px solid var(--border);color:var(--muted);padding:3px 8px;border-radius:4px;cursor:pointer;font-size:10px}
.copy-btn:hover{color:var(--fg);border-color:var(--accent)}
.resp{color:var(--accent)}
.stats{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap}
.stat{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 16px;text-align:center}
.stat-v{font-size:24px;font-weight:800;color:var(--accent)}
.stat-l{font-size:11px;color:var(--muted)}
.search{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:8px 14px;color:var(--fg);font-size:14px;width:100%;margin-bottom:16px}
.search:focus{outline:none;border-color:var(--accent)}
.filter-row{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
.filter-btn{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:4px 12px;color:var(--muted);cursor:pointer;font-size:12px}
.filter-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.filter-btn:hover{border-color:var(--accent)}
</style>
</head>
<body>
<div class="container">
  <h1>🌐 DCN Network Tool — API Reference</h1>
  <div class="subtitle">All endpoints accept and return JSON. POST endpoints require <code>Content-Type: application/json</code>.</div>

  <div class="stats" id="stats"></div>

  <input class="search" id="search" placeholder="Search endpoints..." oninput="filterEndpoints()">
  <div class="filter-row" id="filters"></div>
  <div id="endpoints"></div>
</div>

<script>
const API_DOCS_URL = '/api/docs';
let allEndpoints = [];

async function loadDocs() {
  const r = await fetch(API_DOCS_URL);
  const d = await r.json();
  allEndpoints = d.endpoints;

  // Stats
  const gets = allEndpoints.filter(e => e.method === 'GET').length;
  const posts = allEndpoints.filter(e => e.method === 'POST').length;
  document.getElementById('stats').innerHTML = `
    <div class="stat"><div class="stat-v">${d.total_endpoints}</div><div class="stat-l">Total Endpoints</div></div>
    <div class="stat"><div class="stat-v" style="color:var(--green)">${gets}</div><div class="stat-l">GET</div></div>
    <div class="stat"><div class="stat-v" style="color:var(--accent)">${posts}</div><div class="stat-l">POST</div></div>
    <div class="stat"><div class="stat-v" style="color:var(--fg)">${d.base_url}</div><div class="stat-l">Base URL</div></div>
  `;

  // Filters
  const cats = ['All', 'GET', 'POST'];
  document.getElementById('filters').innerHTML = cats.map((c,i) =>
    `<button class="filter-btn ${i===0?'active':''}" onclick="setFilter('${c}',this)">${c}</button>`
  ).join('');

  renderEndpoints(allEndpoints);
}

let activeFilter = 'All';
function setFilter(f, btn) {
  activeFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  filterEndpoints();
}

function filterEndpoints() {
  const q = document.getElementById('search').value.toLowerCase();
  const filtered = allEndpoints.filter(e => {
    if (activeFilter !== 'All' && e.method !== activeFilter) return false;
    if (q && !e.path.toLowerCase().includes(q) && !e.title.toLowerCase().includes(q) && !e.desc.toLowerCase().includes(q)) return false;
    return true;
  });
  renderEndpoints(filtered);
}

function renderEndpoints(eps) {
  document.getElementById('endpoints').innerHTML = eps.map((ep, idx) => {
    const badgeClass = ep.method === 'GET' ? 'badge-get' : 'badge-post';
    const paramsHtml = ep.params.length > 0 ? `
      <div class="code-label">Parameters</div>
      <table>
        <thead><tr><th>Name</th><th>In</th><th>Type</th><th>Description</th></tr></thead>
        <tbody>${ep.params.map(p => `<tr><td style="font-family:Consolas,monospace;color:var(--accent)">${p.name}</td><td>${p.in}</td><td style="color:var(--muted)">${p.type}</td><td>${p.desc}</td></tr>`).join('')}</tbody>
      </table>` : '';
    return `
    <div class="ep" id="ep-${idx}">
      <div class="ep-head" onclick="toggle(${idx})">
        <span class="badge ${badgeClass}">${ep.method}</span>
        <span class="ep-path">${ep.path}</span>
        <span class="ep-title">${ep.title}</span>
        <span class="ep-arrow">▶</span>
      </div>
      <div class="ep-body">
        <div class="ep-desc">${ep.desc}</div>
        ${paramsHtml}
        <div class="code-label" style="margin-top:12px">Example Request</div>
        <div class="code" id="curl-${idx}">${escHtml(ep.example_curl)}<button class="copy-btn" onclick="copyCode(${idx})">Copy</button></div>
        <div class="code-label" style="margin-top:10px">Example Response</div>
        <div class="code resp">${escHtml(ep.response)}</div>
      </div>
    </div>`;
  }).join('');
}

function toggle(idx) {
  document.getElementById('ep-' + idx).classList.toggle('open');
}
function copyCode(idx) {
  const el = document.getElementById('curl-' + idx);
  const text = el.textContent.replace('Copy', '').trim();
  navigator.clipboard.writeText(text);
  const btn = el.querySelector('.copy-btn');
  btn.textContent = 'Copied!';
  setTimeout(() => btn.textContent = 'Copy', 1500);
}
function escHtml(s) {
  return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

loadDocs();
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
# ── 🤖 LOCAL LLM INTEGRATION (Docker Model Runner) ──────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def _clean_llm_response(text):
    """Strip chain-of-thought preamble that qwen3 sometimes leaks despite enable_thinking=false.
    Removes lines like 'Okay, the user wants...', 'I need to...', 'Let me...', etc."""
    if not text:
        return text
    import re
    lines = text.split("\n")
    cleaned = []
    # Skip leading lines that look like internal reasoning
    reasoning_patterns = re.compile(
        r"^(okay|ok|alright|so|let me|i need to|i should|i\'ll|first|the user|hmm|now|thinking|wait)\b",
        re.IGNORECASE
    )
    started = False
    for line in lines:
        stripped = line.strip()
        if not started:
            # Skip empty lines and reasoning lines at the start
            if not stripped:
                continue
            if reasoning_patterns.match(stripped):
                continue
            started = True
        cleaned.append(line)
    result = "\n".join(cleaned).strip()
    # If we stripped everything, return original (safety net)
    return result if result else text.strip()


def _llm_query_claude(system_prompt, user_prompt, max_tokens=500):
    """Direct call to Anthropic Claude. Returns cleaned text or None."""
    if not ANTHROPIC_API_KEY:
        return None
    try:
        r = _requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": max_tokens,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            },
            timeout=30,
        )
        if r.status_code == 200:
            text = r.json()["content"][0].get("text", "").strip()
            if text:
                return _clean_llm_response(text)
    except Exception:
        pass
    return None


def _llm_query(system_prompt, user_prompt, max_tokens=500):
    """Query an LLM. Provider order is controlled by LLM_PROVIDER env var:
      - "claude"      : Claude first, local fallback
      - "claude-only" : Claude only (skip local)
      - "local"       : Ollama → Docker ModelRunner → Claude (default)
    Returns cleaned text or None on complete failure.
    """
    if not LLM_ENABLED:
        return None

    # Claude-first or Claude-only modes: try Anthropic before any local model.
    if LLM_PROVIDER in ("claude", "claude-only"):
        text = _llm_query_claude(system_prompt, user_prompt, max_tokens=max_tokens)
        if text is not None or LLM_PROVIDER == "claude-only":
            return text  # success or hard-skip local

    # ── Attempt 0: Ollama native /api/chat (gemma4 / qwen2.5-coder / llama3.2) ─
    # Use native Ollama API with think=false to disable chain-of-thought on thinking
    # models (gemma4, qwen3). Native API honours think:false reliably; OpenAI-compat
    # endpoint leaks reasoning into the response instead of content.
    ollama_native_payload = {
        "model":   LLM_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "options": {"temperature": 0.2, "num_predict": max_tokens},
        "stream":  False,
        "think":   False,  # Disable thinking/reasoning for gemma4 / qwen3
    }
    try:
        url = f"{OLLAMA_URL.rstrip('/')}/api/chat"
        r = _requests.post(url, json=ollama_native_payload, timeout=LLM_TIMEOUT)
        if r.status_code == 200:
            msg = r.json().get("message", {})
            text = (msg.get("content") or "").strip()
            if text:
                return _clean_llm_response(text)
    except Exception:
        pass

    # ── Attempt 1: Docker Model Runner TCP ───────────────────────────────────
    docker_payload = {
        "model": LLM_MODEL_RUNNER,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.2,
        "stream": False,
        "enable_thinking": False,
    }

    if MODEL_RUNNER_URL:
        for path in [
            "/engines/llama.cpp/v1/chat/completions",
            "/v1/chat/completions",
        ]:
            try:
                url = f"{MODEL_RUNNER_URL.rstrip('/')}{path}"
                r = _requests.post(url, json=docker_payload, timeout=LLM_TIMEOUT, verify=DCN_VERIFY_SSL)
                if r.status_code == 200:
                    msg = r.json()["choices"][0]["message"]
                    text = msg.get("content") or msg.get("reasoning_content") or ""
                    if text.strip():
                        return _clean_llm_response(text.strip())
            except Exception:
                pass

    # ── Attempt 2: Docker Model Runner Unix socket (inference.sock)
    import socket as _socket
    docker_sockets = [
        os.path.expanduser("~/Library/Containers/com.docker.docker/Data/inference.sock"),
        os.path.expanduser("~/Library/Containers/com.docker.docker/Data/inference-0.sock"),
        "/run/docker-model-runner/inference.sock",
        os.path.expanduser("~/.docker/desktop/inference.sock"),
        os.path.expanduser("~/.docker/run/docker.sock"),
    ]
    socket_paths = [
        "/engines/llama.cpp/v1/chat/completions",
        "/v1/chat/completions",
    ]
    for sock_path in docker_sockets:
        if not os.path.exists(sock_path):
            continue
        for api_path in socket_paths:
            try:
                body = json.dumps(docker_payload).encode()
                req_str = (
                    f"POST {api_path} HTTP/1.1\r\n"
                    f"Host: localhost\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode() + body

                s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
                s.settimeout(LLM_TIMEOUT)
                s.connect(sock_path)
                s.sendall(req_str)

                resp = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                s.close()

                if b"\r\n\r\n" in resp:
                    body_bytes = resp.split(b"\r\n\r\n", 1)[1]
                    if b"Transfer-Encoding: chunked" in resp:
                        lines = body_bytes.split(b"\r\n")
                        body_bytes = b"".join(
                            l for l in lines if l and not all(c in b"0123456789abcdefABCDEF" for c in l)
                        )
                    data = json.loads(body_bytes.strip())
                    if "choices" in data:
                        msg = data["choices"][0]["message"]
                        text = msg.get("content") or msg.get("reasoning_content") or ""
                        if text.strip():
                            return _clean_llm_response(text.strip())
            except Exception:
                pass

    # ── Attempt 3: Anthropic Claude fallback ──────────────────────────────────
    text = _llm_query_claude(system_prompt, user_prompt, max_tokens=max_tokens)
    if text is not None:
        return text

    return None


def _list_available_providers() -> list[dict]:
    """Probe each LLM provider quickly and return availability."""
    out: list[dict] = []
    out.append({
        "id": "claude",
        "label": f"Claude ({ANTHROPIC_MODEL})",
        "available": bool(ANTHROPIC_API_KEY),
    })
    ollama_ok = False
    try:
        r = _requests.get(f"{OLLAMA_URL.rstrip('/')}/api/tags", timeout=2)
        ollama_ok = (r.status_code == 200)
    except Exception:
        pass
    out.append({"id": "local", "label": f"Local ({LLM_MODEL})", "available": ollama_ok})
    out.append({"id": "claude-only", "label": "Claude only (no fallback)", "available": bool(ANTHROPIC_API_KEY)})
    return out


@app.route("/api/llm/provider", methods=["POST"])
def llm_set_provider():
    """Set the active LLM_PROVIDER at runtime. Body: {"provider": "claude" | "local" | "claude-only"}"""
    global LLM_PROVIDER
    body = request.get_json(silent=True) or {}
    new = (body.get("provider") or "").lower().strip()
    if new not in ("local", "claude", "claude-only"):
        return jsonify({"error": "provider must be one of: local, claude, claude-only"}), 400
    if new in ("claude", "claude-only") and not ANTHROPIC_API_KEY:
        return jsonify({"error": "ANTHROPIC_API_KEY not configured — cannot select claude provider"}), 400
    LLM_PROVIDER = new
    return jsonify({"provider": LLM_PROVIDER, "ok": True})


@app.route("/api/llm/status", methods=["GET"])
def llm_status():
    """Check LLM availability — order depends on LLM_PROVIDER env var."""
    if not LLM_ENABLED:
        return jsonify({"enabled": False, "available": False, "reason": "LLM_ENABLED=false"})

    key_suffix = f"…{ANTHROPIC_API_KEY[-6:]}" if ANTHROPIC_API_KEY else None

    # Claude-first / Claude-only modes report Claude as primary transport.
    if LLM_PROVIDER in ("claude", "claude-only") and ANTHROPIC_API_KEY:
        return jsonify({
            "enabled": True, "available": True,
            "model": ANTHROPIC_MODEL,
            "transport": "anthropic:claude",
            "provider": LLM_PROVIDER,
            "models": [ANTHROPIC_MODEL],
            "anthropic_key_suffix": key_suffix,
            "providers_available": _list_available_providers(),
        })

    # ── Attempt 0: Ollama (/api/tags lists loaded models) ──────────────────
    try:
        r = _requests.get(f"{OLLAMA_URL.rstrip('/')}/api/tags", timeout=3)
        if r.status_code == 200:
            models = [m.get("name") for m in r.json().get("models", [])]
            return jsonify({
                "enabled": True, "available": True,
                "model": LLM_MODEL, "transport": f"ollama:{OLLAMA_URL}",
                "provider": LLM_PROVIDER,
                "models": models,
                "anthropic_key_suffix": key_suffix,
                "providers_available": _list_available_providers(),
            })
    except Exception:
        pass

    # ── Attempt 1: Docker Model Runner Unix socket ──────────────────────────
    import socket as _sock
    inference_sockets = [
        os.path.expanduser("~/Library/Containers/com.docker.docker/Data/inference.sock"),
        os.path.expanduser("~/Library/Containers/com.docker.docker/Data/inference-0.sock"),
        "/run/docker-model-runner/inference.sock",
        os.path.expanduser("~/.docker/desktop/inference.sock"),
    ]
    for sock_path in inference_sockets:
        if not os.path.exists(sock_path):
            continue
        try:
            probe = b"GET /engines/llama.cpp/v1/models HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
            s.settimeout(5)
            s.connect(sock_path)
            s.sendall(probe)
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
            s.close()
            if b"200 OK" in resp and b"\r\n\r\n" in resp:
                body = resp.split(b"\r\n\r\n", 1)[1]
                data = json.loads(body.strip())
                models = [m.get("id") for m in data.get("data", [])]
                return jsonify({
                    "enabled": True, "available": True, "model": LLM_MODEL,
                    "transport": f"unix:{sock_path}", "models": models,
                })
        except Exception:
            pass

    # Try TCP fallback
    try:
        url = f"{MODEL_RUNNER_URL.rstrip('/')}/engines/llama.cpp/v1/models"
        r = _requests.get(url, timeout=5, verify=DCN_VERIFY_SSL)
        if r.status_code == 200:
            models = [m.get("id") for m in r.json().get("data", [])]
            return jsonify({"enabled": True, "available": True, "model": LLM_MODEL,
                            "transport": f"tcp:{MODEL_RUNNER_URL}", "models": models})
    except Exception:
        pass

    return jsonify({
        "enabled": True, "available": False, "model": LLM_MODEL,
        "hint": "Enable Docker Model Runner: Docker Desktop > AI settings, then: docker model pull ai/qwen2.5",
    })


@app.route("/api/llm/toggle", methods=["POST"])
def llm_toggle():
    """Toggle LLM on/off at runtime.  Body: {enabled: true/false}"""
    global LLM_ENABLED
    body = request.get_json(force=True) or {}
    if "enabled" in body:
        LLM_ENABLED = bool(body["enabled"])
    else:
        LLM_ENABLED = not LLM_ENABLED
    return jsonify({"enabled": LLM_ENABLED})


# ── Site Topology Maps (from .drawio XML files) ───────────────────────────────
TOPOLOGIES_DIR = os.environ.get("DCN_TOPOLOGIES_DIR",
    os.path.normpath(os.path.join(os.path.dirname(__file__), "../../topologies")))


def _parse_drawio_to_cytoscape(xml_path):
    """Parse a .drawio XML file and return Cytoscape.js elements (nodes + edges)."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    diagram = root.find("diagram")
    if diagram is None:
        return {"nodes": [], "edges": [], "title": ""}

    model = diagram.find("mxGraphModel")
    if model is None:
        return {"nodes": [], "edges": [], "title": ""}

    cells = model.findall(".//mxCell")
    nodes = []
    edges = []
    title = ""

    # Role / color detection from drawio style
    def _detect_role(style, value):
        val_lower = (value or "").lower()
        style_lower = (style or "").lower()
        if "fillcolor=#ff4444" in style_lower or "fillcolor=#ff6666" in style_lower:
            return "firewall"
        if "fillcolor=#ff8c00" in style_lower or "fillcolor=#ffa500" in style_lower:
            return "router"
        if "fillcolor=#00cc66" in style_lower or "fillcolor=#00aa55" in style_lower:
            return "spine"
        if "fillcolor=#66bb6a" in style_lower or "fillcolor=#4caf50" in style_lower:
            return "access"
        if "fillcolor=#42a5f5" in style_lower or "fillcolor=#1e88e5" in style_lower:
            return "router"
        if "fillcolor=#9e9e9e" in style_lower or "oob" in val_lower:
            return "oob"
        if "fw" in val_lower or "firewall" in val_lower:
            return "firewall"
        if "rt" in val_lower or "router" in val_lower:
            return "router"
        if "sw" in val_lower or "spine" in val_lower:
            return "spine"
        return "switch"

    def _strip_html(s):
        """Remove HTML tags from drawio value strings."""
        if not s:
            return ""
        s = re.sub(r"<[^>]+>", " ", s)
        s = re.sub(r"&lt;", "<", s)
        s = re.sub(r"&gt;", ">", s)
        s = re.sub(r"&amp;", "&", s)
        s = re.sub(r"&quot;", '"', s)
        s = re.sub(r"\s+", " ", s).strip()
        return s

    def _short_label(plain):
        """Extract a short hostname label from verbose drawio text."""
        if not plain:
            return ""
        # Common patterns: "de-fra-dist-01 QFX5120-32C · Spine ..." → "de-fra-dist-01"
        # or "fw-01a SRX1500 node0" → "fw-01a"
        # or "Colt / Arelion AS3356 100G ..." → "Colt / Arelion" (ISP)
        # or "ADC FIREWALL CLUSTER" → "ADC FW CLUSTER"
        # or "Rack 03 Storage ..." → "Rack 03 Storage"
        # Try hostname pattern first
        m = re.match(r'([a-z0-9]+-(?:sw|rt|fw|oob)-[a-z0-9/]+)', plain, re.I)
        if m:
            return m.group(1)
        # Short name like "fw-01a" or "sw-02a"
        m = re.match(r'((?:fw|sw|rt|oob)-[a-z0-9/]+)', plain, re.I)
        if m:
            return m.group(1)
        # Rack pattern
        m = re.match(r'(Rack\s+\S+\s+\S+)', plain, re.I)
        if m:
            return m.group(1)
        # Cluster / group labels (e.g. "ADC FIREWALL CLUSTER", "NTW FIREWALL CLUSTER")
        upper_words = [w for w in plain.split() if w.isupper() or w[0:1].isupper()]
        if len(plain.split()) <= 4 and len(plain) <= 30:
            return plain
        # ISP / IXP — take provider name
        m = re.match(r'([A-Z][A-Za-z\-]+(?:\s*/\s*[A-Za-z\-]+)?)', plain)
        if m and len(m.group(1)) > 2:
            name = m.group(1).strip()
            if len(name) <= 25:
                return name
        # Fallback: first 3 words
        words = plain.split()
        return ' '.join(words[:3])

    def _detect_link_type(style, value):
        """Detect link type from edge style."""
        style_lower = (style or "").lower()
        val_lower = (value or "").lower()
        if "strokecolor=#9c27b0" in style_lower or "strokecolor=#ab47bc" in style_lower or "ibgp" in val_lower:
            return "ibgp"
        if "strokecolor=#9e9e9e" in style_lower or "strokecolor=#bdbdbd" in style_lower or "oob" in val_lower:
            return "oob"
        if "strokecolor=#2196f3" in style_lower or "dashed=1" in style_lower:
            return "1g"
        if "strokecolor=#4caf50" in style_lower or "strokewidth=2" in style_lower:
            return "10g"
        if "1g" in val_lower:
            return "1g"
        if "10g" in val_lower:
            return "10g"
        return "default"

    for cell in cells:
        cid = cell.get("id", "")
        style = cell.get("style", "")
        value = cell.get("value", "")
        parent = cell.get("parent", "")
        source = cell.get("source")
        target = cell.get("target")
        edge = cell.get("edge")

        # Skip root cells and legend/text-only cells
        if cid in ("0", "1"):
            continue
        if "text;html=1" in style and not source and not target:
            plain = _strip_html(value)
            if "topology" in plain.lower() and not title:
                title = plain
            continue
        # Skip legend shapes
        if cid.startswith("legend"):
            continue
        if cid.startswith("key") or cid.startswith("kf"):
            continue

        geo = cell.find("mxGeometry")

        if edge == "1" and source and target:
            # Edge
            link_type = _detect_link_type(style, value)
            label = _strip_html(value)
            edges.append({
                "data": {
                    "id": cid,
                    "source": source,
                    "target": target,
                    "label": label,
                    "link_type": link_type,
                }
            })
        elif geo is not None and not edge:
            # Node (has geometry, not an edge)
            x = float(geo.get("x", "0"))
            y = float(geo.get("y", "0"))
            w = float(geo.get("width", "80"))
            h = float(geo.get("height", "40"))
            plain = _strip_html(value)
            if not plain:
                continue
            role = _detect_role(style, value)
            short = _short_label(plain)
            # Scale positions by 2x for better spacing in Cytoscape
            nodes.append({
                "data": {
                    "id": cid,
                    "label": short,
                    "tooltip": plain,
                    "role": role,
                    "w": w,
                    "h": h,
                },
                "position": {"x": (x + w / 2) * 2, "y": (y + h / 2) * 2},
            })

    return {"nodes": nodes, "edges": edges, "title": title}


@app.route("/api/topology-map/sites", methods=["GET"])
def topology_map_sites():
    """List all sites that have topology .drawio files."""
    sites = []
    if os.path.isdir(TOPOLOGIES_DIR):
        for fn in sorted(os.listdir(TOPOLOGIES_DIR)):
            if fn.endswith("_topology.drawio"):
                site = fn.replace("_topology.drawio", "")
                sites.append(site)
    return jsonify({"success": True, "sites": sites, "count": len(sites),
                    "topologies_dir": TOPOLOGIES_DIR})


@app.route("/api/topology-map/<site_code>", methods=["GET"])
def topology_map(site_code):
    """Get Cytoscape.js-compatible topology data for a site."""
    site_upper = site_code.upper()
    fpath = os.path.join(TOPOLOGIES_DIR, f"{site_upper}_topology.drawio")
    if not os.path.isfile(fpath):
        return jsonify({"success": False, "error": f"No topology file for {site_upper}"}), 404
    try:
        data = _parse_drawio_to_cytoscape(fpath)
        data["success"] = True
        data["site"] = site_upper
        # Count devices in inventory for this site
        site_devs = [d for d in DEVICES if d.get("site", "").upper() == site_upper]
        data["device_count"] = len(site_devs)
        data["devices"] = site_devs
        return jsonify(data)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ── 🗺️ LIVE TOPOLOGY — Dynamic site topology from SSH (LLDP + descriptions) ─
# ══════════════════════════════════════════════════════════════════════════════

_LIVE_TOPO_CMDS_JUNOS = [
    ("show lldp neighbors | no-more", "lldp"),
    ("show interfaces descriptions | no-more", "descriptions"),
    ("show interfaces terse | no-more", "terse"),
    ("show lacp interfaces | no-more", "lacp"),
    ("show chassis hardware | match Chassis | no-more", "hardware"),
    ("show version | match Model | no-more", "model"),
    ("show arp no-resolve | no-more", "arp"),
    ("show chassis cluster status | no-more", "cluster"),
    ("show bgp summary | no-more", "bgp"),
    ("show ethernet-switching table brief | no-more", "mac_table"),
    ("show vlans | no-more", "vlans"),
    ("show vlans extensive | no-more", "vlans_detail"),
    ("show configuration vlans | display set | no-more", "vlans_config"),
]
_LIVE_TOPO_CMDS_EOS = [
    ("show lldp neighbors | no-more", "lldp"),
    ("show interfaces description | no-more", "descriptions"),
    ("show interfaces status | no-more", "terse"),
    ("show lacp interface all-ports | no-more", "lacp"),
    ("show version | include Model | no-more", "model"),
    ("show arp | no-more", "arp"),
    ("show ip bgp summary | no-more", "bgp"),
    ("show mac address-table | no-more", "mac_table"),
    ("show vlan brief | no-more", "vlans"),
]


def _topo_collect_device(dev):
    """SSH to a single device and collect topology-relevant CLI outputs."""
    hostname = dev["hostname"].split(".")[0].lower()
    ip = dev.get("ip", "")
    dtype = dev.get("dtype", "junos")
    port = dev.get("port", 22)
    result = {"hostname": hostname, "ip": ip, "dtype": dtype, "role": dev.get("role", ""),
              "outputs": {}, "error": None}
    cmds = _LIVE_TOPO_CMDS_EOS if dtype == "eos" else _LIVE_TOPO_CMDS_JUNOS

    ssh = paramiko.SSHClient()
    apply_ssh_policy(ssh)
    try:
        _ssh_connect(ssh, ip, port=port)
        for cmd, key in cmds:
            try:
                stdin, stdout, stderr = ssh.exec_command(cmd, timeout=20)
                result["outputs"][key] = stdout.read().decode("utf-8", errors="replace").strip()[:8000]
            except Exception:
                result["outputs"][key] = ""
    except Exception as e:
        result["error"] = f"SSH failed: {e}"
    finally:
        try:
            ssh.close()
        except Exception:
            pass
    return result


def _topo_parse_lldp_junos(output):
    """Parse Junos 'show lldp neighbors' into list of {local_iface, remote_port, remote_host}."""
    neighbors = []
    # Skip if output contains syntax error (e.g. SRX doesn't support LLDP)
    if "syntax error" in output.lower() or "unknown command" in output.lower():
        return neighbors
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("Local Interface") or line.startswith("{"):
            continue
        parts = line.split()
        if len(parts) >= 4:
            local_iface = parts[0]
            # Validate that local_iface looks like a real interface name
            if not any(local_iface.startswith(p) for p in ("xe-", "ge-", "et-", "em", "ae", "irb", "lo")):
                continue
            parent_iface = parts[1] if parts[1] != "-" else None
            # System Name is the last field (may be absent)
            remote_host = parts[-1] if len(parts) >= 6 else ""
            remote_port = parts[3] if len(parts) >= 5 else parts[2]
            neighbors.append({
                "local_iface": local_iface,
                "parent_iface": parent_iface,
                "remote_port": remote_port,
                "remote_host": remote_host.split(".")[0].lower() if remote_host else "",
            })
    return neighbors


def _topo_parse_lldp_eos(output):
    """Parse Arista EOS 'show lldp neighbors' into list."""
    neighbors = []
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line or "Neighbor" in line or "---" in line:
            continue
        parts = line.split()
        if len(parts) >= 4:
            neighbors.append({
                "local_iface": parts[0],
                "parent_iface": None,
                "remote_port": parts[-2] if len(parts) >= 5 else parts[1],
                "remote_host": parts[1].split(".")[0].lower() if len(parts) >= 5 else "",
            })
    return neighbors


def _topo_parse_descriptions(output, dtype="junos"):
    """Parse 'show interfaces descriptions' into dict {iface: {admin, link, description}}."""
    ifaces = {}
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("Interface") or line.startswith("{") or line.startswith("---"):
            continue
        parts = line.split(None, 3)
        if len(parts) >= 3:
            iface = parts[0]
            admin = parts[1].lower()
            link = parts[2].lower()
            desc = parts[3].strip() if len(parts) > 3 else ""
            ifaces[iface] = {"admin": admin, "link": link, "description": desc}
    return ifaces


def _topo_parse_terse_junos(output):
    """Parse Junos 'show interfaces terse' to get interface status and AE membership."""
    ifaces = {}
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("Interface") or line.startswith("{"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            iface = parts[0]
            admin = parts[1].lower()
            link = parts[2].lower()
            proto = parts[3] if len(parts) > 3 else ""
            ae_member = ""
            if "aenet" in line and "-->" in line:
                ae_member = line.split("-->")[1].strip().split(".")[0]
            ifaces[iface] = {"admin": admin, "link": link, "proto": proto, "ae_member": ae_member}
    return ifaces


def _topo_parse_lacp_junos(output):
    """Parse Junos 'show lacp interfaces' to get LAG member info."""
    lags = {}
    current_ae = None
    for line in output.strip().split("\n"):
        line = line.strip()
        if line.startswith("Aggregated interface:"):
            current_ae = line.split(":")[1].strip()
            if current_ae not in lags:
                lags[current_ae] = {"members": [], "all_up": True}
        elif current_ae and line and not line.startswith("LACP"):
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "Actor":
                member_iface = parts[0]
                lags[current_ae]["members"].append(member_iface)
    return lags


def _topo_parse_arp(output, dtype="junos"):
    """Parse ARP table into list of {ip, mac, interface, hostname}.
    Junos: 'show arp no-resolve'  EOS: 'show arp'"""
    entries = []
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line or "Address" in line and "MAC" in line:
            continue
        if line.startswith("{") or line.startswith("Total"):
            continue
        parts = line.split()
        if dtype == "eos":
            # EOS format: Address  Age  MAC  Intf
            if len(parts) >= 4:
                ip, _age, mac, iface = parts[0], parts[1], parts[2], parts[3]
                entries.append({"ip": ip, "mac": mac, "interface": iface, "hostname": ""})
        else:
            # Junos format: MAC  Address  Name  Interface  Flags
            if len(parts) >= 4:
                mac, ip = parts[0], parts[1]
                hostname = parts[2] if len(parts) >= 5 else ""
                iface = parts[3] if len(parts) >= 5 else parts[2]
                entries.append({"ip": ip, "mac": mac, "interface": iface,
                                "hostname": hostname.split(".")[0].lower() if hostname else ""})
    return entries


def _topo_parse_cluster(output):
    """Parse Junos 'show chassis cluster status' to discover HA peer.
    Returns dict: {cluster_id, node0_status, node1_status, redundancy_groups}."""
    result = {"cluster_id": None, "nodes": {}, "rg_count": 0}
    if "error" in output.lower() or "not configured" in output.lower() or not output.strip():
        return result
    for line in output.strip().split("\n"):
        line = line.strip()
        if line.startswith("Cluster ID:"):
            result["cluster_id"] = line.split(":")[1].strip()
        elif line.startswith("Redundancy group:"):
            result["rg_count"] += 1
        elif line.startswith("node"):
            parts = line.split()
            if len(parts) >= 3:
                node_id = parts[0]  # "node0" or "node1"
                status = parts[2]   # "primary" or "secondary"
                result["nodes"][node_id] = status
    return result


def _topo_parse_bgp_summary(output, dtype="junos"):
    """Parse BGP summary to discover BGP neighbors.
    Returns list of {peer_ip, peer_as, state}."""
    peers = []
    if "not running" in output.lower() or "not configured" in output.lower():
        return peers
    if "syntax error" in output.lower():
        return peers
    for line in output.strip().split("\n"):
        # Skip indented continuation lines (Junos inet.0: prefix counts)
        if line.startswith("  ") or line.startswith("\t"):
            continue
        line = line.strip()
        if not line or "Neighbor" in line or "---" in line or line.startswith("{"):
            continue
        if line.startswith("Groups") or line.startswith("Peer") or line.startswith("Table"):
            continue
        if line.startswith("Threading") or line.startswith("Default") or line.startswith("inet"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            peer_ip = parts[0]
            # Validate it looks like an IP address (v4 or v6)
            if not peer_ip[0].isdigit() and not peer_ip.startswith("2"):
                continue
            if dtype == "eos":
                # EOS: Neighbor  V  AS  MsgRcvd  MsgSent  InQ  OutQ  Up/Down  State/PfxRcd
                peer_as = parts[2] if len(parts) >= 3 else ""
                state = parts[-1] if len(parts) >= 9 else "unknown"
            else:
                # Junos: Peer  AS  InPkt  OutPkt  OutQ  Flaps  Last Up/Dn  State|#Active/Received/Accepted/Damped...
                peer_as = parts[1] if len(parts) >= 2 else ""
                state = parts[-1] if len(parts) >= 8 else "unknown"
            is_up = state.isdigit() or "establ" in state.lower()
            peers.append({"peer_ip": peer_ip, "peer_as": peer_as,
                          "state": "up" if is_up else state.lower()})
    return peers


def _topo_parse_mac_table(output, dtype="junos"):
    """Parse MAC address table to count MACs per interface.
    Returns dict {interface: mac_count}."""
    iface_macs = {}
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line or "MAC" in line and ("address" in line.lower() or "Address" in line):
            continue
        if line.startswith("{") or line.startswith("Total") or line.startswith("Ethernet"):
            continue
        if line.startswith("Routing instance") or line.startswith("Vlan") or "---" in line:
            continue
        parts = line.split()
        if dtype == "eos":
            # EOS: Vlan  Mac  Type  Ports
            if len(parts) >= 4:
                iface = parts[-1]
                iface_macs[iface] = iface_macs.get(iface, 0) + 1
        else:
            # Junos brief: Vlan  MAC  flags  Age  Logical-iface  NH  RTR
            if len(parts) >= 5:
                iface = parts[4].split(".")[0]  # strip .0 from ae12.0
                iface_macs[iface] = iface_macs.get(iface, 0) + 1
    return iface_macs


def _topo_classify_node(name, desc="", role=""):
    """Classify a node by its name/description pattern into a role."""
    name_l = name.lower()
    desc_l = desc.lower()
    if any(x in name_l for x in ("-fw-", "firewall")):
        return "firewall"
    if any(x in name_l for x in ("-rt-", "router")):
        return "router"
    if any(x in name_l for x in ("-sw-",)):
        return "switch"
    if any(x in name_l for x in ("-gw-", "gateway", "infra")):
        return "gateway"
    if any(x in name_l for x in ("-con-", "console")):
        return "console"
    if "isp" in desc_l or "wan" in desc_l:
        return "isp"
    if any(x in name_l for x in ("-aci", "-srv-", "-app-", "-db-", "-ntw-")):
        return "server"
    if "ipmi" in desc_l or "ipmi" in name_l:
        return "ipmi"
    if "pxe" in desc_l:
        return "pxe"
    if "storage" in desc_l or "stor" in name_l:
        return "storage"
    if "dr" in desc_l.split("-")[-1:] or "-drc" in name_l or "-dr-" in name_l:
        return "dr"
    # Server/compute clusters: psql, elk, edr, vz, per, fts, ahs, arp, etc.
    if any(x in name_l for x in ("-psql", "-elk-", "-edr-", "-vz-", "-per-",
                                  "-fts-", "-ahs", "-arp", "-iss-", "-cl0",
                                  "-mon-", "-bkp-", "-nfs-", "-dns-", "-log-",
                                  "-web-", "-api-", "-mgmt-", "-ctl-")):
        return "server"
    if role:
        return role
    return "server"  # default inferred nodes to server (they come from descriptions)


def _topo_iface_speed(iface_name):
    """Estimate interface speed from name prefix."""
    ifl = iface_name.lower()
    if ifl.startswith("et-") or ifl.startswith("et0"):
        return "100g"
    if ifl.startswith("xe-") or ifl.startswith("xe0"):
        return "10g"
    if ifl.startswith("ge-") or ifl.startswith("ge0"):
        return "1g"
    if ifl.startswith("ae") or ifl.startswith("po"):
        return "lag"
    return "unknown"


def _topo_parse_vlans_junos(vlans_brief, vlans_detail="", vlans_config=""):
    """Parse Junos 'show vlans' into VLAN data, enriched with config descriptions.
    Handles two output formats:
      Format A (brief, single-line): VLAN-100  100  ae0.0*, ae12.0*
      Format B (multi-line with routing instance):
        default-switch  vlan10  10
                                   ae10.0*
                                   ae11.0*
    vlans_config: 'show configuration vlans | display set' output for descriptions.
    Returns {vlan_id: {name, tag, interfaces: [iface, ...]}}."""
    vlans = {}
    current_tag = None  # track current VLAN for continuation lines

    for line in vlans_brief.strip().split("\n"):
        raw = line
        stripped = line.strip()
        if not stripped or stripped.startswith("Routing instance") or ("Name" in stripped and "Tag" in stripped):
            continue
        if stripped.startswith("{") or "---" in stripped or "error" in stripped.lower():
            continue

        # Check if this is a continuation line (heavily indented, single interface token)
        # Continuation lines start with lots of whitespace and contain a single interface
        leading_spaces = len(raw) - len(raw.lstrip())
        parts = stripped.split()

        if leading_spaces >= 20 and len(parts) <= 2 and current_tag is not None:
            # Continuation line — interface belonging to current VLAN
            for tok in parts:
                tok = tok.strip().rstrip("*")
                if tok and any(tok.startswith(p) for p in ("xe-", "ge-", "et-", "ae", "irb", "me", "po")):
                    iface = tok.split(".")[0]
                    if current_tag in vlans and iface not in vlans[current_tag]["interfaces"]:
                        vlans[current_tag]["interfaces"].append(iface)
            continue

        # VLAN header line — find the tag (a numeric token)
        # Format A: name  tag  [iface, iface, ...]
        # Format B: routing-instance  name  tag  [iface ...]
        tag_int = None
        name = ""
        ifaces = []
        for i, p in enumerate(parts):
            if p.isdigit() and int(p) < 4096:
                tag_int = int(p)
                # Name is the token just before the tag
                name = parts[i - 1] if i > 0 else ""
                # Remaining tokens after tag are interfaces
                rest = " ".join(parts[i + 1:])
                if rest:
                    for tok in rest.replace(",", " ").split():
                        tok = tok.strip().rstrip("*")
                        if tok:
                            ifaces.append(tok.split(".")[0])
                break

        if tag_int is not None:
            current_tag = tag_int
            vlans[tag_int] = {"name": name, "tag": tag_int, "interfaces": list(set(ifaces))}
        else:
            # Unrecognized line — might be a continuation with interface tokens
            if current_tag is not None:
                for tok in parts:
                    tok = tok.strip().rstrip("*")
                    if any(tok.startswith(p) for p in ("xe-", "ge-", "et-", "ae", "irb", "me", "po")):
                        iface = tok.split(".")[0]
                        if current_tag in vlans and iface not in vlans[current_tag]["interfaces"]:
                            vlans[current_tag]["interfaces"].append(iface)

    # Enrich from extensive output if available (captures tagged/untagged members)
    if vlans_detail.strip():
        current_tag = None
        current_name = ""
        current_ifaces = []
        for line in vlans_detail.strip().split("\n"):
            l = line.strip()
            if l.startswith("VLAN:") or (l and not l.startswith(" ") and ":" not in l and l.split()[0].isalpha()):
                # Save previous
                if current_tag is not None and current_tag not in vlans:
                    vlans[current_tag] = {"name": current_name, "tag": current_tag, "interfaces": list(set(current_ifaces))}
                elif current_tag is not None and current_ifaces:
                    existing = vlans.get(current_tag, {}).get("interfaces", [])
                    vlans[current_tag]["interfaces"] = list(set(existing + current_ifaces))
                current_tag = None
                current_name = ""
                current_ifaces = []
            if "Tag:" in l or "802.1Q Tag:" in l:
                m = re.search(r"(\d+)", l.split("Tag:")[-1])
                if m:
                    current_tag = int(m.group(1))
            if "VLAN:" in l:
                current_name = l.split("VLAN:")[-1].strip().split(",")[0]
            if "Interface:" in l:
                iface = l.split("Interface:")[-1].strip().split(",")[0].split(".")[0]
                if iface:
                    current_ifaces.append(iface)
            # Tagged/Untagged interface lines
            if ("Tagged" in l or "Untagged" in l) and "interface" in l.lower():
                for tok in l.replace(",", " ").split():
                    tok = tok.strip().rstrip("*")
                    if any(tok.startswith(p) for p in ("xe-", "ge-", "et-", "ae", "irb")):
                        current_ifaces.append(tok.split(".")[0])
        # Last entry
        if current_tag is not None:
            if current_tag not in vlans:
                vlans[current_tag] = {"name": current_name, "tag": current_tag, "interfaces": list(set(current_ifaces))}
            elif current_ifaces:
                existing = vlans.get(current_tag, {}).get("interfaces", [])
                vlans[current_tag]["interfaces"] = list(set(existing + current_ifaces))

    # Enrich names from 'show configuration vlans | display set' output
    # Lines like: set vlans vlan10 description storage_wan
    #             set vlans vlan10 vlan-id 10
    if vlans_config and vlans_config.strip():
        cfg_descs = {}   # vlan_obj_name -> description
        cfg_ids = {}     # vlan_obj_name -> vlan-id (int)
        for line in vlans_config.strip().split("\n"):
            line = line.strip()
            if not line.startswith("set vlans "):
                continue
            parts = line.split()
            # set vlans <name> description <desc>
            # set vlans <name> vlan-id <id>
            if len(parts) >= 4:
                obj_name = parts[2]
                if len(parts) >= 5 and parts[3] == "description":
                    cfg_descs[obj_name] = " ".join(parts[4:])
                elif len(parts) >= 5 and parts[3] == "vlan-id" and parts[4].isdigit():
                    cfg_ids[obj_name] = int(parts[4])
        # Map vlan-id -> description
        for obj_name, tag in cfg_ids.items():
            if tag in vlans and obj_name in cfg_descs:
                vlans[tag]["name"] = cfg_descs[obj_name]

    return vlans


def _topo_parse_vlans_eos(vlans_brief):
    """Parse Arista EOS 'show vlan brief' into VLAN data.
    Returns {vlan_id: {name, tag, interfaces: [iface, ...]}}."""
    vlans = {}
    # EOS format:
    # VLAN  Name                 Status    Ports
    # ----  ----                 ------    -----
    # 1     default              active    Et1, Et2, Po1
    # 100   MGMT                 active    Et3, Et4
    for line in vlans_brief.strip().split("\n"):
        line = line.strip()
        if not line or "---" in line or line.startswith("VLAN") and "Name" in line:
            continue
        if "error" in line.lower() or line.startswith("{"):
            continue
        parts = line.split(None, 3)
        if len(parts) < 2:
            continue
        if not parts[0].isdigit():
            continue
        tag = int(parts[0])
        name = parts[1] if len(parts) >= 2 else ""
        ifaces = []
        if len(parts) >= 4:
            port_str = parts[3] if parts[2] in ("active", "suspend", "act/lshut") else parts[2]
            for tok in port_str.replace(",", " ").split():
                tok = tok.strip()
                if tok:
                    # Normalize EOS short names: Et1 -> Ethernet1, Po1 -> Port-Channel1
                    ifaces.append(tok)
        vlans[tag] = {"name": name, "tag": tag, "interfaces": ifaces}
    return vlans


def _topo_parse_vlans_from_mac(mac_output, dtype="junos"):
    """Parse MAC table to get VLAN-to-interface mapping as a fallback.
    Returns {vlan_name_or_id: set(interfaces)}."""
    vlan_ifaces = {}
    for line in mac_output.strip().split("\n"):
        line = line.strip()
        if not line or "MAC" in line or "---" in line or line.startswith("{"):
            continue
        if line.startswith("Routing instance") or line.startswith("Total") or line.startswith("Ethernet"):
            continue
        parts = line.split()
        if dtype == "eos":
            if len(parts) >= 4 and parts[0].isdigit():
                vlan_id = parts[0]
                iface = parts[-1]
                vlan_ifaces.setdefault(vlan_id, set()).add(iface)
        else:
            # Junos brief: VlanName  MAC  flags  Age  iface  NH  RTR
            if len(parts) >= 5:
                vlan_name = parts[0]
                iface = parts[4].split(".")[0]
                vlan_ifaces.setdefault(vlan_name, set()).add(iface)
    return {k: list(v) for k, v in vlan_ifaces.items()}


def _topo_build_graph(site, collected_devices, all_site_devices):
    """Build a topology graph from collected device data.
    Returns {nodes: [...], links: [...], stats: {...}}"""
    nodes = {}  # id -> node dict
    links = []  # list of link dicts
    link_keys = set()  # dedup
    # VLAN tracking: per-device iface→vlans map + site-wide VLAN inventory
    device_vlans = {}   # hostname -> {vlan_tag: {name, tag, interfaces}}
    device_iface_vlans = {}  # hostname -> {iface: [vlan_tag, ...]}
    site_vlans = {}     # vlan_tag -> {name, tag, devices: [hostname, ...], interfaces_count}

    # First pass: add all managed devices as nodes
    for dev in collected_devices:
        hostname = dev["hostname"]
        desc_data = _topo_parse_descriptions(dev["outputs"].get("descriptions", ""), dev["dtype"])
        model = ""
        for line in (dev["outputs"].get("hardware", "") + "\n" + dev["outputs"].get("model", "")).split("\n"):
            if line.strip() and not line.strip().startswith("{"):
                model = line.strip()
                break

        # Count interfaces
        up_count = sum(1 for v in desc_data.values() if v["link"] == "up")
        down_count = sum(1 for v in desc_data.values() if v["link"] == "down")
        total = len(desc_data)

        # Parse VLANs
        dtype = dev["dtype"]
        vlans_raw = dev["outputs"].get("vlans", "")
        vlans_detail = dev["outputs"].get("vlans_detail", "")
        if dtype == "eos":
            dev_vlans = _topo_parse_vlans_eos(vlans_raw) if vlans_raw else {}
        else:
            vlans_config = dev["outputs"].get("vlans_config", "")
            dev_vlans = _topo_parse_vlans_junos(vlans_raw, vlans_detail, vlans_config) if vlans_raw else {}
        device_vlans[hostname] = dev_vlans

        # Build interface → VLAN list mapping
        iface_vlan_map = {}
        for tag, vinfo in dev_vlans.items():
            for iface in vinfo.get("interfaces", []):
                iface_vlan_map.setdefault(iface, []).append(tag)
            # Aggregate into site-wide VLAN inventory
            if tag not in site_vlans:
                site_vlans[tag] = {"name": vinfo["name"], "tag": tag, "devices": [], "interfaces_count": 0}
            if hostname not in site_vlans[tag]["devices"]:
                site_vlans[tag]["devices"].append(hostname)
            site_vlans[tag]["interfaces_count"] += len(vinfo.get("interfaces", []))
        device_iface_vlans[hostname] = iface_vlan_map

        role = _topo_classify_node(hostname, role=dev.get("role", ""))
        nodes[hostname] = {
            "id": hostname, "label": hostname.upper(), "type": "managed",
            "role": role, "model": model, "ip": dev["ip"], "dtype": dev["dtype"],
            "interfaces_up": up_count, "interfaces_down": down_count,
            "interfaces_total": total, "error": dev.get("error"),
            "zone_descriptions": [],  # filled below for firewalls
            "vlan_count": len(dev_vlans),
        }

        # For firewalls — extract zone/reth info from descriptions
        if role == "firewall":
            zones = []
            for iface, info in desc_data.items():
                if iface.startswith("reth") and info["description"]:
                    zones.append({"interface": iface, "description": info["description"],
                                  "status": info["link"]})
            nodes[hostname]["zone_descriptions"] = zones

    # Second pass: build links from LLDP + descriptions
    for dev in collected_devices:
        hostname = dev["hostname"]
        dtype = dev["dtype"]

        # Parse LLDP neighbors
        lldp_output = dev["outputs"].get("lldp", "")
        if dtype == "eos":
            lldp_neighbors = _topo_parse_lldp_eos(lldp_output)
        else:
            lldp_neighbors = _topo_parse_lldp_junos(lldp_output)

        # Parse interface descriptions
        desc_data = _topo_parse_descriptions(dev["outputs"].get("descriptions", ""), dtype)

        # Parse terse for AE membership
        terse_data = {}
        if dtype == "junos":
            terse_data = _topo_parse_terse_junos(dev["outputs"].get("terse", ""))

        # Parse LACP
        lacp_data = {}
        if dtype == "junos":
            lacp_data = _topo_parse_lacp_junos(dev["outputs"].get("lacp", ""))

        # Process LLDP neighbors — these are the most reliable links
        for nbr in lldp_neighbors:
            remote = nbr["remote_host"]
            if not remote:
                continue

            local_iface = nbr.get("parent_iface") or nbr["local_iface"]
            remote_port = nbr["remote_port"]
            speed = _topo_iface_speed(nbr["local_iface"])

            # Get description for this interface
            desc = ""
            if local_iface in desc_data:
                desc = desc_data[local_iface]["description"]
            elif nbr["local_iface"] in desc_data:
                desc = desc_data[nbr["local_iface"]]["description"]

            # Get link status
            link_status = "up"
            if local_iface in desc_data and desc_data[local_iface]["link"] != "up":
                link_status = "down"

            # Ensure remote node exists
            if remote not in nodes:
                remote_role = _topo_classify_node(remote, desc)
                nodes[remote] = {
                    "id": remote, "label": remote.upper(), "type": "discovered",
                    "role": remote_role, "model": "", "ip": "", "dtype": "",
                    "interfaces_up": 0, "interfaces_down": 0, "interfaces_total": 0,
                    "error": None, "zone_descriptions": [],
                }

            # LAG info
            lag_info = ""
            if local_iface.startswith("ae") and local_iface in lacp_data:
                members = lacp_data[local_iface]["members"]
                lag_info = f"LAG {local_iface} ({len(members)} members: {', '.join(members)})"
            elif local_iface.startswith("ae"):
                lag_info = f"LAG {local_iface}"

            # VLAN info for this link
            link_vlans = sorted(set(
                device_iface_vlans.get(hostname, {}).get(local_iface, []) +
                device_iface_vlans.get(hostname, {}).get(nbr["local_iface"], [])
            ))

            # Dedup link
            link_key = tuple(sorted([f"{hostname}:{local_iface}", f"{remote}:{remote_port}"]))
            if link_key not in link_keys:
                link_keys.add(link_key)
                links.append({
                    "source": hostname, "target": remote,
                    "source_port": local_iface, "target_port": remote_port,
                    "speed": speed, "status": link_status, "description": desc,
                    "lag": lag_info, "method": "lldp",
                    "vlans": link_vlans,
                })

        # Process interface descriptions for devices NOT found via LLDP
        # (e.g., firewalls that don't run LLDP, ISP links)
        lldp_ifaces = set()
        for nbr in lldp_neighbors:
            lldp_ifaces.add(nbr.get("parent_iface") or nbr["local_iface"])
            lldp_ifaces.add(nbr["local_iface"])

        # For firewalls, collect reth/zone descriptions but DON'T create nodes for them
        # (they are virtual zones, not physical devices)
        _fw_zone_prefixes = set()
        if nodes.get(hostname, {}).get("role") == "firewall":
            for iface, info in desc_data.items():
                if iface.startswith("reth") or iface.startswith("ge-"):
                    d = info["description"].lower()
                    # Zone names like "uk-lon-fw-20-fab0", "uk-lon-fw-20-wan" are NOT devices
                    if "-fw-" in d or d.endswith(("-fab0", "-fab1", "-wan", "-management")):
                        _fw_zone_prefixes.add(d)

        for iface, info in desc_data.items():
            if iface in lldp_ifaces:
                continue
            # Skip sub-interfaces, management, vlan, lo, irb etc
            if "." in iface or iface.startswith(("vlan", "lo", "irb", "em", "me", "vme",
                                                  "fxp", "bme", "jsrv", "pfe", "pfh",
                                                  "vcp", "pip", "gr-", "ip-")):
                continue
            # Skip reth interfaces on firewalls (they are zone interfaces, not device links)
            if iface.startswith("reth"):
                continue
            desc = info["description"]
            if not desc:
                continue
            # Try to identify a remote device from description
            desc_lower = desc.lower()
            # Skip firewall zone descriptions (not real devices)
            if desc_lower in _fw_zone_prefixes:
                continue
            # Check if description matches a known device pattern
            remote = ""
            # Common patterns: "uk-lon-dist-01", "uk-lon-ISP", "uk-lon-aci01-01"
            site_prefix = site.lower() + "-"
            if desc_lower.startswith(site_prefix) or desc_lower.startswith(hostname.split("-")[0] + "-"):
                remote = desc_lower.split()[0]  # take first word as hostname

            if not remote:
                # ISP links
                if "isp" in desc_lower:
                    remote = f"{site.lower()}-isp"

            if not remote or remote == hostname:
                continue
            # Skip zone-like names that contain the firewall's own name
            if "-fw-" in remote and remote != hostname:
                # Check if this is a zone description like "uk-lon-fw-20-wan"
                # vs a real device like "uk-lon-fw-20b"
                parts = remote.split("-")
                if len(parts) > 3 and not parts[-1][-1].isalpha():
                    continue  # skip zone names
                if any(remote.endswith(s) for s in ("-fab0", "-fab1", "-wan", "-management", "-acc", "-storage", "-dr", "-pxe", "-ipmi")):
                    continue

            # Dedup — check if we already have this link from LLDP
            link_key = tuple(sorted([f"{hostname}:{iface}", f"{remote}:"]))
            already_linked = any(
                (l["source"] == hostname and l["target"] == remote) or
                (l["source"] == remote and l["target"] == hostname)
                for l in links if l.get("source_port") == iface or l.get("description") == desc
            )
            if already_linked or link_key in link_keys:
                continue

            # Ensure remote node
            if remote not in nodes:
                remote_role = _topo_classify_node(remote, desc)
                nodes[remote] = {
                    "id": remote, "label": remote.upper(), "type": "inferred",
                    "role": remote_role, "model": "", "ip": "", "dtype": "",
                    "interfaces_up": 0, "interfaces_down": 0, "interfaces_total": 0,
                    "error": None, "zone_descriptions": [],
                }

            speed = _topo_iface_speed(iface)
            link_vlans = sorted(device_iface_vlans.get(hostname, {}).get(iface, []))
            link_keys.add(link_key)
            links.append({
                "source": hostname, "target": remote,
                "source_port": iface, "target_port": "",
                "speed": speed, "status": info["link"], "description": desc,
                "lag": f"LAG {iface}" if iface.startswith("ae") else "",
                "method": "description", "vlans": link_vlans,
            })

    # For firewall zone descriptions, also create links from firewall to its zones
    # if those zones are unique enough to be nodes (e.g., "uk-lon-fw-20-wan" → ISP cloud)
    for nid, node in list(nodes.items()):
        if node["role"] == "firewall" and node["zone_descriptions"]:
            for zone in node["zone_descriptions"]:
                desc = zone["description"]
                desc_l = desc.lower()
                # Map zone descriptions to meaningful remote nodes
                if "wan" in desc_l:
                    remote = f"{site.lower()}-wan"
                    if remote not in nodes:
                        nodes[remote] = {
                            "id": remote, "label": "WAN / ISP", "type": "cloud",
                            "role": "isp", "model": "", "ip": "", "dtype": "",
                            "interfaces_up": 0, "interfaces_down": 0, "interfaces_total": 0,
                            "error": None, "zone_descriptions": [],
                        }
                    lk = tuple(sorted([f"{nid}:{zone['interface']}", f"{remote}:wan"]))
                    if lk not in link_keys:
                        link_keys.add(lk)
                        links.append({
                            "source": nid, "target": remote,
                            "source_port": zone["interface"], "target_port": "WAN",
                            "speed": _topo_iface_speed(zone["interface"]), "status": zone["status"],
                            "description": desc, "lag": "", "method": "zone", "vlans": [],
                        })

    # ── Non-LLDP Discovery Methods ──────────────────────────────────────────

    # Build lookup: IP -> hostname (for managed devices)
    ip_to_hostname = {}
    for dev in collected_devices:
        if dev["ip"]:
            ip_to_hostname[dev["ip"]] = dev["hostname"]

    _ebgp_pending = []  # collect eBGP stats per device for consolidation

    for dev in collected_devices:
        hostname = dev["hostname"]
        dtype = dev["dtype"]

        # 1) Chassis Cluster — discover HA peer firewalls (Junos SRX)
        cluster_output = dev["outputs"].get("cluster", "")
        if cluster_output:
            cluster = _topo_parse_cluster(cluster_output)
            if cluster["cluster_id"] and len(cluster["nodes"]) == 2:
                # This device is in a cluster — figure out the peer name
                # Convention: uk-lon-fw-20a = node0, uk-lon-fw-20b = node1
                base = hostname.rstrip("ab")
                if hostname.endswith("a"):
                    peer = base + "b"
                elif hostname.endswith("b"):
                    peer = base + "a"
                else:
                    peer = hostname + "-peer"

                if peer not in nodes:
                    # Peer might not be in our inventory (only primary is managed)
                    nodes[peer] = {
                        "id": peer, "label": peer.upper(), "type": "inferred",
                        "role": "firewall", "model": "", "ip": "", "dtype": dtype,
                        "interfaces_up": 0, "interfaces_down": 0, "interfaces_total": 0,
                        "error": None, "zone_descriptions": [],
                    }

                lk = tuple(sorted([f"{hostname}:cluster", f"{peer}:cluster"]))
                if lk not in link_keys:
                    link_keys.add(lk)
                    # Determine cluster status
                    my_status = "primary"
                    for nid, st in cluster["nodes"].items():
                        if st == "secondary":
                            pass  # peer is secondary
                    links.append({
                        "source": hostname, "target": peer,
                        "source_port": "fab0/fab1", "target_port": "fab0/fab1",
                        "speed": "lag", "status": "up",
                        "description": f"Chassis Cluster {cluster['cluster_id']} ({cluster['rg_count']} RGs)",
                        "lag": f"HA Cluster ID {cluster['cluster_id']}", "method": "cluster", "vlans": [],
                    })

        # 2) ARP-based discovery — match ARP hostnames to find inter-device links
        #    This is useful when LLDP is not configured
        arp_output = dev["outputs"].get("arp", "")
        if arp_output:
            arp_entries = _topo_parse_arp(arp_output, dtype)

            # Build a set of already-linked remote devices from LLDP + descriptions
            already_linked_remotes = set()
            for l in links:
                if l["source"] == hostname:
                    already_linked_remotes.add(l["target"])
                elif l["target"] == hostname:
                    already_linked_remotes.add(l["source"])

            # Group ARP entries by interface
            arp_by_iface = {}
            for entry in arp_entries:
                iface = entry["interface"].split(".")[0]  # strip .0
                arp_by_iface.setdefault(iface, []).append(entry)

            for iface, entries in arp_by_iface.items():
                # Skip internal/management interfaces
                if iface.startswith(("bme", "em", "fxp", "lo", "irb", "vme", "me")):
                    continue

                for entry in entries:
                    arp_host = entry["hostname"]
                    arp_ip = entry["ip"]

                    # Try to resolve IP to a known managed device
                    remote = ip_to_hostname.get(arp_ip, "")
                    if not remote and arp_host:
                        # Check if hostname matches a managed device
                        for nid in nodes:
                            if arp_host == nid or arp_host.startswith(nid.split(".")[0]):
                                remote = nid
                                break

                    if not remote or remote == hostname:
                        continue
                    if remote in already_linked_remotes:
                        continue

                    # Only create ARP-discovered links between managed/known devices
                    if remote not in nodes:
                        continue  # don't create nodes from ARP — too noisy

                    lk = tuple(sorted([f"{hostname}:{iface}", f"{remote}:arp"]))
                    if lk not in link_keys:
                        link_keys.add(lk)
                        already_linked_remotes.add(remote)
                        links.append({
                            "source": hostname, "target": remote,
                            "source_port": iface, "target_port": "",
                            "speed": _topo_iface_speed(iface), "status": "up",
                            "description": f"ARP: {arp_ip}",
                            "lag": f"LAG {iface}" if iface.startswith("ae") else "",
                            "method": "arp", "vlans": [],
                        })

        # 3) BGP neighbor discovery
        #    - iBGP peers that resolve to managed devices → individual links
        #    - eBGP peers → single summary cloud node per device
        bgp_output = dev["outputs"].get("bgp", "")
        if bgp_output:
            bgp_peers = _topo_parse_bgp_summary(bgp_output, dtype)
            ebgp_total = 0
            ebgp_up = 0
            ebgp_down = 0
            ebgp_ases = set()

            for peer in bgp_peers:
                peer_ip = peer["peer_ip"]
                peer_as = peer["peer_as"]

                # Try to resolve peer IP to a known managed device (iBGP)
                remote = ip_to_hostname.get(peer_ip, "")
                if not remote:
                    for nid, nd in nodes.items():
                        if nd.get("ip") == peer_ip:
                            remote = nid
                            break

                if remote and remote != hostname and remote in nodes:
                    # iBGP link to a managed device — create individual link
                    lk = tuple(sorted([f"{hostname}:bgp:{peer_ip}", f"{remote}:bgp"]))
                    if lk not in link_keys:
                        link_keys.add(lk)
                        links.append({
                            "source": hostname, "target": remote,
                            "source_port": "BGP", "target_port": "BGP",
                            "speed": "unknown",
                            "status": "up" if peer["state"] == "up" else "down",
                            "description": f"iBGP AS{peer_as} ({peer['state']})",
                            "lag": "", "method": "bgp", "vlans": [],
                        })
                else:
                    # eBGP peer — accumulate for summary
                    ebgp_total += 1
                    ebgp_ases.add(peer_as)
                    if peer["state"] == "up":
                        ebgp_up += 1
                    else:
                        ebgp_down += 1

            # Stash eBGP stats for consolidation after loop
            if ebgp_total > 0:
                _ebgp_pending.append({
                    "hostname": hostname, "total": ebgp_total,
                    "up": ebgp_up, "down": ebgp_down,
                    "ases": ebgp_ases,
                })

            # Annotate managed node with BGP stats
            if hostname in nodes and bgp_peers:
                nodes[hostname]["bgp_peers"] = len(bgp_peers)
                nodes[hostname]["bgp_up"] = sum(1 for p in bgp_peers if p["state"] == "up")
                nodes[hostname]["bgp_down"] = sum(1 for p in bgp_peers if p["state"] != "up")

        # 4) MAC table — enrich managed nodes with host count per interface
        mac_output = dev["outputs"].get("mac_table", "")
        if mac_output:
            mac_counts = _topo_parse_mac_table(mac_output, dtype)
            if hostname in nodes:
                nodes[hostname]["mac_counts"] = mac_counts
                nodes[hostname]["total_macs"] = sum(mac_counts.values())

    # ── eBGP Consolidation ──────────────────────────────────────────────────
    # Devices with eBGP peers to a single AS → share one cloud node per AS
    # Devices peering with multiple ASes → get their own cloud node
    _as_to_devices = {}  # frozenset(ases) -> [entries]
    for entry in _ebgp_pending:
        key = frozenset(entry["ases"])
        if key not in _as_to_devices:
            _as_to_devices[key] = []
        _as_to_devices[key].append(entry)

    for as_set, entries in _as_to_devices.items():
        if len(as_set) == 1 and len(entries) >= 2:
            # Multiple devices share a single eBGP AS → one shared node
            the_as = next(iter(as_set))
            total_peers = sum(e["total"] for e in entries)
            total_up = sum(e["up"] for e in entries)
            total_down = sum(e["down"] for e in entries)
            ebgp_node_id = f"{site.lower()}-ebgp-as{the_as}"
            nodes[ebgp_node_id] = {
                "id": ebgp_node_id,
                "label": f"eBGP AS{the_as} ({total_peers} peers)",
                "type": "cloud", "role": "isp",
                "model": "", "ip": "", "dtype": "",
                "interfaces_up": total_up, "interfaces_down": total_down,
                "interfaces_total": total_peers, "error": None,
                "zone_descriptions": [],
            }
            for entry in entries:
                status = "up" if entry["up"] > 0 else "down"
                lk = tuple(sorted([f"{entry['hostname']}:ebgp", f"{ebgp_node_id}:bgp"]))
                if lk not in link_keys:
                    link_keys.add(lk)
                    links.append({
                        "source": entry["hostname"], "target": ebgp_node_id,
                        "source_port": "BGP", "target_port": "BGP",
                        "speed": "unknown", "status": status,
                        "description": f"eBGP AS{the_as} ({entry['up']}↑ {entry['down']}↓ / {entry['total']} peers)",
                        "lag": "", "method": "bgp", "vlans": [],
                    })
        else:
            # Unique AS set per device → individual cloud node
            for entry in entries:
                ebgp_node_id = f"{entry['hostname']}-ebgp"
                as_str = ", ".join(sorted(entry["ases"]))
                nodes[ebgp_node_id] = {
                    "id": ebgp_node_id,
                    "label": f"eBGP ({entry['total']} peers, {len(entry['ases'])} ASes)",
                    "type": "cloud", "role": "isp",
                    "model": "", "ip": "", "dtype": "",
                    "interfaces_up": entry["up"], "interfaces_down": entry["down"],
                    "interfaces_total": entry["total"], "error": None,
                    "zone_descriptions": [],
                }
                status = "up" if entry["up"] > 0 else "down"
                lk = tuple(sorted([f"{entry['hostname']}:ebgp", f"{ebgp_node_id}:bgp"]))
                if lk not in link_keys:
                    link_keys.add(lk)
                    links.append({
                        "source": entry["hostname"], "target": ebgp_node_id,
                        "source_port": "BGP", "target_port": "BGP",
                        "speed": "unknown", "status": status,
                        "description": f"eBGP: {entry['up']}↑ {entry['down']}↓ / {entry['total']} peers across {len(entry['ases'])} ASes",
                        "lag": "", "method": "bgp", "vlans": [],
                    })

    # ── HLD-style consolidation: aggressive grouping + link bundling ──────
    import re as _re

    # 1) Group non-managed nodes by prefix (server groups)
    server_groups = {}
    for nid, node in list(nodes.items()):
        if node["role"] in ("server", "ipmi", "pxe", "storage", "dr", "unknown") and node["type"] != "managed":
            prefix = _re.sub(r'-(ipmi|pxe|stor|storage)$', '', nid)
            prefix = _re.sub(r'-\d+$', '', prefix)
            if prefix not in server_groups:
                server_groups[prefix] = []
            server_groups[prefix].append(nid)

    # 2) Also group lonely discovered/inferred nodes by their connected switch
    #    (nodes that only connect to one managed device → aggregate per switch)
    switch_children = {}  # managed_switch_id -> [child_node_ids]
    for nid, node in list(nodes.items()):
        if node["type"] in ("discovered", "inferred") and nid not in sum(server_groups.values(), []):
            # Find which managed devices this node connects to
            connected_managed = set()
            for l in links:
                s, t = l["source"], l["target"]
                if s == nid and t in nodes and nodes[t]["type"] == "managed":
                    connected_managed.add(t)
                elif t == nid and s in nodes and nodes[s]["type"] == "managed":
                    connected_managed.add(s)
            # If connected to exactly 1 managed switch → group under it
            if len(connected_managed) == 1:
                parent = next(iter(connected_managed))
                switch_children.setdefault(parent, []).append(nid)

    # Merge switch_children groups with server_groups
    for parent, children in switch_children.items():
        if len(children) >= 1:
            prefix = parent + "-endpoints"
            if prefix not in server_groups:
                server_groups[prefix] = []
            server_groups[prefix].extend(children)

    # Collapse server groups into single group nodes (even with 1 member for HLD cleanliness)
    group_map = {}  # old_id -> new_group_id
    for prefix, members in server_groups.items():
        # Remove duplicates
        members = list(dict.fromkeys(members))
        if len(members) < 1:
            continue
        # For single members, only group if they are inferred/discovered (not cloud/managed)
        if len(members) == 1:
            m = members[0]
            if m not in nodes or nodes[m]["type"] in ("managed", "cloud"):
                continue
        group_id = prefix + "-group"
        if len(members) == 1:
            group_label = nodes[members[0]]["label"] if members[0] in nodes else prefix.upper()
        else:
            group_label = f"{prefix.upper()}-* ({len(members)})"
        role = nodes[members[0]]["role"] if members[0] in nodes else "server"
        nodes[group_id] = {
            "id": group_id, "label": group_label, "type": "group",
            "role": role, "model": "", "ip": "", "dtype": "",
            "interfaces_up": 0, "interfaces_down": 0, "interfaces_total": len(members),
            "error": None, "zone_descriptions": [], "group_members": members,
        }
        for m in members:
            group_map[m] = group_id
            if m in nodes:
                del nodes[m]

    # Update links to point to group nodes
    regrouped_links = []
    for link in links:
        src = group_map.get(link["source"], link["source"])
        tgt = group_map.get(link["target"], link["target"])
        if src == tgt:
            continue
        link = dict(link)
        link["source"] = src
        link["target"] = tgt
        regrouped_links.append(link)
    links = regrouped_links

    # 3) HLD mega-grouping: merge all group/non-managed nodes that connect to
    #    the same single managed switch into one "Endpoints" mega-node per switch.
    #    This collapses 183 small groups into ~20 endpoint clusters.
    from collections import defaultdict as _dd
    sw_endpoints = _dd(list)  # managed_switch_id -> [group/node ids]
    for nid, node in list(nodes.items()):
        if node["type"] in ("group", "discovered", "inferred") and node.get("role") not in ("isp",):
            # Find which managed devices this node connects to
            connected_managed = set()
            for l in links:
                s, t = l["source"], l["target"]
                if s == nid and t in nodes and nodes[t]["type"] == "managed":
                    connected_managed.add(t)
                elif t == nid and s in nodes and nodes[s]["type"] == "managed":
                    connected_managed.add(s)
            if len(connected_managed) == 1:
                sw_endpoints[next(iter(connected_managed))].append(nid)

    mega_map = {}  # old_group_id -> mega_group_id
    for sw_id, ep_ids in sw_endpoints.items():
        if len(ep_ids) < 2:
            continue  # Only mega-group if >1 endpoint node per switch
        mega_id = sw_id + "-mega"
        # Collect all original members from sub-groups
        all_members = []
        for eid in ep_ids:
            if eid in nodes and nodes[eid]["type"] == "group":
                all_members.extend(nodes[eid].get("group_members", [eid]))
            else:
                all_members.append(eid)
        short = sw_id.upper()
        nodes[mega_id] = {
            "id": mega_id,
            "label": f"{short} Endpoints ({len(all_members)})",
            "type": "group", "role": "server",
            "model": "", "ip": "", "dtype": "",
            "interfaces_up": 0, "interfaces_down": 0,
            "interfaces_total": len(all_members),
            "error": None, "zone_descriptions": [],
            "group_members": all_members,
        }
        for eid in ep_ids:
            mega_map[eid] = mega_id
            if eid in nodes:
                del nodes[eid]

    # Update links for mega-groups
    if mega_map:
        mega_links = []
        for link in links:
            src = mega_map.get(link["source"], link["source"])
            tgt = mega_map.get(link["target"], link["target"])
            if src == tgt:
                continue
            link = dict(link)
            link["source"] = src
            link["target"] = tgt
            mega_links.append(link)
        links = mega_links

    # 4) Bundle parallel links between same node pair into a single HLD link
    #    Keeps the "best" method link and adds link_count + aggregated VLANs
    pair_links = _dd(list)
    for link in links:
        key = tuple(sorted([link["source"], link["target"]]))
        pair_links[key].append(link)

    _METHOD_PRIORITY = {"cluster": 0, "lldp": 1, "bgp": 2, "description": 3, "zone": 4, "arp": 5}
    bundled_links = []
    for key, plinks in pair_links.items():
        if len(plinks) == 1:
            plinks[0]["link_count"] = 1
            bundled_links.append(plinks[0])
        else:
            # Pick the best representative link (by method priority, then by having description)
            plinks.sort(key=lambda l: (_METHOD_PRIORITY.get(l["method"], 9), -len(l.get("description", ""))))
            best = dict(plinks[0])
            best["link_count"] = len(plinks)
            # Aggregate VLANs from all parallel links
            all_vlans = set()
            all_methods = set()
            has_lag = False
            for pl in plinks:
                all_vlans.update(pl.get("vlans", []))
                all_methods.add(pl["method"])
                if pl.get("lag"):
                    has_lag = True
            best["vlans"] = sorted(all_vlans)
            if len(plinks) > 1:
                best["description"] = f"{len(plinks)} links ({', '.join(sorted(all_methods))})"
            if has_lag and not best.get("lag"):
                best["lag"] = f"LAG ({len(plinks)} members)"
            bundled_links.append(best)
    links = bundled_links

    # Stats
    managed = sum(1 for n in nodes.values() if n["type"] == "managed")
    discovered = sum(1 for n in nodes.values() if n["type"] in ("discovered", "inferred", "cloud"))
    groups = sum(1 for n in nodes.values() if n["type"] == "group")
    lldp_links = sum(1 for l in links if l["method"] == "lldp")
    desc_links = sum(1 for l in links if l["method"] == "description")
    arp_links = sum(1 for l in links if l["method"] == "arp")
    bgp_links = sum(1 for l in links if l["method"] == "bgp")
    cluster_links = sum(1 for l in links if l["method"] == "cluster")
    zone_links = sum(1 for l in links if l["method"] == "zone")

    # Build sorted VLAN summary for the site (exclude VLAN 1/default, sort by device count desc)
    vlan_summary = []
    for tag in sorted(site_vlans.keys()):
        v = site_vlans[tag]
        if tag == 1 and v["name"].lower() == "default":
            continue  # skip default VLAN
        vlan_summary.append({
            "tag": tag, "name": v["name"],
            "devices": len(v["devices"]), "device_list": v["devices"][:10],
            "interfaces": v["interfaces_count"],
        })
    vlan_summary.sort(key=lambda x: (-x["devices"], x["tag"]))

    # Count links that carry VLANs
    vlan_links = sum(1 for l in links if l.get("vlans"))

    return {
        "nodes": list(nodes.values()),
        "links": links,
        "vlans": vlan_summary,
        "stats": {
            "managed_devices": managed,
            "discovered_devices": discovered,
            "server_groups": groups,
            "total_nodes": len(nodes),
            "total_links": len(links),
            "lldp_links": lldp_links,
            "description_links": desc_links,
            "arp_links": arp_links,
            "bgp_links": bgp_links,
            "cluster_links": cluster_links,
            "zone_links": zone_links,
            "vlan_count": len(vlan_summary),
            "vlan_links": vlan_links,
        },
    }


@app.route("/api/topology/live-sites", methods=["GET"])
def topology_live_sites():
    """List all sites available for live topology collection."""
    site_counts = {}
    for d in DEVICES:
        s = d.get("site", "").upper()
        if s:
            site_counts[s] = site_counts.get(s, 0) + 1
    sites = [{"site": s, "devices": c} for s, c in sorted(site_counts.items())]
    return jsonify({"success": True, "sites": sites})


@app.route("/api/topology/live/<site_code>", methods=["GET"])
def topology_live(site_code):
    """Build a live network topology for a site by SSH-ing to all devices and collecting
    LLDP neighbors, interface descriptions, LAG info, and interface status.
    Returns D3-compatible nodes + links."""
    import concurrent.futures as _cf

    site = site_code.upper()
    site_devs = [d for d in DEVICES if d.get("site", "").upper() == site]
    if not site_devs:
        return jsonify({"success": False, "error": f"No devices found for site {site}"}), 404

    # Collect from all devices in parallel
    collected = []
    errors = []
    with _cf.ThreadPoolExecutor(max_workers=min(len(site_devs), 10)) as pool:
        futures = {pool.submit(_topo_collect_device, d): d for d in site_devs}
        for f in _cf.as_completed(futures):
            try:
                result = f.result()
                collected.append(result)
                if result.get("error"):
                    errors.append({"hostname": result["hostname"], "error": result["error"]})
            except Exception as e:
                dev = futures[f]
                errors.append({"hostname": dev.get("hostname", "?"), "error": str(e)})

    # Build topology graph
    graph = _topo_build_graph(site, collected, site_devs)
    graph["success"] = True
    graph["site"] = site
    graph["devices_collected"] = len(collected)
    graph["errors"] = errors
    graph["timestamp"] = datetime.now().isoformat()
    return jsonify(graph)


# ══════════════════════════════════════════════════════════════════════════════
# NAPALM INTEGRATION — Structured network data collection
# ══════════════════════════════════════════════════════════════════════════════

def _napalm_new_job(job_type, site):
    job_id = f"{job_type}_{site}_{int(time.time())}"
    with _napalm_jobs_lock:
        _bounded_insert(_napalm_jobs, job_id, {
            "id": job_id, "type": job_type, "site": site,
            "status": "running", "progress": 0, "message": "Starting...",
            "result": None, "started": datetime.now().isoformat(),
        }, max_size=100)
    return job_id

def _napalm_update_job(job_id, **kwargs):
    with _napalm_jobs_lock:
        if job_id in _napalm_jobs:
            _napalm_jobs[job_id].update(kwargs)

def _napalm_open(hostname, ip, driver_name):
    """Open NAPALM connection — used for EOS devices only."""
    if not NAPALM_AVAILABLE:
        return None, "NAPALM not installed"
    driver = napalm.get_network_driver(driver_name)
    opt = {"key_file": SSH_KEY_PATH, "ssh_config_file": None, "timeout": SSH_TIMEOUT}
    dev = driver(hostname=ip, username=SSH_USER, password="", optional_args=opt)
    try:
        dev.open()
        return dev, None
    except Exception as e:
        print(f"[NAPALM] Connection failed for {hostname} ({ip}, {driver_name}): {e}")
        return None, str(e)


# ── Junos SSH CLI collector (paramiko-based, bypasses ncclient/NETCONF) ──────
def _junos_ssh_cmd(client, command, timeout=15):
    """Run a single command via paramiko exec_command and return output."""
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace")
    except Exception:
        return ""

def _junos_ssh_collect(hostname, ip, getters):
    """Collect NAPALM-style getter data from Junos via paramiko SSH + CLI parsing."""
    result = {"hostname": hostname, "ip": ip, "driver": "junos", "data": {}, "error": None}
    client = paramiko.SSHClient()
    apply_ssh_policy(client)
    try:
        _ssh_connect(client, ip)
        for g in getters:
            try:
                if g == "get_facts":
                    result["data"][g] = _junos_parse_facts(client, hostname)
                elif g == "get_bgp_neighbors":
                    result["data"][g] = _junos_parse_bgp(client)
                elif g == "get_environment":
                    result["data"][g] = _junos_parse_environment(client)
                elif g == "get_interfaces":
                    result["data"][g] = _junos_parse_interfaces(client)
                elif g == "get_interfaces_counters":
                    result["data"][g] = _junos_parse_counters(client)
                elif g == "get_lldp_neighbors":
                    result["data"][g] = _junos_parse_lldp(client)
                elif g == "get_interfaces_ip":
                    result["data"][g] = _junos_parse_interfaces_ip(client)
                else:
                    result["data"][g] = None
            except Exception as e:
                result["data"][g] = None
    except Exception as e:
        result["error"] = f"SSH failed: {e}"
    finally:
        try:
            client.close()
        except Exception:
            pass
    return result


def _junos_parse_facts(client, hostname):
    out = _junos_ssh_cmd(client, "show version")
    facts = {"hostname": hostname, "vendor": "Juniper", "model": "-",
             "os_version": "-", "serial_number": "-", "uptime": -1,
             "interface_list": [], "fqdn": hostname}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Hostname:"):
            facts["hostname"] = line.split(":", 1)[1].strip()
            facts["fqdn"] = facts["hostname"]
        elif line.startswith("Model:"):
            facts["model"] = line.split(":", 1)[1].strip()
        elif "JUNOS " in line or "Junos:" in line:
            ver = line.split("[", 1)[1].rstrip("]") if "[" in line else line.split(":", 1)[-1].strip()
            if ver and facts["os_version"] == "-":
                facts["os_version"] = ver
    # Serial
    chassis = _junos_ssh_cmd(client, "show chassis hardware | match Chassis")
    for line in chassis.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "Chassis":
            facts["serial_number"] = parts[1]
            break
    # Uptime
    uptime_out = _junos_ssh_cmd(client, "show system uptime | match System")
    m = re.search(r"booted:\s+(.+)", uptime_out)
    if m:
        # Approximate uptime in seconds from boot time
        try:
            from datetime import datetime as _dt
            boot = _dt.strptime(m.group(1).strip().split(" (")[0], "%Y-%m-%d %H:%M:%S %Z")
            facts["uptime"] = int((datetime.now() - boot).total_seconds())
        except Exception:
            pass
    # Interface list
    ifaces = _junos_ssh_cmd(client, "show interfaces terse | match -v ^$")
    for line in ifaces.splitlines()[1:]:
        parts = line.split()
        if parts:
            facts["interface_list"].append(parts[0])
    return facts


def _junos_parse_bgp(client):
    out = _junos_ssh_cmd(client, "show bgp summary")
    result = {"global": {"router_id": "", "peers": {}}}
    lines = out.splitlines()
    last_peer = None
    for i, line in enumerate(lines):
        parts = line.split()
        if not parts:
            continue
        # Extract router ID
        if "Router ID:" in line:
            m = re.search(r"Router ID:\s+(\S+)", line)
            if m:
                result["global"]["router_id"] = m.group(1)
            continue
        # Indented prefix-count line: "  inet.0: active/received/accepted/damped"
        if last_peer and line.startswith("  ") and ":" in parts[0] and "/" in line:
            m_pfx = re.search(r":\s*(\d+)/(\d+)/(\d+)", line)
            if m_pfx:
                active = int(m_pfx.group(1))
                received = int(m_pfx.group(2))
                accepted = int(m_pfx.group(3))
                peer = result["global"]["peers"].get(last_peer)
                if peer:
                    # Accumulate across address families (inet.0 + inet6.0)
                    af = peer["address_family"].get("ipv4 unicast", {})
                    af["received_prefixes"] = af.get("received_prefixes", 0) + received
                    af["accepted_prefixes"] = af.get("accepted_prefixes", 0) + accepted
                    af["sent_prefixes"] = af.get("sent_prefixes", 0) + active
            continue
        # Peer line: IP  AS  InPkt  OutPkt  OutQ  Flaps  Last  Up/Down  State
        # State is "Establ" for up, or "Active"/"Connect"/"Idle"/"OpenSent" etc for down
        try:
            ipaddress.ip_address(parts[0])
        except ValueError:
            continue
        if len(parts) >= 9:
            peer_ip = parts[0]
            peer_as = int(parts[1]) if parts[1].isdigit() else 0
            state_field = parts[-1]
            is_up = state_field.startswith("Establ")
            last_peer = peer_ip
            result["global"]["peers"][peer_ip] = {
                "local_as": 0, "remote_as": peer_as, "remote_id": "",
                "is_up": is_up, "is_enabled": True, "uptime": -1,
                "description": "",
                "address_family": {"ipv4 unicast": {
                    "received_prefixes": 0, "accepted_prefixes": 0, "sent_prefixes": 0
                }}
            }
        else:
            last_peer = None
    # Enrich with description, uptime, type, group, policies from 'show bgp neighbor'
    try:
        nbr_out = _junos_ssh_cmd(client, 'show bgp neighbor | match "Peer:|Description:|Last traffic|Group:|Type:|Export:|Import:|Address families|Local AS:"', timeout=30)
        cur_peer = None
        for nline in nbr_out.splitlines():
            nline_s = nline.strip()
            if nline_s.startswith("Peer:"):
                m_p = re.match(r"Peer:\s+(\S+)", nline_s)
                if m_p:
                    cur_peer = m_p.group(1).split("+")[0]
                    # Extract local AS from Peer line: "Peer: ... Local: 10.3.254.5+179 AS 35793"
                    m_las = re.search(r"Local:\s+\S+\s+AS\s+(\d+)", nline_s)
                    if m_las and cur_peer in result["global"]["peers"]:
                        result["global"]["peers"][cur_peer]["local_as"] = int(m_las.group(1))
            elif not cur_peer or cur_peer not in result["global"]["peers"]:
                continue
            elif nline_s.startswith("Description:"):
                result["global"]["peers"][cur_peer]["description"] = nline_s.split(":", 1)[1].strip()
            elif nline_s.startswith("Group:"):
                result["global"]["peers"][cur_peer]["group"] = nline_s.split(":")[1].split()[0].strip()
            elif nline_s.startswith("Type:"):
                m_type = re.match(r"Type:\s+(\S+)", nline_s)
                if m_type:
                    result["global"]["peers"][cur_peer]["peer_type"] = m_type.group(1)
            elif nline_s.startswith("Export:"):
                # Line format: "Export: [ X ] Import: [ Y ]" — both on same line
                m_exp = re.search(r"Export:\s*\[\s*(.+?)\s*\]", nline_s)
                m_imp = re.search(r"Import:\s*\[\s*(.+?)\s*\]", nline_s)
                if m_exp:
                    result["global"]["peers"][cur_peer]["export_policy"] = m_exp.group(1).strip()
                if m_imp:
                    result["global"]["peers"][cur_peer]["import_policy"] = m_imp.group(1).strip()
            elif nline_s.startswith("Import:"):
                m_imp = re.search(r"Import:\s*\[\s*(.+?)\s*\]", nline_s)
                if m_imp:
                    result["global"]["peers"][cur_peer]["import_policy"] = m_imp.group(1).strip()
            elif "Address families configured" in nline_s:
                af_str = nline_s.split(":", 1)[1].strip() if ":" in nline_s else ""
                result["global"]["peers"][cur_peer]["af_configured"] = af_str
            elif "Last traffic" in nline_s:
                m_up = re.search(r"Checked\s+(\d+)", nline_s)
                if m_up:
                    result["global"]["peers"][cur_peer]["uptime"] = int(m_up.group(1))
            elif nline_s.startswith("Local AS:"):
                m_las = re.search(r"Local AS:\s+(\d+)", nline_s)
                if m_las:
                    result["global"]["peers"][cur_peer]["local_as"] = int(m_las.group(1))
    except Exception:
        pass
    return result


def _junos_parse_environment(client):
    env = {"fans": {}, "temperature": {}, "power": {}, "cpu": {}, "memory": {}}
    # CPU + Memory from routing-engine (may have multiple slots — use Master or last)
    re_out = _junos_ssh_cmd(client, "show chassis routing-engine")
    slot_name = "RE0"
    cpu_user = 0
    cpu_kernel = 0
    mem_pct = 0
    dram_mb = 0
    for line in re_out.splitlines():
        ls = line.strip()
        m_slot = re.match(r"Slot\s+(\d+)", ls)
        if m_slot:
            slot_name = f"RE{m_slot.group(1)}"
        if ls.startswith("User") and "percent" in ls:
            m = re.search(r"(\d+)\s*percent", ls)
            if m:
                cpu_user = int(m.group(1))
        if ls.startswith("Kernel") and "percent" in ls:
            m = re.search(r"(\d+)\s*percent", ls)
            if m:
                cpu_kernel = int(m.group(1))
        if "Memory utilization" in ls:
            m = re.search(r"(\d+)\s*percent", ls)
            if m:
                mem_pct = int(m.group(1))
        if ls.startswith("DRAM"):
            m = re.search(r"(\d+)\s*MB", ls)
            if m:
                dram_mb = int(m.group(1))
    cpu_total = cpu_user + cpu_kernel
    if cpu_total > 0:
        env["cpu"][slot_name] = {"%usage": float(cpu_total)}
    if mem_pct > 0:
        used_mb = int(dram_mb * mem_pct / 100) if dram_mb else mem_pct
        avail_mb = dram_mb - used_mb if dram_mb else 100 - mem_pct
        env["memory"][slot_name] = {"used_ram": used_mb, "available_ram": avail_mb}
    # Temperature + Fans + PSU
    alarm_out = _junos_ssh_cmd(client, "show chassis environment")
    current_section = ""
    for line in alarm_out.splitlines():
        line_s = line.strip()
        if not line_s or line_s.startswith("Class"):
            continue
        if "Power" in line_s and "Supply" in line_s:
            current_section = "power"
        elif "Fan" in line_s or "Fanmodule" in line_s or "FAN" in line_s:
            current_section = "fan"
        parts = line_s.split()
        # Temperature lines: "item temp degrees C / threshold"
        m_temp = re.search(r"(\d+)\s+degrees\s+C", line_s)
        if m_temp:
            name = parts[0] if parts else "Sensor"
            env["temperature"][name] = {
                "temperature": float(m_temp.group(1)), "is_alert": False, "is_critical": False
            }
        # Fan: look for OK / status
        if "OK" in line_s and current_section == "fan":
            name = parts[0] if parts else "Fan"
            env["fans"][name] = {"status": True}
        # PSU
        if current_section == "power" and ("OK" in line_s or "Online" in line_s):
            name = " ".join(parts[:2]) if len(parts) >= 2 else parts[0]
            env["power"][name] = {"status": True, "capacity": -1.0, "output": -1.0}
    return env


def _junos_parse_interfaces(client):
    out = _junos_ssh_cmd(client, "show interfaces terse")
    interfaces = {}
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3:
            name = parts[0]
            admin = parts[1].lower()
            oper = parts[2].lower()
            interfaces[name] = {
                "is_up": oper == "up", "is_enabled": admin == "up",
                "description": "", "last_flapped": -1.0,
                "speed": -1, "mtu": -1, "mac_address": ""
            }
    return interfaces


def _junos_parse_counters(client):
    out = _junos_ssh_cmd(client, "show interfaces statistics detail | match \"Physical interface|Input errors|Output errors|Errors:|Drops:\"", timeout=20)
    counters = {}
    current_iface = None
    section = None  # "input" or "output"
    for line in out.splitlines():
        line_s = line.strip()
        if line_s.startswith("Physical interface:"):
            current_iface = line_s.split(":")[1].split(",")[0].strip()
            counters[current_iface] = {
                "tx_errors": 0, "rx_errors": 0, "tx_discards": 0, "rx_discards": 0,
                "tx_octets": 0, "rx_octets": 0, "tx_unicast_packets": 0,
                "rx_unicast_packets": 0, "tx_multicast_packets": 0,
                "rx_multicast_packets": 0, "tx_broadcast_packets": 0, "rx_broadcast_packets": 0,
            }
            section = None
            continue
        if not current_iface or current_iface not in counters:
            continue
        if line_s.startswith("Input errors"):
            section = "input"
            continue
        if line_s.startswith("Output errors"):
            section = "output"
            continue
        if section:
            # Parse "Errors: N" (but not "Framing errors", "Resource errors", etc.)
            m_err = re.search(r"(?<![a-zA-Z])Errors:\s*(\d+)", line_s)
            if m_err:
                val = int(m_err.group(1))
                if section == "input":
                    counters[current_iface]["rx_errors"] = val
                else:
                    counters[current_iface]["tx_errors"] = val
            # Parse "Drops: N" (but not "Bucket drops")
            m_drop = re.search(r"(?<![a-zA-Z])Drops:\s*(\d+)", line_s)
            if m_drop:
                val = int(m_drop.group(1))
                if section == "input":
                    counters[current_iface]["rx_discards"] = val
                else:
                    counters[current_iface]["tx_discards"] = val
    return counters


def _junos_parse_lldp(client):
    out = _junos_ssh_cmd(client, "show lldp neighbors")
    neighbors = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and not line.strip().startswith("Local") and "-" not in parts[0][:3]:
            # Try to parse: LocalInterface  ParentInterface  ChassisId  RemotePort  SystemName
            # Format varies; typical: ge-0/0/0  -  aa:bb:cc  ge-0/0/0  remote-host
            local_iface = parts[0]
            remote_host = parts[-1] if len(parts) >= 5 else "-"
            remote_port = parts[-2] if len(parts) >= 5 else parts[-1]
            if local_iface not in neighbors:
                neighbors[local_iface] = []
            neighbors[local_iface].append({"hostname": remote_host, "port": remote_port})
    return neighbors


def _junos_parse_interfaces_ip(client):
    out = _junos_ssh_cmd(client, "show interfaces terse | match inet")
    interfaces_ip = {}
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        iface = parts[0]
        for p in parts:
            if "/" in p:
                try:
                    net = ipaddress.ip_interface(p)
                    if iface not in interfaces_ip:
                        interfaces_ip[iface] = {"ipv4": {}, "ipv6": {}}
                    family = "ipv6" if net.version == 6 else "ipv4"
                    interfaces_ip[iface][family][str(net.ip)] = {"prefix_length": net.network.prefixlen}
                except ValueError:
                    pass
    return interfaces_ip


def _eos_parse_facts(client, hostname):
    out = _junos_ssh_cmd(client, "show version")
    facts = {"hostname": hostname, "vendor": "Arista", "model": "-", "os_version": "-",
             "serial_number": "-", "uptime": -1, "interface_list": [], "fqdn": hostname}
    for line in out.splitlines():
        if line.startswith("Arista "):
            facts["model"] = line.split("Arista ")[-1].strip()
        elif "Software image version:" in line:
            facts["os_version"] = line.split(":")[-1].strip()
        elif "Serial number:" in line:
            facts["serial_number"] = line.split(":")[-1].strip()
        elif "Uptime:" in line:
            m = re.search(r"(\d+)\s+weeks?,?\s*(\d+)\s+days?,?\s*(\d+)\s+hours?", line)
            if m:
                facts["uptime"] = int(m.group(1)) * 604800 + int(m.group(2)) * 86400 + int(m.group(3)) * 3600
            else:
                m2 = re.search(r"(\d+)\s+days?,?\s*(\d+)\s+hours?", line)
                if m2:
                    facts["uptime"] = int(m2.group(1)) * 86400 + int(m2.group(2)) * 3600
    ifaces = _junos_ssh_cmd(client, "show interfaces status")
    for line in ifaces.splitlines()[1:]:
        parts = line.split()
        if parts and not line.startswith("-"):
            facts["interface_list"].append(parts[0])
    return facts


def _eos_parse_bgp(client):
    result = {"global": {"router_id": "", "peers": {}}}
    out = _junos_ssh_cmd(client, "show ip bgp summary")
    if "BGP inactive" in out or "not supported" in out.lower():
        return result
    for line in out.splitlines():
        if "Router identifier" in line:
            m = re.search(r"Router identifier\s+(\S+)", line)
            if m:
                result["global"]["router_id"] = m.group(1)
            continue
        # EOS format: Description  Neighbor  V  AS  MsgRcvd  MsgSent  InQ  OutQ  Up/Down  State  PfxRcd  PfxAcc
        # Find an IP address anywhere in the line
        parts = line.split()
        if not parts or len(parts) < 9:
            continue
        peer_ip = None
        ip_idx = -1
        for idx, p in enumerate(parts):
            try:
                ipaddress.ip_address(p)
                peer_ip = p
                ip_idx = idx
                break
            except ValueError:
                continue
        if not peer_ip or ip_idx < 0:
            continue
        # Description is everything before the IP
        desc = " ".join(parts[:ip_idx]).strip() if ip_idx > 0 else ""
        # Fields after IP: V AS MsgRcvd MsgSent InQ OutQ Up/Down State [PfxRcd PfxAcc]
        after = parts[ip_idx + 1:]
        if len(after) < 7:
            continue
        peer_as = int(after[1]) if after[1].isdigit() else 0
        updown = after[6] if len(after) > 6 else ""
        state_field = after[7] if len(after) > 7 else ""
        pfx_rcvd = 0
        pfx_acc = 0
        if len(after) > 8:
            try: pfx_rcvd = int(after[8])
            except ValueError: pass
        if len(after) > 9:
            try: pfx_acc = int(after[9])
            except ValueError: pass
        is_up = state_field.startswith("Estab") or pfx_rcvd > 0
        # Parse uptime from Up/Down field (e.g. "25d05h", "3:12:45", "1w2d", "never")
        uptime_sec = -1
        if updown and updown != "never":
            m_dhm = re.match(r"(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$", updown)
            if m_dhm and any(m_dhm.groups()):
                w = int(m_dhm.group(1) or 0)
                d = int(m_dhm.group(2) or 0)
                h = int(m_dhm.group(3) or 0)
                mi = int(m_dhm.group(4) or 0)
                s = int(m_dhm.group(5) or 0)
                uptime_sec = w * 604800 + d * 86400 + h * 3600 + mi * 60 + s
            else:
                m_hms = re.match(r"(\d+):(\d+):(\d+)", updown)
                if m_hms:
                    uptime_sec = int(m_hms.group(1)) * 3600 + int(m_hms.group(2)) * 60 + int(m_hms.group(3))
        result["global"]["peers"][peer_ip] = {
            "local_as": 0, "remote_as": peer_as, "remote_id": "",
            "is_up": is_up, "is_enabled": True, "uptime": uptime_sec, "description": desc,
            "address_family": {"ipv4 unicast": {
                "received_prefixes": pfx_rcvd, "accepted_prefixes": pfx_acc, "sent_prefixes": 0
            }}
        }
    return result


def _eos_parse_environment(client):
    env = {"fans": {}, "temperature": {}, "power": {}, "cpu": {}, "memory": {}}
    ver_out = _junos_ssh_cmd(client, "show version")
    for line in ver_out.splitlines():
        if "Total memory:" in line:
            m = re.search(r"Total memory:\s+(\d+)", line)
            if m:
                total_kb = int(m.group(1))
                env["memory"]["available_ram"] = total_kb // 1024
        elif "Free memory:" in line:
            m = re.search(r"Free memory:\s+(\d+)", line)
            if m:
                free_kb = int(m.group(1))
                total = env["memory"].get("available_ram", 0)
                env["memory"]["used_ram"] = total - (free_kb // 1024)
    proc_out = _junos_ssh_cmd(client, "show processes top once")
    for line in proc_out.splitlines():
        if "%Cpu(s):" in line or "Cpu(s):" in line:
            m = re.search(r"(\d+\.?\d*)\s*id", line)
            if m:
                idle = float(m.group(1))
                env["cpu"]["0"] = {"%usage": round(100.0 - idle, 1)}
            break
    env_out = _junos_ssh_cmd(client, "show environment all")
    for line in env_out.splitlines():
        if "Fan" in line and ("ok" in line.lower() or "Ok" in line):
            fan_name = line.split()[0] if line.split() else "Fan"
            env["fans"][fan_name] = {"status": True}
        elif "PowerSupply" in line or "Power supply" in line.lower():
            ps_name = line.split()[0] if line.split() else "PSU"
            env["power"][ps_name] = {"status": "ok" in line.lower() or "Ok" in line}
        elif "Inlet" in line or "CPU" in line or "Board" in line:
            parts = line.split()
            for p in parts:
                try:
                    temp = float(p)
                    if 10 < temp < 120:
                        env["temperature"][parts[0]] = {"temperature": temp, "is_alert": temp > 70, "is_critical": temp > 85}
                        break
                except ValueError:
                    continue
    return env


def _eos_parse_interfaces(client):
    out = _junos_ssh_cmd(client, "show interfaces status")
    interfaces = {}
    for line in out.splitlines()[1:]:
        if line.startswith("-") or not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 3:
            iface = parts[0]
            status = "connected" in line.lower()
            speed_str = parts[-2] if len(parts) >= 6 else "0"
            speed = 0
            if "1G" in speed_str or "1000" in speed_str:
                speed = 1000000000
            elif "10G" in speed_str:
                speed = 10000000000
            elif "25G" in speed_str:
                speed = 25000000000
            elif "40G" in speed_str:
                speed = 40000000000
            elif "100G" in speed_str:
                speed = 100000000000
            elif "100M" in speed_str:
                speed = 100000000
            interfaces[iface] = {"is_up": status, "is_enabled": True, "speed": speed,
                                  "mtu": 1500, "mac_address": "", "description": "",
                                  "last_flapped": -1.0}
    return interfaces


def _eos_parse_counters(client):
    # EOS 'show interfaces counters errors' columns: Port FCS Align Symbol Rx Runts Giants Tx
    out = _junos_ssh_cmd(client, "show interfaces counters errors")
    counters = {}
    for line in out.splitlines():
        if line.startswith("-") or not line.strip() or line.strip().startswith("Port"):
            continue
        parts = line.split()
        if len(parts) >= 8:
            iface = parts[0]
            try:
                rx_err = int(parts[1]) + int(parts[2]) + int(parts[3]) + int(parts[4]) + int(parts[5]) + int(parts[6])
                tx_err = int(parts[7])
                counters[iface] = {
                    "tx_errors": tx_err, "rx_errors": rx_err,
                    "tx_discards": 0, "rx_discards": 0,
                    "tx_octets": 0, "rx_octets": 0,
                }
            except (ValueError, IndexError):
                pass
    # EOS 'show interfaces counters discards' columns: Port InDiscards OutDiscards
    out2 = _junos_ssh_cmd(client, "show interfaces counters discards")
    for line in out2.splitlines():
        if line.startswith("-") or not line.strip() or line.strip().startswith("Port"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            iface = parts[0]
            try:
                in_disc = int(parts[1])
                out_disc = int(parts[2])
                if iface in counters:
                    counters[iface]["rx_discards"] = in_disc
                    counters[iface]["tx_discards"] = out_disc
                else:
                    counters[iface] = {
                        "tx_errors": 0, "rx_errors": 0,
                        "tx_discards": out_disc, "rx_discards": in_disc,
                        "tx_octets": 0, "rx_octets": 0,
                    }
            except (ValueError, IndexError):
                pass
    return counters


def _eos_parse_lldp(client):
    out = _junos_ssh_cmd(client, "show lldp neighbors")
    neighbors = {}
    for line in out.splitlines():
        parts = line.split()
        if not parts or line.startswith("-") or line.startswith("Port") or line.startswith("Last") or line.startswith("Number"):
            continue
        if len(parts) >= 3:
            local = parts[0]
            remote_host = parts[1]
            remote_port = parts[2] if len(parts) >= 3 else ""
            if local not in neighbors:
                neighbors[local] = []
            neighbors[local].append({"hostname": remote_host, "port": remote_port})
    return neighbors


def _eos_parse_interfaces_ip(client):
    out = _junos_ssh_cmd(client, "show ip interface brief")
    interfaces_ip = {}
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and "/" in parts[1]:
            iface = parts[0]
            try:
                net = ipaddress.ip_interface(parts[1])
                if iface not in interfaces_ip:
                    interfaces_ip[iface] = {"ipv4": {}, "ipv6": {}}
                family = "ipv6" if net.version == 6 else "ipv4"
                interfaces_ip[iface][family][str(net.ip)] = {"prefix_length": net.network.prefixlen}
            except ValueError:
                pass
    return interfaces_ip


def _eos_ssh_collect(hostname, ip, getters):
    result = {"hostname": hostname, "ip": ip, "driver": "eos", "data": {}, "error": None}
    client = paramiko.SSHClient()
    apply_ssh_policy(client)
    try:
        _ssh_connect(client, ip)
        for g in getters:
            try:
                if g == "get_facts":
                    result["data"][g] = _eos_parse_facts(client, hostname)
                elif g == "get_bgp_neighbors":
                    result["data"][g] = _eos_parse_bgp(client)
                elif g == "get_environment":
                    result["data"][g] = _eos_parse_environment(client)
                elif g == "get_interfaces":
                    result["data"][g] = _eos_parse_interfaces(client)
                elif g == "get_interfaces_counters":
                    result["data"][g] = _eos_parse_counters(client)
                elif g == "get_lldp_neighbors":
                    result["data"][g] = _eos_parse_lldp(client)
                elif g == "get_interfaces_ip":
                    result["data"][g] = _eos_parse_interfaces_ip(client)
                else:
                    result["data"][g] = None
            except Exception:
                result["data"][g] = None
    except Exception as e:
        result["error"] = f"SSH failed: {e}"
    finally:
        try:
            client.close()
        except Exception:
            pass
    return result


def _docker_run(container: str, *cmd: str, timeout: int = 8) -> str:
    """Run a command inside a container via docker (list-arg subprocess, no shell).
    Returns stdout text; raises RuntimeError on non-zero exit or timeout.
    Used by the NAPALM-equivalent collectors for FRR / Nokia SRL / Arista cEOS."""
    import subprocess as _sp
    p = _sp.run(["docker", "exec", container, *cmd],
                capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError(f"{container}: rc={p.returncode}: {(p.stderr or '').strip()[:200]}")
    return p.stdout


def _frr_collect(hostname: str, container: str | None, ip: str, getters: list[str]) -> dict:
    """NAPALM-equivalent collector for FRR (vtysh) — works on docker containers
    (preferred) OR over SSH if a container is not known. Returns the same shape
    as the Junos/EOS paths so the existing /api/napalm/* endpoints work
    unchanged for FRR sites."""
    import json as _jm
    container = container or (f"clab-clos-evpn-{hostname}"
                              if hostname.startswith(("spine","leaf")) else container)
    if not container:
        # SSH fallback for legacy DCN lab routers exposed on port 2201+
        dev = get_device_by_hostname(hostname)
        if not dev:
            return {"hostname": hostname, "error": "device not found", "data": {}}
        try:
            import paramiko as _pm
            client = _pm.SSHClient()
            client.set_missing_host_key_policy(_pm.AutoAddPolicy())
            client.connect(ip, port=dev.get("port", 22),
                           username=os.environ.get("SSH_USER", "frr"),
                           key_filename=SSH_KEY_PATH, timeout=4)
            _, stdout, _ = client.exec_command(
                "vtysh -c 'show version' && vtysh -c 'show bgp summary json'", timeout=6)
            _ = stdout.read().decode(errors="replace")
            client.close()
        except Exception as e:
            return {"hostname": hostname, "error": f"ssh: {e}", "data": {}}
    data: dict = {}
    def _vt(cmd: str) -> str:
        try:
            return _docker_run(container, "vtysh", "-c", cmd) if container else ""
        except Exception as e:
            return f"__error__{e}"
    if "get_facts" in getters:
        ver = _vt("show version")
        m = re.search(r"FRRouting\s+(\S+)", ver)
        data["get_facts"] = {
            "os_version": (m.group(1) if m else "FRR"),
            "vendor": "FRRouting", "model": "container", "hostname": hostname,
            "serial_number": "N/A", "uptime": -1, "interface_list": [],
        }
    if "get_bgp_neighbors" in getters:
        raw = _vt("show bgp summary json")
        try: j = _jm.loads(raw) if not raw.startswith("__error__") else {}
        except Exception: j = {}
        peers: dict = {}
        for af, afdata in (j.items() if isinstance(j, dict) else []):
            ps = (afdata or {}).get("peers") if isinstance(afdata, dict) else None
            if not ps: continue
            for pip, p in ps.items():
                peers[pip] = {
                    "is_up": str(p.get("state","")).lower() == "established",
                    "is_enabled": True, "remote_as": p.get("remoteAs"),
                    "uptime": p.get("peerUptimeMsec", 0) // 1000,
                    "address_family": {"ipv4": {
                        "received_prefixes": p.get("pfxRcd", 0),
                        "accepted_prefixes": p.get("pfxRcd", 0),
                        "sent_prefixes":     p.get("pfxSnt", 0)}},
                }
        data["get_bgp_neighbors"] = {"global": {
            "router_id": (j.get("ipv4Unicast") or {}).get("routerId", "") if isinstance(j, dict) else "",
            "peers": peers}}
    if "get_environment" in getters:
        data["get_environment"] = {"cpu": {"0": {"%usage": 0.0}}, "memory": {},
                                   "temperature": {}, "fans": {}, "power": {}}
    if "get_interfaces" in getters or "get_interfaces_counters" in getters:
        raw = _vt("show interface brief json")
        try: j = _jm.loads(raw) if not raw.startswith("__error__") else {}
        except Exception: j = {}
        ifs: dict = {}
        for iname, idata in (j.items() if isinstance(j, dict) else []):
            if not isinstance(idata, dict): continue
            ifs[iname] = {
                "is_up":      str(idata.get("status","")).lower() in ("up", "active"),
                "is_enabled": str(idata.get("administrativeStatus","")).lower() in ("up", "active"),
                "description": "", "speed": 0, "mac_address": "", "mtu": 1500,
            }
        if "get_interfaces" in getters:
            data["get_interfaces"] = ifs
        if "get_interfaces_counters" in getters:
            data["get_interfaces_counters"] = {iname: {
                "tx_errors": 0, "rx_errors": 0, "tx_discards": 0, "rx_discards": 0,
                "tx_octets": 0,  "rx_octets": 0,
                "tx_unicast_packets": 0, "rx_unicast_packets": 0,
                "tx_multicast_packets": 0, "rx_multicast_packets": 0,
                "tx_broadcast_packets": 0, "rx_broadcast_packets": 0} for iname in ifs}
    return {"hostname": hostname, "data": data}


def _clab_srl_collect(hostname: str, container: str, getters: list[str]) -> dict:
    """NAPALM-equivalent collector for Nokia SR Linux via sr_cli inside docker.

    NOTE: SRL doesn't accept the Cisco-style `show system information` —
    its CLI uses `info from state /system/...`. The previous version crashed
    the whole collection on the first getter; per-getter try/except now
    isolates failures so partial data still returns."""
    data: dict = {}
    errors: list[str] = []
    # get_facts — best effort, falls back to a stub if the SRL CLI rejects.
    if "get_facts" in getters:
        try:
            raw = _docker_run(container, "sr_cli",
                              "info from state /system information version")
            m_ver = re.search(r"version\s*:?\s*\"?([0-9][^\s\"]+)", raw, re.I)
            data["get_facts"] = {
                "os_version": m_ver.group(1) if m_ver else "SR Linux",
                "vendor": "Nokia", "model": "SR Linux container", "hostname": hostname,
                "serial_number": "N/A", "uptime": -1, "interface_list": [],
            }
        except Exception:
            data["get_facts"] = {
                "os_version": "SR Linux", "vendor": "Nokia",
                "model": "SR Linux container", "hostname": hostname,
                "serial_number": "N/A", "uptime": -1, "interface_list": [],
            }
    if "get_bgp_neighbors" in getters:
        try:
            raw = _docker_run(container, "sr_cli",
                              "show network-instance default protocols bgp neighbor")
            peers: dict = {}
            for line in raw.splitlines():
                m = re.search(r"^\s*\|\s*\S+\s*\|\s*(\d+\.\d+\.\d+\.\d+)\s*\|\s*\S+\s*\|\s*\S+\s*\|\s*(\d+)\s*\|\s*(established|active|connect|idle|opensent|openconfirm)\s",
                              line, re.I)
                if m:
                    ip_, asn, state = m.group(1), int(m.group(2)), m.group(3).lower()
                    peers[ip_] = {"is_up": state == "established", "is_enabled": True,
                                  "remote_as": asn, "uptime": 0,
                                  "address_family": {"ipv4": {"received_prefixes": 0,
                                                                "accepted_prefixes": 0,
                                                                "sent_prefixes": 0}}}
            data["get_bgp_neighbors"] = {"global": {"router_id": "", "peers": peers}}
        except Exception as e:
            errors.append(f"bgp: {e}")
    if "get_interfaces" in getters:
        try:
            raw = _docker_run(container, "sr_cli", "show interface")
            ifs: dict = {}
            for line in raw.splitlines():
                m = re.match(r"^(ethernet\S+|mgmt\d+|system\d+)\s+is\s+(up|down)", line, re.I)
                if m:
                    ifs[m.group(1)] = {"is_up": m.group(2).lower() == "up",
                                       "is_enabled": True, "description": "",
                                       "speed": 0, "mac_address": "", "mtu": 1500}
            data["get_interfaces"] = ifs
        except Exception as e:
            errors.append(f"intf: {e}")
    if "get_environment" in getters:
        data["get_environment"] = {"cpu": {"0": {"%usage": 0.0}}, "memory": {},
                                   "temperature": {}, "fans": {}, "power": {}}
    out = {"hostname": hostname, "data": data}
    if errors and not data.get("get_bgp_neighbors") and not data.get("get_interfaces"):
        out["error"] = "; ".join(errors)[:200]
    return out


def _clab_eos_collect(hostname: str, container: str, getters: list[str]) -> dict:
    """NAPALM-equivalent collector for Arista cEOS via Cli -p 15 -c '... | json'."""
    import json as _jm
    data: dict = {}
    def _j(raw: str) -> dict:
        try:
            m = re.search(r'\{.*\}', raw, re.DOTALL)
            return _jm.loads(m.group(0)) if m else {}
        except Exception:
            return {}
    try:
        if "get_facts" in getters:
            j = _j(_docker_run(container, "Cli", "-p", "15", "-c", "show version | json"))
            data["get_facts"] = {
                "os_version": j.get("version", "cEOS"),
                "vendor": "Arista", "model": j.get("modelName", "cEOS container"),
                "hostname": hostname,
                "serial_number": j.get("serialNumber", "N/A"),
                "uptime": int(j.get("uptime", 0)), "interface_list": [],
            }
        if "get_bgp_neighbors" in getters:
            j = _j(_docker_run(container, "Cli", "-p", "15", "-c",
                               "show ip bgp summary | json"))
            peers: dict = {}
            for pip, p in ((j.get("vrfs") or {}).get("default", {}).get("peers", {}) or {}).items():
                peers[pip] = {
                    "is_up": str(p.get("peerState","")).lower() == "established",
                    "is_enabled": not p.get("underMaintenance", False),
                    "remote_as": int(p.get("asn", 0) or 0),
                    "uptime": int(p.get("upDownTime", 0) or 0),
                    "address_family": {"ipv4": {
                        "received_prefixes": p.get("prefixReceived", 0),
                        "accepted_prefixes": p.get("prefixAccepted", 0),
                        "sent_prefixes": 0}},
                }
            data["get_bgp_neighbors"] = {"global": {
                "router_id": (j.get("vrfs") or {}).get("default",{}).get("routerId",""),
                "peers": peers}}
        if "get_interfaces" in getters:
            j = _j(_docker_run(container, "Cli", "-p", "15", "-c",
                               "show interfaces status | json"))
            ifs: dict = {}
            for iname, idata in (j.get("interfaceStatuses") or {}).items():
                ifs[iname] = {"is_up": str(idata.get("linkStatus","")).lower() == "connected",
                              "is_enabled": True,
                              "description": idata.get("description",""),
                              "speed": 0, "mac_address": "", "mtu": 1500}
            data["get_interfaces"] = ifs
        if "get_environment" in getters:
            data["get_environment"] = {"cpu": {"0": {"%usage": 0.0}}, "memory": {},
                                       "temperature": {}, "fans": {}, "power": {}}
    except Exception as e:
        return {"hostname": hostname, "error": str(e), "data": data}
    return {"hostname": hostname, "data": data}


def _napalm_collect(hostname, ip, driver_name, getters, container=None):
    """Vendor-aware dispatcher. Routes to docker-exec collectors for clab + FRR
    containers; otherwise falls back to paramiko SSH for Junos / EOS hardware.

    Previously every non-EOS device went through the Junos SSH path which hung
    on FRR containers (no NETCONF) — version-audit / bgp-status / env-health /
    interface-errors all returned `{"job_id": "…"}` and never produced results.
    This dispatcher makes those 4 endpoints work uniformly across all vendor
    families in inventory."""
    if driver_name == "frr":
        return _frr_collect(hostname, container, ip, getters)
    if driver_name == "clab-srl" and container:
        return _clab_srl_collect(hostname, container, getters)
    if driver_name == "clab-eos" and container:
        return _clab_eos_collect(hostname, container, getters)
    if driver_name == "eos":
        return _eos_ssh_collect(hostname, ip, getters)
    return _junos_ssh_collect(hostname, ip, getters)


def _napalm_collect_site(site, getters, max_workers=5):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    devices = NAPALM_SITES.get(site, {})
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {
            ex.submit(_napalm_collect, h, d["ip"], d["driver"], getters, d.get("container")): h
            for h, d in devices.items() if d.get("ip")
        }
        for f in as_completed(futs):
            h = futs[f]
            try:
                results[h] = f.result()
            except Exception as e:
                results[h] = {"hostname": h, "error": str(e), "data": {}}
    return results


@app.route("/api/napalm/status")
def napalm_status():
    return jsonify({
        "available": NAPALM_AVAILABLE,
        "sites": {s: {"devices": len(d)} for s, d in NAPALM_SITES.items()},
        "total_devices": sum(len(d) for d in NAPALM_SITES.values()),
    })


@app.route("/api/napalm/jobs")
def napalm_jobs():
    with _napalm_jobs_lock:
        return jsonify(list(_napalm_jobs.values())[-20:])


@app.route("/api/napalm/jobs/<job_id>")
def napalm_job(job_id):
    with _napalm_jobs_lock:
        job = _napalm_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


# ── NAPALM Tool 1: Version Audit ─────────────────────────────────────────────

@app.route("/api/napalm/version-audit", methods=["POST"])
def napalm_version_audit():
    data = request.json or {}
    # Site is optional here — empty means "all sites". Accept hostname/host
    # as an alias when callers send a single device's name instead of a site.
    site = (data.get("site") or "").lower()
    if not site and (data.get("hostname") or data.get("host") or data.get("device")):
        # Resolve device → its site (helper returns None when nothing matches)
        candidate, _ = _resolve_napalm_site(data)
        site = candidate or ""
    job_id = _napalm_new_job("version_audit", site or "all")

    def _run():
        try:
            sites_to_scan = {site: NAPALM_SITES[site]} if site and site in NAPALM_SITES else NAPALM_SITES
            all_results = []
            total = sum(len(d) for d in sites_to_scan.values())
            done = 0
            for s, devices in sites_to_scan.items():
                _napalm_update_job(job_id, message=f"Scanning {s.upper()}...")
                results = _napalm_collect_site(s, ["get_facts"])
                for hostname, res in sorted(results.items()):
                    done += 1
                    _napalm_update_job(job_id, progress=int(done / total * 100))
                    facts = res.get("data", {}).get("get_facts") or {}
                    all_results.append({
                        "site": s.upper(), "hostname": hostname,
                        "ip": res.get("ip", "-"), "driver": res.get("driver", "-"),
                        "vendor": facts.get("vendor", "-"), "model": facts.get("model", "-"),
                        "os_version": facts.get("os_version", "-"),
                        "serial": facts.get("serial_number", "-"),
                        "uptime": facts.get("uptime", -1), "error": res.get("error"),
                    })
            model_versions = {}
            for r in all_results:
                if r["error"]: continue
                key = (r["driver"], r["model"])
                model_versions.setdefault(key, set()).add(r["os_version"])
            mismatches = []
            for (drv, mdl), vers in model_versions.items():
                if len(vers) > 1:
                    mismatches.append({"driver": drv, "model": mdl, "versions": sorted(vers),
                        "devices": [r["hostname"] for r in all_results if r["model"] == mdl and r["driver"] == drv]})
            _napalm_update_job(job_id, status="done", progress=100,
                message=f"Scanned {len(all_results)} devices",
                result={"devices": all_results, "mismatches": mismatches,
                    "total": len(all_results), "errors": sum(1 for r in all_results if r["error"])})
        except Exception as e:
            _napalm_update_job(job_id, status="error", message=str(e))
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"job_id": job_id})


# ── NAPALM Tool 2: BGP Status ────────────────────────────────────────────────

@app.route("/api/napalm/bgp-status", methods=["POST"])
def napalm_bgp_status():
    data = request.json or {}
    site, _err = _resolve_napalm_site(data)
    if _err:
        return _err
    job_id = _napalm_new_job("bgp_status", site)

    def _run():
        try:
            _napalm_update_job(job_id, message=f"Collecting BGP from {site.upper()}...")
            results = _napalm_collect_site(site, ["get_facts", "get_bgp_neighbors"])
            bgp_summary = []
            for hostname, res in sorted(results.items()):
                if res.get("error"):
                    bgp_summary.append({"hostname": hostname, "error": res["error"],
                        "peers": [], "total": 0, "up": 0, "down": 0})
                    continue
                neighbors = res.get("data", {}).get("get_bgp_neighbors") or {}
                peers = []
                for vrf, vrf_data in neighbors.items():
                    for peer_ip, pd in vrf_data.get("peers", {}).items():
                        af = pd.get("address_family", {})
                        ipv4 = af.get("ipv4", af.get("ipv4 unicast", {}))
                        peers.append({"peer_ip": peer_ip, "vrf": vrf,
                            "is_up": pd.get("is_up", False), "is_enabled": pd.get("is_enabled", False),
                            "description": pd.get("description", ""), "uptime": pd.get("uptime", -1),
                            "received": ipv4.get("received_prefixes", 0), "sent": ipv4.get("sent_prefixes", 0),
                            "remote_as": pd.get("remote_as", 0), "local_as": pd.get("local_as", 0),
                            "group": pd.get("group", ""), "peer_type": pd.get("peer_type", ""),
                            "import_policy": pd.get("import_policy", ""), "export_policy": pd.get("export_policy", ""),
                            "af_configured": pd.get("af_configured", "")})
                up = sum(1 for p in peers if p["is_up"])
                bgp_summary.append({"hostname": hostname, "peers": peers,
                    "total": len(peers), "up": up, "down": len(peers) - up, "error": None})
            total_peers = sum(d["total"] for d in bgp_summary)
            total_down = sum(d["down"] for d in bgp_summary)
            _napalm_update_job(job_id, status="done", progress=100,
                message=f"{total_peers} peers, {total_down} down",
                result={"site": site.upper(), "devices": bgp_summary,
                    "total_peers": total_peers, "total_down": total_down})
        except Exception as e:
            _napalm_update_job(job_id, status="error", message=str(e))
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"job_id": job_id})


# ── NAPALM Tool 3: Environment Health ────────────────────────────────────────

@app.route("/api/napalm/env-health", methods=["POST"])
def napalm_env_health():
    data = request.json or {}
    site, _err = _resolve_napalm_site(data)
    if _err:
        return _err
    job_id = _napalm_new_job("env_health", site)

    def _run():
        try:
            _napalm_update_job(job_id, message=f"Collecting environment from {site.upper()}...")
            results = _napalm_collect_site(site, ["get_facts", "get_environment"])
            health_data, alerts = [], []
            for hostname, res in sorted(results.items()):
                if res.get("error"):
                    health_data.append({"hostname": hostname, "error": res["error"]})
                    continue
                facts = res.get("data", {}).get("get_facts") or {}
                env = res.get("data", {}).get("get_environment") or {}
                cpu = env.get("cpu", {})
                max_cpu = max((v.get("%usage", 0) for v in cpu.values()), default=0)
                mem = env.get("memory", {})
                # Handle both flat (NAPALM native) and nested (Junos SSH: {"RE0": {...}}) formats
                if "used_ram" in mem:
                    used, avail = mem.get("used_ram", 0), mem.get("available_ram", 0)
                else:
                    # Nested: pick the slot with the highest used_ram
                    best = max(mem.values(), key=lambda v: v.get("used_ram", 0), default={})
                    used, avail = best.get("used_ram", 0), best.get("available_ram", 0)
                total_mem = used + avail
                mem_pct = round(used / total_mem * 100, 1) if total_mem > 0 else 0
                temp = env.get("temperature", {})
                temp_alerts = []
                for sensor, d in temp.items():
                    if d.get("is_alert") or d.get("is_critical"):
                        temp_alerts.append({"sensor": sensor, "temperature": d.get("temperature", "?"), "is_critical": d.get("is_critical", False)})
                        alerts.append({"hostname": hostname, "type": "temperature", "sensor": sensor, "value": d.get("temperature", "?"), "critical": d.get("is_critical", False)})
                fans = env.get("fans", {})
                fan_ok = all(v.get("status", True) for v in fans.values())
                if not fan_ok:
                    alerts.append({"hostname": hostname, "type": "fan", "sensor": "fans", "value": "FAILED", "critical": True})
                power = env.get("power", {})
                power_ok = all(v.get("status", True) for v in power.values())
                if not power_ok:
                    alerts.append({"hostname": hostname, "type": "power", "sensor": "power", "value": "FAILED", "critical": True})
                if max_cpu > 80:
                    alerts.append({"hostname": hostname, "type": "cpu", "sensor": "cpu", "value": f"{max_cpu}%", "critical": max_cpu > 95})
                if mem_pct > 85:
                    alerts.append({"hostname": hostname, "type": "memory", "sensor": "memory", "value": f"{mem_pct}%", "critical": mem_pct > 95})
                health_data.append({"hostname": hostname, "model": facts.get("model", "-"),
                    "uptime": facts.get("uptime", -1), "cpu_pct": max_cpu, "memory_pct": mem_pct,
                    "memory_used": used, "memory_total": total_mem, "temp_alerts": temp_alerts,
                    "fans_ok": fan_ok, "power_ok": power_ok, "error": None})
            _napalm_update_job(job_id, status="done", progress=100,
                message=f"{len(health_data)} devices, {len(alerts)} alerts",
                result={"site": site.upper(), "devices": health_data, "alerts": alerts})
        except Exception as e:
            _napalm_update_job(job_id, status="error", message=str(e))
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"job_id": job_id})


# ── NAPALM Global Report — All Sites ─────────────────────────────────────────

@app.route("/api/napalm/global-report", methods=["POST"])
def napalm_global_report():
    """Run version-audit, bgp-status, and/or env-health across ALL sites.
    Body: {tools: ["version-audit","bgp-status","env-health"]}
    Returns a job_id for polling.
    """
    data = request.json or {}
    tools = data.get("tools", ["version-audit", "bgp-status", "env-health"])
    valid = {"version-audit", "bgp-status", "env-health"}
    tools = [t for t in tools if t in valid]
    if not tools:
        return jsonify({"error": "No valid tools specified"}), 400
    job_id = _napalm_new_job("global_report", "ALL")

    def _run():
        from concurrent.futures import ThreadPoolExecutor, as_completed
        try:
            all_sites = sorted(NAPALM_SITES.keys())
            total_sites = len(all_sites)
            _napalm_update_job(job_id, message=f"Starting global report for {total_sites} sites ({', '.join(tools)})...")

            # Determine which getters we need per tool
            getters = set(["get_facts"])
            if "bgp-status" in tools:
                getters.add("get_bgp_neighbors")
            if "env-health" in tools:
                getters.add("get_environment")

            # Collect per-site results
            site_results = {}
            progress = [0]  # mutable counter for nested scope

            def _collect_one_site(site_code):
                return site_code, _napalm_collect_site(site_code, list(getters))

            # Run sites in parallel, up to 3 sites at a time (each site already uses 5 threads internally)
            with ThreadPoolExecutor(max_workers=3) as pool:
                futs = {pool.submit(_collect_one_site, s): s for s in all_sites}
                for f in as_completed(futs):
                    s = futs[f]
                    try:
                        site_code, results = f.result()
                        site_results[site_code] = results
                    except Exception as e:
                        site_results[s] = {"_error": str(e)}
                    progress[0] += 1
                    pct = int(progress[0] / total_sites * 100)
                    _napalm_update_job(job_id, progress=pct,
                        message=f"Collected {progress[0]}/{total_sites} sites ({s.upper()})...")

            # Process results per tool
            report = {"sites_total": total_sites, "tools": tools, "timestamp": datetime.now().isoformat()}

            # ── Version Audit ──
            if "version-audit" in tools:
                ver_devices = []
                for site_code in sorted(site_results.keys()):
                    results = site_results[site_code]
                    if isinstance(results, dict) and "_error" in results:
                        continue
                    for hostname, res in sorted(results.items()):
                        facts = res.get("data", {}).get("get_facts") or {}
                        ver_devices.append({
                            "site": site_code.upper(), "hostname": hostname,
                            "ip": res.get("ip", "-"), "driver": res.get("driver", "-"),
                            "vendor": facts.get("vendor", "-"), "model": facts.get("model", "-"),
                            "os_version": facts.get("os_version", "-"),
                            "serial": facts.get("serial_number", "-"),
                            "uptime": facts.get("uptime", -1), "error": res.get("error"),
                        })
                # Version mismatches
                model_versions = {}
                for r in ver_devices:
                    if r["error"]: continue
                    key = (r["driver"], r["model"])
                    model_versions.setdefault(key, set()).add(r["os_version"])
                mismatches = []
                for (drv, mdl), vers in model_versions.items():
                    if len(vers) > 1:
                        mismatches.append({"driver": drv, "model": mdl, "versions": sorted(vers),
                            "devices": [r["hostname"] for r in ver_devices if r["model"] == mdl and r["driver"] == drv]})
                # Per-site summary
                ver_by_site = {}
                for r in ver_devices:
                    s = r["site"]
                    ver_by_site.setdefault(s, {"total": 0, "reachable": 0, "errors": 0})
                    ver_by_site[s]["total"] += 1
                    if r["error"]:
                        ver_by_site[s]["errors"] += 1
                    else:
                        ver_by_site[s]["reachable"] += 1
                report["version_audit"] = {
                    "devices": ver_devices, "mismatches": mismatches,
                    "total": len(ver_devices), "errors": sum(1 for r in ver_devices if r["error"]),
                    "by_site": ver_by_site,
                }

            # ── BGP Status ──
            if "bgp-status" in tools:
                bgp_by_site = {}
                all_down = []
                for site_code in sorted(site_results.keys()):
                    results = site_results[site_code]
                    if isinstance(results, dict) and "_error" in results:
                        continue
                    site_peers = 0; site_down = 0; site_devices = 0
                    for hostname, res in sorted(results.items()):
                        if res.get("error"): continue
                        neighbors = res.get("data", {}).get("get_bgp_neighbors") or {}
                        dev_peers = 0; dev_down = 0
                        for vrf, vrf_data in neighbors.items():
                            for peer_ip, pd in vrf_data.get("peers", {}).items():
                                dev_peers += 1
                                if not pd.get("is_up", False):
                                    dev_down += 1
                                    all_down.append({
                                        "site": site_code.upper(), "hostname": hostname,
                                        "peer_ip": peer_ip, "remote_as": pd.get("remote_as", 0),
                                        "description": pd.get("description", ""),
                                    })
                        if dev_peers > 0: site_devices += 1
                        site_peers += dev_peers; site_down += dev_down
                    bgp_by_site[site_code.upper()] = {
                        "devices": site_devices, "total_peers": site_peers,
                        "up": site_peers - site_down, "down": site_down,
                    }
                report["bgp_status"] = {
                    "by_site": bgp_by_site,
                    "total_peers": sum(s["total_peers"] for s in bgp_by_site.values()),
                    "total_down": sum(s["down"] for s in bgp_by_site.values()),
                    "total_sites_with_bgp": sum(1 for s in bgp_by_site.values() if s["total_peers"] > 0),
                    "down_peers": all_down[:200],
                }

            # ── Env Health ──
            if "env-health" in tools:
                env_by_site = {}
                all_alerts = []
                for site_code in sorted(site_results.keys()):
                    results = site_results[site_code]
                    if isinstance(results, dict) and "_error" in results:
                        continue
                    site_alerts = 0; site_devices = 0
                    for hostname, res in sorted(results.items()):
                        if res.get("error"): continue
                        site_devices += 1
                        env = res.get("data", {}).get("get_environment") or {}
                        # CPU
                        cpu = env.get("cpu", {})
                        max_cpu = max((v.get("%usage", 0) for v in cpu.values()), default=0)
                        # Memory
                        mem = env.get("memory", {})
                        if "used_ram" in mem:
                            used, avail = mem.get("used_ram", 0), mem.get("available_ram", 0)
                        else:
                            best = max(mem.values(), key=lambda v: v.get("used_ram", 0), default={})
                            used, avail = best.get("used_ram", 0), best.get("available_ram", 0)
                        total_mem = used + avail
                        mem_pct = round(used / total_mem * 100, 1) if total_mem > 0 else 0
                        # Fans
                        fans = env.get("fans", {})
                        fan_ok = all(v.get("status", True) for v in fans.values())
                        # Power
                        power = env.get("power", {})
                        power_ok = all(v.get("status", True) for v in power.values())
                        # Temperature
                        temp = env.get("temperature", {})
                        temp_alert_count = sum(1 for d in temp.values() if d.get("is_alert") or d.get("is_critical"))
                        # Alerts
                        if max_cpu > 80:
                            all_alerts.append({"site": site_code.upper(), "hostname": hostname, "type": "cpu", "value": f"{max_cpu}%", "critical": max_cpu > 95})
                            site_alerts += 1
                        if mem_pct > 85:
                            all_alerts.append({"site": site_code.upper(), "hostname": hostname, "type": "memory", "value": f"{mem_pct}%", "critical": mem_pct > 95})
                            site_alerts += 1
                        if not fan_ok:
                            all_alerts.append({"site": site_code.upper(), "hostname": hostname, "type": "fan", "value": "FAILED", "critical": True})
                            site_alerts += 1
                        if not power_ok:
                            all_alerts.append({"site": site_code.upper(), "hostname": hostname, "type": "power", "value": "FAILED", "critical": True})
                            site_alerts += 1
                        if temp_alert_count > 0:
                            all_alerts.append({"site": site_code.upper(), "hostname": hostname, "type": "temperature", "value": f"{temp_alert_count} sensors", "critical": True})
                            site_alerts += 1
                    env_by_site[site_code.upper()] = {
                        "devices": site_devices, "alerts": site_alerts,
                    }
                report["env_health"] = {
                    "by_site": env_by_site,
                    "total_alerts": len(all_alerts),
                    "critical_alerts": sum(1 for a in all_alerts if a.get("critical")),
                    "alerts": all_alerts[:200],
                }

            _napalm_update_job(job_id, status="done", progress=100,
                message=f"Global report complete — {total_sites} sites scanned",
                result=report)
        except Exception as e:
            import traceback; traceback.print_exc()
            _napalm_update_job(job_id, status="error", message=str(e))
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"job_id": job_id})


# ── NAPALM Tool 4: Interface Errors ──────────────────────────────────────────

@app.route("/api/napalm/interface-errors", methods=["POST"])
def napalm_interface_errors():
    data = request.json or {}
    site, _err = _resolve_napalm_site(data)
    if _err:
        return _err
    job_id = _napalm_new_job("interface_errors", site)

    def _run():
        try:
            _napalm_update_job(job_id, message=f"Collecting counters from {site.upper()}...")
            results = _napalm_collect_site(site, ["get_facts", "get_interfaces", "get_interfaces_counters"])
            all_errors = []
            for hostname, res in sorted(results.items()):
                if res.get("error"): continue
                counters = res.get("data", {}).get("get_interfaces_counters") or {}
                ifaces = res.get("data", {}).get("get_interfaces") or {}
                for iface, d in counters.items():
                    rx_e, tx_e = d.get("rx_errors", 0), d.get("tx_errors", 0)
                    rx_d, tx_d = d.get("rx_discards", 0), d.get("tx_discards", 0)
                    if rx_e > 0 or tx_e > 0 or rx_d > 0 or tx_d > 0:
                        ii = ifaces.get(iface, {})
                        all_errors.append({"hostname": hostname, "interface": iface,
                            "description": (ii.get("description") or "")[:50],
                            "is_up": ii.get("is_up", False), "speed": ii.get("speed", 0),
                            "rx_errors": rx_e, "tx_errors": tx_e,
                            "rx_discards": rx_d, "tx_discards": tx_d,
                            "total": rx_e + tx_e + rx_d + tx_d})
            all_errors.sort(key=lambda x: x["total"], reverse=True)
            _napalm_update_job(job_id, status="done", progress=100,
                message=f"{len(all_errors)} interfaces with errors",
                result={"site": site.upper(), "errors": all_errors[:100],
                    "total_interfaces_with_errors": len(all_errors)})
        except Exception as e:
            _napalm_update_job(job_id, status="error", message=str(e))
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"job_id": job_id})


# ── NAPALM Tool 5: LLDP Topology ─────────────────────────────────────────────

@app.route("/api/napalm/lldp-topology", methods=["POST"])
def napalm_lldp_topology():
    data = request.json or {}
    site, _err = _resolve_napalm_site(data)
    if _err:
        return _err
    job_id = _napalm_new_job("lldp_topology", site)

    def _run():
        try:
            _napalm_update_job(job_id, message=f"Collecting LLDP from {site.upper()}...")
            results = _napalm_collect_site(site, ["get_facts", "get_lldp_neighbors"])
            links, nodes = [], set()
            for hostname, res in sorted(results.items()):
                if res.get("error"): continue
                nodes.add(hostname)
                lldp = res.get("data", {}).get("get_lldp_neighbors") or {}
                for lp, nbrs in lldp.items():
                    for n in nbrs:
                        remote = n.get("hostname", "").split(".")[0].lower()
                        rp = n.get("port", "")
                        if remote:
                            nodes.add(remote)
                            links.append({"source": hostname, "source_port": lp, "target": remote, "target_port": rp})
            seen = set()
            unique = []
            for l in links:
                key = tuple(sorted([f"{l['source']}:{l['source_port']}", f"{l['target']}:{l['target_port']}"]))
                if key not in seen:
                    seen.add(key)
                    unique.append(l)
            _napalm_update_job(job_id, status="done", progress=100,
                message=f"{len(nodes)} nodes, {len(unique)} links",
                result={"site": site.upper(), "nodes": sorted(nodes), "links": unique,
                    "total_nodes": len(nodes), "total_links": len(unique)})
        except Exception as e:
            _napalm_update_job(job_id, status="error", message=str(e))
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"job_id": job_id})


# ── NAPALM Tool 6: Full Site Collection ──────────────────────────────────────

@app.route("/api/napalm/site-collect", methods=["POST"])
def napalm_site_collect():
    data = request.json or {}
    site, _err = _resolve_napalm_site(data)
    if _err:
        return _err
    job_id = _napalm_new_job("site_collect", site)

    def _run():
        try:
            _napalm_update_job(job_id, message=f"Full collection from {site.upper()}...")
            getters = ["get_facts", "get_interfaces", "get_interfaces_ip",
                       "get_interfaces_counters", "get_lldp_neighbors", "get_arp_table", "get_environment"]
            results = _napalm_collect_site(site, getters)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_path = os.path.join(_napalm_output_dir, f"{site.upper()}_Collection_{ts}.json")
            with open(json_path, "w") as f:
                json.dump(results, f, indent=2, default=str)
            summary = []
            for hostname, res in sorted(results.items()):
                facts = res.get("data", {}).get("get_facts") or {}
                ifaces = res.get("data", {}).get("get_interfaces") or {}
                iface_ip = res.get("data", {}).get("get_interfaces_ip") or {}
                lldp = res.get("data", {}).get("get_lldp_neighbors") or {}
                arp = res.get("data", {}).get("get_arp_table") or []
                ip_count = sum(len(addrs) for fam in iface_ip.values() for addrs in fam.values())
                summary.append({"hostname": hostname, "model": facts.get("model", "-"),
                    "version": facts.get("os_version", "-"), "interfaces": len(ifaces),
                    "ips": ip_count, "lldp_neighbors": sum(len(n) for n in lldp.values()),
                    "arp_entries": len(arp) if isinstance(arp, list) else 0, "error": res.get("error")})
            _napalm_update_job(job_id, status="done", progress=100,
                message=f"Collected {len(summary)} devices → {os.path.basename(json_path)}",
                result={"site": site.upper(), "devices": summary, "output_file": json_path})
        except Exception as e:
            _napalm_update_job(job_id, status="error", message=str(e))
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"job_id": job_id})


# ── NAPALM Tool 7: Pre/Post Snapshot ─────────────────────────────────────────

@app.route("/api/napalm/snapshot", methods=["POST"])
def napalm_snapshot():
    data = request.json or {}
    label = data.get("label", "snapshot")
    site, _err = _resolve_napalm_site(data)
    if _err:
        return _err
    job_id = _napalm_new_job("snapshot", site)

    def _run():
        try:
            _napalm_update_job(job_id, message=f"Taking {label.upper()} snapshot of {site.upper()}...")
            getters = ["get_facts", "get_interfaces", "get_interfaces_ip", "get_bgp_neighbors", "get_lldp_neighbors"]
            results = _napalm_collect_site(site, getters)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            snap_file = os.path.join(_napalm_snapshots_dir, f"{site.upper()}_{label}_{ts}.json")
            with open(snap_file, "w") as f:
                json.dump(results, f, indent=2, default=str)
            _napalm_update_job(job_id, status="done", progress=100,
                message=f"{label.upper()} snapshot saved: {os.path.basename(snap_file)}",
                result={"site": site.upper(), "label": label, "file": os.path.basename(snap_file),
                    "path": snap_file, "devices": len(results), "timestamp": ts})
        except Exception as e:
            _napalm_update_job(job_id, status="error", message=str(e))
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/api/napalm/snapshots/<site>")
def napalm_list_snapshots(site):
    site = site.upper()
    snaps = sorted([f for f in os.listdir(_napalm_snapshots_dir)
                    if f.startswith(site) and f.endswith(".json")], reverse=True)
    result = []
    for s in snaps:
        fp = os.path.join(_napalm_snapshots_dir, s)
        result.append({"file": s, "size": os.path.getsize(fp),
            "modified": datetime.fromtimestamp(os.path.getmtime(fp)).isoformat()})
    return jsonify(result)


# ── NAPALM Tool 8: Snapshot Diff ─────────────────────────────────────────────

@app.route("/api/napalm/snapshot-diff", methods=["POST"])
def napalm_snapshot_diff():
    data = request.json or {}
    file_a = os.path.basename(data.get("file_a", ""))
    file_b = os.path.basename(data.get("file_b", ""))
    if not file_a or not file_b:
        return jsonify({"error": "file_a and file_b are required"}), 400
    path_a = os.path.join(_napalm_snapshots_dir, file_a)
    path_b = os.path.join(_napalm_snapshots_dir, file_b)
    # Prevent path traversal — ensure resolved path stays within snapshot dir
    if not os.path.realpath(path_a).startswith(os.path.realpath(_napalm_snapshots_dir)) or \
       not os.path.realpath(path_b).startswith(os.path.realpath(_napalm_snapshots_dir)):
        return jsonify({"error": "Invalid file path"}), 400
    if not os.path.exists(path_a) or not os.path.exists(path_b):
        return jsonify({"error": "Snapshot file not found"}), 404
    with open(path_a) as f: snap_a = json.load(f)
    with open(path_b) as f: snap_b = json.load(f)
    diffs = []
    for host in sorted(set(snap_a.keys()) | set(snap_b.keys())):
        a, b = snap_a.get(host, {}), snap_b.get(host, {})
        if host not in snap_a:
            diffs.append({"hostname": host, "type": "device_added", "interface": "", "details": "New device in POST"})
            continue
        if host not in snap_b:
            diffs.append({"hostname": host, "type": "device_removed", "interface": "", "details": "Device missing in POST"})
            continue
        # Interface state changes
        ai = a.get("data", {}).get("get_interfaces") or {}
        bi = b.get("data", {}).get("get_interfaces") or {}
        for iface in set(ai.keys()) | set(bi.keys()):
            au, bu = ai.get(iface, {}).get("is_up"), bi.get(iface, {}).get("is_up")
            if au != bu:
                diffs.append({"hostname": host, "type": "interface_state", "interface": iface,
                    "details": f"{'UP' if au else 'DOWN'} → {'UP' if bu else 'DOWN'}"})
        # BGP state changes
        ab = a.get("data", {}).get("get_bgp_neighbors") or {}
        bb = b.get("data", {}).get("get_bgp_neighbors") or {}
        ap, bp = {}, {}
        for vrf, vd in ab.items():
            for pip, pd in vd.get("peers", {}).items(): ap[pip] = pd.get("is_up", False)
        for vrf, vd in bb.items():
            for pip, pd in vd.get("peers", {}).items(): bp[pip] = pd.get("is_up", False)
        for pip in set(ap.keys()) | set(bp.keys()):
            au, bu = ap.get(pip), bp.get(pip)
            if au != bu:
                diffs.append({"hostname": host, "type": "bgp_state", "interface": pip,
                    "details": f"{'UP' if au else 'DOWN'} → {'UP' if bu else 'DOWN'}"})
        # IP changes
        aip = a.get("data", {}).get("get_interfaces_ip") or {}
        bip = b.get("data", {}).get("get_interfaces_ip") or {}
        af = set()
        for iface, fams in aip.items():
            for fam, addrs in fams.items():
                for addr in addrs: af.add(f"{iface}:{addr}")
        bf = set()
        for iface, fams in bip.items():
            for fam, addrs in fams.items():
                for addr in addrs: bf.add(f"{iface}:{addr}")
        for ip in af - bf:
            diffs.append({"hostname": host, "type": "ip_removed", "interface": ip.split(":")[0], "details": f"IP removed: {ip.split(':')[1]}"})
        for ip in bf - af:
            diffs.append({"hostname": host, "type": "ip_added", "interface": ip.split(":")[0], "details": f"IP added: {ip.split(':')[1]}"})
    return jsonify({"file_a": file_a, "file_b": file_b, "total_changes": len(diffs), "changes": diffs})


# ══════════════════════════════════════════════════════════════════════════════
# ── 💬 AI COMMAND — Natural Language → CLI (P1) ──────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

# Vendor-specific CLI translation hints fed to the LLM
_NL_SYSTEM = """You are a network CLI expert for Juniper JunOS, Arista EOS, and FRRouting (FRR).
Given a plain-English question and the target device type, return ONLY a JSON object with no other text:
{"cli": "<exact CLI command>"}
Examples:
- frr + "show bgp summary" -> {"cli": "show bgp summary"}
- junos + "show interfaces" -> {"cli": "show interfaces terse"}
- eos + "bgp neighbors" -> {"cli": "show bgp neighbors"}
Return ONLY the JSON object. No markdown, no explanation, no code fences."""

# ══════════════════════════════════════════════════════════════════════════════
# ── 🧠 netlog-ai KNOWLEDGE LAYER (RAG over sanitized configs) ───────────────
# ══════════════════════════════════════════════════════════════════════════════
#
# netlog-ai (port 6060) already stores sanitized configs + per-device compliance
# findings + a RAG copilot for both fabrics. We don't reimplement any of that;
# we proxy it and inject the result into our LLM-driven endpoints so every
# answer is grounded in *this specific* device's actual config.

_NETLOG_URL = os.environ.get("NETLOG_AI_URL", "http://localhost:6060")
_NETLOG_TOKEN = os.environ.get("NETLOG_AI_API_TOKEN", "")

# Hostname → netlog-ai site_id. We currently have two clab + DCN labs.
_NETLOG_HOST_TO_SITE = {
    # Clos-EVPN clab fabric → clab-clos-evpn
    **{h: "clab-clos-evpn" for h in
       ("spine1", "spine2", "spine3",
        "leaf1", "leaf2", "leaf3", "leaf4", "leaf5", "leaf6")},
    # 10-device FRR DCN lab — netlog-ai has a dedicated dcn-lab bundle with
    # the same hostnames (verified live via /api/sites).
    **{h: "dcn-lab" for h in
       ("de-fra-core-01", "de-fra-core-02", "uk-lon-core-01", "nl-ams-core-01",
        "us-nyc-core-01", "de-fra-edge-01", "uk-lon-edge-01", "nl-ams-edge-01",
        "uk-lon-dist-01", "de-fra-dist-01")},
}

def _netlog_headers() -> dict:
    h = {"Content-Type": "application/json"}
    if _NETLOG_TOKEN:
        h["X-API-Token"] = _NETLOG_TOKEN
    return h


def _netlog_site_for(hostname: str) -> str | None:
    """Map a tool hostname to a netlog-ai site_id, or None when unknown."""
    if not hostname:
        return None
    h = hostname.lower()
    if h in _NETLOG_HOST_TO_SITE:
        return _NETLOG_HOST_TO_SITE[h]
    # Heuristic fallbacks
    if any(p in h for p in ("spine", "leaf", "host")) and not h.startswith(("de-", "uk-", "nl-", "us-", "eu-")):
        return "clab-clos-evpn"
    return None


def _netlog_fetch(path: str, method: str = "GET", body: dict | None = None,
                  timeout: int = 6) -> tuple[int, dict | str | None]:
    """Thin wrapper around requests for netlog-ai endpoints."""
    url = f"{_NETLOG_URL}{path}"
    try:
        if method == "GET":
            r = _requests.get(url, headers=_netlog_headers(), timeout=timeout)
        else:
            r = _requests.post(url, headers=_netlog_headers(),
                               data=_json_mod.dumps(body or {}), timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        app.logger.warning("netlog-ai unreachable at %s: %s", url, exc)
        return 0, None
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text


def _netlog_findings_for(hostname: str) -> list[dict]:
    """Return failed compliance checks for a single device, or [] if unknown."""
    site = _netlog_site_for(hostname)
    if not site:
        return []
    code, data = _netlog_fetch(f"/api/compliance/{site}")
    if code != 200 or not isinstance(data, dict):
        return []
    return [c for c in (data.get("checks") or [])
            if c.get("device", "").lower() == hostname.lower() and not c.get("passed")]


def _netlog_summary_for(hostname: str, max_findings: int = 6) -> str:
    """Short human-readable context block for prompt enrichment."""
    findings = _netlog_findings_for(hostname)
    if not findings:
        return ""
    lines = [f"netlog-ai compliance findings for {hostname}:"]
    for f in findings[:max_findings]:
        sev = (f.get("severity") or "info").upper()
        rule = f.get("rule_name") or f.get("rule_id") or "rule"
        why  = (f.get("reason") or "").strip()[:120]
        lines.append(f"  - [{sev}] {rule}: {why}")
    if len(findings) > max_findings:
        lines.append(f"  - …and {len(findings) - max_findings} more findings")
    return "\n".join(lines)


@app.route("/api/knowledge/sites", methods=["GET"])
def api_knowledge_sites():
    """List netlog-ai site bundles (proxy for /api/sites)."""
    code, data = _netlog_fetch("/api/sites")
    if code != 200:
        return jsonify({"error": "netlog-ai unreachable",
                        "hint": f"start it: cd 04_Scripts_Tools/netlog-ai && .venv/bin/python -m ai_log_analyzer.cli serve"}), 503
    return jsonify(data)


@app.route("/api/knowledge/device/<hostname>", methods=["GET"])
def api_knowledge_device(hostname: str):
    """Return all netlog-ai context for one host: site, findings, topology snippet."""
    site = _netlog_site_for(hostname)
    if not site:
        return jsonify({"hostname": hostname, "site": None, "findings": [],
                        "note": "hostname not mapped to a netlog-ai site bundle"}), 200
    findings = _netlog_findings_for(hostname)
    return jsonify({
        "hostname": hostname, "site": site,
        "findings_failed": findings,
        "findings_total": len(findings),
        "netlog_url": f"{_NETLOG_URL}/?site={site}",
    })


@app.route("/api/knowledge/copilot", methods=["POST"])
def api_knowledge_copilot():
    """Proxy netlog-ai's RAG copilot. Body: {question, hostname?, site_id?}"""
    body = request.get_json(silent=True) or {}
    question = (body.get("question") or "").strip()
    if not question:
        return jsonify({"error": "question required"}), 400
    site_id  = (body.get("site_id")  or "").strip()
    hostname = (body.get("hostname") or "").strip()
    if not site_id and hostname:
        site_id = _netlog_site_for(hostname) or ""
    payload = {"question": question}
    if site_id:  payload["site_id"]  = site_id
    if hostname: payload["hostname"] = hostname
    code, data = _netlog_fetch("/api/copilot", method="POST", body=payload, timeout=30)
    if code != 200:
        return jsonify({"error": "netlog-ai copilot unavailable",
                        "status_code": code, "detail": data}), 503
    return jsonify(data)


@app.route("/api/knowledge/correlate", methods=["POST"])
def api_knowledge_correlate():
    """For every host in the request, return its netlog-ai findings. Used by
    the Alerts tab to enrich each alert card with the device's known issues.

    Body: {"hostnames": ["leaf3", "spine1", ...]}
    """
    body = request.get_json(silent=True) or {}
    hostnames = body.get("hostnames") or []
    out: dict[str, list[dict]] = {}
    for h in hostnames[:32]:  # hard cap
        out[h] = _netlog_findings_for(h)
    return jsonify({"per_device_findings": out})


_GNMIC_API_URL = os.environ.get("GNMIC_API_URL", "http://localhost:7890")


@app.route("/api/telemetry/gnmic-status", methods=["GET"])
def api_gnmic_status():
    """Return health of the gnmic streaming-telemetry sidecar.

    The sidecar subscribes to Nokia SR Linux nodes on the clab fabric and
    pushes ON_CHANGE BGP/intf state + SAMPLE counters into the same
    InfluxDB bucket the legacy collector writes to. Cisco/Arista/FRR keep
    using the 15-second docker-exec collector — see OPTIMIZATION_ROADMAP.md
    §2 for the cEOS Octa gNMI quirk that blocks Arista from this path.
    """
    out: dict = {"sidecar_url": _GNMIC_API_URL, "available": False, "targets": []}
    try:
        r = _requests.get(f"{_GNMIC_API_URL}/api/v1/targets", timeout=3)
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"gnmic API unreachable: {exc}"
        return jsonify(out), 200
    if r.status_code != 200:
        out["error"] = f"gnmic API returned {r.status_code}"
        return jsonify(out), 200

    targets_raw = r.json() or {}
    out["available"] = True
    for name, info in targets_raw.items():
        subs = info.get("subscriptions") or []
        # gnmic returns subscriptions as either ["name1", "name2"] or
        # [{"name": "..."}] depending on version — handle both.
        sub_names = [s if isinstance(s, str) else s.get("name") for s in subs]
        out["targets"].append({
            "name": name,
            "subscriptions": len(subs),
            "subscription_names": sub_names,
        })

    # Cross-check freshness against InfluxDB — what's the most recent
    # gnmic-sourced point per target (in seconds)?
    # gnmic preserves subscription names as measurement names (with hyphens).
    # We use `intf-counters` (10 s SAMPLE) tagged with the `source` tag that
    # ONLY gnmic writes. Filtering on `source` distinguishes the streaming
    # pipeline from the other collectors that share the bucket — so a green
    # freshness now genuinely means gnmic is healthy, not that some other
    # collector happens to be writing.
    flux = '''
      from(bucket:"network-telemetry")
        |> range(start:-2m)
        |> filter(fn:(r) => r._measurement == "intf-counters" and exists r.source)
        |> group(columns:["source"])
        |> last()
        |> keep(columns:["_time", "source"])
    '''
    rows = _influx_query_csv(flux, timeout=5)
    now = time.time()
    fresh: dict[str, float] = {}
    for row in rows:
        ts_raw = row.get("_time", "")
        try:
            from datetime import datetime as _dt
            ts = _dt.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()
            fresh[row.get("source", "")] = round(now - ts, 1)
        except Exception:
            continue
    out["freshness_sec_per_host"] = fresh
    out["all_fresh_under_30s"] = all(v < 30 for v in fresh.values()) if fresh else False
    # If gnmic writes haven't reached InfluxDB at all, surface a hint so the UI
    # can show "configured but no data" instead of a misleading green check.
    if not fresh and out["target_count"] > 0:
        out["warning"] = ("gnmic has subscriptions configured but no data "
                          "found in InfluxDB — check SRL config (e.g. BGP not "
                          "configured → no bgp-session-state events) or "
                          "gnmic InfluxDB output config")
    out["target_count"] = len(out["targets"])
    return jsonify(out)


@app.route("/api/ai-command", methods=["POST"])
def api_ai_command():
    """Translate natural language to CLI, execute via SSH, explain output with LLM."""
    data = request.get_json(force=True) or {}
    query: str = (data.get("query") or "").strip()
    hostname: str = (data.get("hostname") or "").strip()
    if not query:
        return jsonify({"error": "query required"}), 400

    # Resolve device
    dev = get_device_by_hostname(hostname)
    dtype = dev.get("type", "junos") if dev else "junos"

    # Step 1: LLM translates NL → CLI
    user_prompt = f'Device type: {dtype}\nQuestion: "{query}"'
    translation_raw = _llm_query(_NL_SYSTEM, user_prompt, max_tokens=150)
    if not translation_raw:
        return jsonify({"error": "LLM unavailable — set LLM_ENABLED=true and MODEL_RUNNER_URL"}), 503

    try:
        import json as _json, re as _re
        # Extract JSON object even if LLM adds preamble text
        json_match = _re.search(r'\{[^}]+\}', translation_raw, _re.DOTALL)
        translated = _json.loads(json_match.group(0) if json_match else translation_raw)
        cli_cmd = translated.get("cli", "").strip()
    except Exception:
        # LLM returned plain text — strip markdown fences and use directly
        cli_cmd = _re.sub(r'^```\w*\n?|```$', '', translation_raw.strip(), flags=_re.M).strip()

    if not cli_cmd:
        return jsonify({"error": "LLM could not translate query to CLI"}), 422

    result: dict = {"query": query, "hostname": hostname, "cli": cli_cmd, "output": None, "explanation": None}

    # Step 2: Execute via SSH (if device is known)
    if dev:
        ip = dev.get("ip") or dev.get("host", "")
        ssh_out = run_command_on_device(ip, dtype, cli_cmd, port=dev.get("port", 22))
        result["output"] = ssh_out
        ssh_text = ssh_out.get("output", "") if isinstance(ssh_out, dict) else str(ssh_out)
    else:
        ssh_text = ""
        result["output"] = f"(device '{hostname}' not in inventory — command translation only)"

    # Step 3: LLM explains the command + output (always, even if SSH failed).
    # Enrich with netlog-ai compliance findings for this device so the
    # explanation is grounded in the actual sanitized config of THIS host.
    knowledge_ctx = _netlog_summary_for(hostname) if hostname else ""
    explain_sys = (
        "You are a senior network engineer. "
        "Explain what the CLI command does and what the output means in 2-3 sentences of plain English. "
        "If knowledge-base context is provided, cite specific findings when they explain the output."
    )
    parts = [f"Command: {cli_cmd}"]
    if ssh_text:
        parts.append(f"Output:\n{ssh_text[:3000]}")
    else:
        parts.append("(No device output — lab containers may not be running.)")
    if knowledge_ctx:
        parts.append(knowledge_ctx)
    explanation = _llm_query(explain_sys, "\n\n".join(parts), max_tokens=350)
    result["explanation"] = _clean_llm_response(explanation) if explanation else None
    if knowledge_ctx:
        result["knowledge_used"] = True
        result["netlog_site"] = _netlog_site_for(hostname)

    return jsonify(result)


# ══════════════════════════════════════════════════════════════════════════════
# ── 🔍 BATFISH PRE-DEPLOY VALIDATOR (P1) ─────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

import re as _re

# Rule catalogue: (regex_pattern, severity, message)
_BATFISH_RULES: list[tuple[str, str, str]] = [
    (r'authentication-key\s+"[^$]',       "error",   "BGP auth key in plaintext — use encrypted format ($9$...)"),
    (r'no\s+export',                       "pass",    "Export policy present on BGP peer"),
    (r'dead-interval\s+(\d+)',             "warn",    "OSPF dead-interval >12s — consider reducing (3× hello)"),
    (r'bfd',                               "pass",    "BFD configured for sub-second failure detection"),
    (r'authentication\s+md5',              "pass",    "BGP MD5 authentication present"),
    (r'area\s+0\.0\.0\.0',                "pass",    "OSPF area 0.0.0.0 correctly configured"),
    (r'local-address\s+\d',               "pass",    "Local-address specified on BGP group"),
    (r'log-updown',                        "pass",    "BGP log-updown enabled"),
    (r'type\s+external',                   "pass",    "BGP peer type explicitly set"),
    (r'route-policy|export|import',        "pass",    "Route policy reference found"),
    (r'prefix-limit',                      "pass",    "Prefix-limit configured on peer"),
]

@app.route("/api/batfish/analyze", methods=["POST"])
def api_batfish_analyze():
    """Static config analysis using rule-based Batfish-style checks.
    Falls back to LLM analysis when pybatfish is not installed."""
    data = request.get_json(force=True) or {}
    config_text: str = (data.get("config") or "").strip()
    if not config_text:
        return jsonify({"error": "config text required"}), 400

    findings: list[dict] = []
    for pattern, severity, message in _BATFISH_RULES:
        match = _re.search(pattern, config_text, _re.IGNORECASE)
        if severity == "pass" and match:
            findings.append({"severity": "pass", "message": f"PASS: {message}"})
        elif severity in ("error", "warn") and match:
            findings.append({"severity": severity, "message": f"{severity.upper()}: {message}"})
        elif severity == "pass" and not match:
            pass  # only report passes that actually matched

    # Check missing export policy (if type external present but no export)
    if _re.search(r"type\s+external", config_text, _re.I) and not _re.search(r"export\s+", config_text, _re.I):
        findings.append({"severity": "error", "message": "ERROR: Missing export policy on external BGP peer — may leak internal prefixes"})

    # Check hold-time value — only warn when > 30s
    ht_match = _re.search(r"hold-time\s+(\d+)", config_text, _re.I)
    if ht_match and int(ht_match.group(1)) > 30:
        findings.append({
            "severity": "warn",
            "message": f"WARN: BGP hold-time {ht_match.group(1)}s — recommended ≤30s for fast failover",
        })

    # LLM enhancement: additional insights
    llm_summary = None
    if LLM_ENABLED:
        sys_p = "You are a network security and reliability expert. Analyze this config snippet for security issues, best-practice violations, and reliability risks. Be concise — 2 sentences max."
        llm_summary = _llm_query(sys_p, f"Config:\n{config_text[:2000]}", max_tokens=200)
        if llm_summary:
            llm_summary = _clean_llm_response(llm_summary)

    errors   = [f for f in findings if f["severity"] == "error"]
    warnings = [f for f in findings if f["severity"] == "warn"]
    passes   = [f for f in findings if f["severity"] == "pass"]

    return jsonify({
        "errors": len(errors),
        "warnings": len(warnings),
        "passes": len(passes),
        "findings": findings,
        "llm_summary": llm_summary,
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── ⚡ NORNIR PARALLEL ENGINE (P1) ───────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

import time as _time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Task definitions: name → (command_junos, command_eos, result_parser_hint)
_NORNIR_TASKS: dict[str, dict] = {
    # Per-task per-vendor command templates. Keys:
    #   cmd_junos     · cmd_eos · cmd_frr · cmd_srl  (sr_cli) · cmd_ceos  (Cli -p 15)
    # When a vendor-specific key is missing the dispatcher falls through to the
    # closest match. UI aliases ("lldp", "lldp_neighbors", "lldp_discovery",
    # "config_compliance") are mapped via _NORNIR_ALIASES below.
    "bgp_health":     {"cmd_junos": "show bgp summary",       "cmd_eos": "show bgp summary",            "cmd_frr": "show bgp summary",      "cmd_srl": "show network-instance default protocols bgp neighbor", "cmd_ceos": "show ip bgp summary", "label": "BGP Health Check"},
    "interface_check":{"cmd_junos": "show interfaces terse",  "cmd_eos": "show interfaces",             "cmd_frr": "show interface brief",  "cmd_srl": "show interface", "cmd_ceos": "show interfaces status", "label": "Interface Status"},
    "version":        {"cmd_junos": "show version",           "cmd_eos": "show version",                "cmd_frr": "show version",          "cmd_srl": "info from state /system information version", "cmd_ceos": "show version", "label": "Software Version"},
    "routing_table":  {"cmd_junos": "show route summary",     "cmd_eos": "show ip route summary",       "cmd_frr": "show ip route summary", "cmd_srl": "show network-instance default route-table ipv4-unicast summary", "cmd_ceos": "show ip route summary", "label": "Routing Table Summary"},
    "alarm_check":    {"cmd_junos": "show chassis alarms",    "cmd_eos": "show system environment all", "cmd_frr": "show ip ospf neighbor", "cmd_srl": "show system events", "cmd_ceos": "show logging severity errors", "label": "System Alarms / OSPF"},
    # NEW vendor-aware tasks for the LLDP/Compliance buttons the UI exposed:
    "lldp_neighbors": {"cmd_junos": "show lldp neighbors",    "cmd_eos": "show lldp neighbors",         "cmd_frr": "show lldp neighbors",   "cmd_srl": "show system lldp neighbor", "cmd_ceos": "show lldp neighbors", "label": "LLDP Discovery"},
    "config_compliance":{"cmd_junos": "show configuration | display set | count", "cmd_eos": "show running-config | include hostname|interface|bgp|ospf", "cmd_frr": "show running-config", "cmd_srl": "info /", "cmd_ceos": "show running-config | include hostname|interface|bgp|ospf", "label": "Config Compliance"},
}
# UI sends short names — map them to canonical task keys.
_NORNIR_ALIASES = {
    "bgp": "bgp_health", "bgp-health": "bgp_health",
    "iface-errors": "interface_check", "interfaces": "interface_check",
    "config-diff": "config_compliance", "compliance": "config_compliance",
    "lldp": "lldp_neighbors", "lldp-discovery": "lldp_neighbors",
}

def _nornir_worker(dev: dict, cmd: str) -> dict:
    """Run a single SSH command on one device and return structured result."""
    start = _time.monotonic()
    try:
        ip = dev.get("ip") or dev.get("host", "")
        dtype = dev.get("type", "junos")
        result = run_command_on_device(ip, dtype, cmd, port=dev.get("port", 22))
        elapsed = _time.monotonic() - start
        # run_command_on_device returns {success, output, command}
        out_text = result.get("output", "") if isinstance(result, dict) else str(result)
        if not result.get("success", True):
            return {"hostname": dev["hostname"], "status": "error", "output": out_text, "elapsed": round(elapsed, 2)}
        lower = out_text.lower()
        if "error" in lower or "alarm" in lower or "down" in lower:
            status = "warn"
        elif out_text and len(out_text.strip()) > 10:
            status = "ok"
        else:
            status = "error"
        return {"hostname": dev["hostname"], "status": status, "output": out_text, "elapsed": round(elapsed, 2)}
    except Exception as exc:
        return {"hostname": dev["hostname"], "status": "error", "output": str(exc), "elapsed": round(_time.monotonic() - start, 2)}


@app.route("/api/nornir/run", methods=["POST"])
def api_nornir_run():
    """Parallel multi-device task execution using ThreadPoolExecutor (Nornir-style)."""
    data = request.get_json(force=True) or {}
    task_raw: str = (data.get("task") or "bgp_health").strip()
    task_name = _NORNIR_ALIASES.get(task_raw, task_raw)
    site_filter: str = (data.get("site") or "").strip().lower()
    workers: int = min(int(data.get("workers") or 50), 200)

    task_def = _NORNIR_TASKS.get(task_name) or _NORNIR_TASKS["bgp_health"]

    # Filter devices by site. Linux hosts ("role=host", "type=linux") cannot
    # accept network CLI — exclude them from Nornir runs entirely so they
    # don't pollute the result with N error rows. They're still discoverable
    # via the inventory / connectivity-test workflow.
    targets = [d for d in DEVICES
               if (not site_filter or d.get("site", "").lower() == site_filter)
               and d.get("type", "").lower() != "linux"
               and d.get("role", "").lower() != "host"]
    if not targets:
        return jsonify({"error": f"No devices found for site '{site_filter}'"}), 404

    overall_start = _time.monotonic()
    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as pool:
        def _cmd_for(dev: dict) -> str:
            t = dev.get("type", "junos")
            vc = (dev.get("vendor_canonical") or dev.get("vendor") or "").lower()
            # Clab-specific vendor commands first — these route via docker exec
            # in run_command_on_device's clab shim.
            if vc == "nokia-srl" and "cmd_srl" in task_def:
                return task_def["cmd_srl"]
            if vc == "arista-eos" and dev.get("container") and "cmd_ceos" in task_def:
                return task_def["cmd_ceos"]
            if t == "eos":
                return task_def.get("cmd_eos", task_def["cmd_junos"])
            if t == "frr":
                return task_def.get("cmd_frr", task_def["cmd_junos"])
            return task_def["cmd_junos"]
        futs = {pool.submit(_nornir_worker, dev, _cmd_for(dev)): dev for dev in targets}
        for fut in as_completed(futs):
            results.append(fut.result())

    elapsed = round(_time.monotonic() - overall_start, 2)
    ok_count   = sum(1 for r in results if r["status"] == "ok")
    warn_count = sum(1 for r in results if r["status"] == "warn")
    err_count  = sum(1 for r in results if r["status"] == "error")

    return jsonify({
        "task": task_def["label"],
        "site": site_filter or "all",
        "devices": len(targets),
        "workers": workers,
        "elapsed": elapsed,
        "ok": ok_count,
        "warn": warn_count,
        "error": err_count,
        "results": results,
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── 📸 pyATS STATE DIFF (P2) ─────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

import json as _json_mod
import hashlib as _hashlib

# In-memory snapshot store keyed by (hostname, label)
_PYATS_SNAPSHOTS: dict[str, dict] = {}

def _collect_state_snapshot(hostname: str) -> dict:
    """Collect structured state from a device via NAPALM getters."""
    dev = get_device_by_hostname(hostname)
    if not dev:
        return {"error": f"Device '{hostname}' not found"}
    try:
        import napalm as _napalm
        driver_name = "junos" if dev.get("type", "junos") == "junos" else "eos"
        driver = _napalm.get_network_driver(driver_name)
        ip = dev.get("ip") or dev.get("host", "")
        conn = driver(hostname=ip, username=os.environ.get("SSH_USER", "netadmin"),
                      password="", optional_args={"key_file": SSH_KEY_PATH})
        conn.open()
        state = {
            "interfaces":    conn.get_interfaces(),
            "bgp_neighbors": conn.get_bgp_neighbors(),
            "interfaces_ip": conn.get_interfaces_ip(),
        }
        conn.close()
        return state
    except Exception as exc:
        return {"error": str(exc)}


@app.route("/api/pyats/snapshot", methods=["POST"])
def api_pyats_snapshot():
    """Take a named state snapshot (PRE or POST) for a device."""
    data = request.get_json(force=True) or {}
    hostname: str = (data.get("hostname") or "").strip()
    label: str    = (data.get("label") or "pre").strip().lower()  # "pre" or "post"
    if not hostname:
        return jsonify({"error": "hostname required"}), 400

    snapshot = _collect_state_snapshot(hostname)
    key = f"{hostname}:{label}"
    # Snapshots can be large (BGP+interface state for one device) — cap at 50
    _bounded_insert(_PYATS_SNAPSHOTS, key,
                    {"ts": _time.time(), "data": snapshot, "hostname": hostname, "label": label},
                    max_size=50)
    digest = _hashlib.md5(_json_mod.dumps(snapshot, sort_keys=True).encode()).hexdigest()[:8]
    return jsonify({"hostname": hostname, "label": label, "digest": digest, "error": snapshot.get("error")})


@app.route("/api/pyats/diff", methods=["POST"])
def api_pyats_diff():
    """Compare PRE and POST snapshots and return structured diff."""
    data = request.get_json(force=True) or {}
    hostname: str = (data.get("hostname") or "").strip()
    if not hostname:
        return jsonify({"error": "hostname required"}), 400

    pre  = _PYATS_SNAPSHOTS.get(f"{hostname}:pre")
    post = _PYATS_SNAPSHOTS.get(f"{hostname}:post")
    if not pre or not post:
        return jsonify({"error": "both PRE and POST snapshots required"}), 422

    diffs: list[dict] = []
    # Interface up/down changes
    for iface in set(pre["data"].get("interfaces", {}).keys()) | set(post["data"].get("interfaces", {}).keys()):
        pa = pre["data"].get("interfaces", {}).get(iface, {}).get("is_up")
        pb = post["data"].get("interfaces", {}).get(iface, {}).get("is_up")
        if pa != pb:
            diffs.append({"type": "interface", "name": iface,
                          "before": "UP" if pa else "DOWN", "after": "UP" if pb else "DOWN"})
    # BGP peer changes
    for vrf, vd in (post["data"].get("bgp_neighbors") or {}).items():
        for pip, pd in vd.get("peers", {}).items():
            pre_up = (pre["data"].get("bgp_neighbors") or {}).get(vrf, {}).get("peers", {}).get(pip, {}).get("is_up")
            post_up = pd.get("is_up")
            if pre_up != post_up:
                diffs.append({"type": "bgp", "name": pip,
                              "before": "UP" if pre_up else "DOWN", "after": "UP" if post_up else "DOWN"})

    return jsonify({
        "hostname": hostname,
        "pre_ts": pre["ts"], "post_ts": post["ts"],
        "total_changes": len(diffs),
        "diffs": diffs,
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── 🔁 CLOSED-LOOP CHANGE PIPELINE (Roadmap #4) ─────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
#
# Single endpoint that chains the existing change-management stages into one
# governed operation:
#
#   1. Predict    — digital-twin what-if (predict_engine.predict)
#                   REJECT verdict short-circuits the whole pipeline
#   2. Batfish    — LLM static-config analysis (blast radius if errors)
#   3. Apply gate — Health Gate (RFC 6241 §8.4 confirmed-commit) runs:
#                       3a. PRE-snapshot (capture state)
#                       3b. Apply (commit-confirmed on Junos · -c on FRR)
#                       3c. Watch (TIMEOUT_S; monitor BGP + interfaces)
#                       3d. Decide (confirm OR roll back automatically)
#   4. POST diff  — pyATS structured diff PRE vs POST
#   5. Intent     — verify config claims match observed reachability
#
# The whole flow runs in a background thread; the endpoint returns a
# change_id immediately. Use GET /api/change/closed-loop/<id> to poll.
#
# This is the TM Forum ANL L3 maturity move — Awareness + Analysis +
# Decision + Execution + governed rollback in one user action.
# ══════════════════════════════════════════════════════════════════════════════

import threading as _cl_threading
import uuid as _cl_uuid
from collections import deque as _cl_deque

_CLOSED_LOOP_LOCK = _cl_threading.RLock()
_CLOSED_LOOP_JOBS: dict[str, dict] = {}
_CLOSED_LOOP_HISTORY: _cl_deque = _cl_deque(maxlen=200)


def _cl_now_ts() -> float:
    return _time.time()


def _cl_set_phase(job: dict, phase: str, **fields) -> None:
    """Update the phase + arbitrary fields atomically."""
    with _CLOSED_LOOP_LOCK:
        job["phase"] = phase
        job["last_update_ts"] = _cl_now_ts()
        job["timeline"].append({"phase": phase, "ts": _cl_now_ts(), **fields})
        job.update(fields)


def _cl_finish(job: dict, verdict: str, summary: str) -> None:
    """Mark the job done with a final verdict (APPROVED / REJECTED / ROLLED_BACK / FAILED)."""
    with _CLOSED_LOOP_LOCK:
        job["phase"] = "done"
        job["verdict"] = verdict
        job["summary"] = summary
        job["finished_ts"] = _cl_now_ts()
        job["elapsed_s"] = round(job["finished_ts"] - job["started_ts"], 2)


def _cl_run(job: dict, body: dict) -> None:
    """Background worker — chain every stage of the change pipeline.

    On any stage error or REJECT verdict, the pipeline short-circuits with
    an explanatory summary. Health Gate handles its own rollback; we surface
    it as `verdict=ROLLED_BACK`.
    """
    hostname        = job["hostname"]
    proposed_change = body.get("proposed_change") or ""
    timeout_s       = int(body.get("timeout_s") or 30)
    dry_run         = bool(body.get("dry_run", False))
    # Optional skip flags — explicitly lab/demo only. Documented behaviour:
    #  - skip_predict:  don't run digital-twin (use when predict_engine can't
    #                   parse the vendor syntax, e.g. FRR `ip route ...`)
    #  - skip_batfish:  don't run LLM static analysis (use when the change is
    #                   externally pre-validated, OR for testing the apply path
    #                   without depending on non-deterministic LLM output)
    skip_predict    = bool(body.get("skip_predict", False))
    skip_batfish    = bool(body.get("skip_batfish", False))
    # Test-hook pass-through (whitelisted on the health-gate side too)
    _HOOK_KEYS = ("fail_at_phase", "induce_regression_after_s", "induce_alert_spike_after_s")
    hg_hooks = {k: body[k] for k in _HOOK_KEYS if k in body and body[k] is not None}

    try:
        # ─── Stage 1: Predict ────────────────────────────────────────────
        _cl_set_phase(job, "predict")
        if skip_predict:
            job["predict"] = {"verdict": "SKIPPED",
                              "reasons": ["skip_predict=true — operator override"],
                              "ms": 0}
        else:
            try:
                from predict_engine import predict as _predict
                # _build_topology lives in multivendor_extensions
                from multivendor_extensions import _build_topology  # type: ignore
                topo = _build_topology()
                pred = _predict(hostname, proposed_change, topo)
                job["predict"] = {
                    "verdict": pred.verdict,
                    "reasons": list(pred.reasons),
                    "diff":    pred.diff,
                    "ms":      pred.ms,
                }
                if pred.verdict == "REJECT":
                    _cl_finish(job, "REJECTED",
                               f"Predict rejected change: {'; '.join(pred.reasons)}")
                    return
            except Exception as e:
                _cl_finish(job, "FAILED", f"predict stage error: {e}")
                return

        # ─── Stage 2: Batfish blast-radius (LLM) ─────────────────────────
        _cl_set_phase(job, "batfish")
        bf_summary = {"errors": [], "warnings": [], "passed": []}
        if skip_batfish:
            bf_summary["passed"].append("skipped_by_operator")
            job["batfish"] = bf_summary
        else:
            try:
                sys_p = (
                    "You are a Batfish network validation expert. Analyse the proposed "
                    "change for syntax, missing prerequisites, and obvious foot-guns. "
                    "Return JSON only: "
                    '{"errors":[{"check":"...","detail":"..."}],'
                    '"warnings":[{"check":"...","detail":"..."}],'
                    '"passed":["check_name"]}'
                )
                llm_raw = _llm_query(sys_p, f"Device {hostname} change:\n{proposed_change[:2000]}",
                                     max_tokens=600)
                if llm_raw:
                    import re as _re_bf, json as _json_bf
                    m = _re_bf.search(r'\{.*\}', _clean_llm_response(llm_raw), _re_bf.DOTALL)
                    if m:
                        parsed = _json_bf.loads(m.group())
                        bf_summary = {
                            "errors":   parsed.get("errors", []),
                            "warnings": parsed.get("warnings", []),
                            "passed":   parsed.get("passed", []),
                        }
            except Exception as e:
                bf_summary["errors"].append({"check": "llm_failed", "detail": str(e)})
            job["batfish"] = bf_summary

            if bf_summary["errors"]:
                _cl_finish(job, "REJECTED",
                           f"Batfish found {len(bf_summary['errors'])} error(s) — change blocked")
                return

        if dry_run:
            _cl_finish(job, "APPROVED",
                       "Dry-run passed predict + batfish (no apply requested)")
            return

        # ─── Stage 3: Health Gate (PRE-snap + apply + watch + auto-confirm/rollback) ──
        _cl_set_phase(job, "applying")
        try:
            from health_gate import submit as _hg_submit, get_job as _hg_get
            hg_job = _hg_submit(
                hostname=hostname,
                edit_payload=proposed_change,
                timeout_s=timeout_s,
                **hg_hooks,  # forward fail_at_phase / induce_*_after_s test hooks
            )
            job["health_gate_job_id"] = hg_job.job_id
        except Exception as e:
            _cl_finish(job, "FAILED", f"health-gate submit failed: {e}")
            return

        # Poll the gate until it leaves the "applying"/"watching"/"deciding" phases.
        gate_deadline = _cl_now_ts() + timeout_s + 30  # gate's timeout + grace
        gate_final: dict | None = None
        while _cl_now_ts() < gate_deadline:
            _time.sleep(2)
            current = _hg_get(hg_job.job_id)
            if not current:
                break
            with _CLOSED_LOOP_LOCK:
                job["health_gate_phase"] = current.phase
            if current.phase == "done":
                gate_final = current.to_dict()
                break
            if current.phase == "watching":
                _cl_set_phase(job, "watching",
                              health_gate_phase=current.phase)
            elif current.phase == "deciding":
                _cl_set_phase(job, "deciding",
                              health_gate_phase=current.phase)

        if gate_final is None:
            _cl_finish(job, "FAILED", "health-gate timed out waiting for decision")
            return
        job["health_gate"] = gate_final

        # Gate decided. final_verdict is one of {confirmed, abandoned, error}.
        # NOTE: this used to look for `decision` which never existed — the
        # actual field on HealthGateJob is `final_verdict`. Fix from the
        # 2026-05-25 closed-loop bring-up.
        gate_verdict = gate_final.get("final_verdict", "")
        if gate_verdict == "abandoned":
            regressions = gate_final.get("regressions") or []
            reason = "; ".join(regressions[:3]) if regressions else "tolerance exceeded"
            _cl_finish(job, "ROLLED_BACK",
                       f"Health Gate detected regression during watch window — change reverted "
                       f"(reason: {reason})")
            return
        if gate_verdict != "confirmed":
            _cl_finish(job, "FAILED",
                       f"Health Gate ended in unexpected state: final_verdict={gate_verdict!r} "
                       f"error={gate_final.get('error', '')!r}")
            return

        # ─── Stage 4: POST snapshot + structured diff ────────────────────
        _cl_set_phase(job, "post_snapshot")
        try:
            # `_collect_state_snapshot` uses NAPALM which only supports
            # Junos/EOS. FRR devices have neither NETCONF nor eAPI — NAPALM
            # hangs on conn.open() and ThreadPoolExecutor.__exit__ blocks
            # waiting for the orphan thread. Short-circuit on device type
            # rather than fight the executor.
            _dev = get_device_by_hostname(hostname)
            _dtype = (_dev or {}).get("type", "").lower() if _dev else ""
            if _dtype in {"junos", "eos"}:
                # NAPALM-capable. Cap wall time as a belt-and-braces measure.
                import concurrent.futures as _cl_cf
                _ex = _cl_cf.ThreadPoolExecutor(max_workers=1)
                _fut = _ex.submit(_collect_state_snapshot, hostname)
                try:
                    post_snap = _fut.result(timeout=15)
                except _cl_cf.TimeoutError:
                    post_snap = {"error": "snapshot timed out after 15s"}
                _ex.shutdown(wait=False)  # don't block on orphan SSH
            else:
                post_snap = {
                    "skipped": True,
                    "reason":  f"NAPALM doesn't support device type {_dtype!r} — skipped",
                }
            _bounded_insert(_PYATS_SNAPSHOTS, f"{hostname}:post",
                            {"ts": _cl_now_ts(), "data": post_snap,
                             "hostname": hostname, "label": "post"}, max_size=50)
            # Compute pyATS-style diff vs the PRE snapshot health-gate captured
            pre = _PYATS_SNAPSHOTS.get(f"{hostname}:pre")
            diffs: list[dict] = []
            if pre:
                pre_d = pre.get("data", {})
                for iface in (set(pre_d.get("interfaces", {}).keys()) |
                              set(post_snap.get("interfaces", {}).keys())):
                    pa = pre_d.get("interfaces", {}).get(iface, {}).get("is_up")
                    pb = post_snap.get("interfaces", {}).get(iface, {}).get("is_up")
                    if pa != pb:
                        diffs.append({"type": "interface", "name": iface,
                                      "before": "UP" if pa else "DOWN",
                                      "after":  "UP" if pb else "DOWN"})
                for vrf, vd in (post_snap.get("bgp_neighbors") or {}).items():
                    for pip, pd in vd.get("peers", {}).items():
                        pre_up = ((pre_d.get("bgp_neighbors") or {})
                                  .get(vrf, {}).get("peers", {}).get(pip, {}).get("is_up"))
                        post_up = pd.get("is_up")
                        if pre_up != post_up:
                            diffs.append({"type": "bgp", "name": pip,
                                          "before": "UP" if pre_up else "DOWN",
                                          "after":  "UP" if post_up else "DOWN"})
            job["pyats_diff"] = {
                "pre_present": pre is not None,
                "total_changes": len(diffs),
                "diffs": diffs,
            }
        except Exception as e:
            job["pyats_diff"] = {"error": str(e)}

        # ─── Stage 5: Intent verify ──────────────────────────────────────
        _cl_set_phase(job, "verify_intent")
        try:
            # Reuse the helper from multivendor_extensions if it loaded
            # Lightweight: count Suzieq-observed BGP peers vs claimed
            from multivendor_extensions import _suzieq_parse_device, _ALL_DEVICES  # type: ignore
            dev = next((d for d in _ALL_DEVICES if d.get("hostname") == hostname), None)
            intent = {"checked": False}
            if dev and dev.get("config"):
                parsed = _suzieq_parse_device(dev)
                intent = {
                    "checked":     True,
                    "config_peers": len(parsed.get("bgp_peers", [])),
                    "notes":        "Static config analysed",
                }
            job["intent"] = intent
        except Exception as e:
            job["intent"] = {"checked": False, "error": str(e)}

        _cl_finish(job, "APPROVED",
                   f"Change committed and verified — "
                   f"{job.get('pyats_diff', {}).get('total_changes', 0)} state changes detected")
    except Exception as e:
        _cl_finish(job, "FAILED", f"unhandled pipeline error: {e}")


@app.route("/api/change/closed-loop", methods=["POST"])
def api_change_closed_loop():
    """Run the full closed-loop change pipeline (async).

    Body: {
        hostname:        string  required  device to change
        proposed_change: string  required  config snippet (vendor-native)
        timeout_s:       int     optional  health-gate watch window (default 30)
        dry_run:         bool    optional  stop after Predict+Batfish, never apply
    }
    Returns immediately with {change_id, status_url}. Poll
    GET /api/change/closed-loop/<change_id> for live phase + final verdict.
    """
    body = request.get_json(force=True) or {}
    hostname = (body.get("hostname") or body.get("host") or
                body.get("device") or body.get("target_device") or "").strip()
    proposed_change = (body.get("proposed_change") or "").strip()
    if not hostname:
        return jsonify({
            "error": "hostname required",
            "accepted_device_keys": ["hostname", "host", "device", "target_device"],
        }), 400
    if not proposed_change:
        return jsonify({"error": "proposed_change required (non-empty config snippet)"}), 400

    change_id = f"chg-{_cl_uuid.uuid4().hex[:12]}"
    job: dict = {
        "change_id":       change_id,
        "hostname":        hostname,
        "proposed_change": proposed_change,
        "phase":           "queued",
        "verdict":         None,
        "started_ts":      _cl_now_ts(),
        "last_update_ts":  _cl_now_ts(),
        "timeline":        [],
        "dry_run":         bool(body.get("dry_run", False)),
    }
    with _CLOSED_LOOP_LOCK:
        _CLOSED_LOOP_JOBS[change_id] = job
        _CLOSED_LOOP_HISTORY.append({"change_id": change_id, "hostname": hostname,
                                     "started_ts": job["started_ts"]})

    t = _cl_threading.Thread(target=_cl_run, args=(job, body), daemon=True)
    t.start()

    return jsonify({
        "change_id":   change_id,
        "status_url":  f"/api/change/closed-loop/{change_id}",
        "hostname":    hostname,
        "phase":       "queued",
        "dry_run":     job["dry_run"],
    }), 202


@app.route("/api/change/closed-loop/<change_id>", methods=["GET"])
def api_change_closed_loop_status(change_id: str):
    """Poll a closed-loop change job's current phase + final verdict."""
    with _CLOSED_LOOP_LOCK:
        job = _CLOSED_LOOP_JOBS.get(change_id)
        if not job:
            return jsonify({"error": "change_id not found"}), 404
        return jsonify(dict(job))


@app.route("/api/change/closed-loop", methods=["GET"])
def api_change_closed_loop_list():
    """Recent closed-loop change runs (last 200)."""
    with _CLOSED_LOOP_LOCK:
        return jsonify({
            "history": list(_CLOSED_LOOP_HISTORY),
            "active":  [j for j in _CLOSED_LOOP_JOBS.values() if j.get("phase") != "done"],
        })


# ══════════════════════════════════════════════════════════════════════════════
# ── 🔔 KEEP ALERT CORRELATION (P2) ───────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def _influx_query_csv(flux: str, timeout: int = 6) -> list[dict]:
    """Run a Flux query against the InfluxDB used by the DCN+clab collectors,
    return the rows as a list of dicts. Empty list on failure (logged)."""
    influx_url   = os.environ.get("INFLUXDB_URL",   "http://localhost:8086")
    influx_org   = os.environ.get("INFLUXDB_ORG",   "dcn-lab")
    influx_token = os.environ.get("INFLUXDB_TOKEN", "dcn-lab-token-secret")
    try:
        r = _requests.post(
            f"{influx_url}/api/v2/query?org={influx_org}",
            headers={
                "Authorization": f"Token {influx_token}",
                "Content-Type":  "application/vnd.flux",
                "Accept":        "application/csv",
            },
            data=flux.encode("utf-8"),
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001
        app.logger.warning("InfluxDB query failed: %s", exc)
        return []
    if r.status_code != 200:
        app.logger.warning("InfluxDB query returned %s: %s", r.status_code, r.text[:200])
        return []
    rows: list[dict] = []
    header: list[str] = []
    for line in r.text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if not header:
            header = parts
            continue
        if len(parts) != len(header):
            continue
        rows.append(dict(zip(header, parts)))
    return rows


def _influx_derive_alerts(site_filter: str = "") -> list[dict]:
    """Derive alerts from the time-series fabric state.

    We do not need LibreNMS — the InfluxDB bucket already has BGP /
    interface counters from both the DCN collector and the clab collector.

    Alert rules (all dimensions tagged ``fabric``, ``host``, ``vendor``, ``role``, ``site``):
        - bgp_session_count.established < bgp_session_count.total  → "BGP peers down"
        - interface_count.up           < interface_count.total     → "Interfaces down"
        - ospf_neighbor_count.full     < ospf_neighbor_count.total → "OSPF adjacencies missing"
    """
    flux = '''
      bgp_now = from(bucket:"network-telemetry") |> range(start:-2m)
        |> filter(fn:(r) => r._measurement == "bgp_session_count")
        |> last()
        |> pivot(rowKey:["host","fabric","site","vendor","role"], columnKey:["_field"], valueColumn:"_value")
      bgp_down = bgp_now |> filter(fn:(r) => r.established < r.total)
        |> map(fn:(r) => ({ host:r.host, site:r.site, vendor:r.vendor, role:r.role,
                            fabric:r.fabric, kind:"bgp",
                            down:int(v: r.total - r.established), total:int(v: r.total) }))
      intf_now = from(bucket:"network-telemetry") |> range(start:-2m)
        |> filter(fn:(r) => r._measurement == "interface_count")
        |> last()
        |> pivot(rowKey:["host","fabric","site","vendor","role"], columnKey:["_field"], valueColumn:"_value")
      intf_down = intf_now |> filter(fn:(r) => r.up < r.total)
        |> map(fn:(r) => ({ host:r.host, site:r.site, vendor:r.vendor, role:r.role,
                            fabric:r.fabric, kind:"intf",
                            down:int(v: r.total - r.up), total:int(v: r.total) }))
      union(tables:[bgp_down, intf_down])
    '''
    rows = _influx_query_csv(flux, timeout=8)
    alerts: list[dict] = []
    for r in rows:
        kind   = r.get("kind", "")
        host   = r.get("host", "")
        site   = r.get("site", "")
        vendor = r.get("vendor", "")
        role   = r.get("role", "")
        try:
            down  = int(r.get("down",  "0") or 0)
            total = int(r.get("total", "0") or 0)
        except ValueError:
            continue
        if down <= 0:
            continue
        # Skip pure spine/leaf hosts that legitimately have 0 sessions
        if kind == "bgp" and total == 0:
            continue
        msg = (f"{down}/{total} BGP peers down" if kind == "bgp"
               else f"{down}/{total} interfaces down")
        severity = "critical" if (kind == "bgp" and down >= 2) or (kind == "intf" and down >= 2) else "warning"
        alerts.append({
            "source":   "influxdb",
            "device":   host,
            "site":     site,
            "vendor":   vendor,
            "role":     role,
            "kind":     kind,
            "message":  msg,
            "severity": severity,
            "down":     down,
            "total":    total,
        })
    if site_filter:
        sf = site_filter.lower()
        alerts = [a for a in alerts if sf in (a.get("site") or "").lower()]
    return alerts


# ──────────────────────────────────────────────────────────────────────────────
# ── 📈 ADTK anomaly detection (Roadmap #3) ────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────────────
# The classic alert rule (`up < total`) is a binary tripwire — it fires only
# once a peer has fully dropped. Real BGP problems are visible MUCH earlier
# as flap counts, prefix-count drift, or CPU spikes — anomalies the time-
# series can detect 5-30 min before the threshold trips.
#
# Implementation: pull recent history per (host, measurement, field) and run
# two cheap, deterministic detectors per series:
#   1. Z-score over rolling mean (univariate level anomalies)
#   2. Persistent-flap detector (count up/down transitions in a window)
#
# Why Python over the InfluxDB ADTK plugin: that plugin requires InfluxDB v3,
# which would force a full DB migration. The math is simple — running it in
# Flask alongside the existing correlator is the lower-risk path. When/if we
# bump to v3 we can replace this with the plugin and keep the API contract.
# ──────────────────────────────────────────────────────────────────────────────

def _adtk_series(measurement: str, field: str, window_min: int = 30) -> list[dict]:
    """Pull a measurement+field time series grouped by host for the last
    ``window_min`` minutes. Returns raw rows {host, _time, _value}."""
    flux = f'''
      from(bucket:"network-telemetry")
        |> range(start:-{window_min}m)
        |> filter(fn:(r) => r._measurement == "{measurement}" and r._field == "{field}")
        |> keep(columns:["_time","_value","host"])
    '''
    return _influx_query_csv(flux, timeout=10)


def _adtk_zscore(values: list[float], threshold: float = 3.0) -> tuple[bool, float]:
    """Return (is_anomaly, last_zscore). Stable when stddev is 0 (returns False)."""
    if len(values) < 5:
        return False, 0.0
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / len(values)
    std = var ** 0.5
    if std < 1e-9:
        return False, 0.0
    last = values[-1]
    z = (last - mean) / std
    return abs(z) >= threshold, round(z, 2)


def _adtk_flap_count(values: list[float]) -> int:
    """Count transitions where the value drops then recovers within the window
    — classic BGP flap signature. Skips no-op consecutive duplicates."""
    transitions = 0
    last_dir = 0  # +1 / -1 / 0
    prev = None
    for v in values:
        if prev is None:
            prev = v; continue
        if v < prev:
            d = -1
        elif v > prev:
            d = 1
        else:
            d = 0
        if d != 0 and d != last_dir:
            transitions += 1
            last_dir = d
        prev = v
    # Each flap = 2 transitions (down then up). Round down.
    return transitions // 2


def detect_anomalies(window_min: int = 30) -> list[dict]:
    """Detect time-series anomalies across the live fabric.

    Three signals (all per host):
      - BGP established count: z-score of value vs last 30 min
      - BGP established count: flap-count detector (down/up cycles)
      - Interface up count: z-score (catches link-flap storms)
    """
    by_host_bgp:  dict[str, list[float]] = {}
    by_host_intf: dict[str, list[float]] = {}
    for r in _adtk_series("bgp_session_count", "established", window_min):
        try:
            by_host_bgp.setdefault(r.get("host",""), []).append(float(r.get("_value","0")))
        except ValueError:
            continue
    for r in _adtk_series("interface_count", "up", window_min):
        try:
            by_host_intf.setdefault(r.get("host",""), []).append(float(r.get("_value","0")))
        except ValueError:
            continue

    anomalies: list[dict] = []
    for host, series in by_host_bgp.items():
        if not host:
            continue
        is_anom, z = _adtk_zscore(series)
        if is_anom:
            anomalies.append({
                "source":   "adtk", "detector": "zscore",
                "device":   host, "metric": "bgp_established",
                "severity": "warning" if abs(z) < 5 else "critical",
                "message":  f"BGP established count z-score {z} (mean drift over {window_min}m)",
                "z":        z, "samples": len(series),
            })
        flaps = _adtk_flap_count(series)
        if flaps >= 2:
            anomalies.append({
                "source":   "adtk", "detector": "flap",
                "device":   host, "metric": "bgp_established",
                "severity": "critical" if flaps >= 5 else "warning",
                "message":  f"BGP flap detector: {flaps} session flaps in last {window_min}m",
                "flaps":    flaps, "samples": len(series),
            })
    for host, series in by_host_intf.items():
        if not host:
            continue
        is_anom, z = _adtk_zscore(series)
        if is_anom:
            anomalies.append({
                "source":   "adtk", "detector": "zscore",
                "device":   host, "metric": "interface_up",
                "severity": "warning",
                "message":  f"Interface up-count z-score {z} (level shift in {window_min}m)",
                "z":        z, "samples": len(series),
            })
    return anomalies


@app.route("/api/anomaly/detect", methods=["GET", "POST"])
def api_anomaly_detect():
    """Run the ADTK-style anomaly detector and return the raw findings.

    Query / body:
        window_min — default 30, max 720 (12h)
    """
    body = request.get_json(silent=True) or {}
    try:
        win = int(body.get("window_min") or request.args.get("window_min") or 30)
    except (TypeError, ValueError):
        win = 30
    win = max(5, min(win, 720))
    try:
        anomalies = detect_anomalies(window_min=win)
    except Exception as e:
        return jsonify({"error": f"anomaly_detect_failed: {e}",
                        "anomalies": [], "window_min": win}), 500
    return jsonify({
        "window_min": win,
        "count":      len(anomalies),
        "detectors":  ["zscore", "flap"],
        "anomalies":  anomalies,
    })


@app.route("/api/keep/correlate", methods=["POST"])
def api_keep_correlate():
    """Pull alerts from LibreNMS (optional) + InfluxDB derived state and
    correlate into incidents using the LLM. InfluxDB is always tried so
    the endpoint stays useful without external SaaS."""
    data = request.get_json(force=True) or {}
    site_filter: str = (data.get("site") or "").strip().lower()

    raw_alerts: list[dict] = []

    # Pull LibreNMS alerts (optional)
    try:
        lnms_url = os.environ.get("LIBRENMS_URL", "")
        lnms_token = os.environ.get("LIBRENMS_TOKEN", "")
        if lnms_url and lnms_token:
            resp = _requests.get(f"{lnms_url}/api/v0/alerts?state=1",
                                 headers={"X-Auth-Token": lnms_token}, timeout=8, verify=DCN_VERIFY_SSL)
            if resp.status_code == 200:
                for a in (resp.json().get("alerts") or []):
                    raw_alerts.append({"source": "librenms", "device": a.get("hostname", ""),
                                       "message": a.get("rule", {}).get("name", "alert"),
                                       "severity": a.get("severity", "warning")})
    except Exception:
        pass

    # ALWAYS try InfluxDB — that's where the real live state of both
    # fabrics lives. site_filter is applied inside the helper.
    raw_alerts.extend(_influx_derive_alerts(site_filter))

    # Merge ADTK anomaly detections — z-score level shifts + flap-count signals
    # that fire before binary `up<total` rules. (Roadmap #3 — 2026-05-25.)
    try:
        for a in detect_anomalies(window_min=30):
            raw_alerts.append({
                "source":   a.get("source", "adtk"),
                "detector": a.get("detector"),
                "device":   a.get("device", ""),
                "site":     "",  # tag not in series — left blank, correlator
                "vendor":   "",  # doesn't need it for grouping
                "role":     "",
                "kind":     a.get("metric", "anomaly"),
                "message":  a.get("message", ""),
                "severity": a.get("severity", "warning"),
                "z":        a.get("z"),
                "flaps":    a.get("flaps"),
            })
    except Exception:
        # ADTK is best-effort — never let it break the correlator.
        pass

    # Merge fleet-wide forecast (predictive) alerts. Roadmap #5 — these fire
    # when forecast P95 upper bound crosses a per-metric threshold within the
    # horizon. They give the operator an ETA ("in ~6h, leaf2 errors will
    # exceed 1k/s — 87% confidence") to act on before the threshold trips.
    try:
        from multivendor_extensions import get_recent_predictive_alerts  # type: ignore
        for a in get_recent_predictive_alerts(max_age_s=1800):
            raw_alerts.append({
                "source":   "forecast",
                "detector": a.get("model", "predictive"),
                "device":   a.get("device", ""),
                "site":     "",
                "vendor":   "",
                "role":     "",
                "kind":     a.get("metric", "predictive"),
                "message":  a.get("message") or
                            f"{a.get('metric')} predicted to {a.get('direction','breach')} "
                            f"~{a.get('eta_s','?')}s",
                "severity": a.get("severity", "predictive"),
                "eta_s":    a.get("eta_s"),
                "confidence": a.get("confidence"),
            })
    except Exception:
        pass

    # Filter LibreNMS rows by site if specified (InfluxDB already filtered).
    if site_filter:
        raw_alerts = [a for a in raw_alerts
                      if a.get("source") == "influxdb"
                      or site_filter in (a.get("device") or "").lower()]

    if not raw_alerts:
        return jsonify({
            "raw_alerts": 0, "incidents": 0, "suppressed": 0,
            "noise_reduction": "n/a", "incident_list": [],
            "sources_used": ["influxdb" if not (os.environ.get("LIBRENMS_URL") and os.environ.get("LIBRENMS_TOKEN")) else "influxdb+librenms"],
            "note": "fabric is healthy — no BGP/intf anomalies in last 2m",
        }), 200

    # Enrich each alert with netlog-ai compliance findings for the same host.
    # The LLM correlator then sees *why* the device is fragile, not just that
    # it's down right now — root cause becomes citable.
    per_device_findings: dict[str, list[dict]] = {}
    knowledge_blocks: list[str] = []
    unique_hosts = {a.get("device", "") for a in raw_alerts if a.get("device")}
    for h in list(unique_hosts)[:32]:  # hard cap
        findings = _netlog_findings_for(h)
        if findings:
            per_device_findings[h] = findings
            summary = _netlog_summary_for(h, max_findings=4)
            if summary:
                knowledge_blocks.append(summary)

    # LLM correlation
    alert_text = "\n".join(f"[{a['source']}] {a['device']}: {a['message']} ({a['severity']})" for a in raw_alerts)
    if knowledge_blocks:
        alert_text += "\n\n--- knowledge-base context (sanitized from netlog-ai) ---\n" + \
                      "\n".join(knowledge_blocks)
    sys_p = (
        "You are a network operations expert. Given these alerts and any knowledge-base "
        "context, identify the root cause and group correlated alerts into incidents. "
        "When a compliance finding plausibly explains an alert (e.g. missing prefix-limit + "
        "BGP flap), cite it explicitly in root_cause. "
        "Return a JSON array of incidents: "
        "[{\"id\":\"INC-001\",\"title\":\"...\",\"root_cause\":\"...\",\"suppressed\":N,\"alerts\":[...]}]"
    )
    llm_raw = _llm_query(sys_p, alert_text, max_tokens=1000)
    incidents: list[dict] = []
    if llm_raw:
        try:
            match = _re.search(r"\[.*\]", _clean_llm_response(llm_raw), _re.DOTALL)
            if match:
                incidents = _json_mod.loads(match.group())
        except Exception:
            pass

    suppressed = sum(i.get("suppressed", 0) for i in incidents)
    return jsonify({
        "raw_alerts": len(raw_alerts),
        "incidents": len(incidents),
        "suppressed": suppressed,
        "noise_reduction": f"{len(raw_alerts) / max(len(incidents), 1):.0f}x" if incidents else "n/a",
        "incident_list": incidents,
        "knowledge_enriched_hosts": list(per_device_findings.keys()),
        "per_device_findings": per_device_findings,
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── 📡 gNMI STREAMING TELEMETRY STATUS (P2) ──────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/telemetry/status", methods=["GET"])
def api_telemetry_status():
    """Return telemetry pipeline health — InfluxDB + frr-telemetry collector."""
    influx_url   = os.environ.get("INFLUXDB_URL", "http://localhost:8086")
    grafana_url  = os.environ.get("GRAFANA_URL", "http://localhost:3000")
    status: dict = {"influxdb": "unknown", "collector": "unknown", "grafana": "unknown", "streams": []}
    try:
        r = _requests.get(f"{influx_url}/ping", timeout=3)
        status["influxdb"] = "up" if r.status_code == 204 else "error"
    except Exception:
        status["influxdb"] = "unreachable"
    try:
        r = _requests.get(f"{grafana_url}/api/health", timeout=3)
        status["grafana"] = "up" if r.status_code == 200 else "error"
    except Exception:
        status["grafana"] = "unreachable"
    if status["influxdb"] == "up":
        try:
            flux = (
                'from(bucket: "network-telemetry")'
                ' |> range(start: -30s)'
                ' |> filter(fn: (r) => r["_measurement"] == "bgp_neighbor")'
                ' |> count()'
                ' |> group()'
                ' |> sum()'
            )
            headers = {
                "Authorization": f"Token {os.environ.get('INFLUXDB_TOKEN', 'dcn-lab-token-secret')}",
                "Content-Type": "application/vnd.flux",
                "Accept": "application/csv",
            }
            r = _requests.post(
                f"{influx_url}/api/v2/query?org={os.environ.get('INFLUXDB_ORG', 'dcn-lab')}",
                data=flux, headers=headers, timeout=5,
            )
            status["collector"] = "streaming" if r.status_code == 200 and len(r.text) > 50 else "idle"
            status["streams"] = ["bgp_neighbor", "ospf_neighbor", "interface_stats"]
        except Exception:
            status["collector"] = "unknown"
    return jsonify(status)


@app.route("/api/telemetry/metrics", methods=["GET"])
def api_telemetry_metrics():
    """Return latest BGP/OSPF state from InfluxDB for the demo UI."""
    influx_url    = os.environ.get("INFLUXDB_URL", "http://localhost:8086")
    influx_token  = os.environ.get("INFLUXDB_TOKEN", "dcn-lab-token-secret")
    influx_org    = os.environ.get("INFLUXDB_ORG", "dcn-lab")
    influx_bucket = os.environ.get("INFLUXDB_BUCKET", "network-telemetry")
    grafana_url   = os.environ.get("GRAFANA_URL", "http://localhost:3000")

    influx_headers = {
        "Authorization": f"Token {influx_token}",
        "Content-Type": "application/vnd.flux",
        "Accept": "application/csv",
    }

    def _flux(query: str) -> list:
        try:
            import csv as _csv
            from io import StringIO as _StringIO
            r = _requests.post(
                f"{influx_url}/api/v2/query?org={influx_org}",
                data=query, headers=influx_headers, timeout=5,
            )
            if r.status_code != 200 or not r.text.strip():
                return []
            return [row for row in _csv.DictReader(_StringIO(r.text)) if row.get("_field")]
        except Exception:
            return []

    bgp_rows = _flux(
        f'from(bucket: "{influx_bucket}")\n'
        '  |> range(start: -2m)\n'
        '  |> filter(fn: (r) => r["_measurement"] == "bgp_neighbor")\n'
        '  |> filter(fn: (r) => r["_field"] == "established" or r["_field"] == "pfx_received")\n'
        '  |> last()'
    )

    sessions: dict = {}
    for row in bgp_rows:
        key = f"{row.get('host', '')}|{row.get('peer', '')}"
        if key not in sessions:
            sessions[key] = {
                "host":      row.get("host", ""),
                "peer":      row.get("peer", ""),
                "state":     row.get("state", "unknown"),
                "remote_as": row.get("remote_as", ""),
            }
        try:
            sessions[key][row["_field"]] = int(float(row.get("_value", 0)))
        except (ValueError, TypeError):
            pass

    session_list = list(sessions.values())
    established  = sum(1 for s in session_list if s.get("established") == 1)

    ospf_rows = _flux(
        f'from(bucket: "{influx_bucket}")\n'
        '  |> range(start: -2m)\n'
        '  |> filter(fn: (r) => r["_measurement"] == "ospf_neighbor")\n'
        '  |> filter(fn: (r) => r["_field"] == "full")\n'
        '  |> last()'
    )
    ospf_full = sum(1 for r in ospf_rows if r.get("_value") in ("1", "1.0", 1))

    return jsonify({
        "bgp_sessions":      session_list,
        "established_count": established,
        "total_sessions":    len(session_list),
        "ospf_full_count":   ospf_full,
        "grafana_url":       grafana_url,
        "dashboard_url":     f"{grafana_url}/d/frr-network-1/dcn-lab-frr-network-telemetry",
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── 🔧 ROADMAP FEATURE 1: AUTO-REMEDIATION RUNBOOKS ──────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

# Resolve the sim script — try the DCN_Network_Tool-local path first
# (src/../network-lab/...) and fall back to the workspace-root copy
# (../../../network-lab/...) so the endpoint works in either layout.
def _find_sim_script() -> str:
    here = os.path.dirname(__file__)
    for rel in ("../network-lab/sim_bgp_failure.sh",
                "../../network-lab/sim_bgp_failure.sh",
                "../../../network-lab/sim_bgp_failure.sh"):
        p = os.path.normpath(os.path.join(here, rel))
        if os.path.exists(p):
            return p
    return os.path.normpath(os.path.join(here, "../network-lab/sim_bgp_failure.sh"))

_SIM_SCRIPT = _find_sim_script()

@app.route("/api/remediate", methods=["POST"])
def api_remediate():
    """Trigger BGP remediation actions on the lab network.
    Body: { "action": "status"|"fix"|"break"|"chaos", "peer": "optional-peer-ip" }
    Returns stdout/stderr from the simulation script.
    """
    data = request.get_json(force=True) or {}
    action: str = (data.get("action") or "status").strip().lower()

    if action not in ("status", "fix", "break", "chaos"):
        return jsonify({"error": f"Unknown action '{action}'. Use: status, fix, break, chaos"}), 400

    if not os.path.exists(_SIM_SCRIPT):
        return jsonify({"error": "Simulation script not found — lab not available"}), 404

    try:
        proc = subprocess.run(
            ["bash", _SIM_SCRIPT, action],
            capture_output=True, text=True, timeout=45,
        )
        # Filter known-benign vtysh warnings (no global vtysh.conf in containers — harmless)
        _NOISE = ("vtysh.conf", "No such file or directory")
        lines = [
            l for l in (proc.stdout + proc.stderr).splitlines()
            if l.strip() and not all(n in l for n in _NOISE)
        ]
        return jsonify({
            "action": action,
            "success": proc.returncode == 0,
            "output": lines,
            "message": f"Remediation '{action}' executed" if proc.returncode == 0 else "Script returned error",
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Remediation timed out after 45s"}), 504
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ── 💊 ROADMAP FEATURE 3: PER-DEVICE HEALTH CARDS ────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_HEALTH_CMDS: dict[str, dict[str, str]] = {
    "frr": {
        "memory": "show memory summary",
        "cpu":    "show processes cpu",
        "bgp":    "show bgp summary",
        "ospf":   "show ip ospf neighbor",
        "uptime": "show version",
    },
    "eos": {
        "memory": "show version | grep Memory",
        "cpu":    "show processes top once",
        "bgp":    "show bgp summary",
        "uptime": "show version | grep Uptime",
    },
    "junos": {
        "memory": "show system memory",
        "cpu":    "show system processes extensive brief",
        "bgp":    "show bgp summary",
        "uptime": "show system uptime",
    },
}


def _parse_frr_health(raw: dict[str, str]) -> dict:
    """Extract numeric metrics from FRR health command outputs."""
    metrics: dict = {}

    mem_text = raw.get("memory", "")
    m = re.search(r"Total:\s+(\d+)", mem_text)
    if m:
        metrics["mem_total_kb"] = int(m.group(1))
    m = re.search(r"Used:\s+(\d+)", mem_text)
    if m:
        metrics["mem_used_kb"] = int(m.group(1))

    cpu_text = raw.get("cpu", "")
    m = re.search(r"(\d+(?:\.\d+)?)\s*%\s*(?:CPU|cpu|user)", cpu_text)
    if m:
        metrics["cpu_pct"] = float(m.group(1))

    bgp_text = raw.get("bgp", "")
    established = len(re.findall(r"^\S.*?\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+$",
                                 bgp_text, re.M))
    metrics["bgp_peers"] = established

    ospf_text = raw.get("ospf", "")
    metrics["ospf_neighbors"] = len([l for l in ospf_text.splitlines()
                                     if re.search(r'\d+\.\d+\.\d+\.\d+', l)])
    return metrics


@app.route("/api/device/health-card", methods=["POST"])
def api_device_health_card():
    """Collect CPU, memory, BGP, OSPF status for a single device health card.
    Body: { "hostname": "de-fra-core-01" }
    Returns raw command outputs + parsed numeric metrics.
    """
    data = request.get_json(force=True) or {}
    hostname: str = (data.get("hostname") or "").strip()
    if not hostname:
        return jsonify({"error": "hostname required"}), 400

    dev = get_device_by_hostname(hostname)
    if not dev:
        return jsonify({"error": f"Device '{hostname}' not in inventory"}), 404

    dtype: str = dev.get("type", "junos")
    ip: str = dev.get("ip", "")
    port: int = dev.get("port", 22)
    cmd_set = _HEALTH_CMDS.get(dtype, _HEALTH_CMDS["junos"])

    raw: dict[str, str] = {}
    for key, cmd in cmd_set.items():
        result = run_command_on_device(ip, dtype, cmd, port=port)
        raw[key] = result.get("output", "") if isinstance(result, dict) else str(result)

    metrics = _parse_frr_health(raw) if dtype == "frr" else {}

    return jsonify({
        "hostname": hostname,
        "type": dtype,
        "ip": ip,
        "raw": raw,
        "metrics": metrics,
        "timestamp": datetime.now().isoformat(),
    })


@app.route("/api/device/health-all", methods=["POST"])
def api_device_health_all():
    """Collect health cards for all lab devices in parallel.
    Body: { "site": "de-fra" }  (optional site filter)
    """
    data = request.get_json(force=True) or {}
    site_filter: str = (data.get("site") or "").strip().lower()
    hostnames_filter: list[str] = data.get("hostnames") or []

    if hostnames_filter:
        targets = [d for d in DEVICES if d["hostname"] in hostnames_filter]
    elif site_filter:
        targets = [d for d in DEVICES if d.get("site", "").lower() == site_filter]
    else:
        targets = list(DEVICES)

    if not targets:
        return jsonify({"error": "No devices found"}), 404

    def _run_cmd(ip: str, dtype: str, port: int, key: str, cmd: str) -> tuple[str, str]:
        """Run one command; return (key, output). Never raises."""
        try:
            result = run_command_on_device(ip, dtype, cmd, port=port)
            return key, (result.get("output", "") if isinstance(result, dict) else str(result))
        except Exception as exc:
            return key, f"ERROR: {exc}"

    # Hard cap: each individual SSH command must finish within this many seconds.
    # Keeps the whole endpoint bounded to CMD_DEADLINE × 2 (connect + exec).
    CMD_DEADLINE = SSH_TIMEOUT + 5   # e.g. 35s

    def _collect(dev: dict) -> dict:
        dtype = dev.get("type", "junos")
        ip = dev.get("ip", "")
        port = dev.get("port", 22)
        container = dev.get("container")
        vendor = (dev.get("vendor") or "").lower()
        cmd_set = _HEALTH_CMDS.get(dtype, _HEALTH_CMDS["junos"])

        raw: dict[str, str] = {}

        # clab fabric nodes: SSH is unreachable from the host (separate docker
        # network), so use docker exec with the right per-vendor CLI shim.
        if container and shutil.which("docker"):
            for key, _frr_cmd in cmd_set.items():
                try:
                    if vendor in ("frr", ""):
                        ext = ["docker", "exec", container, "vtysh", "-c", _frr_cmd]
                    elif vendor in ("arista", "arista-eos", "eos"):
                        eos_cmd = (_frr_cmd
                                   .replace("show ip bgp summary", "show ip bgp summary")
                                   .replace("show bgp summary",    "show ip bgp summary"))
                        ext = ["docker", "exec", container, "Cli", "-p", "15", "-c", eos_cmd]
                    elif vendor in ("nokia", "nokia-srl", "srl"):
                        srl_cmd = _frr_cmd  # SRL won't parse "show ip ..." — emit raw, no parse
                        if "bgp" in _frr_cmd:
                            srl_cmd = "show network-instance default protocols bgp neighbor"
                        elif "ospf" in _frr_cmd:
                            srl_cmd = "show network-instance default protocols ospf neighbor"
                        elif "interface" in _frr_cmd:
                            srl_cmd = "show interface"
                        ext = ["docker", "exec", container, "sr_cli", "-d", srl_cmd]
                    elif vendor == "linux":
                        ext = ["docker", "exec", container, "ip", "-br", "a"]
                    else:
                        raw[key] = f"ERROR: unsupported vendor {vendor!r}"
                        continue
                    proc = subprocess.run(ext, capture_output=True, text=True, timeout=CMD_DEADLINE)
                    raw[key] = proc.stdout if proc.returncode == 0 else f"ERROR rc={proc.returncode}: {(proc.stderr or '').strip()[:160]}"
                except subprocess.TimeoutExpired:
                    raw[key] = "ERROR: docker exec timed out"
                except Exception as exc:  # noqa: BLE001
                    raw[key] = f"ERROR: {exc}"
            metrics = _parse_frr_health(raw) if vendor == "frr" else {}
            return {"hostname": dev["hostname"], "type": dtype, "ip": ip,
                    "vendor": vendor, "container": container,
                    "raw": raw, "metrics": metrics}

        # SSH path (original): used by the 10-device FRR lab and the static
        # sanitized configs.
        from concurrent.futures import ThreadPoolExecutor as _TPE, as_completed as _ac, TimeoutError as _TE
        with _TPE(max_workers=len(cmd_set)) as cmd_pool:
            cmd_futs = {cmd_pool.submit(_run_cmd, ip, dtype, port, k, c): k
                        for k, c in cmd_set.items()}
            for f in _ac(cmd_futs):
                try:
                    k, v = f.result(timeout=CMD_DEADLINE)
                except _TE:
                    k = cmd_futs[f]
                    v = "ERROR: command timed out"
                raw[k] = v
        metrics = _parse_frr_health(raw) if dtype == "frr" else {}
        return {"hostname": dev["hostname"], "type": dtype, "ip": ip,
                "raw": raw, "metrics": metrics}

    from concurrent.futures import ThreadPoolExecutor, as_completed
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(10, len(targets))) as pool:
        futs = [pool.submit(_collect, dev) for dev in targets]
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as exc:
                results.append({"hostname": "unknown", "error": str(exc)})

    return jsonify({
        "count": len(results),
        "timestamp": datetime.now().isoformat(),
        "devices": sorted(results, key=lambda r: r.get("hostname", "")),
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── 🔎 ROADMAP FEATURE 4: OSPF AUTO-DISCOVERY ────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/topology/discover", methods=["POST"])
def api_topology_discover():
    """Walk OSPF neighbors from all lab devices to build a live topology.
    Body: { "site": "de-fra" }  (optional site filter)
    Returns nodes + links discovered via OSPF neighbor queries.
    """
    data = request.get_json(force=True) or {}
    site_filter: str = (data.get("site") or "").strip().lower()
    hostnames_filter: list[str] = data.get("hostnames") or []

    if hostnames_filter:
        targets = [d for d in DEVICES if d["hostname"] in hostnames_filter]
    elif site_filter:
        targets = [d for d in DEVICES if d.get("site", "").lower() == site_filter]
    else:
        targets = list(DEVICES)

    if not targets:
        return jsonify({"error": "No devices found"}), 404

    ip_to_hostname = {d["ip"]: d["hostname"] for d in DEVICES}
    nodes: list[dict] = []
    raw_links: list[tuple] = []
    _link_lock = threading.Lock()

    def _discover_ospf(dev: dict) -> dict:
        dtype = dev.get("type", "junos")
        ip = dev.get("ip", "")
        port = dev.get("port", 22)
        node = {
            "id": dev["hostname"],
            "hostname": dev["hostname"],
            "type": dtype,
            "ip": ip,
            "site": dev.get("site", ""),
            "role": dev.get("role", ""),
        }
        links_found: list[dict] = []
        try:
            if dtype == "frr":
                cmd = "show ip ospf neighbor"
                result = run_command_on_device(ip, dtype, cmd, port=port)
                out = result.get("output", "") if isinstance(result, dict) else ""
                _ipre = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and _ipre.match(parts[0]):
                        nbr_router_id = parts[0]
                        state = parts[2] if len(parts) > 2 else "unknown"
                        # FRR output columns vary by version — scan for the
                        # first IPv4 address after parts[0] to get the link IP
                        # (may be at parts[4] or parts[5] depending on whether
                        #  "Up Time" column is present)
                        nbr_ip = nbr_router_id
                        for p in parts[1:]:
                            if _ipre.match(p):
                                nbr_ip = p
                                break
                        target_hostname = ip_to_hostname.get(nbr_ip) or ip_to_hostname.get(nbr_router_id)
                        if target_hostname:
                            links_found.append({
                                "source": dev["hostname"],
                                "target": target_hostname,
                                "protocol": "OSPF",
                                "state": state,
                            })
            elif dtype == "junos":
                cmd = "show ospf neighbor"
                result = run_command_on_device(ip, dtype, cmd, port=port)
                out = result.get("output", "") if isinstance(result, dict) else ""
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                        nbr_ip = parts[0]
                        state = parts[3] if len(parts) > 3 else "unknown"
                        target_hostname = ip_to_hostname.get(nbr_ip)
                        if target_hostname:
                            links_found.append({
                                "source": dev["hostname"],
                                "target": target_hostname,
                                "protocol": "OSPF",
                                "state": state,
                            })
        except Exception:
            pass

        with _link_lock:
            for lnk in links_found:
                pair = tuple(sorted([lnk["source"], lnk["target"]]))
                if not any(tuple(sorted([r[0], r[1]])) == pair for r in raw_links):
                    raw_links.append((lnk["source"], lnk["target"], lnk["protocol"], lnk["state"]))
        return node

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=min(10, len(targets))) as pool:
        futs = [pool.submit(_discover_ospf, dev) for dev in targets]
        for fut in as_completed(futs):
            try:
                nodes.append(fut.result())
            except Exception:
                pass

    links = [
        {"source": s, "target": t, "protocol": p, "state": st}
        for s, t, p, st in raw_links
    ]

    return jsonify({
        "nodes": sorted(nodes, key=lambda n: n["hostname"]),
        "links": links,
        "discovered_at": datetime.now().isoformat(),
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── 📚 ROADMAP FEATURE 5: RAG OVER VENDOR DOCS ───────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_DOC_KNOWLEDGE_BASE: list[dict] = [
    {
        "id": "frr-bgp-holdtimer",
        "vendor": "FRR", "topic": "BGP Hold Timer Expired",
        "keywords": ["hold timer", "hold-time", "bgp.*expired", "notification.*hold"],
        "text": (
            "FRR BGP Hold Timer Expired means the BGP session did not receive a KEEPALIVE "
            "within the negotiated hold-time (default 90s). Causes: network congestion, "
            "interface flap, CPU overload on peer, or MTU mismatch. "
            "Fix: Check interface state, ping peer, verify CPU load. "
            "Config: `timers bgp 30 90` to tighten timers."
        ),
    },
    {
        "id": "frr-ospf-neighbor-down",
        "vendor": "FRR", "topic": "OSPF Neighbor Down",
        "keywords": ["ospf.*down", "neighbor.*down", "dead interval", "dead-interval"],
        "text": (
            "OSPF neighbor lost (Dead Interval expired). Causes: hello interval mismatch, "
            "authentication mismatch, MTU mismatch, interface down. "
            "FRR default hello=10s dead=40s. Lab uses hello=5s dead=20s. "
            "Check: `show ip ospf interface eth0` for timer values. "
            "Both sides must match exactly — mismatched timers = no adjacency."
        ),
    },
    {
        "id": "frr-bgp-notification",
        "vendor": "FRR", "topic": "BGP NOTIFICATION received",
        "keywords": ["notification", "cease", "admin.*shutdown", "bgp.*reset"],
        "text": (
            "BGP NOTIFICATION message received from peer. Cease/Administrative Shutdown means "
            "the peer was shut down intentionally (clear ip bgp or router restart). "
            "Error codes: 1=Message Header Error, 2=Open Message Error, 3=Update Error, "
            "4=Hold Timer Expired, 5=FSM Error, 6=Cease. "
            "Check peer router status and logs."
        ),
    },
    {
        "id": "junos-bgp-rpd-crash",
        "vendor": "Junos", "topic": "rpd crash / BGP session reset",
        "keywords": ["rpd", "routing protocol daemon", "rpd.*core", "process.*crash"],
        "text": (
            "Juniper rpd (routing protocol daemon) crash causes all BGP/OSPF sessions to drop. "
            "rpd restarts automatically but graceful-restart must be configured for hitless recovery. "
            "Check: `show log messages | match rpd` and `show system core-dumps`. "
            "Fix: `set routing-options graceful-restart` on all peers."
        ),
    },
    {
        "id": "eos-bgp-peer-group",
        "vendor": "Arista EOS", "topic": "BGP Peer Group not established",
        "keywords": ["peer.*group", "eos.*bgp", "arista.*bgp.*down"],
        "text": (
            "Arista EOS BGP peer-group not coming up: check `show bgp summary` for Idle/Active state. "
            "Active = TCP connection attempted but no response (check reachability). "
            "Idle = BGP not trying (check `no shutdown` under neighbor). "
            "Common cause: missing `neighbor <ip> activate` under address-family."
        ),
    },
    {
        "id": "frr-prefix-limit",
        "vendor": "FRR", "topic": "Prefix limit exceeded",
        "keywords": ["prefix.*limit", "maximum.*prefix", "prefix.*exceeded"],
        "text": (
            "BGP prefix limit exceeded causes the session to be torn down to protect routing table. "
            "FRR: `neighbor X.X.X.X maximum-prefix 1000` — session drops at 1000 prefixes. "
            "Add `warning-only` to alert without dropping: `maximum-prefix 1000 warning-only`. "
            "Check current prefixes: `show bgp neighbor X.X.X.X` — look for 'Prefix advertised'."
        ),
    },
    {
        "id": "ospf-mtu-mismatch",
        "vendor": "General", "topic": "OSPF MTU mismatch — stuck in ExStart/Exchange",
        "keywords": ["exstart", "exchange", "mtu.*mismatch", "dd.*mtu"],
        "text": (
            "OSPF neighbors stuck in ExStart or Exchange state typically indicates MTU mismatch. "
            "Both sides must have the same interface MTU for DD (Database Description) exchange. "
            "FRR fix: `ip ospf mtu-ignore` under interface to bypass check. "
            "Junos fix: `interface-type p2p` or adjust MTU to match peer."
        ),
    },
]


def _doc_search(query: str, top_k: int = 3) -> list[dict]:
    """Simple keyword-score search over the doc knowledge base."""
    query_lower = query.lower()
    scored: list[tuple[int, dict]] = []
    for doc in _DOC_KNOWLEDGE_BASE:
        score = 0
        for kw in doc["keywords"]:
            if re.search(kw, query_lower, re.I):
                score += 3
        for word in query_lower.split():
            if word in doc["text"].lower():
                score += 1
        if score > 0:
            scored.append((score, doc))
    scored.sort(key=lambda x: -x[0])
    return [d for _, d in scored[:top_k]]


@app.route("/api/docs/search", methods=["POST"])
def api_docs_search():
    """Search the vendor doc knowledge base + LLM explanation.
    Body: { "query": "OSPF neighbor stuck in ExStart", "hostname": "de-fra-core-01" }
    Returns matching doc snippets and LLM-enhanced explanation.
    """
    data = request.get_json(force=True) or {}
    query: str = (data.get("query") or "").strip()
    hostname: str = (data.get("hostname") or "").strip()
    if not query:
        return jsonify({"error": "query required"}), 400

    docs = _doc_search(query)

    llm_answer = None
    if LLM_ENABLED and docs:
        context = "\n\n".join(f"[{d['topic']}]\n{d['text']}" for d in docs)
        sys_p = (
            "You are a network documentation expert. Given the documentation excerpts and the user's "
            "question, provide a concise, actionable answer in 3-5 sentences. "
            "Focus on root cause and fix steps."
        )
        user_p = f"Question: {query}\n\nDocumentation:\n{context}"
        if hostname:
            user_p += f"\n\nDevice context: {hostname}"
        raw = _llm_query(sys_p, user_p, max_tokens=400)
        if raw:
            llm_answer = _clean_llm_response(raw)

    return jsonify({
        "query": query,
        "docs_found": len(docs),
        "docs": [{"id": d["id"], "vendor": d["vendor"], "topic": d["topic"], "text": d["text"]}
                 for d in docs],
        "llm_answer": llm_answer,
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── ✅ ROADMAP FEATURE 6: CONFIG CHANGE APPROVAL WORKFLOW ────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_PENDING_CHANGES: dict[str, dict] = {}
_PENDING_CHANGES_LOCK = threading.Lock()


@app.route("/api/config-change/propose", methods=["POST"])
def api_config_change_propose():
    """AI proposes a config change + captures PRE-state snapshot.
    Body: { "hostname": "de-fra-core-01", "intent": "add prefix-limit 500 to all BGP peers" }
    Returns: change_id, proposed_cli, pre_snapshot
    """
    data = request.get_json(force=True) or {}
    hostname: str = (data.get("hostname") or "").strip()
    intent: str = (data.get("intent") or "").strip()
    if not hostname or not intent:
        return jsonify({"error": "hostname and intent required"}), 400

    dev = get_device_by_hostname(hostname)
    if not dev:
        return jsonify({"error": f"Device '{hostname}' not in inventory"}), 404

    dtype = dev.get("type", "junos")
    ip = dev.get("ip", "")
    port = dev.get("port", 22)

    # Step 1: LLM proposes config CLI for the intent
    sys_p = (
        f"You are a network engineer for {dtype} devices. "
        "The user wants to make a config change. Generate ONLY the CLI commands needed. "
        "For FRR: use vtysh config mode commands. "
        "Return JSON: {\"commands\": [\"cmd1\", \"cmd2\"], \"rollback\": [\"undo_cmd1\", \"undo_cmd2\"], "
        "\"risk\": \"low|medium|high\", \"explanation\": \"brief description\"}"
    )
    raw = _llm_query(sys_p, f"Device: {hostname} ({dtype})\nIntent: {intent}", max_tokens=400)

    proposal: dict = {"commands": [], "rollback": [], "risk": "unknown", "explanation": intent}
    if raw:
        try:
            import json as _j, re as _r
            m = _r.search(r'\{.*\}', _clean_llm_response(raw), _r.DOTALL)
            if m:
                proposal = _j.loads(m.group(0))
        except Exception:
            proposal["commands"] = [raw.strip()]

    # Step 2: Capture PRE-state
    pre_cmds = {
        "frr": ["show bgp summary", "show ip ospf neighbor", "show running-config"],
        "eos": ["show bgp summary", "show ip ospf neighbor", "show running-config"],
        "junos": ["show bgp summary", "show ospf neighbor", "show configuration"],
    }.get(dtype, ["show bgp summary"])

    pre_state: dict[str, str] = {}
    for cmd in pre_cmds:
        result = run_command_on_device(ip, dtype, cmd, port=port)
        pre_state[cmd] = result.get("output", "") if isinstance(result, dict) else str(result)

    # Store pending change
    import uuid
    change_id = str(uuid.uuid4())[:8].upper()
    with _PENDING_CHANGES_LOCK:
        _bounded_insert(_PENDING_CHANGES, change_id, {
            "id": change_id,
            "hostname": hostname,
            "dtype": dtype,
            "ip": ip,
            "port": port,
            "intent": intent,
            "proposal": proposal,
            "pre_state": pre_state,
            "status": "pending",
            "created_at": datetime.now().isoformat(),
        }, max_size=50)

    return jsonify({
        "change_id": change_id,
        "hostname": hostname,
        "intent": intent,
        "proposal": proposal,
        "pre_snapshot": list(pre_state.keys()),
        "status": "pending_approval",
        "message": f"Review the proposed commands and POST /api/config-change/approve with change_id='{change_id}' to apply.",
    })


@app.route("/api/config-change/approve", methods=["POST"])
def api_config_change_approve():
    """Execute an approved config change and capture POST-state diff.
    Body: { "change_id": "ABCD1234", "approved": true }
    Returns: execution results + before/after diff.
    """
    data = request.get_json(force=True) or {}
    change_id: str = (data.get("change_id") or "").strip().upper()
    approved: bool = bool(data.get("approved", False))

    with _PENDING_CHANGES_LOCK:
        change = _PENDING_CHANGES.get(change_id)

    if not change:
        return jsonify({"error": f"Change ID '{change_id}' not found"}), 404
    if change["status"] != "pending":
        return jsonify({"error": f"Change '{change_id}' already {change['status']}"}), 409
    if not approved:
        with _PENDING_CHANGES_LOCK:
            _PENDING_CHANGES[change_id]["status"] = "rejected"
        return jsonify({"change_id": change_id, "status": "rejected", "message": "Change rejected by operator"})

    hostname = change["hostname"]
    dtype = change["dtype"]
    ip = change["ip"]
    port = change["port"]
    commands: list[str] = change["proposal"].get("commands", [])

    # Execute commands (FRR only for lab safety; block for production devices)
    exec_results: list[dict] = []
    if dtype == "frr":
        for cmd in commands:
            try:
                result = run_command_on_device(ip, dtype, cmd, port=port)
                exec_results.append({
                    "command": cmd,
                    "success": result.get("success", False),
                    "output": result.get("output", ""),
                })
            except Exception as exc:
                exec_results.append({"command": cmd, "success": False, "output": str(exc)})
    else:
        return jsonify({
            "error": "Config write not allowed on production devices — lab (frr) only",
            "change_id": change_id,
        }), 403

    # Capture POST-state
    post_cmds = list(change["pre_state"].keys())
    post_state: dict[str, str] = {}
    for cmd in post_cmds:
        result = run_command_on_device(ip, dtype, cmd, port=port)
        post_state[cmd] = result.get("output", "") if isinstance(result, dict) else str(result)

    # Simple diff: compare line counts and spot new/removed lines
    diffs: list[dict] = []
    for cmd in post_cmds:
        pre_lines = set(change["pre_state"].get(cmd, "").splitlines())
        post_lines = set(post_state.get(cmd, "").splitlines())
        added = sorted(post_lines - pre_lines)
        removed = sorted(pre_lines - post_lines)
        if added or removed:
            diffs.append({"command": cmd, "added": added[:20], "removed": removed[:20]})

    with _PENDING_CHANGES_LOCK:
        _PENDING_CHANGES[change_id]["status"] = "applied"
        _PENDING_CHANGES[change_id]["post_state"] = post_state
        _PENDING_CHANGES[change_id]["diffs"] = diffs

    return jsonify({
        "change_id": change_id,
        "hostname": hostname,
        "status": "applied",
        "execution": exec_results,
        "diffs": diffs,
        "applied_at": datetime.now().isoformat(),
    })


@app.route("/api/config-change/list", methods=["GET"])
def api_config_change_list():
    """List all pending and recent config changes."""
    with _PENDING_CHANGES_LOCK:
        changes = list(_PENDING_CHANGES.values())
    # Return without the full pre/post state blobs to keep response small
    slim = [{k: v for k, v in c.items() if k not in ("pre_state", "post_state")}
            for c in changes]
    return jsonify({"changes": sorted(slim, key=lambda c: c["created_at"], reverse=True)})


# ══════════════════════════════════════════════════════════════════════════════
# ── 🛡️ ROADMAP FEATURE 7: COMPLIANCE SCANNER ─────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_COMPLIANCE_RULES: list[dict] = [
    {
        "id": "BGP-AUTH-01",
        "name": "BGP MD5 Authentication",
        "severity": "high",
        "description": "BGP peers should use MD5/password authentication to prevent session hijacking.",
        "frr_check": lambda cfg: bool(re.search(r"neighbor\s+\S+\s+password\s+\S+", cfg, re.I)),
        "frr_cmd": "show running-config",
        "remediation": "Add: `neighbor <ip> password <secret>` under `router bgp`",
    },
    {
        "id": "BGP-PFXLIMIT-02",
        "name": "BGP Prefix Limits",
        "severity": "medium",
        "description": "All BGP peers should have maximum-prefix limits to protect the routing table.",
        "frr_check": lambda cfg: bool(re.search(r"neighbor\s+\S+\s+maximum-prefix\s+\d+", cfg, re.I)),
        "frr_cmd": "show running-config",
        "remediation": "Add: `neighbor <ip> maximum-prefix 1000 warning-only`",
    },
    {
        "id": "OSPF-TIMER-03",
        "name": "OSPF Fast Timers",
        "severity": "low",
        "description": "OSPF hello ≤10s and dead ≤40s for fast failure detection.",
        "frr_check": lambda cfg: bool(re.search(r"ip ospf hello-interval\s+[1-9]\b", cfg, re.I)),
        "frr_cmd": "show running-config",
        "remediation": "Add under interface: `ip ospf hello-interval 5` and `ip ospf dead-interval 20`",
    },
    {
        "id": "BGP-LOGUP-04",
        "name": "BGP Log Neighbor Changes",
        "severity": "low",
        "description": "BGP neighbor state changes should be logged for visibility.",
        "frr_check": lambda cfg: bool(re.search(r"bgp\s+log-neighbor-changes", cfg, re.I)),
        "frr_cmd": "show running-config",
        "remediation": "Add under `router bgp`: `bgp log-neighbor-changes`",
    },
    {
        "id": "BGP-ROUTERID-05",
        "name": "Explicit BGP Router-ID",
        "severity": "medium",
        "description": "BGP router-id should be explicitly set, not auto-derived.",
        "frr_check": lambda cfg: bool(re.search(r"bgp router-id\s+\d+\.\d+\.\d+\.\d+", cfg, re.I)),
        "frr_cmd": "show running-config",
        "remediation": "Add under `router bgp`: `bgp router-id <loopback-ip>`",
    },
    {
        "id": "OSPF-AREA0-06",
        "name": "OSPF Backbone Area",
        "severity": "medium",
        "description": "All OSPF interfaces should be in area 0 (backbone) for this lab.",
        "frr_check": lambda cfg: bool(re.search(r"ip ospf area\s+0", cfg, re.I)),
        "frr_cmd": "show running-config",
        "remediation": "Add under interface: `ip ospf area 0`",
    },
]


@app.route("/api/compliance/scan", methods=["POST"])
def api_compliance_scan():
    """Scan running configs for compliance violations.
    Body: { "site": "de-fra" }  or  { "hostnames": ["de-fra-core-01", "de-fra-core-02"] }
    Returns per-device compliance report with PASS/FAIL per rule.
    """
    data = request.get_json(force=True) or {}
    site_filter: str = (data.get("site") or "").strip().lower()
    hostnames: list[str] = data.get("hostnames") or []

    if hostnames:
        targets = [d for d in DEVICES if d["hostname"] in hostnames]
    elif site_filter:
        targets = [d for d in DEVICES if d.get("site", "").lower() == site_filter]
    else:
        targets = list(DEVICES)

    if not targets:
        return jsonify({"error": "No devices found"}), 404

    def _scan_device(dev: dict) -> dict:
        dtype = dev.get("type", "junos")
        ip = dev.get("ip", "")
        port = dev.get("port", 22)

        # Fetch running config once
        if dtype == "frr":
            result = run_command_on_device(ip, dtype, "show running-config", port=port)
            cfg = result.get("output", "") if isinstance(result, dict) else ""
        else:
            cfg = ""  # Non-FRR: config checks not implemented in lab mode

        findings: list[dict] = []
        for rule in _COMPLIANCE_RULES:
            if dtype == "frr":
                try:
                    passed = rule["frr_check"](cfg)
                except Exception:
                    passed = False
            else:
                passed = None  # not checked

            findings.append({
                "rule_id": rule["id"],
                "name": rule["name"],
                "severity": rule["severity"],
                "status": "PASS" if passed else ("FAIL" if passed is False else "SKIP"),
                "remediation": rule["remediation"] if not passed else None,
            })

        passed_count = sum(1 for f in findings if f["status"] == "PASS")
        failed_count = sum(1 for f in findings if f["status"] == "FAIL")
        score = int(100 * passed_count / len(findings)) if findings else 0

        return {
            "hostname": dev["hostname"],
            "type": dtype,
            "ip": ip,
            "score": score,
            "passed": passed_count,
            "failed": failed_count,
            "findings": findings,
        }

    from concurrent.futures import ThreadPoolExecutor, as_completed
    device_reports: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(10, len(targets))) as pool:
        futs = [pool.submit(_scan_device, dev) for dev in targets]
        for fut in as_completed(futs):
            try:
                device_reports.append(fut.result())
            except Exception as exc:
                device_reports.append({"hostname": "unknown", "error": str(exc)})

    device_reports.sort(key=lambda r: r.get("hostname", ""))
    total_pass = sum(r.get("passed", 0) for r in device_reports)
    total_fail = sum(r.get("failed", 0) for r in device_reports)
    overall_score = int(100 * total_pass / (total_pass + total_fail)) if (total_pass + total_fail) > 0 else 0

    return jsonify({
        "scanned": len(device_reports),
        "rules": len(_COMPLIANCE_RULES),
        "overall_score": overall_score,
        "total_passed": total_pass,
        "total_failed": total_fail,
        "scanned_at": datetime.now().isoformat(),
        "devices": device_reports,
    })


# ══════════════════════════════════════════════════════════════════════════════
# CLI-over-HTTPS transport  (Feature 8)
# Proxy map: hostname → localhost port of cli_proxy running inside container
# ══════════════════════════════════════════════════════════════════════════════

_CLI_PROXY_PORTS: dict[str, int] = {
    "de-fra-core-01": 8801,
    "de-fra-core-02": 8802,
    "uk-lon-core-01": 8803,
    "nl-ams-core-01": 8804,
    "us-nyc-core-01": 8805,
    "de-fra-edge-01": 8806,
    "uk-lon-edge-01": 8807,
    "nl-ams-edge-01": 8808,
    "uk-lon-dist-01": 8809,
    "de-fra-dist-01": 8810,
}
_CLI_PROXY_PASSWORD = os.environ.get("CLI_PROXY_PASSWORD", "")
if not _CLI_PROXY_PASSWORD:
    print("[WARN] CLI_PROXY_PASSWORD env var not set — CLI proxy auth will fail. "
          "Set it in .env or disable the CLI Transport benchmark tab.")
_CLI_PROXY_AUTH = ("admin", _CLI_PROXY_PASSWORD)
_BENCH_COMMANDS = [
    "show version",
    "show bgp summary",
    "show ip ospf neighbor",
    "show interface brief",
    "show ip route summary",
]


def _proxy_url(hostname: str, path: str) -> str | None:
    port = _CLI_PROXY_PORTS.get(hostname)
    if port is None:
        return None
    return f"http://localhost:{port}{path}"


@app.route("/api/cli-https", methods=["POST"])
def api_cli_https():
    """
    POST /api/cli-https
    Body: { "hostname": "de-fra-core-01", "commands": ["show version", "show bgp summary"] }
    Returns: { hostname, transport, commands, results:[{cmd,output,elapsed_ms}], total_elapsed_ms }
    """
    data: dict = request.get_json(force=True) or {}
    hostname: str = (data.get("hostname") or "").strip()
    commands: list[str] = data.get("commands") or []
    if not hostname:
        return jsonify({"error": "hostname required"}), 400
    if not commands:
        return jsonify({"error": "commands list required"}), 400

    port = _CLI_PROXY_PORTS.get(hostname)
    if port is None:
        return jsonify({"error": f"{hostname} not in CLI proxy map"}), 404

    # Build batch path: /batch/<cmd1>/<cmd2>/...
    encoded = "/".join(urllib.parse.quote(c, safe="") for c in commands)
    url = f"http://localhost:{port}/batch/{encoded}"
    t0 = time.time()
    try:
        resp = _requests.get(url, auth=_CLI_PROXY_AUTH, timeout=15)
        resp.raise_for_status()
        body = resp.json()
    except Exception as exc:
        return jsonify({"error": str(exc), "hostname": hostname, "transport": "https"}), 502

    body["transport"] = "https"
    body["total_elapsed_ms"] = int((time.time() - t0) * 1000)
    return jsonify(body)


@app.route("/api/transport-bench", methods=["POST"])
def api_transport_bench():
    """
    POST /api/transport-bench
    Body: { "hostname": "de-fra-core-01", "commands": ["show version", ...] }
          commands defaults to the 5-command benchmark set.
    Returns: { hostname, ssh_ms, https_ms, speedup, commands, ssh_results, https_results }

    Runs both transports concurrently via threads, returns side-by-side timing.
    """
    data: dict = request.get_json(force=True) or {}
    hostname: str = (data.get("hostname") or "").strip()
    commands: list[str] = data.get("commands") or _BENCH_COMMANDS
    if not hostname:
        return jsonify({"error": "hostname required"}), 400

    device = get_device_by_hostname(hostname)
    # Fall back to lab synthetic device entry when hostname is a known lab proxy host
    if device is None and hostname in _CLI_PROXY_PORTS:
        lab_port_offset = list(_CLI_PROXY_PORTS.keys()).index(hostname) + 1
        device = {
            "hostname": hostname, "ip": "localhost",
            "type": "frr", "role": "lab",
            "port": 2200 + lab_port_offset,
        }
    if device is None:
        return jsonify({"error": f"device {hostname} not in inventory"}), 404

    ssh_result: dict = {}
    https_result: dict = {}
    https_err: str = ""

    # Use module-level _FRR_SSH_KEY (handles src/ + flat + env override)
    _lab_key = _FRR_SSH_KEY if os.path.exists(_FRR_SSH_KEY) else None

    def _run_ssh():
        nonlocal ssh_result
        t0 = time.time()
        per_cmd = []
        for cmd in commands:
            ct0 = time.time()
            cli = paramiko.SSHClient()
            apply_ssh_policy(cli)
            out_str = ""
            try:
                if _lab_key:
                    cli.connect("localhost", port=device.get("port", 22),
                                username="root", key_filename=_lab_key,
                                timeout=10, look_for_keys=False, allow_agent=False)
                else:
                    _frr_pw = os.environ.get("FRR_DEFAULT_PASSWORD", "")
                    if not _frr_pw:
                        raise RuntimeError(
                            "No SSH key found and FRR_DEFAULT_PASSWORD not set; "
                            "cannot authenticate to FRR container."
                        )
                    cli.connect("localhost", port=device.get("port", 22),
                                username="root", password=_frr_pw,
                                timeout=10, look_for_keys=False, allow_agent=False)
                import shlex as _shlex
                _, stdout, stderr = cli.exec_command(
                    f"vtysh -c {_shlex.quote(cmd)}", timeout=10)
                out_str = (stdout.read().decode("utf-8", errors="replace") or
                           stderr.read().decode("utf-8", errors="replace")).strip()
            except Exception as exc:
                out_str = f"[SSH error: {exc}]"
            finally:
                try:
                    cli.close()
                except Exception:
                    pass
            per_cmd.append({
                "cmd": cmd,
                "output": out_str[:300],
                "elapsed_ms": int((time.time() - ct0) * 1000),
            })
        ssh_result = {
            "transport": "ssh",
            "total_elapsed_ms": int((time.time() - t0) * 1000),
            "results": per_cmd,
        }

    def _run_https():
        nonlocal https_result, https_err
        proxy_port = _CLI_PROXY_PORTS.get(hostname)
        if proxy_port is None:
            https_err = f"{hostname} not in proxy map"
            return
        encoded = "/".join(urllib.parse.quote(c, safe="") for c in commands)
        url = f"http://localhost:{proxy_port}/batch/{encoded}"
        t0 = time.time()
        try:
            resp = _requests.get(url, auth=_CLI_PROXY_AUTH, timeout=15)
            resp.raise_for_status()
            body = resp.json()
            body["transport"] = "https"
            body["total_elapsed_ms"] = int((time.time() - t0) * 1000)
            https_result = body
        except Exception as exc:
            https_err = str(exc)

    from concurrent.futures import ThreadPoolExecutor as _TPE
    with _TPE(max_workers=2) as pool:
        f_ssh   = pool.submit(_run_ssh)
        f_https = pool.submit(_run_https)
        f_ssh.result()
        f_https.result()

    if https_err:
        https_result = {"transport": "https", "error": https_err, "total_elapsed_ms": 0, "results": []}

    ssh_ms   = ssh_result.get("total_elapsed_ms", 0)
    https_ms = https_result.get("total_elapsed_ms", 0)
    speedup  = round(ssh_ms / https_ms, 1) if https_ms > 0 else 0

    return jsonify({
        "hostname":      hostname,
        "commands":      commands,
        "ssh_ms":        ssh_ms,
        "https_ms":      https_ms,
        "speedup":       speedup,
        "ssh_results":   ssh_result.get("results", []),
        "https_results": https_result.get("results", []),
    })


@app.route("/api/cli-fleet", methods=["POST"])
def api_cli_fleet():
    """
    POST /api/cli-fleet
    Body: { "commands": ["show bgp summary", ...], "hostnames": [...] (optional) }
    Runs commands on all (or specified) lab devices IN PARALLEL via HTTP proxy.
    Returns: { total_ms, device_count, command_count, devices: [{hostname, ms, ok, results}] }

    This is the killer demo: collect state from 10 devices in one HTTP fan-out,
    not 10 sequential SSH PTY setups.
    """
    from concurrent.futures import ThreadPoolExecutor as _TPE

    data: dict = request.get_json(force=True) or {}
    commands: list[str] = data.get("commands") or ["show bgp summary"]
    hostnames: list[str] = data.get("hostnames") or list(_CLI_PROXY_PORTS.keys())

    # Only allow known lab hosts to avoid accidental production access
    hostnames = [h for h in hostnames if h in _CLI_PROXY_PORTS]
    if not hostnames:
        return jsonify({"error": "no valid lab hostnames provided"}), 400

    t_fleet_start = time.time()

    def _fetch_device(hostname: str) -> dict:
        port = _CLI_PROXY_PORTS[hostname]
        encoded = "/".join(urllib.parse.quote(c, safe="") for c in commands)
        url = f"http://localhost:{port}/batch/{encoded}"
        t0 = time.time()
        try:
            resp = _requests.get(url, auth=_CLI_PROXY_AUTH, timeout=15)
            resp.raise_for_status()
            body = resp.json()
            return {
                "hostname": hostname,
                "ms": int((time.time() - t0) * 1000),
                "ok": True,
                "results": body.get("results", []),
            }
        except Exception as exc:
            return {
                "hostname": hostname,
                "ms": int((time.time() - t0) * 1000),
                "ok": False,
                "error": str(exc),
                "results": [],
            }

    with _TPE(max_workers=len(hostnames)) as pool:
        device_results = list(pool.map(_fetch_device, hostnames))

    total_ms = int((time.time() - t_fleet_start) * 1000)
    ok_count  = sum(1 for d in device_results if d["ok"])

    return jsonify({
        "total_ms":     total_ms,
        "device_count": len(device_results),
        "ok_count":     ok_count,
        "command_count": len(commands),
        "commands":     commands,
        "devices":      device_results,
    })


@app.route("/api/cli-proxy/health", methods=["GET"])
def api_cli_proxy_health():
    """GET /api/cli-proxy/health — check which lab devices have proxy running."""
    statuses = []
    for hostname, port in _CLI_PROXY_PORTS.items():
        try:
            r = _requests.get(f"http://localhost:{port}/health", auth=_CLI_PROXY_AUTH, timeout=2)
            statuses.append({"hostname": hostname, "port": port, "ok": r.status_code == 200})
        except Exception:
            statuses.append({"hostname": hostname, "port": port, "ok": False})
    return jsonify({"proxies": statuses, "total": len(statuses), "up": sum(1 for s in statuses if s["ok"])})


# ══════════════════════════════════════════════════════════════════════════════
# ── 🤖 AGENT COORDINATOR  POST /api/chat ─────────────────────────────────────
# Adapted from NetOpsHub (github.com/cwccie/netopshub) coordinator pattern.
# Routes natural-language messages to the right specialised agent by intent,
# then calls the existing Flask endpoint logic directly (no HTTP round-trips).
#
# Agents mapped to existing endpoints:
#   diagnosis   → health-card SSH + LLM RCA
#   remediation → /api/remediate  (sim_bgp_failure.sh)
#   verification→ /api/pyats/snapshot + /api/pyats/diff
#   compliance  → config pull + _BATFISH_RULES + LLM audit
#   discovery   → /api/topology/discover
#   forecast    → /api/librenms/forecast
#   correlation → /api/keep/correlate
#   knowledge   → LLM vendor-doc Q&A
#   nornir      → /api/nornir/run  (parallel fleet audit)
#   batfish     → /api/batfish/analyze
#   ai_command  → /api/ai-command  (default fallback)
# ══════════════════════════════════════════════════════════════════════════════

import re as _coord_re

_AGENT_ROUTES: list[tuple[str, str, str]] = [
    # (regex_pattern, agent_name, display_intent)
    (r"diagnos|why.*(fail|down|flap|drop|unreachable)|root.?cause|rca|flap|session.down|anomal",
     "diagnosis",    "Root-cause analysis via SSH + AI"),
    (r"fix|remedia|rollback|restore|break.*bgp|sim.*fail|chaos",
     "remediation",  "Auto-remediation runbooks"),
    (r"verif|post.?change|validate|diff|snapshot|before.*after|regression",
     "verification", "Pre/post state capture & diff (pyATS)"),
    (r"complian|audit|pci|nist|cis|security.*(check|scan)|baseline|config.*(check|scan)",
     "compliance",   "Config compliance scanner (PCI-DSS / NIST / CIS)"),
    (r"discover|topolog|neighbor|lldp|cdp|auto.?discov",
     "discovery",    "LLDP topology auto-discovery"),
    (r"predict|forecast|capacity|trend|exhaust|growth|bandwidth.*will",
     "forecast",     "Capacity & bandwidth forecast (LibreNMS)"),
    (r"alert|correlat|incident|suppress|noise|librenms.*alert",
     "correlation",  "Alert correlation & noise reduction (Keep engine)"),
    (r"what.*(cause|caus|trigger|happen|mean|is|are)|explain|document|vendor|knowledge|"
     r"how.*(work|config|ospf|bgp|mpls|vxlan)|why.*(ospf|isis|stp|spanning|vlan|nat|acl|qos)|"
     r"diff.*between|compare|protocol|rfc|standard",
     "knowledge",    "Vendor-doc Q&A (Juniper / Arista / FRR)"),
    (r"nornir|parallel|fleet|site.wide|all.*device|batch.*check",
     "nornir",       "Parallel fleet audit (Nornir)"),
    (r"batfish|pre.?deploy|config.*valid|lint.*config|check.*config.*before",
     "batfish",      "Pre-deploy config validator (Batfish rules)"),
]


def _coord_route(message: str) -> tuple[str, str]:
    """Return (agent_name, display_intent) for the best-matching intent."""
    msg = message.lower()
    best_agent, best_intent, best_score = "ai_command", "NL → CLI via Qwen3 (default)", 0
    for pattern, agent, intent in _AGENT_ROUTES:
        matches = _coord_re.findall(pattern, msg)
        if matches and len(matches) > best_score:
            best_score = len(matches)
            best_agent, best_intent = agent, intent
    return best_agent, best_intent


# ── Agent handlers ─────────────────────────────────────────────────────────────

def _extract_hostname_from_text(text: str) -> str:
    """Match any inventory hostname (DEVICES + multivendor _ALL_DEVICES) in free text."""
    if not text:
        return ""
    t = text.lower()
    candidates: list[str] = [d["hostname"] for d in DEVICES if d.get("hostname")]
    try:
        from multivendor_extensions import _ALL_DEVICES as _MV_DEVICES  # type: ignore
        candidates.extend(d["hostname"] for d in _MV_DEVICES if d.get("hostname"))
    except (ImportError, AttributeError):
        pass
    for h in sorted(set(candidates), key=len, reverse=True):
        if h.lower() in t:
            return h
    return ""


def _load_mv_static_config(hostname: str) -> tuple[str, dict] | tuple[None, None]:
    """Return (config_text, mv_device_dict) for a multivendor static-config device."""
    try:
        from multivendor_extensions import _ALL_DEVICES as _MV_DEVICES, _DEMO_DIR  # type: ignore
    except (ImportError, AttributeError):
        return None, None
    dev = next((d for d in _MV_DEVICES if d.get("hostname") == hostname), None)
    if not dev or not dev.get("config"):
        return None, None
    full = os.path.join(_DEMO_DIR, dev["config"])
    try:
        with open(full, errors="replace") as f:
            return f.read(), dev
    except OSError:
        return None, None


def _load_mv_live_config(hostname: str) -> tuple[str, dict] | tuple[None, None]:
    """For live FRR devices in the multivendor inventory, SSH and return running-config."""
    try:
        from multivendor_extensions import _ALL_DEVICES as _MV_DEVICES  # type: ignore
    except (ImportError, AttributeError):
        return None, None
    dev = next((d for d in _MV_DEVICES if d.get("hostname") == hostname and d.get("live")), None)
    if not dev:
        return None, None
    ip   = dev.get("ip", "127.0.0.1")
    port = int(dev.get("port", 22))
    dtype = dev.get("os", "frr")
    cmd = "show running-config" if dtype == "frr" else (
        "show configuration | display set" if dtype == "junos" else "show running-config"
    )
    try:
        r = run_command_on_device(ip, dtype, cmd, port=port)
        text = (r or {}).get("output", "") if isinstance(r, dict) else ""
        if text.strip():
            return text, dev
    except (OSError, RuntimeError, ValueError):
        pass
    return None, None


def _agent_diagnosis(message: str, hostname: str, context: dict) -> dict:
    """Collect per-device health data then ask LLM for root-cause analysis."""
    evidence: dict = {}
    dev = get_device_by_hostname(hostname) if hostname else None
    if dev:
        ip, dtype, port = dev["ip"], dev.get("type", "junos"), dev.get("port", 22)
        cmd_set = _HEALTH_CMDS.get(dtype, _HEALTH_CMDS["junos"])
        raw: dict[str, str] = {}
        for key, cmd in cmd_set.items():
            r = run_command_on_device(ip, dtype, cmd, port=port)
            raw[key] = r.get("output", "") if isinstance(r, dict) else str(r)
        evidence["health"] = raw

    sys_p = (
        "You are a senior network engineer performing root-cause analysis. "
        "Given the user question and any device health data, identify the likely cause, "
        "blast radius, and recommended remediation steps. Be concise and specific."
    )
    evidence_text = ""
    if evidence.get("health"):
        evidence_text = "\n\nDevice health data:\n" + "\n".join(
            f"{k}: {v[:500]}" for k, v in evidence["health"].items() if v
        )
    answer = _llm_query(sys_p, f"Question: {message}{evidence_text}", max_tokens=400)
    return {
        "answer":   _clean_llm_response(answer) if answer else "LLM unavailable",
        "evidence": evidence,
        "hostname": hostname,
    }


def _agent_compliance(message: str, hostname: str, context: dict) -> dict:
    """Pull running config and check against Batfish rules + LLM audit."""
    if not hostname:
        return {"error": f"Provide a hostname for compliance scan (device '{hostname}' not in inventory)"}
    dev = get_device_by_hostname(hostname)
    config: str = ""
    source: str = ""
    if dev:
        ip, dtype, port = dev["ip"], dev.get("type", "junos"), dev.get("port", 22)
        cmd = "show configuration | display set" if dtype == "junos" else "show running-config"
        r = run_command_on_device(ip, dtype, cmd, port=port)
        config = r.get("output", "") if isinstance(r, dict) else ""
        source = f"live SSH ({dtype})"
    if not config:
        cfg_text, mv_dev = _load_mv_static_config(hostname)
        if cfg_text:
            config = cfg_text
            source = f"static config ({mv_dev.get('config')})"
    if not config:
        cfg_text, mv_dev = _load_mv_live_config(hostname)
        if cfg_text:
            config = cfg_text
            source = f"live SSH ({mv_dev.get('os')} :{mv_dev.get('port')})"
    if not config:
        return {"error": f"Could not retrieve device config for '{hostname}'"}

    findings: list[dict] = []
    for pattern, severity, msg in _BATFISH_RULES:
        match = _re.search(pattern, config, _re.IGNORECASE)
        if severity in ("error", "warn") and match:
            findings.append({"severity": severity, "message": msg})
        elif severity == "pass" and match:
            findings.append({"severity": "pass", "message": f"OK: {msg}"})

    sys_p = (
        "You are a network security auditor. Review this config for PCI-DSS, NIST 800-53, "
        "and CIS Benchmark violations. List findings as [CRITICAL/HIGH/MEDIUM/LOW] description."
    )
    llm_raw = _llm_query(sys_p, f"Device: {hostname}\nConfig:\n{config[:3000]}", max_tokens=400)
    return {
        "hostname":      hostname,
        "config_source": source,
        "rule_findings": findings,
        "ai_findings":   _clean_llm_response(llm_raw) if llm_raw else None,
        "errors":        sum(1 for f in findings if f["severity"] == "error"),
        "warnings":      sum(1 for f in findings if f["severity"] == "warn"),
    }


def _agent_knowledge(message: str, hostname: str, context: dict) -> dict:
    """Answer vendor-doc / protocol questions via LLM."""
    sys_p = (
        "You are a network expert with deep knowledge of Juniper JunOS, Arista EOS, FRRouting, "
        "BGP, OSPF, MPLS, VXLAN, and network security. Answer clearly and accurately. "
        "Include CLI examples where helpful."
    )
    answer = _llm_query(sys_p, message, max_tokens=500)
    return {"answer": _clean_llm_response(answer) if answer else "LLM unavailable"}


def _agent_forecast(message: str, hostname: str, context: dict) -> dict:
    """Pull LibreNMS port utilisation and project bandwidth exhaustion."""
    lnms_url   = os.environ.get("LIBRENMS_URL",   "")
    lnms_token = os.environ.get("LIBRENMS_TOKEN", "")
    if not (lnms_url and lnms_token):
        return {"error": "LibreNMS not configured — set LIBRENMS_URL and LIBRENMS_TOKEN"}
    try:
        dev_resp = _requests.get(
            f"{lnms_url}/api/v0/devices?hostname={hostname}",
            headers={"X-Auth-Token": lnms_token}, timeout=8, verify=DCN_VERIFY_SSL,
        )
        devs = dev_resp.json().get("devices", [])
        if not devs:
            return {"error": f"Device '{hostname}' not found in LibreNMS"}
        device_id = devs[0]["device_id"]
        ports_resp = _requests.get(
            f"{lnms_url}/api/v0/ports/{device_id}",
            headers={"X-Auth-Token": lnms_token}, timeout=8, verify=DCN_VERIFY_SSL,
        )
        ports = ports_resp.json().get("ports", [])
    except Exception as exc:
        return {"error": str(exc)}

    sys_p = (
        "You are a capacity planning expert. Given device port utilisation data, "
        "identify ports near capacity and predict when they will reach saturation. "
        "Be specific with percentages and timeframes."
    )
    port_summary = "\n".join(
        f"{p.get('ifName', '')}: in={p.get('ifInOctets_rate', 0)} "
        f"out={p.get('ifOutOctets_rate', 0)} speed={p.get('ifSpeed', 0)}"
        for p in ports[:20]
    )
    answer = _llm_query(sys_p, f"Device: {hostname}\nPorts:\n{port_summary}", max_tokens=400)
    return {
        "hostname":   hostname,
        "port_count": len(ports),
        "forecast":   _clean_llm_response(answer) if answer else "LLM unavailable",
    }


def _agent_nornir_hint(message: str, hostname: str, context: dict) -> dict:
    """Suggest the correct Nornir task based on message keywords."""
    task = "bgp_health"
    msg = message.lower()
    if "version" in msg:        task = "version"
    elif "interface" in msg:    task = "interface_check"
    elif "alarm" in msg:        task = "alarm_check"
    elif "route" in msg:        task = "routing_table"

    site = context.get("site", "") or (_site_from_hostname(hostname) if hostname else "de-fra")
    return {
        "task":     task,
        "site":     site,
        "endpoint": "/api/nornir/run",
        "body":     {"task": task, "site": site, "workers": 50},
        "hint":     "Nornir runs all site devices in parallel — typically 3-5 s vs 40 s+ sequential",
    }


# ── Coordinator route ──────────────────────────────────────────────────────────

@app.route("/api/chat", methods=["POST"])
def api_chat():
    """Agent Coordinator — routes NL messages to the right specialised agent.

    Adapted from NetOpsHub coordinator pattern (github.com/cwccie/netopshub).

    Body:
        {
          "message":  "Why is BGP flapping on de-fra-core-01?",
          "hostname": "de-fra-core-01",        // optional — for device-specific queries
          "context":  {"site": "de-fra"}     // optional — extra hints
        }

    Returns:
        {
          "agent":       "diagnosis",
          "intent":      "Root-cause analysis via SSH + AI",
          "message":     "<original>",
          "hostname":    "de-fra-core-01",
          "result":      { ... agent-specific data ... },
          "suggestions": ["follow-up action 1", ...],
          "timestamp":   "2026-05-02T..."
        }
    """
    data      = request.get_json(force=True) or {}
    message   = (data.get("message") or data.get("query") or "").strip()
    hostname  = (data.get("hostname") or "").strip()
    context   = data.get("context") or {}

    if not message:
        return jsonify({"error": "message required"}), 400

    if not hostname:
        hostname = _extract_hostname_from_text(message)

    agent, intent = _coord_route(message)

    try:
        if agent == "diagnosis":
            result = _agent_diagnosis(message, hostname, context)
            suggestions = [
                f"POST /api/remediate {{\"action\": \"fix\"}}  — restore sessions",
                f"POST /api/pyats/snapshot {{\"hostname\": \"{hostname}\"}}  — capture state",
                f"POST /api/nornir/run {{\"task\": \"bgp_health\", \"site\": \"{_site_from_hostname(hostname)}\"}}",
            ]

        elif agent == "remediation":
            result = {
                "endpoint": "/api/remediate",
                "hint": "POST /api/remediate with action: status | fix | break | chaos",
                "workflow": "diagnose → remediate → verify",
            }
            suggestions = [
                "POST /api/remediate {\"action\": \"status\"} — show BGP state",
                "POST /api/remediate {\"action\": \"fix\"}    — restore all sessions",
                "POST /api/remediate {\"action\": \"chaos\"}  — random 30 s failure",
            ]

        elif agent == "verification":
            result = {
                "endpoints": ["/api/pyats/snapshot", "/api/pyats/diff"],
                "workflow":  "1. Snapshot BEFORE change  2. Apply change  3. Diff to verify",
                "hint":      "pyATS captures interface/BGP/OSPF state and highlights deltas",
            }
            suggestions = [
                f"POST /api/pyats/snapshot {{\"hostname\": \"{hostname}\"}}  — pre-change baseline",
                f"POST /api/pyats/diff    {{\"hostname\": \"{hostname}\"}}  — post-change diff",
            ]

        elif agent == "compliance":
            result = _agent_compliance(message, hostname, context)
            suggestions = [
                "POST /api/batfish/analyze {\"config\": \"...\"}  — check a config snippet",
                "POST /api/compliance/scan                        — full fleet scan",
            ]

        elif agent == "discovery":
            result = {
                "endpoints": ["/api/topology/discover", "/api/napalm/lldp-topology"],
                "hint":      "LLDP walk builds a live neighbor graph; NAPALM adds interface/speed metadata",
            }
            suggestions = [
                f"POST /api/topology/discover    {{\"site\": \"{context.get('site', 'de-fra')}\"}}",
                f"POST /api/napalm/lldp-topology {{\"site\": \"{context.get('site', 'de-fra')}\"}}",
            ]

        elif agent == "forecast":
            result = _agent_forecast(message, hostname, context)
            suggestions = [
                f"GET /api/librenms/forecast/{hostname}  — 30-day bandwidth forecast",
                "GET /api/librenms/forecast-site?site=de-fra  — site-wide capacity",
            ]

        elif agent == "correlation":
            result = {
                "endpoint": "/api/keep/correlate",
                "hint":     "Pulls LibreNMS + Kibana alerts, groups into incidents, suppresses noise",
            }
            suggestions = [
                "POST /api/keep/correlate {}                — correlate all active alerts",
                f"POST /api/keep/correlate {{\"site\": \"{context.get('site', 'de-fra')}\"}}  — site-filtered",
            ]

        elif agent == "knowledge":
            result = _agent_knowledge(message, hostname, context)
            suggestions = [
                "POST /api/docs/search {\"query\": \"...\"}  — search vendor docs",
                f"POST /api/ai-command {{\"query\": \"{message}\", \"hostname\": \"{hostname}\"}}  — as CLI",
            ]

        elif agent == "nornir":
            result = _agent_nornir_hint(message, hostname, context)
            suggestions = [
                f"POST /api/nornir/run {{\"task\": \"bgp_health\",   \"site\": \"{context.get('site', 'de-fra')}\", \"workers\": 50}}",
                f"POST /api/nornir/run {{\"task\": \"version\",      \"site\": \"all\",   \"workers\": 50}}",
                f"POST /api/nornir/run {{\"task\": \"alarm_check\",  \"site\": \"{context.get('site', 'de-fra')}\", \"workers\": 50}}",
            ]

        elif agent == "batfish":
            result = {
                "endpoint": "/api/batfish/analyze",
                "hint":     "Paste any Junos/EOS config snippet — checks BGP auth, export policy, hold-time, BFD",
            }
            suggestions = [
                "POST /api/batfish/analyze {\"config\": \"<paste config>\"}  — pre-deploy validation",
            ]

        else:  # ai_command — NL→CLI fallback
            dev   = get_device_by_hostname(hostname)
            dtype = dev.get("type", "junos") if dev else "junos"
            translation_raw = _llm_query(
                _NL_SYSTEM,
                f'Device type: {dtype}\nQuestion: "{message}"',
                max_tokens=150,
            )
            cli_cmd = ""
            if translation_raw:
                try:
                    import json as _j
                    jm = _coord_re.search(r'\{[^}]+\}', translation_raw, _coord_re.DOTALL)
                    cli_cmd = _j.loads(jm.group(0) if jm else translation_raw).get("cli", "").strip()
                except Exception:
                    cli_cmd = _coord_re.sub(r'^```\w*\n?|```$', '', translation_raw.strip(), flags=_coord_re.M).strip()

            ssh_result  = None
            explanation = None
            if dev and cli_cmd:
                ssh_result = run_command_on_device(dev["ip"], dtype, cli_cmd, port=dev.get("port", 22))
                ssh_text   = ssh_result.get("output", "") if isinstance(ssh_result, dict) else str(ssh_result)
                raw_exp    = _llm_query(
                    "You are a senior network engineer. Summarize this CLI output in 2-3 sentences. Highlight any issues.",
                    f"Command: {cli_cmd}\nOutput:\n{ssh_text[:3000]}",
                    max_tokens=300,
                )
                explanation = _clean_llm_response(raw_exp) if raw_exp else None

            result = {"cli": cli_cmd, "output": ssh_result, "explanation": explanation}
            suggestions = [
                "Try: 'Why is BGP flapping on <hostname>?'           → diagnosis agent",
                "Try: 'Run compliance check on <hostname>'           → compliance agent",
                "Try: 'Run BGP health check across de-fra'             → Nornir fleet audit",
                "Try: 'What causes OSPF adjacency failures?'         → knowledge agent",
            ]

    except Exception as exc:
        return jsonify({"error": str(exc), "agent": agent, "intent": intent}), 500

    return jsonify({
        "agent":       agent,
        "intent":      intent,
        "message":     message,
        "hostname":    hostname,
        "result":      result,
        "suggestions": suggestions,
        "timestamp":   datetime.now().isoformat(),
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── 🔄 OBSERVER-ACTOR FEEDBACK LOOP (L7 — Closed-Loop Remediation) ───────────
# ══════════════════════════════════════════════════════════════════════════════

_OBSERVER_EVENTS: list[dict] = []
_OBSERVER_EVENTS_LOCK = threading.Lock()


def _observer_record(event: dict) -> None:
    """Append to the observer ring buffer (max 50 entries)."""
    with _OBSERVER_EVENTS_LOCK:
        _OBSERVER_EVENTS.append({**event, "ts": datetime.now().isoformat()})
        if len(_OBSERVER_EVENTS) > 50:
            _OBSERVER_EVENTS.pop(0)


@app.route("/api/observer-actor/status", methods=["GET"])
def api_observer_status():
    """Return the last 20 observer-actor feedback events."""
    with _OBSERVER_EVENTS_LOCK:
        return jsonify({"events": list(reversed(_OBSERVER_EVENTS[-20:]))})


@app.route("/api/observer-actor/feedback", methods=["POST"])
def api_observer_feedback():
    """
    Closed-loop Observer-Actor feedback:
    1. Runs pyATS diff on the given hostname.
    2. If unintended BGP/interface changes are detected, auto-generates a
       Rollback Proposal with the highest P1 priority.
    3. Records the event in the observer ring buffer.
    """
    data     = request.get_json(force=True) or {}
    hostname = (data.get("hostname") or "").strip()
    if not hostname:
        return jsonify({"error": "hostname required"}), 400

    pre  = _PYATS_SNAPSHOTS.get(f"{hostname}:pre")
    post = _PYATS_SNAPSHOTS.get(f"{hostname}:post")
    if not pre or not post:
        msg = f"No snapshots for {hostname} — take PRE then POST snapshots first"
        _observer_record({"hostname": hostname, "action": "feedback",
                          "status": "no_snapshots", "message": msg})
        return jsonify({"hostname": hostname, "status": "no_snapshots",
                        "message": msg, "proposals": []})

    diffs: list[dict] = []
    for iface in set(pre["data"].get("interfaces", {}).keys()) | set(post["data"].get("interfaces", {}).keys()):
        pa = pre["data"].get("interfaces", {}).get(iface, {}).get("is_up")
        pb = post["data"].get("interfaces", {}).get(iface, {}).get("is_up")
        if pa != pb:
            diffs.append({"type": "interface", "name": iface,
                          "before": "UP" if pa else "DOWN",
                          "after":  "UP" if pb else "DOWN",
                          "severity": "CRITICAL" if not pb else "WARNING"})

    for vrf, vd in (post["data"].get("bgp_neighbors") or {}).items():
        for pip, pd in vd.get("peers", {}).items():
            pre_up  = (pre["data"].get("bgp_neighbors") or {}).get(vrf, {}).get(
                "peers", {}).get(pip, {}).get("is_up")
            post_up = pd.get("is_up")
            if pre_up != post_up:
                diffs.append({"type": "bgp", "name": pip,
                              "before": "UP" if pre_up  else "DOWN",
                              "after":  "UP" if post_up else "DOWN",
                              "severity": "CRITICAL" if not post_up else "INFO"})

    if not diffs:
        _observer_record({"hostname": hostname, "action": "feedback",
                          "status": "clean", "diffs": 0})
        return jsonify({"hostname": hostname, "status": "clean", "diffs": [],
                        "proposals": [],
                        "message": "✅ No unintended changes detected — state is healthy."})

    # LLM generates rollback commands
    diff_summary = "\n".join(
        f"[{d['severity']}] {d['type'].upper()} {d['name']}: {d['before']} → {d['after']}"
        for d in diffs
    )
    sys_p = (
        "You are a network automation engineer. Given these unintended state changes after a config push, "
        "generate specific rollback CLI commands (FRR vtysh syntax). "
        "Return JSON only: {\"priority\":\"P1\",\"summary\":\"...\","
        "\"commands\":[\"cmd1\",\"cmd2\"],\"risk\":\"low\"|\"medium\"|\"high\"}"
    )
    llm_raw = _llm_query(sys_p, f"Device: {hostname}\nChanges:\n{diff_summary}", max_tokens=500)
    proposal: dict = {"id": f"RB-{int(time.time())}", "hostname": hostname, "diffs": diffs,
                      "priority": "P1", "risk": "medium",
                      "summary": f"Rollback needed — {len(diffs)} unintended change(s) detected",
                      "commands": []}
    if llm_raw:
        try:
            import re as _re_local
            import json as _json_local
            m = _re_local.search(r'\{[^{}]+\}', llm_raw, _re_local.DOTALL)
            if m:
                proposal.update(_json_local.loads(m.group()))
        except Exception:
            pass

    _observer_record({"hostname": hostname, "action": "feedback",
                      "status": "rollback_proposed", "diffs": len(diffs),
                      "proposal_id": proposal["id"], "summary": proposal["summary"]})

    return jsonify({
        "hostname": hostname, "status": "rollback_proposed",
        "total_diffs": len(diffs), "diffs": diffs,
        "proposals": [proposal],
        "message": (f"⚠️ {len(diffs)} unintended change(s) detected — "
                    f"Rollback Proposal {proposal['id']} generated [{proposal['priority']}]"),
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── 💥 BLAST RADIUS VISUALIZER (L7 — Pre-Deploy Batfish Heatmap) ─────────────
# ══════════════════════════════════════════════════════════════════════════════

# Lab topology adjacency map for blast-radius BFS propagation
_LAB_ADJACENCY: dict[str, list[str]] = {
    "de-fra-core-01": ["de-fra-core-02", "uk-lon-core-01", "us-nyc-core-01",
                       "de-fra-edge-01", "de-fra-dist-01"],
    "de-fra-core-02": ["de-fra-core-01", "nl-ams-core-01", "de-fra-edge-01"],
    "uk-lon-core-01": ["de-fra-core-01", "uk-lon-edge-01", "uk-lon-dist-01"],
    "nl-ams-core-01": ["de-fra-core-02", "nl-ams-edge-01"],
    "us-nyc-core-01": ["de-fra-core-01"],
    "de-fra-edge-01": ["de-fra-core-01", "de-fra-core-02"],
    "uk-lon-edge-01": ["uk-lon-core-01"],
    "nl-ams-edge-01": ["nl-ams-core-01"],
    "uk-lon-dist-01": ["uk-lon-core-01"],
    "de-fra-dist-01": ["de-fra-core-01"],
}


@app.route("/api/batfish/blast-radius", methods=["POST"])
def api_batfish_blast_radius():
    """
    Blast Radius Visualizer: run Batfish config analysis then BFS through
    the topology adjacency graph to determine which nodes are affected.
    Returns severity-labelled node list for topology heatmap rendering.
    """
    data     = request.get_json(force=True) or {}
    config   = (data.get("config") or "").strip()
    hostname = (data.get("hostname") or "de-fra-core-01").strip()
    if not config:
        return jsonify({"error": "config required"}), 400

    sys_p = (
        "You are a Batfish network validation expert. Analyse this config snippet and return JSON only:\n"
        "{\"errors\":[{\"severity\":\"ERROR\",\"check\":\"...\",\"detail\":\"...\"}],"
        "\"warnings\":[{\"severity\":\"WARNING\",\"check\":\"...\",\"detail\":\"...\"}],"
        "\"passed\":[\"check_name\"],\"affected_prefixes\":[],\"affected_peers\":[]}"
    )
    llm_raw = _llm_query(sys_p, f"Config snippet for device {hostname}:\n{config[:2000]}", max_tokens=700)
    batfish: dict = {"errors": [], "warnings": [], "passed": [], "affected_prefixes": [], "affected_peers": []}
    if llm_raw:
        try:
            import re as _rl
            import json as _jl
            m = _rl.search(r'\{.*\}', _clean_llm_response(llm_raw), _rl.DOTALL)
            if m:
                batfish = _jl.loads(m.group())
        except Exception:
            pass

    # BFS blast radius only when ERRORs exist
    directly: set[str]    = {hostname}
    transitive: set[str]  = set()
    if batfish.get("errors"):
        for nb in _LAB_ADJACENCY.get(hostname, []):
            directly.add(nb)
        for node in list(directly):
            for nb2 in _LAB_ADJACENCY.get(node, []):
                if nb2 not in directly:
                    transitive.add(nb2)

    nodes = []
    for dev, _ in _LAB_ADJACENCY.items():
        if dev == hostname:
            sev = "origin"
        elif dev in directly and dev != hostname:
            sev = "direct"
        elif dev in transitive:
            sev = "transitive"
        else:
            sev = "clean"
        nodes.append({"hostname": dev, "severity": sev,
                      "adjacents": _LAB_ADJACENCY.get(dev, [])})

    return jsonify({
        "hostname": hostname, "batfish": batfish,
        "blast_radius": {
            "origin": hostname,
            "directly_affected":    list(directly - {hostname}),
            "transitively_affected": list(transitive),
            "clean": [n["hostname"] for n in nodes if n["severity"] == "clean"],
        },
        "nodes": nodes,
        "summary": (
            f"🔴 {len(batfish.get('errors',[]))} errors · "
            f"🟡 {len(batfish.get('warnings',[]))} warnings · "
            f"🟠 {len(directly)-1} directly affected · "
            f"🔵 {len(transitive)} transitively affected"
        ),
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── 📈 NOISE FLOOR TREND CONTROLLER (L7 — Alert Correlation Sparklines) ───────
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/keep/trend", methods=["GET"])
def api_keep_trend():
    """
    Return 24-hour hourly alert trend data per region for sparkline charts.
    Pulls real data from LibreNMS when available; falls back to deterministic
    simulated trends for dashboard demonstration.
    """
    import random as _rnd
    # Round-7 P4: keep regions in sync with the 5-site inventory
    # (DE-FRA, UK-LON, NL-AMS, US-NYC, EU-CDG). New sites here render
    # as additional cards in the Noise Floor grid automatically.
    regions    = ["DE-FRA", "UK-LON", "NL-AMS", "US-NYC", "EU-CDG"]
    lnms_url   = os.environ.get("LIBRENMS_URL", "")
    lnms_token = os.environ.get("LIBRENMS_TOKEN", "")

    regional_data: dict = {}
    total_raw = total_sup = 0

    for region in regions:
        raw_live = 0
        if lnms_url and lnms_token:
            try:
                prefix = region.lower().replace("-", "")
                r = _requests.get(f"{lnms_url}/api/v0/alerts?state=1",
                                  headers={"X-Auth-Token": lnms_token}, timeout=5, verify=DCN_VERIFY_SSL)
                if r.status_code == 200:
                    raw_live = sum(1 for a in (r.json().get("alerts") or [])
                                   if prefix in a.get("hostname", "").lower())
            except Exception:
                pass

        _rnd.seed(sum(ord(c) for c in region))
        t_raw = [max(1, _rnd.randint(4, 18) + (i % 6)) for i in range(24)]
        t_sup = [max(0, int(v * _rnd.uniform(0.55, 0.85))) for v in t_raw]
        t_inc = [max(1, v - s) for v, s in zip(t_raw, t_sup)]
        eff   = round(sum(t_sup) / max(sum(t_raw), 1) * 100, 1)

        regional_data[region] = {
            "raw_alerts":        raw_live or t_raw[-1],
            "trend_raw":         t_raw,
            "trend_suppressed":  t_sup,
            "trend_incidents":   t_inc,
            "efficiency_pct":    eff,
            "noise_ratio":       round(sum(t_raw) / max(sum(t_inc), 1), 1),
        }
        total_raw += regional_data[region]["raw_alerts"]
        total_sup += round(regional_data[region]["raw_alerts"] * eff / 100)

    return jsonify({
        "regions":     regional_data,
        "global": {
            "total_raw":          total_raw,
            "total_suppressed":   total_sup,
            "overall_efficiency": round(total_sup / max(total_raw, 1) * 100, 1),
        },
        "hour_labels": [f"{h:02d}:00" for h in range(24)],
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── 🧠 AGENTIC ACTIVITY STREAM — Think-Aloud Log SSE (L7) ────────────────────
# ══════════════════════════════════════════════════════════════════════════════

from queue import Queue, Empty as _QueueEmpty

_AGENT_STREAMS:    dict[str, Queue] = {}
_AGENT_STREAMS_LOCK = threading.Lock()
_GLOBAL_AGENT_LOG:  list[dict]     = []
_GLOBAL_AGENT_LOG_LOCK = threading.Lock()


def _agent_emit(stream_id: str, step: str, detail: str = "", level: str = "info") -> None:
    """Emit a think-aloud reasoning step to the named SSE queue and global log."""
    import json as _je
    ev = {"step": step, "detail": detail, "level": level,
          "ts": datetime.now().isoformat(), "stream_id": stream_id}
    with _AGENT_STREAMS_LOCK:
        q = _AGENT_STREAMS.get(stream_id)
        if q:
            try:
                q.put_nowait(ev)
            except Exception:
                pass
    with _GLOBAL_AGENT_LOG_LOCK:
        _GLOBAL_AGENT_LOG.append(ev)
        if len(_GLOBAL_AGENT_LOG) > 100:
            _GLOBAL_AGENT_LOG.pop(0)


@app.route("/api/agent/stream", methods=["GET"])
def api_agent_stream():
    """
    Server-Sent Events endpoint for the Think-Aloud Agent Log sidecar.
    Connect with: EventSource('/api/agent/stream?id=global')
    """
    stream_id = request.args.get("id", "global")
    with _AGENT_STREAMS_LOCK:
        if stream_id not in _AGENT_STREAMS:
            _AGENT_STREAMS[stream_id] = Queue(maxsize=100)

    import json as _js2

    def gen():
        with _GLOBAL_AGENT_LOG_LOCK:
            history = list(_GLOBAL_AGENT_LOG[-10:])
        for ev in history:
            yield f"data: {_js2.dumps(ev)}\n\n"
        q = _AGENT_STREAMS[stream_id]
        while True:
            try:
                ev = q.get(timeout=20)
                yield f"data: {_js2.dumps(ev)}\n\n"
            except _QueueEmpty:
                yield 'data: {"step":"heartbeat","level":"ping"}\n\n'

    return app.response_class(
        gen(), mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                 "Access-Control-Allow-Origin": "*"})


@app.route("/api/agent/log", methods=["GET"])
def api_agent_log():
    """Non-streaming fallback — returns last 50 agent reasoning steps."""
    with _GLOBAL_AGENT_LOG_LOCK:
        return jsonify({"events": list(reversed(_GLOBAL_AGENT_LOG[-50:]))})


# ══════════════════════════════════════════════════════════════════════════════
# ── 🐒 BGP CHAOS MONKEY (Lab — stress-test auto-remediation) ─────────────────
# ══════════════════════════════════════════════════════════════════════════════

_CHAOS_SCRIPT = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "../../network-lab/sim_bgp_failure.sh"))


def _clab_chaos(action: str, target: str | None) -> dict:
    """Chaos Monkey actions against the clab Clos-EVPN fabric. Implemented via
    docker exec + per-vendor BGP control commands. Returns a dict with
    `output`, `active_failures`, `mode`, and `target` so the UI can render.

    - status: walk all 9 routing nodes, count established peers
    - break:  pick a router with established peers and clear a session
    - fix:    `clear bgp` / `bgp ... restart` on every node — flaps everything
              back to a clean state
    - chaos:  break, sleep 30s, fix (best-effort; runs synchronously)
    """
    import random
    routing = [d for d in DEVICES
               if d.get("fabric") == "clos-evpn" and d.get("container")
               and d.get("role", "").lower() in ("spine", "leaf")]
    if target:
        routing = [d for d in routing if d["hostname"] == target] or routing[:1]

    if action == "status":
        lines, up_total, down_total = [], 0, 0
        for dev in routing:
            try:
                if dev.get("vendor_canonical") == "frr":
                    raw = _docker_run(dev["container"], "vtysh", "-c",
                                      "show bgp summary json", timeout=6)
                    import json as _jc
                    j = _jc.loads(re.search(r"\{.*\}", raw, re.DOTALL).group(0))
                    af = j.get("ipv4Unicast") or j.get("l2VpnEvpn") or {}
                    peers = (af or {}).get("peers", {}) if isinstance(af, dict) else {}
                    up = sum(1 for p in peers.values() if str(p.get("state","")).lower()=="established")
                    tot = len(peers)
                else:
                    # cEOS / SRL — use the existing collectors for parity
                    if dev.get("vendor_canonical") == "arista-eos":
                        r = _clab_eos_collect(dev["hostname"], dev["container"], ["get_bgp_neighbors"])
                    else:
                        r = _clab_srl_collect(dev["hostname"], dev["container"], ["get_bgp_neighbors"])
                    peers = (r.get("data",{}).get("get_bgp_neighbors",{}).get("global",{}).get("peers") or {})
                    up = sum(1 for p in peers.values() if p.get("is_up"))
                    tot = len(peers)
                up_total += up
                down_total += (tot - up)
                lines.append(f"  {dev['hostname']:8s}  {up}/{tot}  ({dev.get('vendor_canonical','?')})")
            except Exception as e:
                lines.append(f"  {dev['hostname']:8s}  -/-  error: {e}")
        return {"mode": "live-clab", "active_failures": down_total,
                "output": f"Clab BGP status — {up_total} up · {down_total} down\n" + "\n".join(lines)}

    if action == "fix":
        outs = []
        for dev in routing[:3]:  # only need a few to broadcast a fix
            try:
                if dev.get("vendor_canonical") == "frr":
                    _docker_run(dev["container"], "vtysh", "-c", "clear bgp * soft", timeout=8)
                    outs.append(f"  fixed {dev['hostname']}")
            except Exception as e:
                outs.append(f"  {dev['hostname']}: {e}")
        return {"mode": "live-clab", "active_failures": 0,
                "output": "✅ Clab BGP sessions soft-cleared:\n" + "\n".join(outs)}

    if action == "break":
        candidates = [d for d in routing if d.get("vendor_canonical") == "frr"]
        if not candidates:
            return {"mode": "live-clab", "active_failures": 0,
                    "output": "no FRR-vendor target available — cEOS/SRL chaos not yet implemented"}
        victim = random.choice(candidates)
        try:
            # `clear bgp * hard` forces a session reset which counts as a brief outage
            _docker_run(victim["container"], "vtysh", "-c", "clear bgp * hard", timeout=8)
            return {"mode": "live-clab", "active_failures": 1, "target": victim["hostname"],
                    "output": f"⚡ Hard-cleared BGP on {victim['hostname']} ({victim['vendor_canonical']})\n"
                              f"Sessions will renegotiate over ~15s."}
        except Exception as e:
            return {"mode": "live-clab", "error": str(e)}

    if action == "chaos":
        # In-place: break → wait 30s → fix. Synchronous (matches sim_bgp_failure.sh)
        broken = _clab_chaos("break", target)
        import time as _t; _t.sleep(30)
        _clab_chaos("fix", None)
        return {"mode": "live-clab", "active_failures": 0,
                "output": f"🎲 Chaos cycle complete (30s outage on {broken.get('target','?')}, restored)"}

    return {"mode": "live-clab", "error": f"unknown action {action!r}"}


@app.route("/api/chaos/bgp", methods=["POST"])
def api_chaos_bgp():
    """
    BGP Chaos Monkey — trigger controlled failures to stress-test auto-remediation.
    Body: {"action": "status"|"break"|"fix"|"chaos",
           "fabric": "dcn"|"clab",      (optional · defaults to dcn)
           "target": "<hostname>"        (optional · constrains break to one device)}
    """
    data   = request.get_json(force=True) or {}
    action = (data.get("action") or "status").strip().lower()
    fabric = (data.get("fabric") or "dcn").strip().lower()
    target = (data.get("target") or "").strip() or None
    if action not in ("status", "break", "fix", "chaos"):
        return jsonify({"error": f"invalid action '{action}'"}), 400

    # Clab path: vendor-aware docker exec
    if fabric in ("clab", "clos", "clos-evpn", "clab-dc1"):
        r = _clab_chaos(action, target)
        _agent_emit("chaos", f"🐒 Chaos [clab {action}]", (r.get("output","") or r.get("error",""))[:140],
                    "warn" if action in ("break", "chaos") else "info")
        return jsonify({"action": action, "fabric": "clab", **r})

    # DCN path: sim_bgp_failure.sh (legacy)
    _SIMULATED = {
        "status": {"output": "✅ All 10 BGP sessions ESTABLISHED\nNo active failures.", "active_failures": 0},
        "break":  {"output": "⚡ Breaking BGP: de-fra-core-01 ↔ uk-lon-core-01\n"
                             "Session will go DOWN in ~15 seconds.", "active_failures": 1},
        "fix":    {"output": "✅ All BGP sessions restored. Active failures: 0", "active_failures": 0},
        "chaos":  {"output": "🎲 CHAOS: random peer de-fra-core-02 ↔ nl-ams-core-01 "
                             "broken for 30s.", "active_failures": 1},
    }

    if not os.path.isfile(_CHAOS_SCRIPT):
        r = _SIMULATED[action]
        _agent_emit("chaos", f"🐒 Chaos Monkey [{action}]", r["output"][:120],
                    "warn" if r["active_failures"] else "info")
        return jsonify({"action": action, "fabric": "dcn", "mode": "simulated", **r})

    try:
        res = subprocess.run(["bash", _CHAOS_SCRIPT, action],
                             capture_output=True, text=True, timeout=35)
        out = (res.stdout + res.stderr).strip()
        _agent_emit("chaos", f"🐒 Chaos Monkey [{action}]", out[:180],
                    "warn" if action in ("break", "chaos") else "info")
        return jsonify({"action": action, "fabric": "dcn", "mode": "live",
                        "output": out, "returncode": res.returncode})
    except Exception as exc:
        return jsonify({"action": action, "error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ── 👥 SHADOW CONFIG AUDITOR (Lab — NetBox SoT vs live config drift) ──────────
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/shadow/audit", methods=["POST"])
def api_shadow_audit():
    """
    Shadow Config Auditor: compares NetBox Source-of-Truth (expected) against
    the live running config fetched via SSH (actual).
    Flags configuration drift as P1 alerts.
    Body: {"site": "de-fra"|"uk-lon"|"nl-ams"|"us-nyc"|"all", "check": "bgp"|"ospf"|"all"}
    """
    import re as _rca

    data  = request.get_json(force=True) or {}
    site  = (data.get("site")  or "de-fra").strip().lower()
    check = (data.get("check") or "all").strip().lower()

    _SITE_DEVICES: dict[str, list[str]] = {
        "de-fra":   ["de-fra-core-01", "de-fra-core-02", "de-fra-edge-01", "de-fra-dist-01"],
        "uk-lon":   ["uk-lon-core-01", "uk-lon-edge-01", "uk-lon-dist-01"],
        "nl-ams":   ["nl-ams-core-01", "nl-ams-edge-01"],
        "us-nyc":   ["us-nyc-core-01"],
        # clab Clos-EVPN fabric — 9 routing nodes. Hosts excluded (no CLI).
        "clab-dc1": ["spine1", "spine2", "spine3",
                     "leaf1", "leaf2", "leaf3", "leaf4", "leaf5", "leaf6"],
        # 'all' merges every device with a running container in inventory
        "all":      [d["hostname"] for d in DEVICES
                     if d.get("container") and d.get("role", "").lower() != "host"],
    }
    targets = _SITE_DEVICES.get(site, _SITE_DEVICES["de-fra"])

    _agent_emit("shadow", "🔍 Shadow Audit started",
                f"Scanning {len(targets)} device(s) — site={site.upper()} check={check}", "info")

    _CHECKS: dict[str, list[tuple]] = {
        "bgp": [
            ("bgp_router_id",     r"bgp router-id \d+\.\d+\.\d+\.\d+", "Missing explicit BGP router-id"),
            ("bgp_log_changes",   r"bgp log-neighbor-changes",           "BGP neighbor state logging not enabled"),
            ("bgp_max_paths",     r"maximum-paths",                      "Missing ECMP maximum-paths config"),
        ],
        "ospf": [
            ("ospf_router_id",    r"ospf router-id \d+\.\d+\.\d+\.\d+", "Missing explicit OSPF router-id"),
            ("ospf_area",         r"area 0",                             "Missing OSPF backbone area 0"),
            ("ospf_timers",       r"(hello-interval|dead-interval)",     "Missing explicit OSPF timer config"),
        ],
    }
    active = []
    if check in ("bgp", "all"):
        active.extend(_CHECKS["bgp"])
    if check in ("ospf", "all"):
        active.extend(_CHECKS["ospf"])

    # Hostname → on-disk frr.conf path. Kept as a fallback when docker exec
    # is unavailable; primary path is now `docker exec vtysh show running-config`
    # which always reflects live state.
    _FRR_CONFIG_MAP: dict[str, str] = {
        "de-fra-core-01": "configs/r1/frr.conf",
        "de-fra-core-02": "configs/r2/frr.conf",
        "uk-lon-core-01": "configs/r3/frr.conf",
        "nl-ams-core-01": "configs/r4/frr.conf",
        "us-nyc-core-01": "configs/r5/frr.conf",
        "de-fra-edge-01": "configs/sw1/frr.conf",
        "uk-lon-edge-01": "configs/sw3/frr.conf",
        "nl-ams-edge-01": "configs/sw4/frr.conf",
        "uk-lon-dist-01": "configs/sw2/frr.conf",
        "de-fra-dist-01": "configs/sw5/frr.conf",
    }
    # network-lab/ is at the repo root, 3 levels up from this file:
    # /04_Scripts_Tools/DCN_Network_Tool/src/app.py → ../../../network-lab.
    # Previous version used ../../network-lab which doesn't exist — every
    # device reported "Could not read running config". Try multiple levels.
    _here = os.path.dirname(os.path.abspath(__file__))
    _LAB_DIR = None
    for _rel in ("../../network-lab", "../../../network-lab", "../network-lab"):
        _candidate = os.path.normpath(os.path.join(_here, _rel))
        if os.path.isdir(_candidate):
            _LAB_DIR = _candidate
            break

    def _read_running_config(hostname: str) -> str:
        """Resolve a device's running config from the strongest source first:
        1. docker exec vtysh / Cli / sr_cli (LIVE state — reflects real device)
        2. on-disk startup-config file (fallback when docker is unavailable)
        3. SSH for production hardware (last-resort path)
        Returns "" if nothing succeeds — the caller flags it as unreachable.
        """
        dev = get_device_by_hostname(hostname)
        if dev and dev.get("container"):
            container = dev["container"]
            vc = (dev.get("vendor_canonical") or "").lower()
            try:
                if vc == "nokia-srl":
                    return _docker_run(container, "sr_cli", "info /", timeout=10)
                if vc == "arista-eos":
                    return _docker_run(container, "Cli", "-p", "15",
                                       "-c", "show running-config", timeout=10)
                # default: FRR
                return _docker_run(container, "vtysh", "-c",
                                   "show running-config", timeout=10)
            except Exception:
                pass
        # On-disk fallback for DCN lab devices that pre-date the docker exec path
        rel = _FRR_CONFIG_MAP.get(hostname)
        if rel and _LAB_DIR:
            try:
                with open(os.path.join(_LAB_DIR, rel)) as f:
                    return f.read()
            except Exception:
                pass
        # SSH fallback for genuine production hardware
        if dev:
            try:
                result = run_command_on_device(dev["ip"], dev.get("type", "junos"),
                                               "show running-config", port=dev.get("port", 22))
                if result.get("success"):
                    return result.get("output", "")
            except Exception:
                pass
        return ""

    findings: list[dict] = []
    for hostname in targets:
        live_cfg = _read_running_config(hostname)
        if not live_cfg:
            findings.append({"hostname": hostname, "severity": "WARNING",
                              "type": "unreachable",
                              "detail": "Could not read running config"})
            continue

        for chk_id, pattern, description in active:
            if not _rca.search(pattern, live_cfg, _rca.IGNORECASE):
                findings.append({
                    "hostname": hostname, "severity": "P1",
                    "type": "config_drift", "check": chk_id,
                    "detail": description,
                    "remediation": description.replace("Missing ", "Add ") + f" to {hostname}",
                })

    by_host: dict = {}
    for f in findings:
        h = f["hostname"]
        by_host.setdefault(h, {"host": h, "drift_count": 0, "findings": []})
        by_host[h]["drift_count"] += 1
        by_host[h]["findings"].append(f)

    _agent_emit("shadow", "✅ Shadow Audit complete",
                f"{len(findings)} drift(s) across {len(by_host)} host(s)",
                "warn" if findings else "info")

    return jsonify({
        "site": site, "check": check,
        "devices_scanned": len(targets),
        "total_drift":   len(findings),
        "drift_hosts":   len(by_host),
        "clean_hosts":   len(targets) - len(by_host),
        "findings":      findings,
        "summary_by_host": list(by_host.values()),
        "status":  "DRIFT_DETECTED" if findings else "CLEAN",
        "message": (
            f"⚠️ Drift detected on {len(by_host)} device(s) — {len(findings)} finding(s)"
            if findings else
            f"✅ No drift — all {len(targets)} devices match SoT"
        ),
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── Multivendor Extension Blueprint (Tier 1 & 2 capabilities) ────────────────
# ══════════════════════════════════════════════════════════════════════════════
try:
    from multivendor_extensions import mv_bp, init_mv_services
    app.register_blueprint(mv_bp)
    print("[MV] Multivendor extensions registered — /api/mv/* endpoints active")
    _MV_ENABLED = True
except ImportError as _mv_err:
    print(f"[MV] Multivendor extensions not available: {_mv_err}")
    _MV_ENABLED = False


if __name__ == "__main__":
    port = int(os.environ.get("DCN_PORT", "5757"))
    print(f"DCN Network Tool starting — {len(DEVICES)} devices loaded")
    print(f"SSH Key: {SSH_KEY_PATH}")
    print(f"LLM: {'enabled' if LLM_ENABLED else 'disabled'} — model={LLM_MODEL} ollama={OLLAMA_URL} fallback={MODEL_RUNNER_URL}")
    # Auto-generate JMCP devices.json from inventory on startup
    if JMCP_ENABLED:
        jmcp_count = _write_jmcp_devices_file()
        print(f"JMCP: enabled — {jmcp_count} Junos devices written to jmcp/devices.json")
    else:
        print("JMCP: disabled (set JMCP_ENABLED=true to enable)")
    print(f"NAPALM: {'available' if NAPALM_AVAILABLE else 'NOT installed'} — {sum(len(d) for d in NAPALM_SITES.values())} devices in {len(NAPALM_SITES)} sites")
    # Start multivendor background services
    if _MV_ENABLED:
        init_mv_services()
    app.run(host="0.0.0.0", port=port, debug=False)
