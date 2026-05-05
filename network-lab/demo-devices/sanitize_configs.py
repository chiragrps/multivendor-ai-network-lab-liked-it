#!/usr/bin/env python3
"""
Sanitize real network device configs for demo/lab use.
Removes: company names, real usernames, SSH keys, real IPs (partial), SNMP secrets.
Replaces with: generic lab equivalents using RFC 5737/1918 address space.
"""

import re, os, sys

# ── Replacement maps ──────────────────────────────────────────────────────────
# Tokens are loaded from sanitize_tokens.json (gitignored). The script remains
# fully functional locally, but the public repo carries no source-company tokens.
import json as _json

_TOKENS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sanitize_tokens.json')
if os.path.exists(_TOKENS_FILE):
    with open(_TOKENS_FILE) as _f:
        _T = _json.load(_f)
else:
    _T = {
        "company_names":  [],   # list of [pattern, replacement, ignore_case_bool]
        "as_numbers":     [],
        "usernames":      [],
        "email_domains":  [],
        "public_ips":     [],
        "snmp_strings":   [],
        "dns_ranges":     [],
        "misc":           [],
    }

def _build_replacements(tokens: dict) -> list:
    out = []
    for cat in ("company_names", "as_numbers", "usernames", "email_domains",
                "public_ips", "snmp_strings", "dns_ranges", "misc"):
        for entry in tokens.get(cat, []):
            pat, repl, ic = entry[0], entry[1], (re.IGNORECASE if (len(entry) > 2 and entry[2]) else 0)
            out.append((pat, repl, ic))
    # Generic public-safe defaults (never reveal source company)
    out.extend([
        (r'YubiKey-\S+', 'HW-TOKEN', 0),
        (r'service unsupported-transceiver \S+ \S+',
         'service unsupported-transceiver LabUnlockKey 00000000', 0),
        (r'## Last commit:.*\n',
         '## Last commit: 2026-01-01 00:00:00 UTC by netadmin1\n', 0),
    ])
    return out

COMPANY_REPLACEMENTS = _build_replacements(_T)

# Strip SSH public key lines (replace with generic placeholder)
# Comment field is optional — some Junos configs emit keys without a trailing comment.
SSH_KEY_LINE_PATTERNS = [
    re.compile(r'^\s+ssh-ecdsa "ecdsa-sha2-nistp256 [A-Za-z0-9+/=]+(?:\s+[^"]+)?";.*$', re.MULTILINE),
    re.compile(r'^\s+ssh-ecdsa "ecdsa-sha2-nistp384 [A-Za-z0-9+/=]+(?:\s+[^"]+)?";.*$', re.MULTILINE),
    re.compile(r'^\s+ssh-rsa   "ssh-rsa [A-Za-z0-9+/=]+(?:\s+[^"]+)?";.*$', re.MULTILINE),
    re.compile(r'^\s+ssh-rsa "ssh-rsa [A-Za-z0-9+/=]+(?:\s+[^"]+)?";.*$', re.MULTILINE),
    re.compile(r'^\s+ssh-ed25519 "ssh-ed25519 [A-Za-z0-9+/=]+(?:\s+[^"]+)?";.*$', re.MULTILINE),
]
SSH_KEY_EOS_PATTERNS = [
    re.compile(r'^username \S+ ssh-key ecdsa-sha2-nistp256 [A-Za-z0-9+/=]+ [^\n]*$', re.MULTILINE),
    re.compile(r'^username \S+ ssh-key ssh-rsa [A-Za-z0-9+/=]+ [^\n]*$', re.MULTILINE),
]

# Generic placeholder SSH key (not real, safe to publish)
GENERIC_JUNOS_SSH = '                ssh-ecdsa "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGVORklFWUlOR0tFWVBMQUNFSE9MREVSX05PVF9SRUFMXzEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg= admin@netlab.local";'

def sanitize(text: str, is_eos: bool = False) -> str:
    # Remove SSH public key lines
    for pat in (SSH_KEY_EOS_PATTERNS if is_eos else SSH_KEY_LINE_PATTERNS):
        text = pat.sub('', text)
    # Remove blank lines left by SSH key removal (max 2 consecutive)
    text = re.sub(r'\n{3,}', '\n\n', text)
    # Apply all string replacements
    for pattern, replacement, flags in COMPANY_REPLACEMENTS:
        text = re.sub(pattern, replacement, text, flags=flags)
    # Strip trailing whitespace per line
    lines = [l.rstrip() for l in text.splitlines()]
    return '\n'.join(lines) + '\n'

# ── Device selection: (source_file, target_file, new_hostname, vendor, role, site) ──
SELECTIONS = [
    # Juniper SRX Firewalls
    ('junos/bll1-fw-01.txt',    'junos/fra-fw-01.txt',     'fra-fw-01',    'junos', 'srx-fw',    'DE-FRA'),
    ('junos/auh1-fw-20.txt',    'junos/lon-fw-01.txt',     'lon-fw-01',    'junos', 'srx-fw',    'UK-LON'),
    ('junos/bud1-fw-20.txt',    'junos/ams-fw-01.txt',     'ams-fw-01',    'junos', 'srx-fw',    'NL-AMS'),
    ('junos/bom1-fw-01.txt',    'junos/nyc-fw-01.txt',     'nyc-fw-01',    'junos', 'srx-fw',    'US-NYC'),
    # Juniper MX Routers
    ('junos/bom1-rt-01.txt',    'junos/fra-mx-01.txt',     'fra-mx-01',    'junos', 'mx-router',  'DE-FRA'),
    ('junos/cdg1-rt-01.txt',    'junos/cdg-mx-01.txt',     'cdg-mx-01',    'junos', 'mx-router',  'EU-CDG'),
    # Juniper EX Switches
    ('junos/bll1-sw-01.txt',    'junos/fra-ex-01.txt',     'fra-ex-01',    'junos', 'ex-switch',  'DE-FRA'),
    ('junos/bll1-sw-02.txt',    'junos/fra-ex-02.txt',     'fra-ex-02',    'junos', 'ex-switch',  'DE-FRA'),
    ('junos/bll1-sw-03.txt',    'junos/lon-ex-01.txt',     'lon-ex-01',    'junos', 'ex-switch',  'UK-LON'),
    ('junos/auh1-sw-01.txt',    'junos/ams-ex-01.txt',     'ams-ex-01',    'junos', 'ex-switch',  'NL-AMS'),
    # Arista EOS Routers
    ('eos/ams1-rt-02.txt',      'eos/ams-eos-rt-01.txt',   'ams-eos-rt-01','eos',   'eos-router', 'NL-AMS'),
    ('eos/fra4-rt-02.txt',      'eos/fra-eos-rt-01.txt',   'fra-eos-rt-01','eos',   'eos-router', 'DE-FRA'),
    ('eos/cdg1-rt-02.txt',      'eos/cdg-eos-rt-01.txt',   'cdg-eos-rt-01','eos',   'eos-router', 'EU-CDG'),
    # Arista EOS Switches
    ('eos/gru2-sw-01a.txt',     'eos/ams-eos-sw-01.txt',   'ams-eos-sw-01','eos',   'eos-switch', 'NL-AMS'),
    ('eos/gru2-sw-02.txt',      'eos/fra-eos-sw-01.txt',   'fra-eos-sw-01','eos',   'eos-switch', 'DE-FRA'),
    ('eos/dfw1-rt-02.txt',      'eos/nyc-eos-rt-01.txt',   'nyc-eos-rt-01','eos',   'eos-router', 'US-NYC'),
]

BASE = '/sessions/amazing-eager-shannon/mnt/VSS_Code_Georgi/01_Device_Configurations'
OUT  = '/sessions/amazing-eager-shannon/mnt/VSS_Code_Georgi/network-lab/demo-devices'

results = []
for src_rel, dst_rel, new_hostname, vendor, role, site in SELECTIONS:
    src = os.path.join(BASE, src_rel)
    dst = os.path.join(OUT, dst_rel)
    if not os.path.exists(src):
        print(f"  SKIP  {src_rel} (not found)")
        continue
    with open(src, 'r', errors='replace') as f:
        text = f.read()

    # Rename old hostname → new hostname (all variations)
    old_hostname = src_rel.split('/')[-1].replace('.txt', '')
    text = re.sub(rf'\b{re.escape(old_hostname)}[a-b]?\b', new_hostname, text)
    text = re.sub(rf'host-name {re.escape(old_hostname)};', f'host-name {new_hostname};', text)
    text = re.sub(rf'hostname {re.escape(old_hostname)}\b', f'hostname {new_hostname}', text)
    # Site code replacement in references (e.g. BLL1 → FRA)
    old_site = old_hostname.split('-')[0].upper()
    new_site_short = site.replace('-', '').replace('EU', '')

    is_eos = (vendor == 'eos')
    text = sanitize(text, is_eos=is_eos)

    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, 'w') as f:
        f.write(text)
    size = len(text.splitlines())
    results.append((dst_rel, new_hostname, vendor, role, site, size))
    print(f"  OK    {dst_rel:45s} ({size:4d} lines)  [{vendor:5s}] {role:12s} @ {site}")

print(f"\nSanitized {len(results)}/16 device configs into {OUT}/")
