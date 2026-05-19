"""
Seed a local NetBox instance with the lab's 26 devices.

Run AFTER `docker compose -f docker-compose.netbox.yml up -d` and after NetBox
has finished its initial migration (~60s on first boot):

    python3 network-lab/seed_netbox.py

Reads inventory.json, creates sites + device-roles + manufacturers + device-types
+ devices, and tags everything with `multivendor-lab` so the SoT panel can
filter on it.

This script is idempotent — running it twice does not duplicate records.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

try:
    import pynetbox
except ImportError:
    sys.exit("pynetbox not installed — `pip install pynetbox`")

NETBOX_URL = os.environ.get("NETBOX_URL", "http://localhost:8000")
NETBOX_TOKEN = os.environ.get(
    "NETBOX_TOKEN", "0123456789abcdef0123456789abcdef01234567"
)
TAG_SLUG = os.environ.get("NETBOX_SOT_TAG", "multivendor-lab")
HERE = Path(__file__).resolve().parent
INVENTORY_PATH = HERE / "demo-devices" / "inventory.json"


def _slug(s: str) -> str:
    return s.lower().replace("_", "-").replace(" ", "-")


def main() -> int:
    if not INVENTORY_PATH.exists():
        sys.exit(f"inventory not found: {INVENTORY_PATH}")
    inventory = json.loads(INVENTORY_PATH.read_text())
    devices = inventory.get("devices") or []
    sites = sorted({d["site"] for d in devices if d.get("site")})
    print(f"Connecting to {NETBOX_URL} ...")
    nb = pynetbox.api(NETBOX_URL, token=NETBOX_TOKEN)
    # Validate connection
    try:
        nb.status()
    except Exception as exc:
        sys.exit(f"NetBox not reachable: {exc}")

    # Tag
    tag = nb.extras.tags.get(slug=TAG_SLUG)
    if not tag:
        tag = nb.extras.tags.create(name=TAG_SLUG, slug=TAG_SLUG)
        print(f"  created tag: {TAG_SLUG}")

    # Sites
    for site_name in sites:
        slug = _slug(site_name)
        if not nb.dcim.sites.get(slug=slug):
            nb.dcim.sites.create(name=site_name, slug=slug, status="active")
            print(f"  created site: {site_name}")

    # Manufacturers (from `vendor`)
    vendors = sorted({d.get("vendor") for d in devices if d.get("vendor")})
    for v in vendors:
        if not nb.dcim.manufacturers.get(slug=v):
            nb.dcim.manufacturers.create(name=v.title(), slug=v)
            print(f"  created manufacturer: {v}")

    # Roles (from `role`)
    roles = sorted({d.get("role") for d in devices if d.get("role")})
    for r in roles:
        if not nb.dcim.device_roles.get(slug=r):
            nb.dcim.device_roles.create(name=r.title(), slug=r, color="2196f3")
            print(f"  created role: {r}")

    # Device-types (vendor + model combinations)
    for d in devices:
        vendor, model = d.get("vendor"), d.get("model")
        if not (vendor and model):
            continue
        slug = _slug(f"{vendor}-{model}")
        if not nb.dcim.device_types.get(slug=slug):
            mfg = nb.dcim.manufacturers.get(slug=vendor)
            if mfg:
                nb.dcim.device_types.create(
                    manufacturer=mfg.id, model=model, slug=slug
                )

    # Devices + primary IPs
    created = 0
    for d in devices:
        hostname = d.get("hostname")
        if not hostname:
            continue
        if nb.dcim.devices.get(name=hostname):
            continue
        site = nb.dcim.sites.get(slug=_slug(d["site"]))
        role = nb.dcim.device_roles.get(slug=d.get("role", "core"))
        dtype = nb.dcim.device_types.get(
            slug=_slug(f"{d.get('vendor', '')}-{d.get('model', '')}")
        )
        if not (site and role and dtype):
            print(f"  skip {hostname}: missing FK")
            continue
        device = nb.dcim.devices.create(
            name=hostname,
            device_type=dtype.id,
            role=role.id,
            site=site.id,
            status="active",
            tags=[{"slug": TAG_SLUG}],
        )
        if d.get("ip"):
            ip = nb.ipam.ip_addresses.create(
                address=f"{d['ip']}/32",
                status="active",
                tags=[{"slug": TAG_SLUG}],
            )
            device.update({"primary_ip4": ip.id})
        created += 1
    print(f"seeded {created} devices · {len(sites)} sites · tag={TAG_SLUG}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
