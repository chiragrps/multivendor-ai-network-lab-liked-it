"""
toon_serializer.py — Tabular Object Oriented Notation.

Inspired by NetClaw (40-60% token savings vs JSON for tabular data).
For arrays of homogeneous dicts, emit a header row + value rows separated by `|`.

JSON:
    [{"hostname": "fra-fw-01", "vendor": "juniper", "site": "DE-FRA"}, ...]

TOON:
    hostname|vendor|site
    fra-fw-01|juniper|DE-FRA
    lon-fw-01|juniper|UK-LON
"""
from __future__ import annotations
from typing import Any


_FIELD_SEP = "|"
_NULL = "~"


def _escape(value: Any) -> str:
    """Render a scalar safely, escaping the field separator."""
    if value is None:
        return _NULL
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    s = str(value)
    return s.replace(_FIELD_SEP, "/").replace("\n", " ").replace("\r", "")


def to_toon(rows: list[dict[str, Any]], columns: list[str] | None = None) -> str:
    """
    Serialize a list of homogeneous dicts as TOON.

    Args:
        rows:    list of dicts (homogeneous schema)
        columns: optional explicit column order; default = union of keys in declared order

    Returns:
        TOON-formatted string. Empty input returns empty string.
    """
    if not rows:
        return ""

    if columns is None:
        seen: dict[str, None] = {}
        for r in rows:
            for k in r.keys():
                if k not in seen:
                    seen[k] = None
        columns = list(seen.keys())

    out: list[str] = [_FIELD_SEP.join(columns)]
    for r in rows:
        out.append(_FIELD_SEP.join(_escape(r.get(col)) for col in columns))
    return "\n".join(out)


def from_toon(text: str) -> list[dict[str, Any]]:
    """Parse TOON text back into a list of dicts. Round-trips scalars only."""
    if not text or not text.strip():
        return []
    lines = text.strip().split("\n")
    if len(lines) < 2:
        return []
    columns = lines[0].split(_FIELD_SEP)
    rows: list[dict[str, Any]] = []
    for line in lines[1:]:
        values = line.split(_FIELD_SEP)
        d: dict[str, Any] = {}
        for i, col in enumerate(columns):
            v = values[i] if i < len(values) else ""
            d[col] = None if v == _NULL else v
        rows.append(d)
    return rows


def size_savings(rows: list[dict[str, Any]]) -> dict[str, int | float]:
    """Compute byte-size savings for the given rows."""
    import json
    json_bytes = len(json.dumps(rows).encode())
    toon_bytes = len(to_toon(rows).encode())
    if json_bytes == 0:
        return {"json_bytes": 0, "toon_bytes": 0, "savings_pct": 0.0}
    savings = (json_bytes - toon_bytes) / json_bytes * 100.0
    return {
        "json_bytes": json_bytes,
        "toon_bytes": toon_bytes,
        "savings_pct": round(savings, 1),
    }
