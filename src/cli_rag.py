"""
CLI RAG — Day-10.

Lightweight BM25 retrieval over a structured CLI corpus. Pairs with the
sibling project `multivendor-cli-configurator` (gesh75.github.io) — when
the user paste a snippet or asks a vendor-config question in the AI
Coordinator, this module returns the matching documented entries.

Design constraints honored from prior reviews:
  - No new dependencies. Pure stdlib BM25 implementation (~30 lines).
  - Stays sharp: the corpus itself is the knowledge graph, this module is
    just the retrieval lens over it.
  - Works with any corpus size — tested on 56 entries, ready for 7,700.

Corpus format (list of dicts):
    {
      "os":     "ios|junos|eos|frr|...",
      "vendor": "Cisco|Juniper|Arista|...",
      "role":   "router|switch|firewall|...",
      "cat":    "BGP|OSPF|VPN|AAA|...",
      "title":  "short title (e.g. command first line)",
      "cmd":    "the actual CLI commands (may be multi-line w/ comments)",
      "desc":   "human description (e.g. 'BGP > IPv4 Address Family')"
    }

Public surface:
    load_corpus(path) -> list[Entry]
    Index(entries) -> indexed retriever
    search(q, k, vendor?, os?, cat?) -> list[ScoredEntry]
    stats() -> dict
"""
from __future__ import annotations

import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


_HERE = Path(__file__).resolve().parent
DEFAULT_CORPUS_PATH = _HERE.parent / "cli_corpus" / "cli-export.json"
# The sibling project is a single-page app — there is no cheatsheet.html
# subpage. Deep links go to the SPA with a ?q= query string so the search
# filter pre-populates. Day-15-fix: replaced the dead cheatsheet.html URL.
SIBLING_DEEP_LINK = "https://gesh75.github.io/multivendor-cli-configurator/"


# ──────────────────────────────────────────────────────────────────────────────
# Datamodel
# ──────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Entry:
    """One CLI doc entry — frozen so it can be a dict key if needed."""
    os: str
    vendor: str
    role: str
    cat: str
    title: str
    cmd: str
    desc: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def cite_url(self) -> str:
        """Deep link back to the sibling SPA — uses ?q=<title> because the
        cheatsheet has no per-command anchors. The SPA's URLSearchParams
        handler restores filters + search from the query string."""
        from urllib.parse import quote
        # Use the title as the search query — short, distinctive, vendor-stable.
        # Strip trailing comments / multi-line tails for a clean URL.
        raw = (self.title or self.desc or "")
        lines = raw.splitlines()
        q = lines[0].strip() if lines else ""
        # Cap to a reasonable length so the URL stays readable
        q = q[:80]
        if not q:
            return SIBLING_DEEP_LINK
        return f"{SIBLING_DEEP_LINK}?q={quote(q)}"


@dataclass(frozen=True)
class ScoredEntry:
    entry: Entry
    score: float

    def to_dict(self) -> dict[str, Any]:
        return {**self.entry.to_dict(), "score": round(self.score, 4),
                "cite_url": self.entry.cite_url}


# ──────────────────────────────────────────────────────────────────────────────
# Tokenization — light + deterministic
# ──────────────────────────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9\-_]+")


def tokenize(text: str) -> list[str]:
    """Lowercase alphanumeric tokens, length ≥ 2."""
    if not text:
        return []
    return [t.lower() for t in _TOKEN_RE.findall(text) if len(t) >= 2]


def _doc_text(e: Entry) -> str:
    """The string we tokenize when building the document for an entry."""
    return " ".join([e.title, e.cmd, e.desc, e.cat, e.vendor, e.os, e.role])


# ──────────────────────────────────────────────────────────────────────────────
# BM25 index — stdlib only, ~40 lines
# ──────────────────────────────────────────────────────────────────────────────


class Index:
    """Okapi BM25 over the corpus. Built once, queried many times."""

    K1 = 1.5
    B = 0.75

    def __init__(self, entries: list[Entry]) -> None:
        self.entries = entries
        self.doc_tokens: list[list[str]] = [tokenize(_doc_text(e)) for e in entries]
        self.doc_lens: list[int] = [len(toks) for toks in self.doc_tokens]
        self.avg_dl: float = (sum(self.doc_lens) / len(self.doc_lens)) if self.doc_lens else 0.0
        # Inverted index: term -> {doc_idx: tf}
        self.postings: dict[str, dict[int, int]] = {}
        for i, toks in enumerate(self.doc_tokens):
            for t, n in Counter(toks).items():
                self.postings.setdefault(t, {})[i] = n
        # IDF: log((N - df + 0.5) / (df + 0.5) + 1)
        N = len(entries) or 1
        self.idf: dict[str, float] = {}
        for t, posting in self.postings.items():
            df = len(posting)
            self.idf[t] = math.log((N - df + 0.5) / (df + 0.5) + 1.0)

    def score(self, query_tokens: list[str], doc_idx: int) -> float:
        dl = self.doc_lens[doc_idx] or 1
        s = 0.0
        for t in query_tokens:
            if t not in self.postings:
                continue
            tf = self.postings[t].get(doc_idx, 0)
            if tf == 0:
                continue
            idf = self.idf.get(t, 0.0)
            denom = tf + self.K1 * (1 - self.B + self.B * dl / (self.avg_dl or 1))
            s += idf * tf * (self.K1 + 1) / denom
        return s

    def search(
        self,
        query: str,
        k: int = 5,
        *,
        vendor: str | None = None,
        os: str | None = None,
        cat: str | None = None,
    ) -> list[ScoredEntry]:
        toks = tokenize(query)
        if not toks:
            return []
        # candidate docs: union of postings for query terms
        candidates: set[int] = set()
        for t in toks:
            if t in self.postings:
                candidates.update(self.postings[t].keys())
        if not candidates:
            return []
        scored: list[ScoredEntry] = []
        vlc = vendor.lower() if vendor else None
        olc = os.lower() if os else None
        clc = cat.lower() if cat else None
        for i in candidates:
            e = self.entries[i]
            if vlc and e.vendor.lower() != vlc:
                continue
            if olc and e.os.lower() != olc:
                continue
            if clc and e.cat.lower() != clc:
                continue
            sc = self.score(toks, i)
            if sc > 0:
                scored.append(ScoredEntry(entry=e, score=sc))
        scored.sort(key=lambda s: s.score, reverse=True)
        return scored[:max(1, k)]


# ──────────────────────────────────────────────────────────────────────────────
# Module-level singleton (lazy load)
# ──────────────────────────────────────────────────────────────────────────────

_INDEX: Index | None = None
_CORPUS_PATH: Path = DEFAULT_CORPUS_PATH


def load_corpus(path: Path | None = None) -> list[Entry]:
    p = Path(path) if path else _CORPUS_PATH
    if not p.exists():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[Entry] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        out.append(Entry(
            os=str(item.get("os") or "").strip(),
            vendor=str(item.get("vendor") or "").strip(),
            role=str(item.get("role") or "").strip(),
            cat=str(item.get("cat") or "").strip(),
            title=str(item.get("title") or "").strip(),
            cmd=str(item.get("cmd") or "").strip(),
            desc=str(item.get("desc") or "").strip(),
        ))
    return out


def _get_index() -> Index:
    """Build the index on first use; cheap (<<1s for 7,700 entries)."""
    global _INDEX
    if _INDEX is None:
        _INDEX = Index(load_corpus())
    return _INDEX


def reindex(path: Path | None = None) -> dict[str, Any]:
    """Force a corpus re-read + index rebuild. Returns stats."""
    global _INDEX, _CORPUS_PATH
    if path is not None:
        _CORPUS_PATH = Path(path)
    _INDEX = Index(load_corpus())
    return stats()


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────


def search(
    query: str,
    k: int = 5,
    *,
    vendor: str | None = None,
    os: str | None = None,
    cat: str | None = None,
) -> dict[str, Any]:
    """Return top-k matches for a query string."""
    idx = _get_index()
    results = idx.search(query, k=k, vendor=vendor, os=os, cat=cat)
    return {
        "query": query,
        "k": k,
        "filters": {"vendor": vendor, "os": os, "cat": cat},
        "results": [r.to_dict() for r in results],
        "corpus_size": len(idx.entries),
    }


def explain(snippet: str, vendor: str | None = None) -> dict[str, Any]:
    """
    Retrieval-only explanation for a CLI snippet. Returns the top-3 matches
    grouped by vendor — caller can then feed these to an LLM for a final
    grounded answer, or render them directly.
    """
    if not snippet or not snippet.strip():
        return {"snippet": "", "matches": [], "corpus_size": len(_get_index().entries)}
    result = search(snippet, k=3, vendor=vendor)
    return {
        "snippet": snippet,
        "matches": result["results"],
        "corpus_size": result["corpus_size"],
        "citation_note": (
            "Matches link back to the source-of-truth cheatsheet at "
            f"{SIBLING_DEEP_LINK}. Edit there → re-export → run "
            "POST /api/mv/cli-rag/reindex to refresh."
        ),
    }


def stats() -> dict[str, Any]:
    idx = _get_index()
    by_vendor = Counter(e.vendor for e in idx.entries)
    by_os = Counter(e.os for e in idx.entries)
    by_cat = Counter(e.cat for e in idx.entries)
    return {
        "corpus_size": len(idx.entries),
        "corpus_path": str(_CORPUS_PATH),
        "by_vendor": dict(by_vendor.most_common()),
        "by_os": dict(by_os.most_common()),
        "by_cat": dict(by_cat.most_common(10)),
        "unique_tokens": len(idx.postings),
        "avg_doc_length": round(idx.avg_dl, 1),
    }


__all__ = [
    "Entry", "ScoredEntry", "Index",
    "load_corpus", "tokenize",
    "search", "explain", "stats", "reindex",
    "SIBLING_DEEP_LINK", "DEFAULT_CORPUS_PATH",
]
