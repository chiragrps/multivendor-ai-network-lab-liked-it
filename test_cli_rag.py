"""
Tests for CLI RAG (Day-10).

Run:
    cd 04_Scripts_Tools/DCN_Network_Tool
    venv/bin/python -m pytest test_cli_rag.py -v

Covers:
  - Entry / ScoredEntry dataclass shapes + cite_url derivation
  - Tokenizer: drops single chars, hyphens kept, lowercased
  - load_corpus(): returns entries; missing file → empty list (resilient)
  - Index: postings, IDF, BM25 scoring, query without hits → []
  - search(): filter by vendor / os / cat, k cap, empty query
  - explain(): empty snippet → empty matches; real snippet → top-3
  - stats(): correct shape with all aggregates
  - reindex(): swaps corpus path + rebuilds
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / "src"))

import cli_rag as rag  # noqa: E402


# ─── Helpers ────────────────────────────────────────────────────────────────


def _entry(**overrides) -> rag.Entry:
    base = dict(os="ios", vendor="Cisco", role="router", cat="BGP",
                title="router bgp 100", cmd="router bgp 100",
                desc="BGP > Configure local AS")
    base.update(overrides)
    return rag.Entry(**base)


def _corpus_file(tmp_path: Path, items: list[dict]) -> Path:
    p = tmp_path / "corpus.json"
    p.write_text(json.dumps(items), encoding="utf-8")
    return p


# ─── Datamodel ──────────────────────────────────────────────────────────────


class TestEntry:
    def test_to_dict_round_trip(self):
        e = _entry()
        d = e.to_dict()
        assert d["vendor"] == "Cisco" and d["cmd"] == "router bgp 100"

    def test_cite_url_anchor_from_desc(self):
        e = _entry(desc="BGP > IPv4 Address Family")
        assert e.cite_url.endswith("#bgp-ipv4-address-family")

    def test_cite_url_falls_back_when_desc_empty(self):
        e = _entry(desc="")
        assert e.cite_url == rag.SIBLING_DEEP_LINK


# ─── Tokenizer ──────────────────────────────────────────────────────────────


class TestTokenize:
    def test_lowercased(self):
        assert "bgp" in rag.tokenize("show BGP summary")

    def test_min_length_two(self):
        # Single-char tokens dropped
        assert "a" not in rag.tokenize("show a route")

    def test_hyphens_kept(self):
        toks = rag.tokenize("show ip bgp neighbor 10.1.1.1 advertised-routes")
        assert "advertised-routes" in toks

    def test_empty_string_returns_empty(self):
        assert rag.tokenize("") == []


# ─── load_corpus ────────────────────────────────────────────────────────────


class TestLoadCorpus:
    def test_loads_well_formed(self, tmp_path):
        p = _corpus_file(tmp_path, [
            {"os": "ios", "vendor": "Cisco", "cat": "BGP",
             "title": "router bgp 100", "cmd": "router bgp 100",
             "desc": "BGP > local AS", "role": "router"},
        ])
        out = rag.load_corpus(p)
        assert len(out) == 1 and out[0].vendor == "Cisco"

    def test_missing_file_returns_empty(self, tmp_path):
        assert rag.load_corpus(tmp_path / "nope.json") == []

    def test_bad_json_returns_empty(self, tmp_path):
        p = tmp_path / "broken.json"
        p.write_text("{ not valid json", encoding="utf-8")
        assert rag.load_corpus(p) == []

    def test_skips_non_dict_items(self, tmp_path):
        p = _corpus_file(tmp_path, [
            {"os": "ios", "vendor": "Cisco", "cmd": "x"}, "not a dict", 42,
        ])
        out = rag.load_corpus(p)
        assert len(out) == 1


# ─── Index + BM25 ───────────────────────────────────────────────────────────


class TestIndex:
    def test_build_index_avg_dl(self):
        entries = [_entry(cmd="hello world"), _entry(cmd="hello there friend")]
        idx = rag.Index(entries)
        assert idx.avg_dl > 0
        assert "hello" in idx.postings
        assert "world" in idx.postings

    def test_search_orders_by_relevance(self):
        entries = [
            _entry(title="bgp summary", cmd="show ip bgp summary",
                   desc="BGP > status"),
            _entry(title="ospf neighbors", cmd="show ip ospf neighbors",
                   desc="OSPF > neighbors"),
        ]
        idx = rag.Index(entries)
        results = idx.search("bgp summary", k=2)
        assert len(results) >= 1
        assert "bgp" in results[0].entry.cmd.lower()

    def test_empty_query_returns_empty(self):
        idx = rag.Index([_entry()])
        assert idx.search("", k=5) == []

    def test_no_match_returns_empty(self):
        idx = rag.Index([_entry(cmd="completely unrelated content here")])
        assert idx.search("frobnicate quoxal", k=5) == []

    def test_filter_by_vendor(self):
        entries = [
            _entry(vendor="Cisco", cmd="show bgp summary"),
            _entry(vendor="Juniper", cmd="show bgp summary"),
        ]
        idx = rag.Index(entries)
        results = idx.search("bgp summary", k=5, vendor="Juniper")
        assert len(results) == 1 and results[0].entry.vendor == "Juniper"

    def test_filter_by_os(self):
        entries = [
            _entry(os="ios", cmd="show bgp summary"),
            _entry(os="junos", cmd="show bgp summary"),
        ]
        idx = rag.Index(entries)
        results = idx.search("bgp", k=5, os="junos")
        assert len(results) == 1 and results[0].entry.os == "junos"


# ─── Public search() ────────────────────────────────────────────────────────


class TestSearchAPI:
    def test_search_shape(self, tmp_path, monkeypatch):
        p = _corpus_file(tmp_path, [
            {"os": "ios", "vendor": "Cisco", "cat": "BGP", "title": "t",
             "cmd": "router bgp 100", "desc": "BGP > local",
             "role": "router"},
        ])
        rag.reindex(p)
        out = rag.search("router bgp", k=3)
        assert out["query"] == "router bgp"
        assert out["corpus_size"] == 1
        assert isinstance(out["results"], list)
        assert out["filters"] == {"vendor": None, "os": None, "cat": None}

    def test_search_results_include_score_and_cite(self, tmp_path):
        p = _corpus_file(tmp_path, [
            {"os": "ios", "vendor": "Cisco", "cat": "BGP", "title": "t",
             "cmd": "router bgp 100", "desc": "BGP > local",
             "role": "router"},
        ])
        rag.reindex(p)
        out = rag.search("router bgp 100", k=1)
        assert out["results"][0]["score"] > 0
        assert "cite_url" in out["results"][0]


# ─── explain() ──────────────────────────────────────────────────────────────


class TestExplain:
    def test_empty_snippet_returns_empty_matches(self, tmp_path):
        rag.reindex(_corpus_file(tmp_path, []))
        out = rag.explain("")
        assert out["matches"] == []

    def test_whitespace_snippet_returns_empty(self, tmp_path):
        rag.reindex(_corpus_file(tmp_path, []))
        assert rag.explain("   ")["matches"] == []

    def test_real_snippet_returns_matches(self, tmp_path):
        p = _corpus_file(tmp_path, [
            {"os": "ios", "vendor": "Cisco", "cat": "BGP", "title": "t",
             "cmd": "neighbor 10.1.1.1 remote-as 200", "desc": "BGP > peer",
             "role": "router"},
        ])
        rag.reindex(p)
        out = rag.explain("neighbor remote-as")
        assert len(out["matches"]) >= 1
        assert "citation_note" in out


# ─── stats() + reindex() ────────────────────────────────────────────────────


class TestStatsAndReindex:
    def test_stats_shape(self, tmp_path):
        p = _corpus_file(tmp_path, [
            {"os": "ios", "vendor": "Cisco", "cat": "BGP", "cmd": "x"},
            {"os": "junos", "vendor": "Juniper", "cat": "OSPF", "cmd": "y"},
        ])
        rag.reindex(p)
        s = rag.stats()
        assert s["corpus_size"] == 2
        assert s["by_vendor"]["Cisco"] == 1 and s["by_vendor"]["Juniper"] == 1
        assert s["by_os"]["ios"] == 1
        assert s["unique_tokens"] > 0

    def test_reindex_switches_corpus_path(self, tmp_path):
        # Use distinct filenames so reindex actually sees two separate corpora.
        a = tmp_path / "a.json"
        a.write_text(json.dumps([{"os": "ios", "vendor": "A", "cmd": "x"}]), encoding="utf-8")
        b = tmp_path / "b.json"
        b.write_text(json.dumps([
            {"os": "ios", "vendor": "B", "cmd": "x"},
            {"os": "ios", "vendor": "C", "cmd": "y"},
        ]), encoding="utf-8")
        s1 = rag.reindex(a)
        assert s1["corpus_size"] == 1
        s2 = rag.reindex(b)
        assert s2["corpus_size"] == 2
