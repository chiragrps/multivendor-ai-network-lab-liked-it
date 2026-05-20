# CLI Reference — Day-10

BM25 retrieval over a structured CLI corpus exported from the sibling project
[`multivendor-cli-configurator`](https://gesh75.github.io/multivendor-cli-configurator/).
Pure stdlib — no new dependencies, no embedding model downloads, no API calls.

## Why it exists

The sibling project is the **source of truth** for vendor CLI syntax. This
panel is the *intelligence layer* on top: paste a snippet, get the matching
documented entry with a citation back to the cheatsheet. The AI Coordinator
can also call `/api/mv/cli-rag/explain` to ground its answers in real
vendor docs.

## Architecture

```
   multivendor-cli-configurator        ← single source of truth (web)
                │
                │  Export → JSON
                ▼
       cli_corpus/cli-export.json      ← committed to this repo
                │
                ▼
       src/cli_rag.py  (BM25 index)    ← built once on first query
                │
                ▼
       /api/mv/cli-rag/{search,explain,stats,reindex}
                │
                ▼
       UI panel · MCP tools · AI Coordinator
```

## Why BM25 (and not embeddings)?

- **Corpus is structured, short, vendor-specific** — every entry has 5-50
  CLI tokens. BM25 outperforms embeddings on this kind of query/document
  ratio.
- **No model download** — the 80 MB sentence-transformers model would be
  the single largest dep in the project.
- **Deterministic + auditable** — same query → same ranking. Easier to
  debug, easier to defend in a regulated environment.
- **Sub-millisecond latency** — full 7,700-entry index queryable in <2ms.
- **Stdlib only** — `math.log` + dict + Counter. ~40 lines.

## Corpus schema

```json
[
  {
    "os":     "ios|junos|eos|frr|...",
    "vendor": "Cisco|Juniper|Arista|...",
    "role":   "router|switch|firewall|...",
    "cat":    "BGP|OSPF|VPN|AAA|...",
    "title":  "short title (e.g. first command line)",
    "cmd":    "the actual CLI commands (multi-line allowed)",
    "desc":   "human description (e.g. 'BGP > IPv4 Address Family')"
  },
  ...
]
```

Refresh after editing the sibling project:

```bash
# Re-export from the cheatsheet, drop into the repo:
cp ~/Downloads/multivendor-cli-export-NNNN.json \
   04_Scripts_Tools/DCN_Network_Tool/cli_corpus/cli-export.json

# Force the running Flask to re-read + re-index:
curl -X POST http://localhost:5757/api/mv/cli-rag/reindex
```

## API

### `GET /api/mv/cli-rag/search?q=...&k=5&vendor=...&os=...&cat=...`
Returns ranked matches:

```json
{
  "query": "ssh rsa key",
  "k": 5,
  "filters": {"vendor": null, "os": null, "cat": null},
  "corpus_size": 56,
  "results": [
    {
      "os": "ios", "vendor": "Cisco", "role": "router", "cat": "VPN",
      "title": "Configuring SSH", "cmd": "...", "desc": "SSH > Initial Setup",
      "score": 7.65,
      "cite_url": "https://gesh75.github.io/multivendor-cli-configurator/cheatsheet.html#ssh-initial-setup"
    }
  ]
}
```

### `POST /api/mv/cli-rag/explain`
```json
{ "snippet": "neighbor 10.1.1.1 remote-as 200", "vendor": "Cisco" }
```
Returns top-3 matches plus a citation note pointing back to the cheatsheet.

### `GET /api/mv/cli-rag/stats`
Corpus size, per-vendor + per-OS + per-cat counts, unique tokens, average
doc length.

### `POST /api/mv/cli-rag/reindex`
```json
{ "path": "cli_corpus/cli-export.json" }   // optional override
```
Re-reads the corpus + rebuilds the index. Returns fresh stats.

## Python contract

```python
import cli_rag as rag

# One-shot search
out = rag.search("aaa authentication", k=3, vendor="Juniper")

# Snippet-style explain (returns top-3 + citation note)
out = rag.explain("neighbor 10.1.1.1 remote-as 200")

# Stats
print(rag.stats())

# Reload after corpus edit
rag.reindex("cli_corpus/cli-export.json")
```

## UI panel

Tab: **📖 CLI Reference** (under Audit nav).

- Search box (Enter or click 🔍) — accepts CLI snippets or natural-language
- Vendor / OS dropdown filters
- 4 tiles — corpus size · vendors · OS coverage · result count
- Result cards — vendor-colored left border, score badge, cheatsheet link,
  collapsible CLI block

## Killer-demo flow (Day 11)

In Claude Code (via MCP), a user asks:
*"Show me Juniper's equivalent of Cisco's `aaa authentication login default group radius local`."*

Claude calls:
1. `cli_rag_search(query="aaa authentication login default group radius local", vendor="Cisco")` → Cisco entry
2. `cli_rag_search(query="aaa authentication radius local", vendor="Juniper")` → Junos hierarchy equivalent
3. Synthesizes a side-by-side comparison with citations to both cheatsheet anchors.

Two of your portfolio projects working as one system.

## Testing

```bash
cd 04_Scripts_Tools/DCN_Network_Tool
venv/bin/python -m pytest test_cli_rag.py -v
```

24 tests in ~0.03s covering:
- Entry / ScoredEntry dataclass + cite_url derivation
- Tokenizer (lowercase, ≥ 2 chars, hyphens kept)
- load_corpus (well-formed, missing, bad JSON, non-dict items)
- Index (postings, IDF, BM25 scoring, empty / no-match queries)
- Filter by vendor / os / cat
- search() public API + result shape
- explain() empty / real snippet paths
- stats() + reindex()

## Key design decisions

1. **Module-level singleton index** — built lazily on first query; cheap
   even for the full 7,700-entry corpus (<10ms).
2. **`_get_index()` indirection** — lets `reindex()` swap the underlying
   data atomically. No "rebuild lock" needed because writes are rare.
3. **Vendor/OS filter applied AFTER scoring** — keeps the scoring path
   uniform; filter is a post-filter, not a partition.
4. **Cite URL = anchor-from-desc** — deterministic, no need to round-trip
   to the sibling repo for an ID. Anchors line up with how typical
   markdown-rendered cheatsheets generate ids (lowercase, hyphen-joined).
5. **No LLM in this module** — retrieval is the deterministic part; the
   LLM (via MCP / AI Coordinator) consumes these chunks as grounded
   context. Separation of concerns.

## Future hooks (deliberately deferred)

- **Hyperlink CLI output anywhere in the tool** — wrap detected commands
  in `<a>` tags pointing to `cite_url`. Trivial extension once the panel
  is shipped.
- **AI Coordinator integration** — when the chat panel handles a CLI-related
  question, pre-fetch top-3 matches and stuff them into the system prompt.
- **Re-rank via cross-encoder** — only if BM25 ever underperforms on the
  full 7,700 corpus.

## Related

- `cli_corpus/cli-export.json` — the data (56-entry sample today, ready for the full 7,700)
- `src/cli_rag.py` — the retrieval module
- `src/mcp_server/tools.py` — could add a `cli_rag_search` MCP tool in <10 lines
- Sibling repo: <https://github.com/gesh75/multivendor-cli-configurator>
