/* ─────────────────────────────────────────────────────────────
 * Phase 3: Orchestrator / Intent / Eval / Path / GAIT / CVE
 * Built using safe DOM helpers (no innerHTML on user-derived data).
 * ───────────────────────────────────────────────────────────── */
(function () {
  'use strict';
  const API_BASE = (typeof API !== 'undefined') ? API : 'http://localhost:5757';
  const VENDOR_COLOR = { juniper: '#84b935', arista: '#00adef', frr: '#a855f7' };

  // ── tiny safe DOM builder: el('div', {style:'…',cls:'x'}, child, child…) ──
  function el(tag, attrs, ...children) {
    const node = document.createElementNS(
      tag === 'svg' || tag === 'g' || tag === 'circle' || tag === 'line' ||
      tag === 'text' || tag === 'defs' || tag === 'filter' || tag === 'feDropShadow'
        ? 'http://www.w3.org/2000/svg' : 'http://www.w3.org/1999/xhtml',
      tag
    );
    if (attrs) {
      for (const k in attrs) {
        if (k === 'cls') node.setAttribute('class', attrs[k]);
        else if (k === 'text') node.textContent = attrs[k];
        else if (k === 'on') {
          for (const ev in attrs[k]) node.addEventListener(ev, attrs[k][ev]);
        } else if (attrs[k] != null) node.setAttribute(k, attrs[k]);
      }
    }
    for (const c of children) {
      if (c == null) continue;
      if (typeof c === 'string' || typeof c === 'number') node.appendChild(document.createTextNode(String(c)));
      else node.appendChild(c);
    }
    return node;
  }

  function clear(id) {
    const n = document.getElementById(id);
    if (n) while (n.firstChild) n.removeChild(n.firstChild);
    return n;
  }

  function setText(id, val) {
    const n = document.getElementById(id);
    if (n) n.textContent = (val == null ? '—' : String(val));
  }

  async function api(path, opts) {
    const r = await fetch(API_BASE + path, opts || {});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return await r.json();
  }

  // ── Orchestrator ──────────────────────────────────────────────
  async function runOrchestrator() {
    const prompt = (document.getElementById('orch-prompt').value || '').trim();
    if (!prompt) { setText('orch-status', 'enter a prompt'); return; }
    setText('orch-status', '⏳ diagnosing…');
    const t0 = performance.now();
    try {
      const j = await api('/api/mv/orchestrator', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt })
      });
      const ms = Math.round(performance.now() - t0);
      setText('orch-agent', (j.agent || '?').toUpperCase());
      setText('orch-online', j.online ? 'live' : 'offline');
      const onl = document.getElementById('orch-online');
      if (onl) onl.style.color = j.online ? 'var(--green)' : 'var(--yellow)';
      setText('orch-conf', (j.result && j.result.confidence != null) ? j.result.confidence : '—');
      setText('orch-ms', ms);
      setText('orch-rendered', j.rendered || '(empty)');
      setText('orch-json', JSON.stringify(j.result || {}, null, 2));
      setText('orch-status', '✓ done');
    } catch (e) { setText('orch-status', '✗ ' + e.message); }
  }

  // ── Intent Verify ─────────────────────────────────────────────
  async function loadIntent() {
    setText('intent-status', '⏳ verifying…');
    try {
      const j = await api('/api/mv/intent/verify');
      setText('int-score', j.intent_score);
      setText('int-drift', j.drift_count);
      setText('int-checked', j.total_sessions_checked);
      const out = clear('intent-out');
      if (!j.drift || !j.drift.length) {
        out.appendChild(el('div', { style: 'color:var(--green);padding:10px', text: 'No drift detected — intent matches observed config.' }));
      } else {
        const grid = el('div', { style: 'display:grid;grid-template-columns:200px 160px 1fr;gap:6px;font-size:12px' });
        ['Type','Device','Detail'].forEach(h => grid.appendChild(
          el('div', { style: 'font-size:10px;text-transform:uppercase;color:var(--muted);padding:4px 8px', text: h })
        ));
        for (const d of j.drift) {
          const color = d.type === 'claimed_peer_missing' ? 'var(--red)' : 'var(--yellow)';
          grid.appendChild(el('div', { style: `background:var(--bg2);border-left:3px solid ${color};padding:6px 8px;color:${color}`, text: d.type }));
          grid.appendChild(el('div', { style: 'background:var(--bg2);padding:6px 8px;font-family:Consolas,monospace', text: d.device || '—' }));
          const detail = d.claimed_peer ? `claims peer ${d.claimed_peer} (${d.claimed_peer_ip || ''})`
                       : d.observed_peer ? `observes peer ${d.observed_peer} (${d.observed_peer_ip || ''})`
                       : JSON.stringify(d);
          grid.appendChild(el('div', { style: 'background:var(--bg2);padding:6px 8px', text: detail }));
        }
        out.appendChild(grid);
      }
      setText('intent-status', '✓ done');
    } catch (e) { setText('intent-status', '✗ ' + e.message); }
  }

  // ── Eval Harness ──────────────────────────────────────────────
  let _evalLoaded = false;
  async function loadEvalScenarios() {
    const sel = document.getElementById('eval-scenario');
    if (!sel || _evalLoaded) return;
    _evalLoaded = true;
    while (sel.firstChild) sel.removeChild(sel.firstChild);
    try {
      const j = await api('/api/mv/eval/scenarios');
      for (const s of (j.scenarios || [])) {
        const opt = el('option', { value: s.id, text: s.id + ' · ' + s.title });
        sel.appendChild(opt);
      }
    } catch (e) { _evalLoaded = false; setText('eval-status', '✗ ' + e.message); }
  }

  async function runEval() {
    const sid = document.getElementById('eval-scenario').value;
    const agent = document.getElementById('eval-agent').value;
    if (!sid) { setText('eval-status', 'pick scenario'); return; }
    setText('eval-status', `⏳ ${sid} via ${agent}…`);
    try {
      const j = await api('/api/mv/eval/run', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario_id: sid, agent })
      });
      setText('eval-kw', j.keyword_score ? j.keyword_score.score : '—');
      setText('eval-llm', j.llm_score ? j.llm_score.score : 'n/a');
      setText('eval-ms', j.total_ms);
      const hits = (j.keyword_score && j.keyword_score.root_cause_hits) || [];
      const remH = (j.keyword_score && j.keyword_score.remediation_hits) || [];
      const out = clear('eval-out');
      const card = el('div', { style: 'background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:10px;font-size:11.5px;display:grid;grid-template-columns:1fr 1fr;gap:10px' });
      const left = el('div');
      left.appendChild(el('div', { style: 'font-size:10px;text-transform:uppercase;color:var(--muted)', text: 'Symptom' }));
      left.appendChild(el('pre', { style: 'margin:4px 0;white-space:pre-wrap;color:var(--accent)', text: j.symptom || '' }));
      left.appendChild(el('div', { style: 'font-size:10px;text-transform:uppercase;color:var(--muted);margin-top:8px', text: 'Keyword hits' }));
      const rcLine = el('div', { style: 'margin-top:4px' }, 'root-cause: ');
      rcLine.appendChild(el('span', { style: 'color:var(--green)', text: hits.join(', ') || '—' }));
      left.appendChild(rcLine);
      const rmLine = el('div', null, 'remediation: ');
      rmLine.appendChild(el('span', { style: 'color:var(--accent)', text: remH.join(', ') || '—' }));
      left.appendChild(rmLine);
      const right = el('div');
      right.appendChild(el('div', { style: 'font-size:10px;text-transform:uppercase;color:var(--muted)', text: 'Agent output' }));
      right.appendChild(el('pre', { style: 'margin:4px 0;white-space:pre-wrap;color:var(--text)', text: j.agent_output || '' }));
      card.appendChild(left); card.appendChild(right);
      out.appendChild(card);
      setText('eval-status', `✓ ${sid} scored ${j.keyword_score.score}/10`);
    } catch (e) { setText('eval-status', '✗ ' + e.message); }
  }

  async function runEvalAll() {
    setText('eval-status', '⏳ running 10 scenarios…');
    const sel = document.getElementById('eval-scenario');
    const agent = document.getElementById('eval-agent').value;
    const ids = Array.from(sel.options).map(o => o.value);
    const rows = [];
    for (const id of ids) {
      try {
        const j = await api('/api/mv/eval/run', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario_id: id, agent })
        });
        rows.push({ id, score: j.keyword_score ? j.keyword_score.score : 0, ms: j.total_ms, title: (j.scenario || {}).title });
      } catch (e) { rows.push({ id, score: 0, ms: 0, title: 'ERROR ' + e.message }); }
    }
    const avg = rows.reduce((a, b) => a + b.score, 0) / Math.max(rows.length, 1);
    setText('eval-kw', avg.toFixed(1));
    const out = clear('eval-out');
    const grid = el('div', { style: 'display:grid;grid-template-columns:90px 1fr 80px 80px;gap:0;background:var(--bg2);border:1px solid var(--border);border-radius:6px;overflow:hidden;font-size:12px' });
    ['ID','Title','Score','ms'].forEach(h => grid.appendChild(
      el('div', { style: 'padding:6px 10px;font-size:10px;text-transform:uppercase;color:var(--muted);background:var(--bg3)', text: h })
    ));
    for (const r of rows) {
      const c = r.score >= 7 ? 'var(--green)' : r.score >= 4 ? 'var(--yellow)' : 'var(--red)';
      grid.appendChild(el('div', { style: 'padding:6px 10px;font-family:Consolas,monospace', text: r.id }));
      grid.appendChild(el('div', { style: 'padding:6px 10px', text: r.title || '' }));
      grid.appendChild(el('div', { style: `padding:6px 10px;color:${c};font-weight:700`, text: r.score }));
      grid.appendChild(el('div', { style: 'padding:6px 10px;color:var(--muted)', text: r.ms }));
    }
    out.appendChild(grid);
    setText('eval-status', `✓ ran ${rows.length}, avg ${avg.toFixed(1)}/10`);
  }

  // ── Path Trace ────────────────────────────────────────────────
  let _pathLoaded = false;
  async function loadPathDevices() {
    const src = document.getElementById('path-src');
    const dst = document.getElementById('path-dst');
    if (!src || _pathLoaded) return;
    _pathLoaded = true;
    while (src.firstChild) src.removeChild(src.firstChild);
    while (dst.firstChild) dst.removeChild(dst.firstChild);
    try {
      const j = await api('/api/mv/topology');
      for (const d of (j.devices || [])) {
        src.appendChild(el('option', { value: d.hostname, text: `${d.hostname} · ${d.site}` }));
        dst.appendChild(el('option', { value: d.hostname, text: `${d.hostname} · ${d.site}` }));
      }
      if (src.options.length > 4) dst.selectedIndex = 4;
    } catch (e) { _pathLoaded = false; setText('path-status', '✗ ' + e.message); }
  }

  async function runPathTrace() {
    const src = document.getElementById('path-src').value;
    const dst = document.getElementById('path-dst').value;
    if (src === dst) { setText('path-status', 'pick different devices'); return; }
    setText('path-status', `⏳ ${src} → ${dst}`);
    try {
      const j = await api(`/api/mv/path/trace?src=${encodeURIComponent(src)}&dst=${encodeURIComponent(dst)}`);
      if (j.error) { setText('path-status', '✗ ' + j.error); clear('path-svg-wrap'); return; }
      setText('path-hops', j.hops);
      const vendors = Array.from(new Set(j.nodes.map(n => n.vendor)));
      const sites = Array.from(new Set(j.nodes.map(n => n.site)));
      setText('path-vendors', vendors.join(', '));
      setText('path-sites', sites.join(', '));
      const W = 1200, H = 260, gap = (W - 100) / Math.max(j.nodes.length - 1, 1);
      const x = (i) => 50 + i * gap;
      const cy = H / 2;
      const wrap = clear('path-svg-wrap');
      const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, style: 'width:100%;height:260px' });
      // edges with type labels (eBGP / iBGP / site-LAN)
      const EDGE_COLOR = { 'eBGP': '#f59e0b', 'iBGP': '#22d3ee', 'site-LAN': '#94a3b8', 'BGP': '#94a3b8', 'unknown': '#586069' };
      for (let i = 0; i < j.edges.length; i++) {
        const et = j.edges[i].type || 'unknown';
        const color = EDGE_COLOR[et] || '#586069';
        const x1 = x(i) + 45, x2 = x(i + 1) - 45;
        svg.appendChild(el('line', {
          x1, y1: cy, x2, y2: cy,
          stroke: color, 'stroke-width': '2.5',
          'stroke-dasharray': et === 'site-LAN' ? '4,3' : null,
        }));
        const mx = (x1 + x2) / 2;
        svg.appendChild(el('text', {
          x: mx, y: cy - 8, 'text-anchor': 'middle',
          fill: color, 'font-size': '10', 'font-family': 'Consolas, monospace',
          'font-weight': '600', text: et,
        }));
      }
      // nodes
      for (let i = 0; i < j.nodes.length; i++) {
        const n = j.nodes[i];
        const g = el('g', { transform: `translate(${x(i)}, ${cy})` });
        g.appendChild(el('circle', { r: 42, fill: n.color + '22', stroke: n.color, 'stroke-width': '2.5' }));
        g.appendChild(el('text', { y: -50, 'text-anchor': 'middle', fill: '#94a3b8', 'font-size': '10', 'font-family': 'Consolas, monospace', text: 'hop ' + n.hop }));
        g.appendChild(el('text', { y: 0, 'text-anchor': 'middle', fill: '#e6edf3', 'font-size': '11', 'font-family': 'Consolas, monospace', 'font-weight': '700', text: n.hostname }));
        g.appendChild(el('text', { y: 14, 'text-anchor': 'middle', fill: n.color, 'font-size': '9', 'font-family': 'Consolas, monospace', text: (n.vendor || '').toUpperCase() + ' · ' + n.role }));
        g.appendChild(el('text', { y: 60, 'text-anchor': 'middle', fill: '#94a3b8', 'font-size': '10', text: n.site }));
        svg.appendChild(g);
      }
      wrap.appendChild(svg);
      setText('path-status', `✓ ${j.hops} hops · ${vendors.length} vendor(s)`);
    } catch (e) { setText('path-status', '✗ ' + e.message); }
  }

  // ── GAIT ──────────────────────────────────────────────────────
  async function loadGait() {
    const actor = document.getElementById('gait-actor').value;
    setText('gait-status', '⏳ loading…');
    try {
      const [r1, r2] = await Promise.all([
        api(`/api/mv/gait/recent?limit=100${actor ? '&actor=' + actor : ''}`),
        api('/api/mv/gait/stats')
      ]);
      const events = r1.events || [];
      setText('gait-total', r2.total_events);
      setText('gait-tokens-in', (r2.tokens || {}).input || 0);
      setText('gait-tokens-out', (r2.tokens || {}).output || 0);
      const out = clear('gait-out');
      if (!events.length) {
        out.appendChild(el('div', { style: 'color:var(--muted);padding:10px', text: 'No GAIT events yet — invoke the Orchestrator or Eval Harness to generate audit entries.' }));
      } else {
        const grid = el('div', { style: 'display:grid;grid-template-columns:140px 110px 110px 1fr 1fr;gap:0;background:var(--bg2);border:1px solid var(--border);border-radius:6px;overflow:hidden;font-size:11px' });
        ['Time','Actor','Action','Target/Tools','Response'].forEach(h => grid.appendChild(
          el('div', { style: 'padding:5px 8px;font-size:10px;text-transform:uppercase;color:var(--muted);background:var(--bg3);font-weight:600', text: h })
        ));
        for (const e of events) {
          const sc = e.status === 'ok' ? 'var(--green)' : e.status === 'blocked' ? 'var(--yellow)' : 'var(--red)';
          grid.appendChild(el('div', { style: 'padding:5px 8px;color:var(--muted);font-family:Consolas,monospace', text: (e.ts || '').slice(11, 19) }));
          grid.appendChild(el('div', { style: `padding:5px 8px;color:${sc}`, text: e.actor }));
          grid.appendChild(el('div', { style: 'padding:5px 8px', text: e.action || '' }));
          grid.appendChild(el('div', { style: 'padding:5px 8px;color:var(--accent);font-family:Consolas,monospace', text: (e.target || '') + ' ' + (e.tools_called || []).join(' ') }));
          grid.appendChild(el('div', { style: 'padding:5px 8px;color:var(--muted)', text: (e.response || '').slice(0, 80) }));
        }
        out.appendChild(grid);
      }
      setText('gait-status', `✓ ${events.length} events`);
    } catch (e) { setText('gait-status', '✗ ' + e.message); }
  }

  // Expose to global so onclick handlers can find them
  window.runOrchestrator = runOrchestrator;
  window.loadIntent = loadIntent;
  window.loadEvalScenarios = loadEvalScenarios;
  window.runEval = runEval;
  window.runEvalAll = runEvalAll;
  window.loadPathDevices = loadPathDevices;
  window.runPathTrace = runPathTrace;
  window.loadGait = loadGait;

  // Wire MV tabs → loaders for the new tabs.
  // Hooks both the .tab buttons in the tab bar AND the yellow quick-launch
  // buttons in the ⚡ MV Features bar (which call window.switchTabById).
  function wireMvTabs() {
    if (typeof window.MV_TAB_INIT !== 'object') window.MV_TAB_INIT = {};
    Object.assign(window.MV_TAB_INIT, {
      'mv-orchestrator': () => {},
      'mv-intent': loadIntent,
      'mv-eval': loadEvalScenarios,
      'mv-path': loadPathDevices,
      'mv-gait': loadGait,
    });
    document.querySelectorAll('.tab[data-tab^="mv-"]').forEach(tab => {
      tab.addEventListener('click', () => {
        const t = tab.dataset.tab;
        if (window.MV_TAB_INIT[t]) setTimeout(window.MV_TAB_INIT[t], 50);
      });
    });

    // Wrap window.switchTabById so the yellow quick-launch buttons also fire loaders.
    if (typeof window.switchTabById === 'function' && !window.__mvSwitchWrapped) {
      const orig = window.switchTabById;
      window.switchTabById = function (tabId) {
        const r = orig.apply(this, arguments);
        if (window.MV_TAB_INIT[tabId]) setTimeout(window.MV_TAB_INIT[tabId], 50);
        return r;
      };
      window.__mvSwitchWrapped = true;
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wireMvTabs);
  } else {
    wireMvTabs();
  }
})();
