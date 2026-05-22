'use strict';
/*
 * Multivendor AI Network Lab · FULL FEATURE TOUR (~5-6 min, 1280×720).
 *
 * Companion to the tight 0:52 LinkedIn cut. This is the "everything" video —
 * every major panel, every primary CTA, every closed-loop beat, explained
 * in caption form. Linked from the LinkedIn post as a deep-dive.
 *
 * Structure:
 *   PROLOGUE  — title + chrome sweep
 *   ACT I     — OBSERVE telemetry surfaces
 *   ACT II    — INVENTORY + AUDIT trail
 *   ACT III   — DIAGNOSE: AI surfaces
 *   ACT IV    — OPERATE: change pipeline + closed loop
 *   ACT V     — TOPOLOGY + PATH TRACE
 *   ACT VI    — VERIFY & TEST: chaos + eval
 *   EPILOGUE  — keyboard chords + credits + repo URL
 *
 * Caption rules (identical to LinkedIn cut):
 *   - top caption: small top-LEFT uppercase pill
 *   - bottom caption: lifted 40px above persistent dock
 *
 * Usage:
 *   node record-full-tour.cjs --rehearse
 *   node record-full-tour.cjs
 */
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const BASE = 'http://localhost:8080/';
const OUT_DIR = __dirname;
const OUT_NAME = 'full-tour-demo.webm';
const REHEARSAL = process.argv.includes('--rehearse');
const W = 1280, H = 720;
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function injectCursor(page){
  await page.evaluate(() => {
    if (document.getElementById('demo-cursor')) return;
    const NS = 'http://www.w3.org/2000/svg';
    const wrap = document.createElement('div'); wrap.id = 'demo-cursor';
    wrap.style.cssText = 'position:fixed;z-index:999999;pointer-events:none;width:24px;height:24px;'
      +'transition:left .08s,top .08s;filter:drop-shadow(1px 1px 2px rgba(0,0,0,.4));left:0;top:0';
    const svg = document.createElementNS(NS,'svg'); svg.setAttribute('width','24'); svg.setAttribute('height','24'); svg.setAttribute('viewBox','0 0 24 24');
    const p = document.createElementNS(NS,'path'); p.setAttribute('d','M5 3L19 12L12 13L9 20L5 3Z'); p.setAttribute('fill','white'); p.setAttribute('stroke','black'); p.setAttribute('stroke-width','1.5'); p.setAttribute('stroke-linejoin','round');
    svg.appendChild(p); wrap.appendChild(svg); document.body.appendChild(wrap);
    document.addEventListener('mousemove',(e)=>{ wrap.style.left=e.clientX+'px'; wrap.style.top=e.clientY+'px'; });
  });
}

async function injectSubtitle(page){
  await page.evaluate(() => {
    if (!document.getElementById('demo-subtitle')) {
      const bar=document.createElement('div'); bar.id='demo-subtitle';
      bar.style.cssText='position:fixed;bottom:40px;left:50%;transform:translateX(-50%);'
        +'z-index:999998;padding:8px 18px;max-width:80%;text-align:center;'
        +'background:rgba(13,17,23,.92);color:#e6edf3;border:1px solid rgba(63,185,80,.3);'
        +'border-radius:6px;font-family:-apple-system,sans-serif;font-size:14px;'
        +'font-weight:500;letter-spacing:.2px;transition:opacity .2s;pointer-events:none;opacity:0';
      document.body.appendChild(bar);
    }
    if (!document.getElementById('demo-top')) {
      const top=document.createElement('div'); top.id='demo-top';
      top.style.cssText='position:fixed;top:12px;left:14px;z-index:999998;padding:5px 11px;'
        +'background:rgba(63,185,80,.92);color:#0d1117;font-weight:700;font-size:11px;'
        +'letter-spacing:.6px;border-radius:4px;font-family:-apple-system,sans-serif;'
        +'transition:opacity .2s;opacity:0;text-transform:uppercase';
      document.body.appendChild(top);
    }
  });
}

async function caption(page, t, ms=1400){
  await page.evaluate((x)=>{ const e=document.getElementById('demo-subtitle'); if(e){ e.textContent=x||''; e.style.opacity=x?'1':'0'; } }, t);
  if (t) await sleep(ms);
}
async function topCaption(page, t, ms=1100){
  await page.evaluate((x)=>{ const e=document.getElementById('demo-top'); if(e){ e.textContent=x||''; e.style.opacity=x?'1':'0'; } }, t);
  if (t) await sleep(ms);
}
async function moveAndClick(page, sel, label, post=400){
  const el = page.locator(sel).first();
  if (!await el.isVisible().catch(()=>false)) { console.warn(`WARN ${label} not visible`); return false; }
  try {
    await el.scrollIntoViewIfNeeded(); await sleep(120);
    const box = await el.boundingBox();
    if (box) { await page.mouse.move(box.x+box.width/2, box.y+box.height/2, {steps:10}); await sleep(220); }
    await el.click();
  } catch(e){ return false; }
  await sleep(post);
  return true;
}
async function pan(page, points=[]){
  for (const [x,y] of points){ await page.mouse.move(x,y,{steps:10}); await sleep(300); }
}
async function typeSlowly(page, sel, text){
  const el = page.locator(sel).first();
  if (!await el.isVisible().catch(()=>false)) return false;
  await el.click(); await sleep(140);
  await el.fill('');
  await el.pressSequentially(text, { delay: 24 });
  await sleep(260);
  return true;
}

const NAV = (t) => `.nav-item[data-target="${t}"]`;

// ───────────────────────────────────────────────────────────────────────────
// Panel script — each entry visits one panel, captions it, and optionally
// triggers a primary CTA. Keep entries ~7-9s total visible time.
// ───────────────────────────────────────────────────────────────────────────
const PANELS = [
  { act: 'OBSERVE · TELEMETRY + ALERTS' },
  { target: 'health',       label: 'Home / Health',           desc: 'Per-device health cards · CPU · memory · BGP · OSPF · auto-fetch on landing.',
    pan: [[700, 340], [950, 340]] },
  { target: 'mv-gnmi',      label: 'gNMI Telemetry',          desc: 'OpenConfig sensors pulled live from 10 FRR containers via vtysh shim.' },
  { target: 'telemetry',    label: 'Streaming Telemetry',     desc: 'High-rate metric stream · per-device sparklines · live update toggle.' },
  { target: 'mv-syslog',    label: 'Syslog',                  desc: 'UDP :5140 receiver · severity tiles click-to-filter · CSV export.' },
  { target: 'mv-snmp',      label: 'SNMP Traps',              desc: 'UDP :1162 · per-site filter · OID + binding column · unmanaged-source badge.' },
  { target: 'alerts',       label: 'Alert Correlation',       desc: 'Multi-source dedup with inline remediation guidance.' },
  { target: 'noise-floor',  label: 'Noise Floor',             desc: '5-site sparklines · raw · suppressed · incidents · suppression efficiency.' },

  { act: 'INVENTORY + AUDIT' },
  { target: 'mv-inventory', label: 'Inventory',               desc: '26-device table · free-text filter · sortable columns · aria-grid.',
    cta: '#mv-inv-filter', typeText: 'core', clearAfter: true },
  { target: 'netbox-sot',   label: 'NetBox SoT drift',        desc: 'Severity-tiered drift detector · NetBox view vs running lab.',
    cta: '#nb-refresh-btn', postCta: 1200 },
  { target: 'mv-fleet',     label: 'Fleet Audit',             desc: 'Batfish-style fleet config analysis · per-device score.' },
  { target: 'compliance',   label: 'Compliance',              desc: 'Scans configs for BGP MD5 auth · prefix-limits · OSPF timers · router-ID.' },
  { target: 'mv-gait',      label: 'GAIT Audit',              desc: 'Immutable append-only AI audit trail · tokens-in/out · download today.' },
  { target: 'postmortem',   label: 'Auto-Postmortem',         desc: 'GAIT + Health Gate + Remediation → markdown · ~0.2 s to generate.',
    cta: '#pm-detect-btn', cta2: '#pm-generate-btn', postCta: 700, postCta2: 2400 },
  { target: 'cli-rag',      label: 'CLI Reference · BM25',    desc: '9,802 commands · Cisco · Juniper · Arista · sub-millisecond · stdlib only.',
    cta: '#cr-q', typeText: 'bgp md5 authentication', cta2: '#cr-search-btn', postCta2: 1000 },
  { target: 'shadow',       label: 'Shadow Auditor',          desc: 'Async second-opinion audit channel running in parallel.' },

  { act: 'DIAGNOSE · AI SURFACES' },
  { target: 'chat',         label: 'Agent Chat',              desc: 'AI Coordinator routes plain English to 10 specialist agents.' },
  { target: 'ai-cmd',       label: 'AI Command · NL → CLI',   desc: 'Translates English to vendor CLI · live device-context chip.' },
  { target: 'mv-orchestrator', label: 'Pydantic-AI Orchestrator', desc: 'Routing / ACL / Incident agents · strictly-typed JSON · no hallucinations.' },
  { target: 'observer',     label: 'AI Insights',             desc: 'Deep log intelligence · config drift · security audit.' },
  { target: 'docs',         label: 'Doc Search RAG',          desc: 'Grounded answers over OSPF · BGP · Junos · EOS manuals.' },
  { target: 'mv-suzieq',    label: 'SuzieQ',                  desc: 'Offline config-parsing observability · vendor quick-filter chips.' },
  { target: 'mv-intent',    label: 'Intent Verify',           desc: 'Config-claimed vs SuzieQ-observed · per-session drift score.' },

  { act: 'OPERATE · CHANGE PIPELINE' },
  { target: 'change-pipeline',  label: 'Change Pipeline · 5-step', desc: 'Propose → Approve → Health Gate → Confirm → Postmortem · one view.' },
  { target: 'change-approval',  label: 'Change Approval',     desc: 'Pending changes queue · approvers · per-change audit lineage.' },
  { target: 'health-gate',      label: 'Health Gate',         desc: 'RFC 6241 §8.4 confirmed-commit · BGP/iface/alerts watcher · auto-revert.' },
  { target: 'auto-remediate',   label: 'Auto-Remediate',      desc: 'AI proposes runbooks · human approves · executes through Health Gate.',
    cta: '#ar-import-drift-btn', postCta: 1300 },
  { target: 'commands',         label: 'Commands · Raw CLI',  desc: 'Real SSH against the lab · per-device output panes · vendor-aware.' },
  { target: 'napalm',           label: 'NAPALM Audit',        desc: 'Standardized state collection across all vendors.' },
  { target: 'nornir',           label: 'Nornir Parallel',     desc: 'Audit fleet in parallel · per-device task results · worker pool.' },
  { target: 'batfish',          label: 'Batfish Analysis',    desc: 'Static config analysis · routing-table simulation · reachability.' },
  { target: 'statediff',        label: 'State Diff',          desc: 'Pre/post snapshot comparison · highlights what actually changed.' },
  { target: 'discover',         label: 'Discover · LLDP/OSPF',desc: 'Live neighbor walk · auto-builds topology from running devices.' },
  { target: 'collect',          label: 'Site Collect',        desc: 'Per-site config + state collection · CSV/JSON exports.' },
  { target: 'analysis',         label: 'Site Analysis',       desc: 'Cross-site comparison · drift heatmap · vendor distribution.' },

  { act: 'TOPOLOGY + PATH TRACE' },
  { target: 'topo',         label: 'Live BGP Topology',       desc: '26 devices · 5 sites · 36 BGP sessions · drag · zoom · vendor-colored.',
    holdMs: 1500 },
  { target: 'mv-path',      label: 'Multivendor Path Trace',  desc: 'Hop-by-hop BFS · Juniper → FRR → Arista in one click · vendor-colored.' },

  { act: 'VERIFY · CHAOS · EVAL' },
  { target: 'mv-eval',      label: 'Eval Harness',            desc: '10 incident scenarios · keyword + LLM-as-judge · regression-detect.' },
  { target: 'chaos',        label: 'Chaos Monkey · LAB',      desc: 'Break a BGP session on demand · self-healing demo.' },
  { target: 'cli-bench',    label: 'CLI Bench',               desc: 'Side-by-side CLI execution across vendors · output diff.' },
  { target: 'blast',        label: 'Blast Radius',            desc: 'What does this change touch? · pre-deploy impact analysis.' },
];

// Keep every .nav-item.parent expanded so .nav-children stay visible.
// The rail's own click handler collapses other parents on each parent-click
// (index.html L8394), so we re-apply this before every navigation.
async function reExpandParents(page){
  await page.evaluate(() => {
    try {
      document.querySelectorAll('.nav-section.collapsed').forEach(s => s.classList.remove('collapsed'));
      document.querySelectorAll('.nav-item.parent').forEach(p => p.classList.add('expanded'));
    } catch(e){}
  });
}

async function visitPanel(page, p){
  if (p.act){
    await topCaption(page, p.act, 1300);
    await topCaption(page, '', 50);
    return;
  }
  await reExpandParents(page);
  await topCaption(page, p.label, 0);
  await moveAndClick(page, NAV(p.target), 'nav ' + p.target, 320);
  await caption(page, p.desc, p.descMs || 1500);
  if (p.cta){
    if (p.typeText){
      await typeSlowly(page, p.cta, p.typeText);
    } else {
      await moveAndClick(page, p.cta, 'cta ' + p.target, p.postCta || 700);
    }
  }
  if (p.cta2){
    await moveAndClick(page, p.cta2, 'cta2 ' + p.target, p.postCta2 || 800);
  }
  if (p.pan){
    await pan(page, p.pan);
  }
  if (p.clearAfter && p.cta){
    await page.locator(p.cta).fill('').catch(()=>{});
  }
  await sleep(p.holdMs || 500);
  await caption(page, '', 50);
  await topCaption(page, '', 50);
}

async function runDemo(page){
  await page.goto(BASE);
  await sleep(2200);
  await injectCursor(page);
  await injectSubtitle(page);
  await page.evaluate(async () => {
    try { const r = await fetch('http://localhost:5757/api/devices'); if (r.ok && window.setLive) window.setLive(true); } catch(e){}
    try { localStorage.removeItem('ui.mode'); window.setMode && window.setMode(''); } catch(e){}
    try {
      window.toggleUnifiedDock && window.toggleUnifiedDock(false);
      const d = document.getElementById('unified-dock');
      if (d) { d.classList.remove('open'); d.style.setProperty('display','none','important'); }
    } catch(e){}
    // Day-18 #D accordion: some sections may be collapsed from prior user state
    // persisted in localStorage. Force-expand every section so all nav items
    // are reachable during the tour.
    try {
      localStorage.removeItem('navRail.collapsedSections');
      document.querySelectorAll('.nav-section.collapsed').forEach(s => s.classList.remove('collapsed'));
    } catch(e){}
    // Also expand every .nav-item.parent so its sibling .nav-children block is
    // visible (covers discover, collect, cli-bench, blast).
    try {
      document.querySelectorAll('.nav-item.parent').forEach(p => p.classList.add('expanded'));
    } catch(e){}
  });
  await sleep(500);

  // Seed Health Gate event so Postmortem has signal
  await page.evaluate(async () => {
    try {
      await fetch('http://localhost:5757/api/mv/health-gate/apply', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({hostname:'de-fra-core-01', timeout_s:3, induce_regression_after_s:0})
      });
    } catch(e){}
  });
  await sleep(3500);

  // ── PROLOGUE ───────────────────────────────────────────────
  await topCaption(page, 'Multivendor AI Network Lab · v4', 1900);
  await caption(page, 'Full feature tour · 35 panels · 220+ buttons · 40+ endpoints.', 2400);
  await caption(page, '26 devices · 5 sites · Juniper · Arista · FRR · MIT · single laptop.', 2400);
  await topCaption(page, '', 50);
  await pan(page, [[120, 200], [200, 360], [640, 60]]);
  await sleep(300);

  // ── PANEL TOUR ─────────────────────────────────────────────
  for (const p of PANELS){
    await visitPanel(page, p);
  }

  // ── CLOSED-LOOP PUNCH LINE ─────────────────────────────────
  await topCaption(page, 'The closed loop in one sequence', 1800);
  await caption(page, 'Drift → Propose → Approve → Watch → Auto-Revert OR Confirm → Postmortem.', 3000);
  await topCaption(page, '', 50);

  // ── KEYBOARD CHORDS QUICK REFERENCE ────────────────────────
  await topCaption(page, 'Keyboard chords', 1500);
  await caption(page, 'm + o/d/p/u  =  Observe · Diagnose · Operate · aUdit modes.', 2200);
  await caption(page, 'g + h/i/c/t/a  =  jump to Health · Inventory · CLI · Topology · Alerts.', 2400);
  await caption(page, '? help · / focus search · ` toggle dock · Esc close.', 2300);
  await topCaption(page, '', 50);

  // ── EPILOGUE ──────────────────────────────────────────────
  await topCaption(page, 'Open source · MIT · single laptop · no cloud', 1900);
  await caption(page, '137/137 pytest · 49-tool MCP server · 9,802-command CLI corpus.', 2500);
  await caption(page, 'Built solo over 20 focused days.', 2100);
  await caption(page, 'github.com/gesh75/multivendor-ai-network-lab', 3200);
  await caption(page, '', 200);
  await topCaption(page, '', 200);
  await sleep(500);
}

async function rehearse(page){
  await page.goto(BASE);
  await sleep(2000);
  await page.evaluate(async ()=>{
    try{ const r=await fetch('http://localhost:5757/api/devices'); if(r.ok && window.setLive) window.setLive(true); }catch(e){}
    try{ window.toggleUnifiedDock && window.toggleUnifiedDock(false); }catch(e){}
    try{
      localStorage.removeItem('navRail.collapsedSections');
      document.querySelectorAll('.nav-section.collapsed').forEach(s => s.classList.remove('collapsed'));
      document.querySelectorAll('.nav-item.parent').forEach(p => p.classList.add('expanded'));
    }catch(e){}
  });
  await sleep(500);
  let ok = true;
  let panelCount = 0;
  for (const p of PANELS){
    if (p.act) continue;
    panelCount++;
    await reExpandParents(page);
    const navOk = await page.locator(NAV(p.target)).first().isVisible().catch(()=>false);
    if (!navOk) { console.log('  FAIL nav ' + p.target); ok = false; continue; }
    await page.locator(NAV(p.target)).first().click();
    await sleep(220);
    console.log('  OK   ' + p.target);
    if (p.cta){
      const ctaOk = await page.locator(p.cta).first().isVisible().catch(()=>false);
      console.log((ctaOk?'  ok ':'  FAIL ')+' cta ' + p.cta);
      if (!ctaOk) ok = false;
    }
    if (p.cta2){
      const cta2Ok = await page.locator(p.cta2).first().isVisible().catch(()=>false);
      console.log((cta2Ok?'  ok ':'  FAIL ')+' cta2 ' + p.cta2);
      if (!cta2Ok) ok = false;
    }
  }
  console.log(`── rehearsed ${panelCount} panels ──`);
  return ok;
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  if (REHEARSAL) {
    const ctx = await browser.newContext({ viewport: { width: W, height: H } });
    const page = await ctx.newPage();
    const ok = await rehearse(page);
    await browser.close();
    if (!ok) { console.error('REHEARSAL FAILED'); process.exit(1); }
    console.log('REHEARSAL PASSED'); return;
  }
  const ctx = await browser.newContext({
    recordVideo: { dir: OUT_DIR, size: { width: W, height: H } },
    viewport: { width: W, height: H },
  });
  const page = await ctx.newPage();
  try { await runDemo(page); } catch(e){ console.error('DEMO ERROR:', e.message); }
  finally {
    await ctx.close();
    const video = page.video();
    if (video) {
      const src = await video.path();
      const dest = path.join(OUT_DIR, OUT_NAME);
      try { fs.copyFileSync(src, dest); console.log('Saved:', dest); }
      catch(e){ console.error('copy fail:', e.message); }
    }
    await browser.close();
  }
})();
