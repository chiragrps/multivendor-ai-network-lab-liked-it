'use strict';
/*
 * LinkedIn-ready Phase 4 demo (~90s, 1280×720).
 *
 * Voice continuity with Phase 3 post: this video must NOT re-show
 * Phase 3 features (LLM switcher, path trace, NIKA harness, command
 * translator, MCP tool list). Phase 4 = the safety + autonomy layer.
 *
 * Narrative arc (one round trip of the closed loop):
 *   Act 0  · Cold open · briefly show the persistent dock + close it
 *   Act 1  · Mode chord (m+o) — workflow-aware sidebar dimming
 *   Act 2  · NetBox SoT drift — severity-tiered audit mode
 *   Act 3  · Auto-Remediate — AI proposes, human approves
 *   Act 4  · Health Gate — confirmed-commit countdown ring + verdict
 *   Act 5  · Auto-Postmortem — Markdown report written automatically
 *   Act 6  · CLI Reference BM25 — 9,802 commands · vendor-correct
 *   Outro  · Repo URL + numbers
 *
 * Captions:
 *   - top caption: small, top-LEFT corner, never covers center content
 *   - bottom caption: lifted 40px to clear the 32px persistent dock bar
 *
 * Usage:
 *   node record-linkedin.cjs --rehearse   # selector verification
 *   node record-linkedin.cjs              # records linkedin-demo.webm
 */
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const BASE = 'http://localhost:8080/';
const OUT_DIR = __dirname;
const OUT_NAME = 'linkedin-demo.webm';
const REHEARSAL = process.argv.includes('--rehearse');
const W = 1280, H = 720;
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function injectCursor(page){
  await page.evaluate(() => {
    if (document.getElementById('demo-cursor')) return;
    const NS = 'http://www.w3.org/2000/svg';
    const wrap = document.createElement('div'); wrap.id = 'demo-cursor';
    wrap.style.cssText = 'position:fixed;z-index:999999;pointer-events:none;width:24px;height:24px;'
      +'transition:left .1s,top .1s;filter:drop-shadow(1px 1px 2px rgba(0,0,0,.4));left:0;top:0';
    const svg = document.createElementNS(NS,'svg'); svg.setAttribute('width','24'); svg.setAttribute('height','24'); svg.setAttribute('viewBox','0 0 24 24');
    const p = document.createElementNS(NS,'path'); p.setAttribute('d','M5 3L19 12L12 13L9 20L5 3Z'); p.setAttribute('fill','white'); p.setAttribute('stroke','black'); p.setAttribute('stroke-width','1.5'); p.setAttribute('stroke-linejoin','round');
    svg.appendChild(p); wrap.appendChild(svg); document.body.appendChild(wrap);
    document.addEventListener('mousemove',(e)=>{ wrap.style.left=e.clientX+'px'; wrap.style.top=e.clientY+'px'; });
  });
}

async function injectSubtitle(page){
  await page.evaluate(() => {
    // Bottom caption — lifted above the 32px persistent dock bar
    if (!document.getElementById('demo-subtitle')) {
      const bar=document.createElement('div'); bar.id='demo-subtitle';
      bar.style.cssText='position:fixed;bottom:40px;left:50%;transform:translateX(-50%);'
        +'z-index:999998;padding:8px 18px;max-width:80%;text-align:center;'
        +'background:rgba(13,17,23,.92);color:#e6edf3;border:1px solid rgba(63,185,80,.3);'
        +'border-radius:6px;font-family:-apple-system,sans-serif;font-size:14px;'
        +'font-weight:500;letter-spacing:.2px;transition:opacity .25s;pointer-events:none;opacity:0';
      document.body.appendChild(bar);
    }
    // Top caption — TOP-LEFT pill, never covers center content
    if (!document.getElementById('demo-top')) {
      const top=document.createElement('div'); top.id='demo-top';
      top.style.cssText='position:fixed;top:12px;left:14px;z-index:999998;padding:5px 11px;'
        +'background:rgba(63,185,80,.92);color:#0d1117;font-weight:700;font-size:11px;'
        +'letter-spacing:.6px;border-radius:4px;font-family:-apple-system,sans-serif;'
        +'transition:opacity .25s;opacity:0;text-transform:uppercase';
      document.body.appendChild(top);
    }
  });
}

async function caption(page, t, ms=1100){
  await page.evaluate((x)=>{ const e=document.getElementById('demo-subtitle'); if(e){ e.textContent=x||''; e.style.opacity=x?'1':'0'; } }, t);
  if (t) await sleep(ms);
}
async function topCaption(page, t, ms=1300){
  await page.evaluate((x)=>{ const e=document.getElementById('demo-top'); if(e){ e.textContent=x||''; e.style.opacity=x?'1':'0'; } }, t);
  if (t) await sleep(ms);
}
async function moveAndClick(page, sel, label, post=600){
  const el = page.locator(sel).first();
  if (!await el.isVisible().catch(()=>false)) { console.warn(`WARN ${label} not visible`); return false; }
  try {
    await el.scrollIntoViewIfNeeded(); await sleep(180);
    const box = await el.boundingBox();
    if (box) { await page.mouse.move(box.x+box.width/2, box.y+box.height/2, {steps:12}); await sleep(300); }
    await el.click();
  } catch(e){ return false; }
  await sleep(post);
  return true;
}
async function pan(page, points=[]){
  for (const [x,y] of points){ await page.mouse.move(x,y,{steps:14}); await sleep(380); }
}
async function typeSlowly(page, sel, text){
  const el = page.locator(sel).first();
  if (!await el.isVisible().catch(()=>false)) return false;
  await el.click(); await sleep(200);
  await el.fill('');
  await el.pressSequentially(text, { delay: 32 });
  await sleep(400);
  return true;
}
async function pressChord(page, keys, gap=160){
  // Mode/nav chords like m,o — press, release, then next key after a small gap
  for (const k of keys){ await page.keyboard.press(k); await sleep(gap); }
}

const NAV = (t) => `.nav-item[data-target="${t}"]`;

async function runDemo(page){
  await page.goto(BASE);
  await sleep(2400);
  await injectCursor(page);
  await injectSubtitle(page);
  await page.evaluate(async () => {
    try { const r = await fetch('http://localhost:5757/api/devices'); if (r.ok && window.setLive) window.setLive(true); } catch(e){}
    try { localStorage.removeItem('ui.mode'); window.setMode && window.setMode(''); } catch(e){}
    // Make sure the bottom dock is hidden before we start (index.html L807 has
    // a stuck `bottom:32px !important` that defeats the toggle — force display:none).
    try {
      window.toggleUnifiedDock && window.toggleUnifiedDock(false);
      const d = document.getElementById('unified-dock');
      if (d) { d.classList.remove('open'); d.style.setProperty('display','none','important'); }
    } catch(e){}
  });
  await sleep(700);

  // Seed a Health Gate abandon → makes Postmortem + Remediate have signal
  await page.evaluate(async () => {
    try {
      await fetch('http://localhost:5757/api/mv/health-gate/apply', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({hostname:'de-fra-core-01', timeout_s:3, induce_regression_after_s:0})
      });
    } catch(e){}
  });
  await sleep(4500);

  // Helper: hard-hide the dock + blur any focused element so chords don't land in inputs.
  // Note: index.html L807 has `#unified-dock{bottom:32px !important}` which defeats the
  // built-in collapse — we have to force display:none ourselves.
  const closeDockAndBlur = async () => {
    await page.evaluate(() => {
      try { window.toggleUnifiedDock && window.toggleUnifiedDock(false); } catch(e){}
      try {
        const d = document.getElementById('unified-dock');
        if (d) { d.classList.remove('open'); d.style.setProperty('display','none','important'); }
      } catch(e){}
      try { if (document.activeElement && document.activeElement !== document.body) document.activeElement.blur(); } catch(e){}
      try { document.body.focus(); } catch(e){}
    });
    await page.keyboard.press('Escape').catch(()=>{});
    await sleep(300);
  };
  const showDock = async () => {
    await page.evaluate(() => {
      try {
        const d = document.getElementById('unified-dock');
        if (d) { d.style.removeProperty('display'); }
        window.toggleUnifiedDock && window.toggleUnifiedDock(true);
        window.udSelectTab && window.udSelectTab('terminal');
      } catch(e){}
    });
  };

  // ── ACT 0 · COLD OPEN + DOCK PEEK ───────────────────────────
  await topCaption(page, 'Phase 4 · the safety + autonomy layer', 1800);
  await caption(page, 'A config push that watches itself.', 1900);
  // Open the unified dock briefly, then close
  await showDock();
  await sleep(1100);
  await caption(page, 'Terminal · Agent Log · Alerts — one dock, always one keystroke away.', 1900);
  await closeDockAndBlur();
  await topCaption(page, '', 80);

  // ── ACT 1 · MODE CHORDS ─────────────────────────────────────
  await topCaption(page, 'Mode chords · m + o = Observe', 1600);
  await caption(page, 'Workflow modes dim the sidebar to what matters for the task.', 1700);
  // Belt-and-suspenders: drive mode change via the API directly (avoids stray-key risk)
  await page.evaluate(()=>{ try{ window.setMode && window.setMode('observe'); }catch(e){} });
  await sleep(900);
  await pan(page, [[120, 360], [120, 480]]);
  await caption(page, 'FRR live targets stay bright · Juniper/Arista fade to 28%.', 1900);
  await page.evaluate(()=>{ try{ window.setMode && window.setMode(''); }catch(e){} });
  await sleep(400);
  await topCaption(page, '', 80);

  // ── ACT 2 · NETBOX SOT DRIFT ────────────────────────────────
  await topCaption(page, 'NetBox SoT drift · severity-tiered', 1700);
  await moveAndClick(page, NAV('netbox-sot'), 'nav SoT');
  await sleep(700);
  await caption(page, 'Compare source-of-truth against the running lab.', 1500);
  await moveAndClick(page, '#nb-refresh-btn', 'refresh drift', 1600);
  await sleep(1100);
  await caption(page, 'Wrong AS = high · extra device = critical · wrong model = low.', 2200);
  await pan(page, [[600, 300], [900, 300], [600, 420]]);
  await topCaption(page, '', 80);

  // ── ACT 3 · AUTO-REMEDIATE ──────────────────────────────────
  await topCaption(page, 'Auto-Remediate · AI proposes · human approves', 1700);
  await moveAndClick(page, NAV('auto-remediate'), 'nav remediate');
  await sleep(700);
  await caption(page, 'Each drift row maps to a runbook via a deterministic table.', 1900);
  await moveAndClick(page, '#ar-import-drift-btn', 'import drift', 1700);
  await sleep(1300);
  await caption(page, 'Cosmetic drift auto-rejects · real drift queues for approval.', 2100);
  const approve = page.locator('#ar-out button:has-text("Approve")').first();
  if (await approve.isVisible().catch(()=>false)) {
    const box = await approve.boundingBox();
    if (box) { await page.mouse.move(box.x+box.width/2, box.y+box.height/2, {steps:10}); await sleep(280); }
    await approve.click().catch(()=>{});
  }
  await sleep(800);
  await topCaption(page, '', 80);

  // ── ACT 4 · HEALTH GATE ─────────────────────────────────────
  await topCaption(page, 'Health Gate · RFC 6241 §8.4 confirmed-commit', 1700);
  await caption(page, 'Watches BGP peers, interface state, and alert count.', 1900);
  // Wait for confirmed-count to tick — meanwhile pan over the panel
  await pan(page, [[800, 380], [800, 480], [600, 420]]);
  await page.waitForFunction(() => {
    const c = document.getElementById('ar-confirmed-count');
    return c && parseInt(c.textContent.trim(), 10) >= 1;
  }, { timeout: 16000 }).catch(()=>{});
  await sleep(700);
  await caption(page, 'Any signal degrades → device auto-reverts at the NETCONF timeout.', 2300);
  await topCaption(page, '', 80);

  // ── ACT 5 · AUTO-POSTMORTEM ─────────────────────────────────
  await topCaption(page, 'Auto-Postmortem · GAIT + HG + Remediation → markdown', 1700);
  await moveAndClick(page, NAV('postmortem'), 'nav postmortem');
  await sleep(700);
  await moveAndClick(page, '#pm-detect-btn', 'auto detect', 1400);
  await sleep(4200);
  await caption(page, 'P1 incident auto-correlated · root cause auto-identified.', 2100);
  // Pan over the markdown body to show the report
  await pan(page, [[470, 480], [470, 560], [470, 420]]);
  await caption(page, '~0.2 s · ready to paste into a ticket.', 1800);
  await topCaption(page, '', 80);

  // ── ACT 6 · CLI REFERENCE BM25 ──────────────────────────────
  await topCaption(page, 'CLI Reference · BM25 over 9,802 commands', 1700);
  await moveAndClick(page, NAV('cli-rag'), 'nav cli-rag');
  await sleep(700);
  await typeSlowly(page, '#cr-q', 'bgp md5 authentication');
  await moveAndClick(page, '#cr-search-btn', 'search', 1100);
  await sleep(900);
  await caption(page, 'Sub-millisecond · pure stdlib · no embedding model · deterministic.', 2100);
  await page.locator('#cr-vendor').selectOption('Juniper').catch(()=>{});
  await moveAndClick(page, '#cr-search-btn', 'juniper filter', 1000);
  await sleep(900);
  await caption(page, 'Filter to one vendor → completely different snippets.', 1900);
  await topCaption(page, '', 80);

  // ── OUTRO ──────────────────────────────────────────────────
  await topCaption(page, 'Phase 4 ships', 1300);
  await caption(page, '26 devices · 5 sites · 40 endpoints · 137/137 pytest · MIT.', 2300);
  await caption(page, 'github.com/gesh75/multivendor-ai-network-lab', 3000);
  await caption(page, '', 200);
  await topCaption(page, '', 200);
  await sleep(500);
}

async function rehearse(page){
  await page.goto(BASE);
  await sleep(2200);
  await page.evaluate(async ()=>{
    try{ const r=await fetch('http://localhost:5757/api/devices'); if(r.ok && window.setLive) window.setLive(true); }catch(e){}
    try{ window.toggleUnifiedDock && window.toggleUnifiedDock(false); }catch(e){}
  });
  await sleep(500);
  let ok = true;
  const groups = [
    { nav: NAV('netbox-sot'),     inside: ['#nb-refresh-btn'] },
    { nav: NAV('auto-remediate'), inside: ['#ar-import-drift-btn'] },
    { nav: NAV('postmortem'),     inside: ['#pm-detect-btn'] },
    { nav: NAV('cli-rag'),        inside: ['#cr-q','#cr-search-btn','#cr-vendor'] },
  ];
  // Also verify the dock-toggle global is wired
  const hasDock = await page.evaluate(() => typeof window.toggleUnifiedDock === 'function');
  console.log((hasDock?'  OK   ':'  FAIL ') + 'window.toggleUnifiedDock');
  if (!hasDock) ok = false;
  const hasMode = await page.evaluate(() => typeof window.setMode === 'function');
  console.log((hasMode?'  OK   ':'  FAIL ') + 'window.setMode');
  if (!hasMode) ok = false;
  for (const g of groups) {
    if (!(await page.locator(g.nav).first().isVisible().catch(()=>false))) {
      console.log('  FAIL ' + g.nav); ok = false; continue;
    }
    console.log('  OK   ' + g.nav);
    await page.locator(g.nav).first().click();
    await sleep(500);
    for (const s of g.inside) {
      const v = await page.locator(s).first().isVisible().catch(()=>false);
      console.log((v?'  OK   ':'  FAIL ')+s); if (!v) ok = false;
    }
  }
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
