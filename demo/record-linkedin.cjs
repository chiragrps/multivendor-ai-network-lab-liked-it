'use strict';
/*
 * LinkedIn-ready Phase 4 demo · TIGHT CUT v2 (~65s, 1280×720).
 *
 * v2 changes vs the 1:30 cut:
 *   - drops dock-peek cold open (was Phase-3 territory, didn't carry weight)
 *   - drops mode-chord act (UX win, not the headline story)
 *   - compressed dwells everywhere (captions ~1.5s, post-clicks ~0.4s)
 *   - one tight loop: drift → propose → approve → Health Gate → postmortem
 *   - CLI Reference is a 6s coda
 *
 * Caption rules:
 *   - top caption: small top-LEFT pill, ALWAYS uppercase act label
 *   - bottom caption: lifted 40px (clear of the persistent dock bar)
 *
 * Usage:
 *   node record-linkedin.cjs --rehearse
 *   node record-linkedin.cjs
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

async function caption(page, t, ms=1300){
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
  for (const [x,y] of points){ await page.mouse.move(x,y,{steps:10}); await sleep(280); }
}
async function typeSlowly(page, sel, text){
  const el = page.locator(sel).first();
  if (!await el.isVisible().catch(()=>false)) return false;
  await el.click(); await sleep(160);
  await el.fill('');
  await el.pressSequentially(text, { delay: 26 });
  await sleep(280);
  return true;
}

const NAV = (t) => `.nav-item[data-target="${t}"]`;

async function runDemo(page){
  await page.goto(BASE);
  await sleep(2000);
  await injectCursor(page);
  await injectSubtitle(page);
  await page.evaluate(async () => {
    try { const r = await fetch('http://localhost:5757/api/devices'); if (r.ok && window.setLive) window.setLive(true); } catch(e){}
    try { localStorage.removeItem('ui.mode'); window.setMode && window.setMode(''); } catch(e){}
    // Hard-hide the persistent dock for the whole take
    try {
      window.toggleUnifiedDock && window.toggleUnifiedDock(false);
      const d = document.getElementById('unified-dock');
      if (d) { d.classList.remove('open'); d.style.setProperty('display','none','important'); }
    } catch(e){}
  });
  await sleep(500);

  // Seed Health Gate abandon ahead of time so Postmortem & Remediate have signal
  await page.evaluate(async () => {
    try {
      await fetch('http://localhost:5757/api/mv/health-gate/apply', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({hostname:'de-fra-core-01', timeout_s:3, induce_regression_after_s:0})
      });
    } catch(e){}
  });
  await sleep(3800);

  // ── 0:00–0:05 · COLD OPEN ──────────────────────────────────
  await topCaption(page, 'Phase 4 · the closed-loop phase', 1500);
  await caption(page, 'A config push that watches itself — and takes itself back if it goes wrong.', 2400);
  await topCaption(page, '', 50);

  // ── 0:05–0:18 · DRIFT ──────────────────────────────────────
  await topCaption(page, 'NetBox SoT drift · severity-tiered', 1300);
  await moveAndClick(page, NAV('netbox-sot'), 'nav SoT', 500);
  await caption(page, 'Source-of-truth vs running lab.', 1100);
  await moveAndClick(page, '#nb-refresh-btn', 'refresh drift', 1100);
  await caption(page, 'Wrong AS = high · extra device = critical · wrong model = low.', 1900);
  await topCaption(page, '', 50);

  // ── 0:18–0:32 · AUTO-REMEDIATE ─────────────────────────────
  await topCaption(page, 'Auto-Remediate · AI proposes · human approves', 1300);
  await moveAndClick(page, NAV('auto-remediate'), 'nav remediate', 500);
  await caption(page, 'Each row maps to a runbook · cosmetic drift auto-rejects.', 1500);
  await moveAndClick(page, '#ar-import-drift-btn', 'import drift', 1300);
  const approve = page.locator('#ar-out button:has-text("Approve")').first();
  if (await approve.isVisible().catch(()=>false)) {
    const box = await approve.boundingBox();
    if (box) { await page.mouse.move(box.x+box.width/2, box.y+box.height/2, {steps:8}); await sleep(220); }
    await approve.click().catch(()=>{});
  }
  await caption(page, 'Approve → executes through Health Gate.', 1500);
  await topCaption(page, '', 50);

  // ── 0:32–0:46 · HEALTH GATE ────────────────────────────────
  await topCaption(page, 'Health Gate · RFC 6241 §8.4 confirmed-commit', 1300);
  await caption(page, 'Watches BGP peers, interface state, alerts — auto-reverts on regression.', 2300);
  await pan(page, [[820, 380], [820, 480]]);
  await page.waitForFunction(() => {
    const c = document.getElementById('ar-confirmed-count');
    return c && parseInt(c.textContent.trim(), 10) >= 1;
  }, { timeout: 11000 }).catch(()=>{});
  await sleep(400);
  await caption(page, '', 50);
  await topCaption(page, '', 50);

  // ── 0:46–1:00 · POSTMORTEM ─────────────────────────────────
  await topCaption(page, 'Auto-Postmortem · GAIT + HG + remediation → markdown', 1300);
  await moveAndClick(page, NAV('postmortem'), 'nav postmortem', 500);
  await moveAndClick(page, '#pm-detect-btn', 'auto detect', 900);
  // detect fills the severity tiles; generate produces the actual markdown
  await moveAndClick(page, '#pm-generate-btn', 'generate now', 800);
  // wait for the markdown body to populate; pan over it
  await page.waitForFunction(() => {
    const out = document.getElementById('pm-out');
    return out && out.textContent && out.textContent.length > 200;
  }, { timeout: 5000 }).catch(()=>{});
  await pan(page, [[700, 470], [700, 560], [700, 430]]);
  await caption(page, 'P1 correlated · root cause identified · ~0.2 s · paste-ready Markdown.', 2100);
  await topCaption(page, '', 50);

  // ── 0:56–1:04 · CLI REFERENCE ──────────────────────────────
  await topCaption(page, 'CLI Reference · 9,802 commands · BM25', 1200);
  await moveAndClick(page, NAV('cli-rag'), 'nav cli-rag', 400);
  await typeSlowly(page, '#cr-q', 'bgp md5 authentication');
  await moveAndClick(page, '#cr-search-btn', 'search', 700);
  await caption(page, 'Sub-millisecond · stdlib only · no embedding model.', 1700);
  await topCaption(page, '', 50);

  // ── 1:04–1:12 · OUTRO ──────────────────────────────────────
  await topCaption(page, 'Phase 4 ships', 1200);
  await caption(page, '26 devices · 5 sites · 40 endpoints · 137/137 pytest · MIT.', 2100);
  await caption(page, 'github.com/gesh75/multivendor-ai-network-lab', 2400);
  await caption(page, '', 200);
  await topCaption(page, '', 200);
  await sleep(400);
}

async function rehearse(page){
  await page.goto(BASE);
  await sleep(1800);
  await page.evaluate(async ()=>{
    try{ const r=await fetch('http://localhost:5757/api/devices'); if(r.ok && window.setLive) window.setLive(true); }catch(e){}
    try{ window.toggleUnifiedDock && window.toggleUnifiedDock(false); }catch(e){}
  });
  await sleep(400);
  let ok = true;
  const groups = [
    { nav: NAV('netbox-sot'),     inside: ['#nb-refresh-btn'] },
    { nav: NAV('auto-remediate'), inside: ['#ar-import-drift-btn'] },
    { nav: NAV('postmortem'),     inside: ['#pm-detect-btn'] },
    { nav: NAV('cli-rag'),        inside: ['#cr-q','#cr-search-btn'] },
  ];
  for (const g of groups) {
    if (!(await page.locator(g.nav).first().isVisible().catch(()=>false))) {
      console.log('  FAIL ' + g.nav); ok = false; continue;
    }
    console.log('  OK   ' + g.nav);
    await page.locator(g.nav).first().click();
    await sleep(400);
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
