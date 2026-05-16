'use strict';
/*
 * AI Network Tool v4.0 — rapid feature-tour demo (every panel, no dead air)
 *
 * Usage:
 *   node record-demo.cjs --rehearse
 *   node record-demo.cjs
 */

const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const BASE = 'http://localhost:8080/index.html?v=demo-tour';
const OUT_DIR = path.join(__dirname);
const OUT_NAME = 'multivendor-ai-network-tool-demo-r27.webm';
const REHEARSAL = process.argv.includes('--rehearse');
const W = 1920, H = 1080;

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ─── Pacing constants — TIGHT for feature tour ─────────────────────
const PANEL_DWELL  = 1100;   // ms each panel stays on screen
const CAPTION_HOLD = 500;    // ms after caption appears before continuing
const TYPING_DELAY = 32;     // ms/char (fast typist)
const FAST_PAUSE   = 250;    // micro-pause between snappy actions

// ─── Overlay injection (no innerHTML for user content) ─────────────
async function injectCursor(page) {
  await page.evaluate(() => {
    if (document.getElementById('demo-cursor')) return;
    const cursor = document.createElement('div');
    cursor.id = 'demo-cursor';
    const svgNS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('width', '32'); svg.setAttribute('height', '32');
    svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('fill', 'none');
    const path = document.createElementNS(svgNS, 'path');
    path.setAttribute('d', 'M5 3L19 12L12 13L9 20L5 3Z');
    path.setAttribute('fill', 'white');
    path.setAttribute('stroke', 'black');
    path.setAttribute('stroke-width', '1.5');
    path.setAttribute('stroke-linejoin', 'round');
    svg.appendChild(path); cursor.appendChild(svg);
    cursor.style.cssText = 'position:fixed;z-index:999999;pointer-events:none;width:32px;height:32px;left:100px;top:100px;transition:left .08s ease-out,top .08s ease-out;filter:drop-shadow(2px 2px 3px rgba(0,0,0,.6));';
    document.body.appendChild(cursor);
    document.addEventListener('mousemove', (e) => {
      cursor.style.left = e.clientX + 'px';
      cursor.style.top  = e.clientY + 'px';
    });
  });
}

async function injectOverlays(page) {
  await page.evaluate(() => {
    if (!document.getElementById('demo-subtitle')) {
      const bar = document.createElement('div');
      bar.id = 'demo-subtitle';
      bar.style.cssText = "position:fixed;bottom:32px;left:50%;transform:translateX(-50%);z-index:999998;padding:12px 24px;max-width:80%;text-align:center;background:rgba(0,0,0,.82);color:white;font-family:'Inter',-apple-system,system-ui,sans-serif;font-size:22px;font-weight:600;letter-spacing:.3px;border-radius:10px;box-shadow:0 10px 40px rgba(0,0,0,.5);transition:opacity .2s,transform .2s;pointer-events:none;opacity:0";
      document.body.appendChild(bar);
    }
    if (!document.getElementById('demo-tag-top')) {
      const tag = document.createElement('div');
      tag.id = 'demo-tag-top';
      tag.style.cssText = "position:fixed;top:24px;left:50%;transform:translateX(-50%);z-index:999998;padding:9px 20px;background:linear-gradient(135deg,rgba(88,166,255,.95),rgba(167,139,250,.95));color:#0d1117;font-family:'Inter',-apple-system,system-ui,sans-serif;font-size:15px;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;border-radius:6px;box-shadow:0 6px 20px rgba(88,166,255,.4);opacity:0;transition:opacity .2s;pointer-events:none";
      document.body.appendChild(tag);
    }
    // Feature counter bottom-right
    if (!document.getElementById('demo-counter')) {
      const c = document.createElement('div');
      c.id = 'demo-counter';
      c.style.cssText = "position:fixed;bottom:32px;right:32px;z-index:999998;padding:8px 14px;background:rgba(0,0,0,.6);color:#58a6ff;font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;border-radius:6px;border:1px solid rgba(88,166,255,.3);opacity:0;transition:opacity .2s;pointer-events:none";
      document.body.appendChild(c);
    }
  });
}

async function caption(page, text) {
  await page.evaluate((t) => {
    const bar = document.getElementById('demo-subtitle');
    if (!bar) return;
    if (t) { bar.textContent = t; bar.style.opacity = '1'; }
    else   { bar.style.opacity = '0'; }
  }, text);
}

async function tagTop(page, text) {
  await page.evaluate((t) => {
    const tag = document.getElementById('demo-tag-top');
    if (!tag) return;
    if (t) { tag.textContent = t; tag.style.opacity = '1'; }
    else   { tag.style.opacity = '0'; }
  }, text);
}

async function counter(page, n, total) {
  await page.evaluate(({n, total}) => {
    const c = document.getElementById('demo-counter');
    if (!c) return;
    if (n === null) { c.style.opacity = '0'; return; }
    c.textContent = `feature ${n} / ${total}`;
    c.style.opacity = '1';
  }, {n, total});
}

async function setupOverlays(page) {
  await injectCursor(page);
  await injectOverlays(page);
}

// ─── Title cards (DOM-built, no innerHTML) ─────────────────────────
async function showTitleCard(page, title, subtitle, sub2, ms = 3000) {
  await page.evaluate(({title, subtitle, sub2}) => {
    document.getElementById('demo-title-card')?.remove();
    const v = document.createElement('div');
    v.id = 'demo-title-card';
    v.style.cssText = "position:fixed;inset:0;background:#000;z-index:1000001;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#fff;font-family:'Inter',-apple-system,system-ui,sans-serif;opacity:0;transition:opacity .3s;text-align:center;padding:40px;";
    const t = document.createElement('div');
    t.textContent = title;
    t.style.cssText = "font-size:64px;font-weight:800;letter-spacing:-1px;background:linear-gradient(135deg,#58a6ff,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:24px";
    const s = document.createElement('div');
    s.textContent = subtitle;
    s.style.cssText = "font-size:30px;font-weight:500;color:#e6edf3;margin-bottom:12px";
    const s2 = document.createElement('div');
    s2.textContent = sub2 || '';
    s2.style.cssText = "font-size:20px;font-weight:400;color:#8b949e;font-family:'JetBrains Mono',monospace";
    v.append(t, s, s2);
    document.body.appendChild(v);
    requestAnimationFrame(() => { v.style.opacity = '1'; });
  }, {title, subtitle, sub2});
  await sleep(ms);
  await page.evaluate(() => {
    const v = document.getElementById('demo-title-card');
    if (v) { v.style.opacity = '0'; setTimeout(() => v.remove(), 300); }
  });
  await sleep(320);
}

// ─── Tour primitives ──────────────────────────────────────────────
async function visitPanel(page, tabId, tagText, captionText, dwell = PANEL_DWELL) {
  await page.evaluate((id) => { if (window.switchTabById) window.switchTabById(id); }, tabId);
  await tagTop(page, tagText);
  await caption(page, captionText);
  await sleep(dwell);
}

async function hoverElement(page, selector) {
  const el = page.locator(selector).first();
  if (await el.count() === 0) return false;
  const box = await el.boundingBox().catch(() => null);
  if (!box) return false;
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 10 });
  return true;
}

async function moveAndClick(page, locator, post = 400) {
  const el = typeof locator === 'string' ? page.locator(locator).first() : locator;
  if (await el.count() === 0) return false;
  const box = await el.boundingBox().catch(() => null);
  if (box) {
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 10 });
    await sleep(150);
  }
  await el.click().catch(() => {});
  await sleep(post);
  return true;
}

async function typeSlowly(page, selector, text) {
  const el = page.locator(selector).first();
  if (await el.count() === 0) return false;
  await moveAndClick(page, selector, 100);
  await el.fill('');
  await el.pressSequentially(text, { delay: TYPING_DELAY });
  return true;
}

async function pressKey(page, key) {
  await page.keyboard.press(key);
  await sleep(FAST_PAUSE);
}

async function pressChord(page, k1, k2) {
  await page.keyboard.press(k1);
  await sleep(120);
  await page.keyboard.press(k2);
  await sleep(FAST_PAUSE);
}

// ─── Rehearsal ─────────────────────────────────────────────────────
async function rehearse(page) {
  console.log('\n══ REHEARSAL — verifying all 34 panels ══\n');
  await page.goto(BASE);
  await page.waitForLoadState('networkidle').catch(() => {});
  await sleep(1500);

  const panels = [
    'health','mv-gnmi','telemetry','mv-syslog','mv-snmp','alerts','noise-floor',
    'mv-inventory','mv-fleet','compliance','mv-gait','shadow',
    'chat','ai-cmd','mv-orchestrator','analysis','docs','mv-suzieq',
    'commands','collect','cli-bench','napalm','nornir',
    'change-approval','statediff','observer','batfish','blast',
    'topo','discover','mv-path',
    'mv-intent','mv-eval','chaos',
  ];
  let ok = true;
  for (const id of panels) {
    const exists = await page.locator(`#tab-${id}`).count() > 0;
    console.log(`  ${exists ? '✓' : '✗'} tab-${id}`);
    if (!exists) ok = false;
  }
  console.log(`\n══ REHEARSAL ${ok ? 'PASSED ✓' : 'FAILED ✗'} (${panels.length} panels) ══\n`);
  return ok;
}

// ─── Tour scenes ───────────────────────────────────────────────────
async function sceneOpen(page) {
  console.log('▶ 1. Cold open + title');
  await page.goto(BASE);
  await page.waitForLoadState('networkidle').catch(() => {});
  await sleep(600);
  await page.evaluate(() => {
    try {
      localStorage.removeItem('ui.mode'); localStorage.removeItem('ui.nocWall');
      localStorage.removeItem('ui.nocCycle'); localStorage.removeItem('ui.nocLastTab');
      sessionStorage.clear();
    } catch (_) {}
  });
  await setupOverlays(page);
  await showTitleCard(page,
    'AI Network Tool v4.0',
    '34 panels · 185 buttons · 0 unlabelled · keyboard-driven',
    'github.com/gesh75/multivendor-ai-network-lab',
    2800);
}

async function sceneKeyboard(page) {
  console.log('▶ 2. Keyboard tour (mode + nav chords)');
  await setupOverlays(page);
  await tagTop(page, 'Keyboard-Driven Operation');
  await caption(page, '? — open help · m o/d/p/u/l — modes · g h/t/i — nav');
  await pressKey(page, '?');
  await sleep(2200);
  await pressKey(page, 'Escape');
  // Mode chord demo
  await caption(page, 'm + o → Observe mode (dims non-FRR devices)');
  await pressChord(page, 'm', 'o');
  await sleep(1500);
  await caption(page, 'm + l → reset to All');
  await pressChord(page, 'm', 'l');
  await sleep(700);
}

const TOUR = [
  // [tabId, tagTop, caption]
  ['health',          '1 · Home / Health',           'Live device-health cards · auto-fetch on landing'],
  ['mv-gnmi',         '2 · gNMI Telemetry',          'OpenConfig telemetry from FRR containers'],
  ['telemetry',       '3 · Streaming Telemetry',     'High-rate metric stream · per-device sparklines'],
  ['mv-syslog',       '4 · Syslog',                  'Severity tiles click-to-filter · device column'],
  ['mv-snmp',         '5 · SNMP Traps',              'Per-site filter · OID + binding · unmanaged-host badge'],
  ['alerts',          '6 · Alert Correlation',       'Multi-source alert dedup + correlation'],
  ['noise-floor',     '7 · Noise Floor',             '5-site sparklines · suppression efficiency'],
  ['mv-inventory',    '8 · Inventory',               '26 devices · free-text filter across 5 columns'],
  ['mv-fleet',        '9 · Fleet Audit',             'Batfish-style fleet config analysis'],
  ['compliance',      '10 · Compliance',             'BGP auth · prefix limits · OSPF · backbone area'],
  ['mv-gait',         '11 · GAIT Audit',             'Immutable AI audit trail · clickable hostnames'],
  ['shadow',          '12 · Shadow Auditor',         'Async second-opinion audit channel'],
  ['chat',            '13 · Agent Chat',             'AI Coordinator routes to 10 specialist agents'],
  ['ai-cmd',          '14 · AI Command',             'NL → CLI translation · live device-context chip'],
  ['mv-orchestrator', '15 · Orchestrator',           'Pydantic-AI router · routing / ACL / incident'],
  ['analysis',        '16 · AI Insights',            'Deep analysis · log intelligence · drift · security'],
  ['docs',            '17 · Doc Search',             'Vendor docs RAG · grounded answers'],
  ['mv-suzieq',       '18 · SuzieQ',                 'Offline config parsing · vendor quick-chips'],
  ['commands',        '19 · CLI / Terminal',         'Raw SSH execution · quick command chips'],
  ['collect',         '20 · Collect',                'Quick snapshot · full investigation · device guard'],
  ['cli-bench',       '21 · CLI Transport',          'SSH · NETCONF · gNMI · REST benchmarks'],
  ['napalm',          '22 · NAPALM',                 'Multi-vendor abstraction · per-site collection'],
  ['nornir',          '23 · Nornir Engine',          'Parallel fleet tasks · ~10× sequential Netmiko'],
  ['change-approval', '24 · Change Approval',        'AI proposes · human approves · pyATS diff'],
  ['statediff',       '25 · State Diff',             'Pre/post snapshot · BGP + interface deltas'],
  ['observer',        '26 · Observer-Actor',         'Auto-rollback proposals from chaos events'],
  ['batfish',         '27 · Pre-Deploy',             'What-if config simulation before rollout'],
  ['blast',           '28 · Blast Radius',           'Predicted impact of a proposed change'],
  ['topo',            '29 · BGP Topology',           '26 devices · 5 sites · 36 BGP sessions UP'],
  ['discover',        '30 · OSPF Discover',          'Live neighbor walk auto-discovery'],
  ['mv-path',         '31 · Path Trace',             'Hop-by-hop BFS · multi-vendor edges'],
  ['mv-intent',       '32 · Intent Verify',          'Config-claimed vs observed · drift detection'],
  ['mv-eval',         '33 · Eval Harness',           '10 scenarios · keyword + LLM-as-judge scoring'],
  ['chaos',           '34 · Chaos Monkey',           'Break BGP · Observer-Actor self-heal'],
];

async function sceneTour(page) {
  console.log(`▶ 3. Feature tour (${TOUR.length} panels)`);
  await tagTop(page, 'Feature Tour');
  await caption(page, '34 panels · rapid pass · hover to see each capability');
  await sleep(900);
  for (let i = 0; i < TOUR.length; i++) {
    const [id, t, c] = TOUR[i];
    await counter(page, i + 1, TOUR.length);
    console.log(`  ${(i+1).toString().padStart(2)} · ${t}`);
    await visitPanel(page, id, t, c, PANEL_DWELL);
    // Move the cursor to the active tab so viewer's eye follows
    const tab = page.locator(`.tab[data-tab="${id}"]`).first();
    if (await tab.count() > 0) {
      const box = await tab.boundingBox().catch(() => null);
      if (box) await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 6 });
    }
  }
  await counter(page, null);
}

async function sceneHighlights(page) {
  console.log('▶ 4. Highlight reel');
  // NOC Wall quick demo
  await tagTop(page, 'NOC Wall · n');
  await caption(page, 'Press n · arrow-key cycle · 30s auto-rotate · survives reload');
  await pressKey(page, 'n');
  await sleep(1200);
  await pressKey(page, 'ArrowRight'); await sleep(900);
  await pressKey(page, 'ArrowRight'); await sleep(900);
  await pressKey(page, 'Escape');
  await sleep(400);
  // Quick filter demo on Inventory
  await tagTop(page, 'g i + type to filter');
  await caption(page, '/ to focus · model · vendor · site · role · all live');
  await pressChord(page, 'g', 'i');
  await sleep(500);
  await typeSlowly(page, '#mv-inv-filter', 'SRX');
  await sleep(900);
  await page.evaluate(() => {
    const i = document.getElementById('mv-inv-filter');
    if (i) { i.value = ''; i.dispatchEvent(new Event('input', {bubbles:true})); }
  });
}

async function sceneEnd(page) {
  console.log('▶ 5. End frame');
  await caption(page, '');
  await tagTop(page, '');
  await showTitleCard(page,
    'AI Network Tool v4.0',
    'Open source · Multivendor · Built for operators',
    'github.com/gesh75/multivendor-ai-network-lab',
    3500);
}

// ─── Main ──────────────────────────────────────────────────────────
(async () => {
  if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, {recursive: true});

  const browser = await chromium.launch({headless: true});

  if (REHEARSAL) {
    const ctx = await browser.newContext({viewport: {width: W, height: H}});
    const page = await ctx.newPage();
    const ok = await rehearse(page);
    await browser.close();
    process.exit(ok ? 0 : 1);
  }

  const ctx = await browser.newContext({
    viewport: {width: W, height: H},
    recordVideo: {dir: OUT_DIR, size: {width: W, height: H}},
  });
  const page = await ctx.newPage();

  const t0 = Date.now();
  try {
    await sceneOpen(page);
    await sceneKeyboard(page);
    await sceneTour(page);
    await sceneHighlights(page);
    await sceneEnd(page);
  } catch (e) {
    console.error('Demo error:', e.message);
    console.error(e.stack);
  } finally {
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    console.log(`\nElapsed: ${elapsed}s`);
    await ctx.close();
    const video = page.video();
    if (video) {
      const src = await video.path();
      const dest = path.join(OUT_DIR, OUT_NAME);
      try {
        fs.copyFileSync(src, dest);
        const stats = fs.statSync(dest);
        console.log(`✓ Video saved: ${dest} (${(stats.size/1024/1024).toFixed(1)} MB)`);
      } catch (e) {
        console.error('Copy failed:', e.message);
      }
    }
    await browser.close();
  }
})();
