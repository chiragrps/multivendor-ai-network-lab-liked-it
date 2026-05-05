// DCN Network Tool — Frontend Logic
const API = "http://localhost:5757/api";
let allDevices = [], selectedDev = null, roleFilter = "", cmdHistory = [], lastMultiData = {};
let lastPortData = null, lastAnalysisData = null, lastISPData = null;

// ── Init ──────────────────────────────────────────────────────────────────────
async function init() {
  try {
    const r = await fetch(`${API}/health`);
    const d = await r.json();
    const pill = document.getElementById("api-pill");
    pill.className = "status-pill online";
    document.getElementById("stxt").textContent = `API OK — ${d.devices_loaded} devices`;
  } catch(e) {
    const pill = document.getElementById("api-pill");
    pill.className = "status-pill offline";
    document.getElementById("stxt").textContent = "API Offline";
  }
  await loadDevices();
  checkLLMStatus();
  setInterval(checkLLMStatus, 60000);
  _jmcpInit();
  _initKeyboardShortcuts();
}

async function checkLLMStatus() {
  try {
    const r = await fetch(`${API}/llm/status`);
    const d = await r.json();
    const badge = document.getElementById("llm-badge");
    const tog = document.getElementById("llm-toggle");
    if (!badge) return;
    if (!d.enabled) {
      badge.className = "status-pill offline";
      badge.innerHTML = '<span class="pill-dot"></span> LLM: disabled';
      badge.title = "LLM is turned OFF — no AI analysis";
      if (tog) { tog.textContent = "🔌 OFF"; tog.style.color = "var(--red)"; tog.style.borderColor = "var(--red)"; }
    } else if (d.available) {
      badge.className = "status-pill ai";
      badge.innerHTML = '<span class="pill-dot"></span> LLM: ' + (d.model || "active");
      badge.title = "Docker Model Runner active — AI-powered analysis enabled";
      if (tog) { tog.textContent = "🔌 ON"; tog.style.color = "var(--green)"; tog.style.borderColor = "var(--green)"; }
    } else {
      badge.className = "status-pill offline";
      badge.innerHTML = '<span class="pill-dot"></span> LLM: offline';
      badge.title = d.hint || "Docker Model Runner not available — using rule-based analysis";
      if (tog) { tog.textContent = "🔌 ON"; tog.style.color = "var(--muted)"; tog.style.borderColor = "var(--border)"; }
    }
  } catch(_) {
    const badge = document.getElementById("llm-badge");
    if (badge) { badge.className = "status-pill offline"; badge.innerHTML = '<span class="pill-dot"></span> LLM: offline'; }
  }
}

async function toggleLLM() {
  const tog = document.getElementById("llm-toggle");
  if (tog) { tog.disabled = true; tog.textContent = "⏳ …"; }
  try {
    const r = await fetch(`${API}/llm/toggle`, { method: "POST", headers: {"Content-Type": "application/json"}, body: "{}" });
    const d = await r.json();
    if (tog) {
      tog.disabled = false;
      if (d.enabled) {
        tog.textContent = "🔌 ON"; tog.style.color = "var(--green)"; tog.style.borderColor = "var(--green)";
      } else {
        tog.textContent = "🔌 OFF"; tog.style.color = "var(--red)"; tog.style.borderColor = "var(--red)";
      }
    }
    checkLLMStatus();
  } catch(e) {
    if (tog) { tog.disabled = false; tog.textContent = "🔌 ERR"; }
  }
}

function renderLLMNarrative(containerId, narrative) {
  if (!narrative) return;
  const el = document.getElementById(containerId);
  if (!el) return;
  const lines = narrative.split("\\n").filter(l => l.trim());
  const html = `<div style="margin:10px 0;padding:10px 14px;background:rgba(88,166,255,0.08);border-left:3px solid var(--accent);border-radius:4px;">
    <div style="font-size:10px;color:var(--accent);font-weight:600;letter-spacing:0.08em;margin-bottom:6px;">🤖 LLM ANALYSIS (Docker Model Runner)</div>
    ${lines.map(l => `<div style="font-size:12px;color:var(--muted);line-height:1.6;margin-bottom:2px;">${escHtml(l)}</div>`).join("")}
  </div>`;
  el.insertAdjacentHTML("afterbegin", html);
}

async function loadDevices() {
  try {
    const r = await fetch(`${API}/devices`);
    allDevices = await r.json();
    document.getElementById("total-count").textContent = allDevices.length;
    document.getElementById("st-total").textContent = allDevices.length;
    document.getElementById("st-sites").textContent = new Set(allDevices.map(d => d.site)).size;
    document.getElementById("st-fw").textContent = allDevices.filter(d => d.role === "firewall").length;
    document.getElementById("st-rt").textContent = allDevices.filter(d => d.role === "router").length;
    document.getElementById("st-sw").textContent = allDevices.filter(d => d.role === "switch").length;
    const sites = [...new Set(allDevices.map(d => d.site))].sort();
    const sel = document.getElementById("site-sel");
    sites.forEach(s => { const o = document.createElement("option"); o.value = s; o.textContent = s; sel.appendChild(o); });
    renderList(allDevices);
  } catch(e) { console.error("Load devices failed:", e); }
}

// ── Device List ───────────────────────────────────────────────────────────────
const _roleIcon = r => r === 'firewall' ? '🛡️' : r === 'router' ? '🔀' : '🖥️';
let _collapsedSites = new Set();

function renderList(devs) {
  const el = document.getElementById("dev-list");
  if (!devs.length) { el.innerHTML = '<div style="padding:14px;color:var(--muted);font-size:12px;text-align:center">No devices match filter</div>'; return; }
  const groups = {};
  devs.forEach(d => { if (!groups[d.site]) groups[d.site] = []; groups[d.site].push(d); });
  el.innerHTML = Object.keys(groups).sort().map(site => {
    const collapsed = _collapsedSites.has(site);
    return `<div class="site-group${collapsed ? ' collapsed' : ''}" data-site="${site}">
    <div class="site-lbl" onclick="_toggleSite('${site}')"><span><span class="chevron">▼</span> ${site}</span><span style="color:var(--border)">${groups[site].length}</span></div>
    ${groups[site].map(d => `
      <div class="dev-item${selectedDev && selectedDev.ip === d.ip ? ' active' : ''}" id="di-${d.ip.replace(/\./g,'-')}"
           onclick='selectDev(${JSON.stringify(d)})'>
        <span class="role-icon">${_roleIcon(d.role)}</span>
        <span class="dn" title="${d.hostname}">${d.hostname}</span>
        <span class="dtype ${d.type==='junos'?'t-j':'t-e'}">${d.type==='junos'?'JNS':'EOS'}</span>
      </div>`).join('')}
    </div>`;
  }).join('');
}

function _toggleSite(site) {
  if (_collapsedSites.has(site)) _collapsedSites.delete(site);
  else _collapsedSites.add(site);
  const grp = document.querySelector(`.site-group[data-site="${site}"]`);
  if (grp) grp.classList.toggle('collapsed');
}

function filterDevices() {
  const q = document.getElementById("search-in").value.toLowerCase();
  const site = document.getElementById("site-sel").value;
  let r = allDevices;
  if (q) r = r.filter(d => d.hostname.toLowerCase().includes(q) || d.ip.includes(q));
  if (site) r = r.filter(d => d.site === site);
  if (roleFilter) r = r.filter(d => d.role === roleFilter);
  renderList(r);
}

function setRole(el, role) {
  roleFilter = role;
  document.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
  el.classList.add("active");
  filterDevices();
}

// ── Select Device ─────────────────────────────────────────────────────────────
function selectDev(d) {
  selectedDev = d;
  lastMultiData = {};
  // Re-render list to update active state
  filterDevices();
  // Show device header
  document.getElementById("empty-st").style.display = "none";
  document.getElementById("tabs").style.display = "flex";
  const roleClass = d.role === 'firewall' ? 'fw' : d.role === 'router' ? 'rt' : 'sw';
  document.getElementById("dev-hdr").innerHTML = `
    <div class="dev-card" style="padding:0;gap:10px;display:flex;align-items:center;width:100%">
      <div class="dev-role-icon ${roleClass}">${_roleIcon(d.role)}</div>
      <div style="flex:1;min-width:0">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <span class="dtitle">${d.hostname}</span>
          <span class="dmeta">${d.ip}</span>
          <span class="dtype ${d.type==='junos'?'t-j':'t-e'}" style="font-size:11px;padding:2px 5px">${d.type.toUpperCase()}</span>
        </div>
        <div style="font-size:10px;color:var(--muted);margin-top:1px">${d.site} · ${d.role}</div>
      </div>
      <button class="btn" onclick="pingDevice()">📡 Test SSH</button>
    </div>
  `;
  buildCmdGrid(d.type);
  // Sync JMCP device selector with sidebar selection
  const jmcpSel = document.getElementById("jmcp-device");
  if (jmcpSel && d.type === "junos") {
    const shortName = d.hostname.split(".")[0].toLowerCase();
    if (jmcpSel.querySelector(`option[value="${shortName}"]`)) {
      jmcpSel.value = shortName;
    }
  }
  // Always open Commands tab when selecting a new device
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  document.querySelectorAll(".tp").forEach(p => p.classList.remove("active"));
  document.querySelector('[data-tab="commands"]').classList.add("active");
  document.getElementById("tab-commands").classList.add("active");
  clearOutput();
}

async function pingDevice() {
  if (!selectedDev) return;
  const btn = event.target;
  btn.disabled = true; btn.textContent = "⏳ Testing…";
  try {
    const r = await fetch(`${API}/ping`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ ip: selectedDev.ip, dtype: selectedDev.type }) });
    const d = await r.json();
    btn.textContent = d.reachable ? "✅ Reachable" : "❌ Unreachable";
    setTimeout(() => { btn.textContent = "📡 Test SSH"; btn.disabled = false; }, 3000);
  } catch(e) {
    btn.textContent = "❌ Error"; setTimeout(() => { btn.textContent = "📡 Test SSH"; btn.disabled = false; }, 3000);
  }
}

// ── Tabs ──────────────────────────────────────────────────────────────────────
function switchTab(el) {
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  document.querySelectorAll(".tp").forEach(p => p.classList.remove("active"));
  el.classList.add("active");
  document.getElementById("tab-" + el.dataset.tab).classList.add("active");
}

// ── Command Grid ──────────────────────────────────────────────────────────────
const CMD_CATEGORIES = {
  'Routing': ['bgp','bgp_detail','config_bgp','config_routing','ospf','isis','route','route_table','mpls'],
  'Interfaces': ['interfaces','interfaces_detail','ports_all','ports_up','ports_count','ports_errors','ports_hw','isp_ifaces','isp_optics','lacp','lldp','mtu','traffic'],
  'Switching': ['vlans','spanning_tree','mac_table'],
  'Security': ['firewall','ike','ipsec','nat'],
  'Monitoring': ['alarms','chassis','logs','logs_error','pfe','uptime','version','arp'],
  'Config': ['config_full','config_ifaces'],
};

async function buildCmdGrid(dtype) {
  try {
    const r = await fetch(`${API}/commands/${dtype}`);
    const cmds = await r.json();
    const keys = Object.keys(cmds);
    const categorized = new Set();
    let html = '';
    for (const [cat, catKeys] of Object.entries(CMD_CATEGORIES)) {
      const matching = catKeys.filter(k => keys.includes(k));
      if (!matching.length) continue;
      matching.forEach(k => categorized.add(k));
      html += `<div class="cmd-cat-label">${cat}</div>`;
      html += matching.map(k => `<button class="cbtn" onclick="runCmd('${k}')" title="${cmds[k]}">${k}</button>`).join('');
    }
    const uncategorized = keys.filter(k => !categorized.has(k));
    if (uncategorized.length) {
      html += `<div class="cmd-cat-label">Other</div>`;
      html += uncategorized.map(k => `<button class="cbtn" onclick="runCmd('${k}')" title="${cmds[k]}">${k}</button>`).join('');
    }
    document.getElementById("cmd-grid").innerHTML = html;
  } catch(e) {}
}

// ── Run Commands ──────────────────────────────────────────────────────────────
async function runCmd(cmdKey) {
  if (!selectedDev) return;
  const btn = document.querySelector(`.cbtn[onclick="runCmd('${cmdKey}')"]`);
  if (btn) { btn.style.borderColor = "var(--yellow)"; btn.style.color = "var(--yellow)"; }
  setOutputLoading(`Running: ${cmdKey}…`);
  try {
    const r = await fetch(`${API}/run`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ ip: selectedDev.ip, dtype: selectedDev.type, cmd_key: cmdKey }) });
    const d = await r.json();
    displayOutput(cmdKey, d);
    addHistory(cmdKey, d.command || cmdKey, d.success, selectedDev.hostname);
    lastMultiData[cmdKey] = d.output || d.error || "";
  } catch(e) {
    setOutputError("Fetch error: " + e);
  }
  if (btn) { btn.style.borderColor = ""; btn.style.color = ""; }
}

async function runRaw() {
  if (!selectedDev) return;
  const cmd = document.getElementById("raw-cmd").value.trim();
  if (!cmd) return;
  const btn = document.getElementById("btn-raw");
  btn.disabled = true;
  setOutputLoading(`Running: ${cmd}…`);
  try {
    const r = await fetch(`${API}/run`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ ip: selectedDev.ip, dtype: selectedDev.type, raw: cmd }) });
    const d = await r.json();
    displayOutput(cmd, d);
    addHistory(cmd, cmd, d.success, selectedDev.hostname);
    lastMultiData["raw_" + Date.now()] = d.output || d.error || "";
  } catch(e) {
    setOutputError("Fetch error: " + e);
  }
  btn.disabled = false;
}

function setOutputLoading(msg) {
  document.getElementById("cmd-lbl").textContent = msg;
  document.getElementById("out-pre").innerHTML = '<span class="spin"></span> Running…';
}

function setOutputError(msg) {
  document.getElementById("cmd-lbl").textContent = "Error";
  document.getElementById("out-pre").innerHTML = `<span style="color:var(--red)">${msg}</span>`;
}

function _highlightLine(line) {
  let h = line.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  // Errors / critical
  h = h.replace(/\b(error|fail|down|dead|unreachable|timeout|denied|reject|alarm|critical)\b/gi, '<span class="hl-err">$1</span>');
  // OK / up / established
  h = h.replace(/\b(established|up|active|ok|running|online|success)\b/gi, '<span class="hl-ok">$1</span>');
  // Warnings
  h = h.replace(/\b(warning|flap|degraded|mismatch)\b/gi, '<span class="hl-warn">$1</span>');
  // IP addresses
  h = h.replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)\b/g, '<span class="hl-ip">$1</span>');
  // Interface names
  h = h.replace(/\b((?:ge|xe|et|ae|lo|irb|vlan|em|fxp|me|gr|st|reth|sp)-?\d[\w\/\.\-:]*)\b/gi, '<span class="hl-iface">$1</span>');
  return h;
}

function displayOutput(label, d) {
  const ts = d.timestamp ? d.timestamp.slice(0,19).replace('T',' ') : "";
  document.getElementById("cmd-lbl").textContent = `${label}  [${ts}]  ${d.success ? "✓ OK" : "✗ ERROR"}`;
  const pre = document.getElementById("out-pre");
  if (d.success) {
    const text = d.output || "(empty response)";
    const lines = text.split('\n');
    if (lines.length > 3) {
      pre.innerHTML = '<div class="line-nums">' + lines.map(l => `<div class="ln">${_highlightLine(l)}</div>`).join('') + '</div>';
    } else {
      pre.innerHTML = lines.map(l => _highlightLine(l)).join('\n');
    }
  } else {
    pre.innerHTML = `<span style="color:var(--red)">ERROR: ${escHtml(d.error)}</span>`;
  }
}

function clearOutput() {
  document.getElementById("out-pre").innerHTML = '<span style="color:var(--muted)">Output cleared</span>';
  document.getElementById("cmd-lbl").textContent = "No command run yet";
  document.getElementById("raw-cmd").value = "";
}

function clearOutput2(id) {
  document.getElementById(id).innerHTML = '<span style="color:var(--muted)">Cleared</span>';
}

function copyOutput() {
  const txt = document.getElementById("out-pre").textContent;
  navigator.clipboard.writeText(txt).then(() => {
    const btn = event.target; const orig = btn.textContent;
    btn.textContent = "✅ Copied"; setTimeout(() => btn.textContent = orig, 1500);
  });
}

function downloadOutput() {
  if (!selectedDev) return;
  const txt = document.getElementById("out-pre").textContent;
  const ts = new Date().toISOString().replace(/[:.]/g,"-").slice(0,19);
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([txt], {type:"text/plain"}));
  a.download = `${selectedDev.hostname}_${ts}.txt`; a.click();
}

// ── Active Probing (ping, traceroute, capture, etc.) ─────────────────────────
async function runProbe(type) {
  if (!selectedDev) return;
  const src    = document.getElementById("probe-src").value.trim();
  const dtype  = selectedDev.type;

  let cmd = "";
  const labels = { monitor:"📈 Monitor Interface" };
  document.getElementById("cmd-lbl").textContent = `Running ${labels[type] || type}…`;
  document.getElementById("out-pre").innerHTML = '<span class="spin"></span> Running…';

  if (dtype === "junos") {
    cmd = src ? `show interfaces ${src} extensive | no-more` : "show interfaces | match \"bps|pps|Physical\" | no-more";
  } else { // EOS
    cmd = src ? `show interfaces ${src} counters rates` : "show interfaces counters rates | head 30";
  }

  try {
    const r = await fetch(`${API}/run`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ ip: selectedDev.ip, dtype: selectedDev.type, raw: cmd }) });
    const d = await r.json();
    const ts = d.timestamp ? d.timestamp.slice(0,19).replace('T',' ') : "";
    document.getElementById("cmd-lbl").textContent = `${labels[type]} — ${cmd}  [${ts}]  ${d.success?"✓":"✗ ERROR"}`;
    document.getElementById("out-pre").textContent = d.success ? (d.output||"(empty)") : `ERROR: ${d.error}`;
    addHistory(type, cmd, d.success, selectedDev.hostname);
    lastMultiData["probe_"+type] = d.output || d.error || "";
  } catch(e) {
    document.getElementById("out-pre").innerHTML = `<span style="color:var(--red)">Fetch error: ${e}</span>`;
  }
}

// ── Port Capacity ─────────────────────────────────────────────────────────────
async function runPortCapacity() {
  if (!selectedDev) return;
  const btn = document.getElementById("btn-ports");
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Scanning ports…';
  document.getElementById("port-summary").style.display = "none";
  clearMulti("cap-out");
  try {
    const r = await fetch(`${API}/ports`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ ip: selectedDev.ip, dtype: selectedDev.type, hostname: selectedDev.hostname }) });
    const d = await r.json();
    if (d.success) {
      Object.assign(lastMultiData, d.raw || {});
      lastPortData = d;
      renderPortSummary(d);
      // Also show the raw data cards below
      if (d.raw && Object.keys(d.raw).length) {
        renderMultiOutput("cap-out", d.raw, d.timestamp);
      }
    } else {
      document.getElementById("cap-out").innerHTML = `<div style="color:var(--red);padding:14px">ERROR: ${d.error}</div>`;
    }
    addHistory("ports", "Port Capacity", d.success, selectedDev.hostname);
  } catch(e) {
    document.getElementById("cap-out").innerHTML = `<div style="color:var(--red);padding:14px">Fetch error: ${e}</div>`;
  }
  // Also fetch capacity forecasting (utilization + predictions) in the background
  btn.innerHTML = '<span class="spin"></span> Analyzing utilization…';
  try {
    const r2 = await fetch(`${API}/capacity`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ ip: selectedDev.ip, dtype: selectedDev.type, hostname: selectedDev.hostname }) });
    const d2 = await r2.json();
    if (d2.success) {
      lastCapData = d2;
      // Append utilization + forecasts below the port summary
      const capDiv = document.createElement("div");
      capDiv.id = "cap-forecast-inline";
      capDiv.style.cssText = "flex-shrink:0";
      const ps = document.getElementById("port-summary");
      if (ps && ps.style.display !== "none") ps.parentNode.insertBefore(capDiv, ps.nextSibling);
      renderCapacityInline(d2, "cap-forecast-inline");
    }
  } catch(_) { /* utilization is optional enhancement */ }
  btn.disabled = false; btn.innerHTML = "🔌 Port Capacity";
}

function renderPortSummary(d) {
  const el = document.getElementById("port-summary");
  el.style.display = "block";

  const total   = d.total    || 0;
  const up      = d.up       || 0;
  const free    = d.free     || 0;
  const dis     = d.disabled || 0;
  const optics  = d.optics_installed || 0;
  const model   = d.model    || "—";
  const platform = d.platform || "";
  const breakout = d.breakout_count || 0;
  const logical  = d.logical_ports  || 0;

  // For utilization bar: use physical slots (total) for % used
  const slotsUsed = total - free;
  const pct_used = total > 0 ? Math.round((slotsUsed / total) * 100) : 0;
  const pct_free = total > 0 ? Math.round((free / total) * 100) : 0;
  const barColor = pct_used >= 85 ? "var(--red)" : pct_used >= 65 ? "var(--yellow)" : "var(--green)";

  // By-speed breakdown table (use by_speed first, fallback to by_type)
  const bySpeed = d.by_speed || d.by_type || {};
  const speedOrder = ["100G","40G","25G","10G","1G","other","et","xe","ge"];
  const speedLabels = {"et":"100G","xe":"10G","ge":"1G"};
  const typeRows = speedOrder
    .filter(t => bySpeed[t])
    .map(t => {
      const bt = bySpeed[t];
      const speed = speedLabels[t] || t;
      const pct = bt.total > 0 ? Math.round((bt.up / bt.total) * 100) : 0;
      const col = pct >= 85 ? "var(--red)" : pct >= 65 ? "var(--yellow)" : "var(--green)";
      return `<tr>
        <td style="padding:4px 10px;font-family:Consolas,monospace;color:var(--accent)">${speed}</td>
        <td style="padding:4px 10px;text-align:right">${bt.total}</td>
        <td style="padding:4px 10px;text-align:right;color:var(--green)">${bt.up}</td>
        <td style="padding:4px 10px;text-align:right;color:var(--yellow)">${bt.down||0}</td>
        <td style="padding:4px 10px;text-align:right;color:var(--muted)">${bt.disabled||0}</td>
        <td style="padding:4px 10px;text-align:right;color:${col};font-weight:700">${pct}%</td>
      </tr>`;
    }).join('');

  // Breakout info badge
  const breakoutBadge = breakout > 0
    ? `<span style="font-size:10px;background:rgba(136,132,216,.15);color:#8884d8;padding:2px 7px;border-radius:10px;border:1px solid rgba(136,132,216,.3)">🔀 ${breakout} port${breakout!==1?'s':''} channelized → ${logical} logical</span>`
    : '';

  el.innerHTML = `
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:8px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap">
      <span style="font-size:14px;font-weight:700;font-family:Consolas,monospace">${selectedDev.hostname}</span>
      <span style="font-size:12px;color:var(--muted)">${model}</span>
      <span style="font-size:11px;color:var(--muted)">${platform}</span>
      <span style="font-size:10px;background:#1a3d1a;color:#4caf50;padding:2px 7px;border-radius:10px;border:1px solid #2a5a2a">🔌 Live SSH</span>
      ${breakoutBadge}
      <div class="spacer"></div>
      <span style="font-size:11px;color:var(--muted)">${(d.timestamp||'').slice(0,19).replace('T',' ')}</span>
    </div>

    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
      <div class="stat-card" style="flex:1;min-width:90px">
        <div class="sv" style="color:var(--text)">${total}</div>
        <div class="sl">Physical Slots</div>
      </div>
      <div class="stat-card" style="flex:1;min-width:90px">
        <div class="sv" style="color:var(--green)">${up}</div>
        <div class="sl">In Use (UP)</div>
      </div>
      <div class="stat-card" style="flex:1;min-width:90px">
        <div class="sv" style="color:var(--accent)">${free}</div>
        <div class="sl">Empty Slots</div>
      </div>
      <div class="stat-card" style="flex:1;min-width:90px">
        <div class="sv" style="color:var(--muted)">${dis}</div>
        <div class="sl">Admin Disabled</div>
      </div>
      <div class="stat-card" style="flex:1;min-width:90px">
        <div class="sv" style="color:var(--orange)">${optics}</div>
        <div class="sl">Optics Installed</div>
      </div>
    </div>

    <div style="margin-bottom:12px">
      <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--muted);margin-bottom:4px">
        <span>Port Utilization</span>
        <span style="color:${barColor};font-weight:700">${pct_used}% used · ${pct_free}% free</span>
      </div>
      <div style="background:var(--bg3);border-radius:4px;height:14px;overflow:hidden;border:1px solid var(--border)">
        <div style="height:100%;width:${pct_used}%;background:${barColor};border-radius:4px;transition:.3s"></div>
      </div>
    </div>

    ${typeRows ? `
    <div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-bottom:6px">Breakdown by Speed</div>
    <table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead>
        <tr style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px">
          <th style="padding:3px 10px;text-align:left">Speed</th>
          <th style="padding:3px 10px;text-align:right">Total</th>
          <th style="padding:3px 10px;text-align:right">Up</th>
          <th style="padding:3px 10px;text-align:right">Down</th>
          <th style="padding:3px 10px;text-align:right">Disabled</th>
          <th style="padding:3px 10px;text-align:right">Used%</th>
        </tr>
      </thead>
      <tbody>${typeRows}</tbody>
    </table>` : '<div style="color:var(--muted);font-size:12px">No port breakdown available</div>'}
  </div>`;
}

function renderCapacityInline(d, containerId) {
  const el = document.getElementById(containerId);
  if (!el) return;
  let html = '';
  // Findings
  const sevConf = { critical:{bg:"rgba(244,67,54,.1)",icon:"🔴"}, high:{bg:"rgba(248,81,73,.1)",icon:"🟠"}, medium:{bg:"rgba(255,193,7,.1)",icon:"🟡"}, low:{bg:"rgba(139,148,158,.08)",icon:"⚪"}, ok:{bg:"rgba(34,197,94,.08)",icon:"✅"} };
  if (d.findings && d.findings.length) {
    html += `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 14px;margin-top:8px">
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-bottom:6px">📋 Findings</div>`;
    d.findings.forEach(f => {
      const s = sevConf[f.severity] || sevConf.ok;
      html += `<div style="background:${s.bg};border:1px solid var(--border);border-radius:5px;padding:6px 10px;margin:3px 0;display:flex;align-items:center;gap:8px;font-size:12px">
        <span>${s.icon}</span><span style="font-weight:600;flex:1">${escHtml(f.title)}</span><span style="color:var(--muted);font-size:11px">${escHtml(f.detail)}</span>
      </div>`;
    });
    html += `</div>`;
  }
  // Top port utilization bars
  const util = d.utilization_top20 || [];
  if (util.length > 0) {
    html += `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 14px;margin-top:8px">
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-bottom:6px">📈 Top Port Utilization</div>`;
    util.forEach(p => {
      const pct = p.max_pct;
      const bc = pct > 90 ? "#ef4444" : pct > 80 ? "#f97316" : pct > 70 ? "#eab308" : pct > 50 ? "#06b6d4" : "#22c55e";
      html += `<div style="display:flex;align-items:center;gap:8px;margin:2px 0;font-size:11px">
        <span style="width:110px;font-family:Consolas,monospace;flex-shrink:0">${escHtml(p.port)}</span>
        <div style="flex:1;height:14px;background:var(--bg3);border-radius:3px;overflow:hidden;position:relative">
          <div style="width:${Math.min(pct,100)}%;height:100%;background:${bc};border-radius:3px;opacity:0.7"></div>
          <span style="position:absolute;left:4px;top:0;font-size:9px;font-weight:700;color:#fff;text-shadow:0 0 2px #000">${pct}%</span>
        </div>
        <span style="width:90px;text-align:right;color:var(--muted);font-size:10px">IN:${p.in_pct}% OUT:${p.out_pct}%</span>
      </div>`;
    });
    html += `</div>`;
  }
  el.innerHTML = html;
}

function clearCapacity() {
  document.getElementById("port-summary").style.display = "none";
  document.getElementById("forecast-summary").style.display = "none";
  const inlineForecast = document.getElementById("cap-forecast-inline");
  if (inlineForecast) inlineForecast.remove();
  clearMulti("cap-out");
}

// ── Snapshot ──────────────────────────────────────────────────────────────────
async function runSnapshot() {
  if (!selectedDev) return;
  const btn = document.getElementById("btn-snap");
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Collecting…';
  clearMulti("collect-out");
  try {
    const r = await fetch(`${API}/snapshot`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ ip: selectedDev.ip, dtype: selectedDev.type }) });
    const d = await r.json();
    if (d.success) {
      Object.assign(lastMultiData, d.results);
      renderMultiOutput("collect-out", d.results, d.timestamp);
    } else {
      document.getElementById("collect-out").innerHTML = `<div style="color:var(--red);padding:14px">ERROR: ${d.error}</div>`;
    }
    addHistory("snapshot", "Full Snapshot", d.success, selectedDev.hostname);
  } catch(e) {
    document.getElementById("collect-out").innerHTML = `<div style="color:var(--red);padding:14px">Fetch error: ${e}</div>`;
  }
  btn.disabled = false; btn.innerHTML = "⚡ Quick Snapshot";
}

// ── Incident ──────────────────────────────────────────────────────────────────
async function runIncident() {
  if (!selectedDev) return;
  const btn = document.getElementById("btn-inc");
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Investigating…';
  clearMulti("collect-out");
  try {
    const r = await fetch(`${API}/incident`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ ip: selectedDev.ip, dtype: selectedDev.type }) });
    const d = await r.json();
    if (d.success) {
      let results = d.results;
      const grepFilter = document.getElementById("log-filter").value.trim().toLowerCase();
      if (grepFilter) {
        const filtered = {};
        Object.entries(results).forEach(([k, v]) => {
          if (k.includes("log")) {
            const lines = v.split('\n').filter(l => l.toLowerCase().includes(grepFilter));
            filtered[k] = lines.join('\n') || "(no matches for filter)";
          } else {
            filtered[k] = v;
          }
        });
        results = filtered;
      }
      Object.assign(lastMultiData, results);
      renderMultiOutput("collect-out", results, d.timestamp);
    } else {
      document.getElementById("collect-out").innerHTML = `<div style="color:var(--red);padding:14px">ERROR: ${d.error}</div>`;
    }
    addHistory("incident", "Incident Investigation", d.success, selectedDev.hostname);
  } catch(e) {
    document.getElementById("collect-out").innerHTML = `<div style="color:var(--red);padding:14px">Fetch error: ${e}</div>`;
  }
  btn.disabled = false; btn.innerHTML = "🚨 Full Investigation";
}

// ── Render Multi-Output Cards ─────────────────────────────────────────────────
function renderMultiOutput(containerId, results, timestamp) {
  const el = document.getElementById(containerId);
  const ts = timestamp ? timestamp.slice(0,19).replace('T',' ') : "";
  el.innerHTML = `<div style="font-size:11px;color:var(--muted);padding:2px 0">Collected at ${ts} — click cards to expand/collapse</div>` +
    Object.entries(results).map(([k, v]) => {
      const hasError = typeof v === "string" && v.toUpperCase().startsWith("ERROR");
      const isEmpty = !v || v.trim() === "";
      const lines = typeof v === "string" ? v.split('\n').length : 0;
      const icon = hasError ? '<span class="err-ic">✗</span>' : '<span class="ok-ic">✓</span>';
      const meta = hasError ? '<span style="color:var(--red)">ERROR</span>' : `<span style="color:var(--muted)">${lines} lines</span>`;

      // Special rendering for MTU — parse into a clean table
      let bodyHtml;
      if (k === "mtu" && typeof v === "string" && !hasError && !isEmpty) {
        bodyHtml = parseMtuTable(v, selectedDev ? selectedDev.type : "junos");
      } else {
        bodyHtml = `<pre style="margin:0;white-space:pre-wrap;word-break:break-all">${escHtml(isEmpty ? "(empty)" : (typeof v === "string" ? v : JSON.stringify(v,null,2)))}</pre>`;
      }

      return `<div class="ocard" id="oc-${k}">
        <div class="ocard-hdr" onclick="toggleCard('oc-${k}')">
          ${icon}
          <span style="font-weight:600;min-width:140px">${k}</span>
          ${meta}
          <span style="color:var(--muted);margin-left:auto;font-size:10px">▼</span>
        </div>
        <div class="ocard-body">${bodyHtml}</div>
      </div>`;
    }).join('');
}

function parseMtuTable(raw, dtype) {
  const entries = [];
  let currentIface = null;

  for (const line of raw.split('\n')) {
    const s = line.trim();
    if (!s) continue;

    if (dtype === "junos") {
      // Junos: "Physical interface: xe-0/0/0, ..." then "  Link-level ... MTU: 9192 ..."
      const mPhys = s.match(/^Physical interface:\s+(\S+)/);
      if (mPhys) { currentIface = mPhys[1].replace(/,$/, ''); continue; }
      if (currentIface) {
        const mMtu = s.match(/MTU:\s*(\d+)/);
        if (mMtu) { entries.push({ iface: currentIface, mtu: parseInt(mMtu[1]) }); currentIface = null; }
      }
    } else {
      // EOS: "Ethernet1 ... MTU 9214 ..."
      const mEos = s.match(/^(Ethernet\S+|Et\S+|Vlan\S+|Port-Channel\S+).*MTU\s+(\d+)/i);
      if (mEos) { entries.push({ iface: mEos[1], mtu: parseInt(mEos[2]) }); }
    }
  }

  if (!entries.length) return `<pre style="margin:0;white-space:pre-wrap">${escHtml(raw)}</pre>`;

  // Compute stats
  const mtuCounts = {};
  entries.forEach(e => { mtuCounts[e.mtu] = (mtuCounts[e.mtu] || 0) + 1; });
  const uniqueMtus = Object.keys(mtuCounts).length;
  const mismatch = uniqueMtus > 1;
  const summaryParts = Object.entries(mtuCounts).sort((a,b) => b[1]-a[1]).map(([m, c]) => {
    const col = parseInt(m) >= 9000 ? "var(--green)" : parseInt(m) <= 1500 ? "var(--red)" : "var(--yellow)";
    return `<span style="color:${col};font-weight:600">${m}</span> <span style="color:var(--muted)">(${c} ports)</span>`;
  });

  // Build table rows
  const rows = entries.map(e => {
    const col = e.mtu >= 9000 ? "var(--green)" : e.mtu <= 1500 ? "var(--red)" : "var(--yellow)";
    const badge = e.mtu >= 9000 ? "JUMBO" : e.mtu <= 1500 ? "DEFAULT" : "NON-STD";
    const badgeBg = e.mtu >= 9000 ? "rgba(76,175,80,.15)" : e.mtu <= 1500 ? "rgba(244,67,54,.15)" : "rgba(255,193,7,.15)";
    return `<tr>
      <td style="padding:3px 10px;font-family:Consolas,monospace;color:var(--accent)">${escHtml(e.iface)}</td>
      <td style="padding:3px 10px;text-align:right;color:${col};font-weight:700">${e.mtu}</td>
      <td style="padding:3px 10px;text-align:center"><span style="font-size:9px;padding:1px 6px;border-radius:8px;background:${badgeBg};color:${col}">${badge}</span></td>
    </tr>`;
  }).join('');

  return `
    <div style="margin-bottom:10px;display:flex;align-items:center;gap:12px;flex-wrap:wrap">
      <span style="font-size:12px;font-weight:700">${entries.length} interfaces</span>
      ${mismatch ? '<span style="font-size:10px;background:rgba(255,193,7,.15);color:var(--yellow);padding:2px 8px;border-radius:10px;border:1px solid rgba(255,193,7,.3)">⚠️ Mixed MTU</span>' : '<span style="font-size:10px;background:rgba(76,175,80,.15);color:var(--green);padding:2px 8px;border-radius:10px;border:1px solid rgba(76,175,80,.3)">✓ Consistent</span>'}
      <span style="font-size:11px">${summaryParts.join(' · ')}</span>
    </div>
    <div style="max-height:400px;overflow-y:auto">
    <table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead>
        <tr style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;background:var(--bg2)">
          <th style="padding:3px 10px;text-align:left">Interface</th>
          <th style="padding:3px 10px;text-align:right">MTU</th>
          <th style="padding:3px 10px;text-align:center">Status</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
    </div>`;
}

function toggleCard(id) {
  document.getElementById(id).classList.toggle("col");
}

function clearMulti(id) {
  document.getElementById(id).innerHTML = '<div style="color:var(--muted);text-align:center;padding:30px;font-size:12px">Cleared</div>';
}

function escHtml(s) {
  return String(s == null ? '' : s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

// ── Analysis ──────────────────────────────────────────────────────────────────
async function analyzeLastData() {
  if (!selectedDev || !Object.keys(lastMultiData).length) {
    document.getElementById("ana-panel").innerHTML = '<div style="color:var(--yellow);padding:14px;font-size:12px">⚠️ No data to analyze — run Snapshot, Capacity, or Incident first</div>';
    switchTabById("analysis");
    return;
  }
  const btn = event ? event.target : null;
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Analyzing…'; }
  try {
    const r = await fetch(`${API}/analyze`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ hostname: selectedDev.hostname, dtype: selectedDev.type, data: lastMultiData }) });
    const d = await r.json();
    renderAnalysis(d);
    switchTabById("analysis");
  } catch(e) {
    document.getElementById("ana-panel").innerHTML = `<div style="color:var(--red);padding:14px">Analysis error: ${e}</div>`;
  }
  if (btn) { btn.disabled = false; btn.innerHTML = btn.id === "btn-ana" ? "📸🤖 Snapshot + Analyze" : "🤖 Analyze Last Data"; }
}

// ── IP Analysis (Subnet Exhaustion) ───────────────────────────────────────────
let lastSubnetData = null;

async function runSubnetAnalysis() {
  if (!selectedDev) { alert("Select a device first"); return; }
  const btn = document.getElementById("btn-subnet");
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Analyzing…';
  const summEl = document.getElementById("ipa-summary");
  const outEl = document.getElementById("ipa-output");
  summEl.style.display = "none";
  outEl.style.display = "block";
  outEl.innerHTML = `<div style="text-align:center;padding:60px;color:var(--muted)"><span class="spin"></span> Collecting ARP, interfaces, and MAC table from <b style="color:var(--text)">${escHtml(selectedDev.hostname)}</b>…</div>`;

  try {
    const r = await fetch(`${API}/subnet-analysis`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ ip: selectedDev.ip, dtype: selectedDev.type, hostname: selectedDev.hostname })
    });
    const d = await r.json();
    console.log("subnet-analysis response:", JSON.stringify(d.summary), "subnets:", d.subnets?.length);
    if (d.success) {
      lastSubnetData = d;
      renderSubnetAnalysis(d);
      addHistory("ipanalysis", `IP Analysis ${selectedDev.hostname}`, true, selectedDev.hostname);
    } else {
      summEl.style.display = "none";
      outEl.innerHTML = `<div style="color:var(--red);padding:20px">⚠️ ${escHtml(d.error || "Unknown error")}</div>`;
      addHistory("ipanalysis", `IP Analysis ${selectedDev.hostname}`, false, selectedDev.hostname);
    }
  } catch(e) {
    outEl.innerHTML = `<div style="color:var(--red);padding:20px">Error: ${e}</div>`;
  }
  btn.disabled = false;
  btn.innerHTML = "🔍 Device Subnets";
}

function renderSubnetAnalysis(d) {
  const s = d.summary;
  const summEl = document.getElementById("ipa-summary");
  const outEl = document.getElementById("ipa-output");

  // Summary cards
  const statusColor = s.overall_utilization >= 75 ? "var(--red)" : s.overall_utilization >= 50 ? "#f59e0b" : "var(--green)";
  const macOnly = s.mac_only_devices || 0;
  summEl.style.display = "flex";
  summEl.innerHTML = `
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 16px;min-width:110px;text-align:center">
        <div style="font-size:22px;font-weight:800;color:var(--text)">${s.total_subnets}</div>
        <div style="font-size:10px;color:var(--muted)">Subnets</div>
      </div>
      <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 16px;min-width:110px;text-align:center">
        <div style="font-size:22px;font-weight:800;color:var(--text)">${s.total_ips}</div>
        <div style="font-size:10px;color:var(--muted)">Total IPs</div>
      </div>
      <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 16px;min-width:110px;text-align:center">
        <div style="font-size:22px;font-weight:800;color:var(--green)">${s.active_hosts}</div>
        <div style="font-size:10px;color:var(--muted)">ARP Hosts</div>
      </div>
      <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 16px;min-width:110px;text-align:center">
        <div style="font-size:22px;font-weight:800;color:#3b82f6">${s.free_ips}</div>
        <div style="font-size:10px;color:var(--muted)">Free IPs</div>
      </div>
      <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 16px;min-width:110px;text-align:center">
        <div style="font-size:22px;font-weight:800;color:${statusColor}">${s.overall_utilization}%</div>
        <div style="font-size:10px;color:var(--muted)">Overall Usage</div>
      </div>
      ${s.critical_subnets ? `<div style="background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.3);border-radius:8px;padding:10px 16px;min-width:110px;text-align:center">
        <div style="font-size:22px;font-weight:800;color:var(--red)">${s.critical_subnets}</div>
        <div style="font-size:10px;color:var(--red)">Critical</div>
      </div>` : ""}
      ${s.warning_subnets ? `<div style="background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.3);border-radius:8px;padding:10px 16px;min-width:110px;text-align:center">
        <div style="font-size:22px;font-weight:800;color:#f59e0b">${s.warning_subnets}</div>
        <div style="font-size:10px;color:#f59e0b">Warning</div>
      </div>` : ""}
      <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 16px;min-width:110px;text-align:center">
        <div style="font-size:22px;font-weight:800;color:var(--muted)">${s.mac_entries}</div>
        <div style="font-size:10px;color:var(--muted)">MAC Table</div>
      </div>
      ${macOnly > 0 ? `<div style="background:rgba(168,85,247,.1);border:1px solid rgba(168,85,247,.3);border-radius:8px;padding:10px 16px;min-width:110px;text-align:center">
        <div style="font-size:22px;font-weight:800;color:#a855f7">${macOnly}</div>
        <div style="font-size:10px;color:#a855f7">L2-Only</div>
      </div>` : ""}
    </div>
    <div style="font-size:9px;color:var(--muted);margin-top:6px">Sources: <b>ARP table</b> (L3 active hosts) · <b>MAC table</b> (L2 devices) · <b>Interface descriptions</b> — click rows to expand host list</div>`;

  // Subnet table
  if (!d.subnets || d.subnets.length === 0) {
    outEl.innerHTML = `<div style="color:var(--muted);text-align:center;padding:40px">No subnets found on this device (might be an L2 switch with no IP interfaces)</div>`;
    return;
  }

  const statusIcon = {"critical":"🔴","warning":"🟡","moderate":"🟠","healthy":"🟢"};
  const barColors = {"critical":"#f87171","warning":"#fbbf24","moderate":"#fb923c","healthy":"#4ade80"};

  let html = `<table style="width:100%;border-collapse:collapse;font-size:11px">
    <thead><tr style="border-bottom:1px solid var(--border);color:var(--muted);text-align:left">
      <th style="padding:6px 8px">Status</th>
      <th style="padding:6px 8px">Subnet</th>
      <th style="padding:6px 8px">Interface</th>
      <th style="padding:6px 8px">Description</th>
      <th style="padding:6px 8px;text-align:right">Total</th>
      <th style="padding:6px 8px;text-align:right">ARP</th>
      <th style="padding:6px 8px;text-align:right" title="L2-only devices (MAC but no ARP entry)">L2</th>
      <th style="padding:6px 8px;text-align:right">Free</th>
      <th style="padding:6px 8px;min-width:140px">Utilization</th>
    </tr></thead><tbody>`;

  d.subnets.forEach((sn, idx) => {
    const icon = statusIcon[sn.status] || "⚪";
    const barColor = barColors[sn.status] || "#4ade80";
    const pct = sn.utilization_pct;
    const rowId = `ipa-row-${idx}`;
    const desc = sn.description || "";
    const macOnly = sn.mac_only || 0;

    html += `<tr style="border-bottom:1px solid var(--border);cursor:pointer" onclick="document.getElementById('${rowId}').style.display=document.getElementById('${rowId}').style.display==='none'?'table-row':'none'" title="Click to expand host list">
      <td style="padding:6px 8px">${icon}</td>
      <td style="padding:6px 8px;font-family:Consolas,monospace;font-weight:700;color:var(--text)">${escHtml(sn.subnet)}</td>
      <td style="padding:6px 8px;font-family:Consolas,monospace;color:var(--muted);font-size:10px">${escHtml(sn.interface)}<br><span style="color:var(--muted);font-size:9px">${escHtml(sn.gateway)}</span></td>
      <td style="padding:6px 8px;color:${desc ? '#8b5cf6' : 'var(--muted)'};font-size:10px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(desc)}">${escHtml(desc || "—")}</td>
      <td style="padding:6px 8px;text-align:right;color:var(--text)">${sn.total_ips}</td>
      <td style="padding:6px 8px;text-align:right;color:var(--green);font-weight:700">${sn.active_hosts}</td>
      <td style="padding:6px 8px;text-align:right;color:${macOnly > 0 ? '#a855f7' : 'var(--muted)'}">${macOnly > 0 ? macOnly : '—'}</td>
      <td style="padding:6px 8px;text-align:right;color:#3b82f6">${sn.free_ips}</td>
      <td style="padding:6px 8px">
        <div style="display:flex;align-items:center;gap:6px">
          <div style="flex:1;background:var(--bg3);border-radius:4px;height:14px;overflow:hidden;position:relative">
            <div style="width:${pct}%;height:100%;background:${barColor};border-radius:4px;transition:width 0.5s"></div>
          </div>
          <span style="font-weight:700;font-size:11px;color:${barColor};min-width:36px;text-align:right">${pct}%</span>
        </div>
      </td>
    </tr>`;

    // Expandable host detail row
    const hostRows = sn.hosts.map(h =>
      `<tr style="border-bottom:1px solid var(--bg3)">
        <td style="padding:3px 8px;font-family:Consolas,monospace;color:var(--text)">${escHtml(h.ip)}</td>
        <td style="padding:3px 8px;font-family:Consolas,monospace;color:var(--muted)">${escHtml(h.mac)}</td>
        <td style="padding:3px 8px;color:${h.name ? 'var(--text)' : 'var(--muted)'}">${escHtml(h.name || "—")}</td>
        <td style="padding:3px 8px;font-size:9px;color:var(--muted)">${escHtml(h.source || "arp")}</td>
      </tr>`
    ).join("");

    html += `<tr id="${rowId}" style="display:none">
      <td colspan="9" style="padding:0 8px 8px 28px;background:var(--bg2)">
        <div style="font-size:10px;color:var(--muted);margin:6px 0 4px">
          Active hosts in <b>${escHtml(sn.subnet)}</b> (${sn.active_hosts} ARP${macOnly > 0 ? ` + ${macOnly} L2-only` : ''} of ${sn.total_ips} total)
          ${sn.vlan ? ` · VLAN: <b>${escHtml(sn.vlan)}</b>` : ''}
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:10px">
          <thead><tr style="color:var(--muted)">
            <th style="padding:3px 8px;text-align:left">IP</th>
            <th style="padding:3px 8px;text-align:left">MAC</th>
            <th style="padding:3px 8px;text-align:left">Hostname</th>
            <th style="padding:3px 8px;text-align:left">Source</th>
          </tr></thead>
          <tbody>${hostRows || '<tr><td colspan="4" style="color:var(--muted);padding:8px">No ARP entries in this subnet</td></tr>'}</tbody>
        </table>
      </td>
    </tr>`;
  });

  html += `</tbody></table>`;
  outEl.innerHTML = html;
}

function exportSubnetAnalysis(format) {
  if (!lastSubnetData || !lastSubnetData.subnets) { alert("Run IP Analysis first"); return; }
  const d = lastSubnetData;
  const hostname = d.hostname || "unknown";
  const ts_str = new Date().toISOString().slice(0,10);

  if (format === "csv") {
    let csv = "Subnet,Interface,Description,Gateway,Prefix,Total IPs,ARP Hosts,L2-Only,Free IPs,Utilization %,Status,VLAN\n";
    d.subnets.forEach(sn => {
      csv += `${sn.subnet},${sn.interface},"${sn.description || ""}",${sn.gateway},/${sn.prefix},${sn.total_ips},${sn.active_hosts},${sn.mac_only || 0},${sn.free_ips},${sn.utilization_pct},${sn.status},${sn.vlan || ""}\n`;
    });
    csv += "\nHost Detail\nSubnet,IP,MAC,Hostname,Source\n";
    d.subnets.forEach(sn => {
      sn.hosts.forEach(h => {
        csv += `${sn.subnet},${h.ip},${h.mac},${h.name || ""},${h.source || "arp"}\n`;
      });
    });
    downloadFile(csv, `ip_analysis_${hostname}_${ts_str}.csv`, "text/csv");
  } else {
    const s = d.summary;
    let md = `# IP Exhaustion Analysis — ${hostname}\n`;
    md += `**Date:** ${d.timestamp || ts_str}\n\n`;
    md += `## Summary\n`;
    md += `| Metric | Value |\n|--------|-------|\n`;
    md += `| Subnets | ${s.total_subnets} |\n`;
    md += `| Total IPs | ${s.total_ips} |\n`;
    md += `| ARP Hosts (L3) | ${s.active_hosts} |\n`;
    md += `| L2-Only Devices | ${s.mac_only_devices || 0} |\n`;
    md += `| Free IPs | ${s.free_ips} |\n`;
    md += `| Overall Utilization | ${s.overall_utilization}% |\n`;
    md += `| Critical Subnets | ${s.critical_subnets} |\n`;
    md += `| Warning Subnets | ${s.warning_subnets} |\n`;
    md += `| MAC Table Entries | ${s.mac_entries} |\n\n`;
    md += `> **Data sources:** ARP table (L3 active hosts), MAC address table (L2 devices), Interface descriptions\n\n`;
    md += `## Subnets\n\n`;
    md += `| Status | Subnet | Interface | Description | Total | ARP | L2 | Free | Usage |\n`;
    md += `|--------|--------|-----------|-------------|-------|-----|-----|------|-------|\n`;
    d.subnets.forEach(sn => {
      const icon = {"critical":"🔴","warning":"🟡","moderate":"🟠","healthy":"🟢"}[sn.status] || "⚪";
      md += `| ${icon} ${sn.status} | ${sn.subnet} | ${sn.interface} | ${sn.description || "—"} | ${sn.total_ips} | ${sn.active_hosts} | ${sn.mac_only || 0} | ${sn.free_ips} | ${sn.utilization_pct}% |\n`;
    });
    md += `\n## Host Detail\n\n`;
    d.subnets.forEach(sn => {
      if (sn.hosts.length === 0) return;
      md += `### ${sn.subnet} (${sn.interface}) — ${sn.description || "no description"}\n`;
      md += `**${sn.active_hosts} ARP hosts${sn.mac_only ? ` + ${sn.mac_only} L2-only` : ""} / ${sn.total_ips} total IPs**${sn.vlan ? ` · VLAN: ${sn.vlan}` : ""}\n\n`;
      md += `| IP | MAC | Hostname | Source |\n|-----|-----|----------|--------|\n`;
      sn.hosts.forEach(h => {
        md += `| ${h.ip} | ${h.mac} | ${h.name || "—"} | ${h.source || "arp"} |\n`;
      });
      md += `\n`;
    });
    downloadFile(md, `ip_analysis_${hostname}_${ts_str}.md`, "text/markdown");
  }
}

// ── ISP Links Health Check (Network-Wide) ─────────────────────────────────────
let lastIPExhData = null;
function _hideAllReportPanels() {
  document.getElementById("rpt-isp").style.display = "none";
  document.getElementById("rpt-bgp").style.display = "none";
  document.getElementById("rpt-ip").style.display = "none";
  document.getElementById("ipa-summary").style.display = "none";
  document.getElementById("ipa-output").style.display = "none";
  document.getElementById("rpt-netportal").style.display = "none";
  document.getElementById("rpt-out").style.display = "none";
}

async function runISPLinks() {
  _hideAllReportPanels();
  const btn = document.getElementById("btn-isp");
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Scanning all ISP links…';
  try {
    const r = await fetch(`${API}/isp-links`);
    const d = await r.json();
    if (d.success === false) {
      document.getElementById("rpt-isp").style.display = "block";
      document.getElementById("rpt-isp").innerHTML = `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:8px;color:var(--red)">⚠️ ISP check failed: ${d.error || 'Unknown error'}</div>`;
    } else {
      renderISPLinks(d);
    }
    if (d.success !== false) lastISPData = d;
    addHistory("isp-links", "ISP Links Check", d.success !== false, "ALL");
  } catch(e) {
    document.getElementById("rpt-isp").style.display = "block";
    document.getElementById("rpt-isp").innerHTML = `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:8px;color:var(--red)">Fetch error: ${e}</div>`;
  }
  btn.disabled = false; btn.innerHTML = "🌐 ISP Links (Live)";
}

function renderISPLinks(d) {
  const el = document.getElementById("rpt-isp");
  el.style.display = "block";

  const s = d.summary || {};
  const links = d.links || [];
  const sites = d.sites || [];
  const growth = d.monthly_growth_pct || 5;

  // Risk color helpers
  const riskCol = r => r==="down"?"var(--red)":r==="critical"?"var(--red)":r==="warning"?"var(--orange)":r==="watch"?"var(--yellow)":"var(--green)";
  const riskIcon = r => r==="down"?"⬛":r==="critical"?"🔴":r==="warning"?"🟠":r==="watch"?"🟡":"✅";
  const riskLabel = r => r==="down"?"DOWN":r==="critical"?"CRITICAL":r==="warning"?"WARNING":r==="watch"?"WATCH":"OK";

  // Summary badges
  const badges = [];
  if (s.links_down > 0) badges.push(`<span style="font-size:10px;background:rgba(244,67,54,.15);color:var(--red);padding:2px 8px;border-radius:10px;border:1px solid rgba(244,67,54,.3);font-weight:700">⬛ ${s.links_down} DOWN</span>`);
  if (s.critical_6mo > 0) badges.push(`<span style="font-size:10px;background:rgba(244,67,54,.15);color:var(--red);padding:2px 8px;border-radius:10px;border:1px solid rgba(244,67,54,.3);font-weight:700">🔴 ${s.critical_6mo} CRITICAL</span>`);
  if (s.warning_6mo > 0) badges.push(`<span style="font-size:10px;background:rgba(255,152,0,.15);color:var(--orange);padding:2px 8px;border-radius:10px;border:1px solid rgba(255,152,0,.3);font-weight:700">🟠 ${s.warning_6mo} WARNING</span>`);
  if (s.watch > 0) badges.push(`<span style="font-size:10px;background:rgba(255,193,7,.15);color:var(--yellow);padding:2px 8px;border-radius:10px;border:1px solid rgba(255,193,7,.3);font-weight:700">🟡 ${s.watch} WATCH</span>`);
  if (!s.links_down && !s.critical_6mo && !s.warning_6mo) badges.push(`<span style="font-size:10px;background:rgba(76,175,80,.15);color:var(--green);padding:2px 8px;border-radius:10px;border:1px solid rgba(76,175,80,.3);font-weight:700">✅ ALL ISP LINKS HEALTHY</span>`);

  // Site summary rows
  const siteRows = sites.map(st => {
    const worst = st.down > 0 ? "var(--red)" : st.critical > 0 ? "var(--red)" : st.warning > 0 ? "var(--orange)" : "var(--green)";
    return `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:3px 8px;font-weight:700;color:var(--accent);font-size:11px">${escHtml(st.site)}</td>
      <td style="padding:3px 8px;text-align:center;font-size:11px">${st.links}</td>
      <td style="padding:3px 8px;text-align:center;font-size:11px;color:${st.down?'var(--red)':'var(--muted)'}">${st.down||'—'}</td>
      <td style="padding:3px 8px;text-align:center;font-size:11px;color:${st.critical?'var(--red)':'var(--muted)'}">${st.critical||'—'}</td>
      <td style="padding:3px 8px;text-align:center;font-size:11px;color:${st.warning?'var(--orange)':'var(--muted)'}">${st.warning||'—'}</td>
      <td style="padding:3px 8px;text-align:right;font-size:11px;color:${worst}">${st.avg_util}%</td>
    </tr>`;
  }).join('');

  // ISP link rows
  const linkRows = links.map(l => {
    const rc = riskCol(l.risk);
    const ri = riskIcon(l.risk);
    const rl = riskLabel(l.risk);
    const barW = Math.min(l.current_util_pct, 100);
    const barCol = l.current_util_pct >= 80 ? "var(--red)" : l.current_util_pct >= 60 ? "var(--yellow)" : "var(--green)";
    const bar6W = Math.min(l.projected_6mo_util_pct, 100);
    const bar6Col = l.projected_6mo_util_pct >= 100 ? "var(--red)" : l.projected_6mo_util_pct >= 80 ? "var(--orange)" : l.projected_6mo_util_pct >= 60 ? "var(--yellow)" : "var(--green)";
    const totalErr = (l.in_errors||0) + (l.out_errors||0);
    const errCol = totalErr > 1000 ? "var(--red)" : totalErr > 0 ? "var(--yellow)" : "var(--muted)";
    const errBadge = totalErr > 0 ? `<span style="font-size:9px;color:${errCol}" title="In: ${l.in_errors}\nOut: ${l.out_errors}\n(cumulative counters)">⚠ ${totalErr > 999999 ? (totalErr/1e6).toFixed(1)+'M' : totalErr > 999 ? (totalErr/1e3).toFixed(1)+'K' : totalErr}</span>` : '';

    return `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:4px 6px;font-size:11px;font-weight:600;color:var(--accent)">${escHtml(l.site)}</td>
      <td style="padding:4px 6px;font-size:11px;font-family:Consolas,monospace;color:var(--text)">${escHtml(l.hostname)}</td>
      <td style="padding:4px 6px;font-size:11px;font-family:Consolas,monospace;color:var(--muted)">${escHtml(l.ifName)}</td>
      <td style="padding:4px 6px;font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(l.description)}">${escHtml(l.description)}</td>
      <td style="padding:4px 6px;text-align:right;font-size:11px">${l.speed_gbps}G</td>
      <td style="padding:4px 6px;text-align:right;font-size:10px;font-family:Consolas,monospace">${l.in_mbps}M</td>
      <td style="padding:4px 6px;text-align:right;font-size:10px;font-family:Consolas,monospace">${l.out_mbps}M</td>
      <td style="padding:4px 4px;width:70px">
        <div style="display:flex;align-items:center;gap:3px">
          <div style="flex:1;background:var(--bg3);border-radius:3px;height:7px;overflow:hidden"><div style="height:100%;width:${barW}%;background:${barCol};border-radius:3px"></div></div>
          <span style="font-size:9px;color:${barCol};font-weight:700;min-width:28px;text-align:right">${l.current_util_pct}%</span>
        </div>
      </td>
      <td style="padding:4px 4px;width:70px">
        <div style="display:flex;align-items:center;gap:3px">
          <div style="flex:1;background:var(--bg3);border-radius:3px;height:7px;overflow:hidden"><div style="height:100%;width:${bar6W}%;background:${bar6Col};border-radius:3px"></div></div>
          <span style="font-size:9px;color:${bar6Col};font-weight:700;min-width:28px;text-align:right">${l.projected_6mo_util_pct}%</span>
        </div>
      </td>
      <td style="padding:4px 6px;text-align:center;font-size:10px;color:${rc};font-weight:700">${ri} ${rl}</td>
      <td style="padding:4px 6px;text-align:center;font-size:10px">${errBadge}</td>
    </tr>`;
  }).join('');

  el.innerHTML = `
  <div style="background:var(--bg2);border:1px solid #10b981;border-radius:8px;padding:14px;margin-bottom:8px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap">
      <span style="font-size:14px;font-weight:700;font-family:Consolas,monospace;color:#10b981">🌐 ISP Links (Live) — All Sites</span>
      <span style="font-size:9px;background:rgba(16,185,129,.1);color:var(--muted);padding:2px 6px;border-radius:8px">Source: LibreNMS · real-time 5-min poll</span>
      <span style="font-size:10px;background:rgba(16,185,129,.15);color:#10b981;padding:2px 7px;border-radius:10px;border:1px solid rgba(16,185,129,.3)">3 regions · ${s.devices_scanned||0} devices scanned</span>
      <span style="font-size:10px;background:rgba(16,185,129,.1);color:var(--muted);padding:2px 7px;border-radius:10px">${growth}%/mo growth · 6-month projection</span>
      ${badges.join(' ')}
    </div>

    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
      <div class="stat-card" style="flex:1;min-width:80px">
        <div class="sv" style="color:var(--text)">${s.total_isp_links||0}</div>
        <div class="sl">Total ISP Links</div>
      </div>
      <div class="stat-card" style="flex:1;min-width:80px">
        <div class="sv" style="color:var(--green)">${s.links_up||0}</div>
        <div class="sl">Links Up</div>
      </div>
      <div class="stat-card" style="flex:1;min-width:80px">
        <div class="sv" style="color:${s.links_down?'var(--red)':'var(--muted)'}">${s.links_down||0}</div>
        <div class="sl">Links Down</div>
      </div>
      <div class="stat-card" style="flex:1;min-width:80px">
        <div class="sv" style="color:var(--accent)">${s.total_capacity_gbps||0} Gbps</div>
        <div class="sl">Total Capacity</div>
      </div>
      <div class="stat-card" style="flex:1;min-width:80px">
        <div class="sv" style="color:var(--text)">${s.total_used_gbps||0} Gbps</div>
        <div class="sl">Total Used</div>
      </div>
      <div class="stat-card" style="flex:1;min-width:80px">
        <div class="sv" style="color:${s.avg_utilization_pct>=60?'var(--yellow)':s.avg_utilization_pct>=80?'var(--red)':'var(--green)'}">${s.avg_utilization_pct||0}%</div>
        <div class="sl">Avg Utilization</div>
      </div>
    </div>

    ${d.llm_narrative ? `<div style="margin:10px 0;padding:10px 14px;background:rgba(88,166,255,0.08);border-left:3px solid #58a6ff;border-radius:4px;">
      <div style="font-size:10px;color:#58a6ff;font-weight:600;letter-spacing:0.08em;margin-bottom:6px;">🤖 LLM ISP ANALYSIS (Docker Model Runner)</div>
      ${d.llm_narrative.split("\\n").filter(l=>l.trim()).map(l=>`<div style="font-size:12px;color:var(--muted);line-height:1.6;margin-bottom:2px;">${escHtml(l)}</div>`).join("")}
    </div>` : ''}

    <div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-bottom:6px">Site Summary</div>
    <div style="max-height:200px;overflow-y:auto;margin-bottom:14px">
    <table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead>
        <tr style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;background:var(--bg2)">
          <th style="padding:3px 8px;text-align:left">Site</th>
          <th style="padding:3px 8px;text-align:center">Links</th>
          <th style="padding:3px 8px;text-align:center">Down</th>
          <th style="padding:3px 8px;text-align:center">Critical</th>
          <th style="padding:3px 8px;text-align:center">Warning</th>
          <th style="padding:3px 8px;text-align:right">Avg Util</th>
        </tr>
      </thead>
      <tbody>${siteRows}</tbody>
    </table>
    </div>

    <div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-bottom:6px">All ISP Links (${links.length} total)</div>
    <div style="max-height:600px;overflow-y:auto">
    <table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead>
        <tr style="color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;background:var(--bg2)">
          <th style="padding:3px 6px;text-align:left">Site</th>
          <th style="padding:3px 6px;text-align:left">Device</th>
          <th style="padding:3px 6px;text-align:left">Port</th>
          <th style="padding:3px 6px;text-align:left">Description</th>
          <th style="padding:3px 6px;text-align:right">Speed</th>
          <th style="padding:3px 6px;text-align:right">In</th>
          <th style="padding:3px 6px;text-align:right">Out</th>
          <th style="padding:3px 4px;text-align:left">Now</th>
          <th style="padding:3px 4px;text-align:left">6-Mo</th>
          <th style="padding:3px 6px;text-align:center">Risk</th>
          <th style="padding:3px 6px;text-align:center">Err</th>
        </tr>
      </thead>
      <tbody>${linkRows}</tbody>
    </table>
    </div>
  </div>`;
}

// ── Network-Wide Port Capacity Report (REMOVED — use NetPortal Capacity instead) ──
let lastAllBGPData = null;


// ── Network-Wide BGP Summary Report ───────────────────────────────────────────
async function runAllBGP() {
  _hideAllReportPanels();
  const btn = document.getElementById("btn-allbgp");
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Scanning all BGP sessions…';
  try {
    const r = await fetch(`${API}/report/bgp`);
    const d = await r.json();
    if (d.success) { lastAllBGPData = d; renderAllBGP(d); }
    else { document.getElementById("rpt-bgp").style.display = "block"; document.getElementById("rpt-bgp").innerHTML = `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px;color:var(--red)">⚠️ ${d.error||'Failed'}</div>`; }
    addHistory("report-bgp", "BGP Summary (All Sites)", d.success !== false, "ALL");
  } catch(e) {
    document.getElementById("rpt-bgp").style.display = "block";
    document.getElementById("rpt-bgp").innerHTML = `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px;color:var(--red)">Fetch error: ${e}</div>`;
  }
  btn.disabled = false; btn.innerHTML = "🔗 BGP Summary";
}

function renderAllBGP(d) {
  const el = document.getElementById("rpt-bgp");
  el.style.display = "block";
  const s = d.summary || {};
  const sites = d.sites || [];
  const sessions = d.sessions || [];

  const stateCol = st => st==="established"?"var(--green)":st==="idle"?"var(--red)":"var(--orange)";
  const stateIcon = st => st==="established"?"✅":st==="idle"?"🔴":"🟠";

  const badges = [];
  if (s.idle > 0) badges.push(`<span style="font-size:10px;background:rgba(244,67,54,.15);color:var(--red);padding:2px 8px;border-radius:10px;border:1px solid rgba(244,67,54,.3);font-weight:700">🔴 ${s.idle} IDLE</span>`);
  if (s.active_connect > 0) badges.push(`<span style="font-size:10px;background:rgba(255,152,0,.15);color:var(--orange);padding:2px 8px;border-radius:10px;border:1px solid rgba(255,152,0,.3);font-weight:700">🟠 ${s.active_connect} ACTIVE/CONNECT</span>`);
  if (s.not_established === 0) badges.push(`<span style="font-size:10px;background:rgba(76,175,80,.15);color:var(--green);padding:2px 8px;border-radius:10px;border:1px solid rgba(76,175,80,.3);font-weight:700">✅ ALL BGP ESTABLISHED</span>`);

  const siteRows = sites.map(st => {
    const worst = st.idle > 0 ? "var(--red)" : st.not_established > 0 ? "var(--orange)" : "var(--green)";
    return `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:3px 8px;font-weight:700;color:var(--accent);font-size:11px">${escHtml(st.site)}</td>
      <td style="padding:3px 8px;text-align:center;font-size:11px">${st.total}</td>
      <td style="padding:3px 8px;text-align:center;font-size:11px;color:var(--green)">${st.established}</td>
      <td style="padding:3px 8px;text-align:center;font-size:11px;color:${st.not_established?'var(--red)':'var(--muted)'}">${st.not_established||'—'}</td>
      <td style="padding:3px 8px;text-align:center;font-size:11px;color:${st.idle?'var(--red)':'var(--muted)'}">${st.idle||'—'}</td>
      <td style="padding:3px 8px;text-align:center;font-size:11px">${st.ebgp}</td>
      <td style="padding:3px 8px;text-align:center;font-size:11px">${st.ibgp}</td>
    </tr>`;
  }).join('');

  const sessRows = sessions.map(ss => {
    const sc = stateCol(ss.state);
    const si = stateIcon(ss.state);
    const typeCol = ss.session_type === "eBGP" ? "color:#f59e0b;font-weight:700" : "color:var(--muted)";
    const asName = ss.as_name || '';
    return `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:3px 6px;font-size:11px;font-weight:600;color:var(--accent)">${escHtml(ss.site)}</td>
      <td style="padding:3px 6px;font-size:11px;font-family:Consolas,monospace">${escHtml(ss.hostname)}</td>
      <td style="padding:3px 6px;font-size:10px;font-family:Consolas,monospace;color:var(--muted)">${escHtml(ss.peer_ip)}</td>
      <td style="padding:3px 6px;text-align:center;font-size:10px">${ss.remote_as}</td>
      <td style="padding:3px 6px;font-size:10px;color:${asName?'var(--accent)':'var(--muted)'};white-space:nowrap">${asName||'—'}</td>
      <td style="padding:3px 6px;text-align:center;font-size:10px;${typeCol}">${ss.session_type}</td>
      <td style="padding:3px 6px;text-align:center;font-size:10px;color:${sc};font-weight:700">${si} ${ss.state}</td>
      <td style="padding:3px 6px;text-align:right;font-size:10px">${ss.prefixes_accepted||'—'}</td>
    </tr>`;
  }).join('');

  el.innerHTML = `
  <div style="background:var(--bg2);border:1px solid #f59e0b;border-radius:8px;padding:14px;margin-bottom:8px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap">
      <span style="font-size:14px;font-weight:700;font-family:Consolas,monospace;color:#f59e0b">🔗 BGP Summary — All Sites</span>
      <span style="font-size:10px;background:rgba(245,158,11,.15);color:#f59e0b;padding:2px 7px;border-radius:10px;border:1px solid rgba(245,158,11,.3)">${s.devices_with_bgp||0} devices · ${s.sites_with_bgp||0} sites</span>
      ${badges.join(' ')}
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
      <div class="stat-card" style="flex:1;min-width:80px"><div class="sv" style="color:var(--text)">${s.total_sessions||0}</div><div class="sl">Total Sessions</div></div>
      <div class="stat-card" style="flex:1;min-width:80px"><div class="sv" style="color:var(--green)">${s.established||0}</div><div class="sl">Established</div></div>
      <div class="stat-card" style="flex:1;min-width:80px"><div class="sv" style="color:${s.not_established?'var(--red)':'var(--muted)'}">${s.not_established||0}</div><div class="sl">Not Established</div></div>
      <div class="stat-card" style="flex:1;min-width:80px"><div class="sv" style="color:#f59e0b">${s.ebgp_sessions||0}</div><div class="sl">eBGP</div></div>
      <div class="stat-card" style="flex:1;min-width:80px"><div class="sv" style="color:var(--muted)">${s.ibgp_sessions||0}</div><div class="sl">iBGP</div></div>
    </div>
    <div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-bottom:6px">Site Summary</div>
    <div style="max-height:200px;overflow-y:auto;margin-bottom:14px">
    <table style="width:100%;border-collapse:collapse"><thead>
      <tr style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;background:var(--bg2)">
        <th style="padding:3px 8px;text-align:left">Site</th><th style="padding:3px 8px;text-align:center">Total</th>
        <th style="padding:3px 8px;text-align:center">Established</th><th style="padding:3px 8px;text-align:center">Not Est.</th>
        <th style="padding:3px 8px;text-align:center">Idle</th><th style="padding:3px 8px;text-align:center">eBGP</th>
        <th style="padding:3px 8px;text-align:center">iBGP</th>
      </tr></thead><tbody>${siteRows}</tbody></table></div>
    <div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-bottom:6px">All BGP Sessions (${sessions.length})</div>
    <div style="max-height:600px;overflow-y:auto">
    <table style="width:100%;border-collapse:collapse"><thead>
      <tr style="color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;background:var(--bg2)">
        <th style="padding:3px 6px;text-align:left">Site</th><th style="padding:3px 6px;text-align:left">Device</th>
        <th style="padding:3px 6px;text-align:left">Peer IP</th><th style="padding:3px 6px;text-align:center">Remote AS</th>
        <th style="padding:3px 6px;text-align:left">AS Name</th>
        <th style="padding:3px 6px;text-align:center">Type</th><th style="padding:3px 6px;text-align:center">State</th>
        <th style="padding:3px 6px;text-align:right">Prefixes</th>
      </tr></thead><tbody>${sessRows}</tbody></table></div>
  </div>`;
}

// ── Network-Wide IP Exhaustion Report ─────────────────────────────────────────

// Populate the site selector dropdown from the API
(function _populateIPExhSites() {
  const sel = document.getElementById("ipexh-site");
  if (!sel) return;
  fetch(`${API}/sites`).then(r=>r.json()).then(arr => {
    if (!Array.isArray(arr) || !arr.length) return;
    const sorted = arr.map(s => s.toLowerCase()).sort();
    sel.innerHTML = '<option value="">All Sites</option>' + sorted.map(s => `<option value="${s}">${s.toUpperCase()}</option>`).join('');
  }).catch(()=>{});
})();

async function runIPExhaustion() {
  _hideAllReportPanels();
  const btn = document.getElementById("btn-ipexh");
  const site = document.getElementById("ipexh-site").value;
  const label = site ? site.toUpperCase() : "All Sites";
  btn.disabled = true; btn.innerHTML = `<span class="spin"></span> Scanning ${label}…`;
  const el = document.getElementById("rpt-ip");
  el.style.display = "block";
  el.innerHTML = `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:40px;text-align:center;color:var(--muted)"><span class="spin"></span> Scanning subnets on ${label} via SSH… This may take a while for all sites.</div>`;

  try {
    const url = site ? `${API}/report/ip-exhaustion?site=${site}` : `${API}/report/ip-exhaustion`;
    const r = await fetch(url);
    const d = await r.json();
    if (d.success) {
      lastIPExhData = d;
      renderIPExhaustion(d);
    } else {
      el.innerHTML = `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px;color:var(--red)">⚠️ ${d.error||'Failed'}</div>`;
    }
    addHistory("report-ip", `IP Exhaustion ${label}`, d.success !== false, label);
  } catch(e) {
    el.innerHTML = `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px;color:var(--red)">Fetch error: ${e}</div>`;
  }
  btn.disabled = false; btn.innerHTML = "🏠 IP Exhaustion";
}

function renderIPExhaustion(d) {
  const el = document.getElementById("rpt-ip");
  el.style.display = "block";
  const s = d.summary || {};
  const sites = d.sites || [];
  const errors = d.errors || [];
  const target = d.target_site || "ALL";

  const statusCol = st => st==="critical"?"var(--red)":st==="warning"?"var(--orange)":"var(--green)";
  const statusIcon = st => st==="critical"?"🔴":st==="warning"?"🟠":"✅";
  const utilCol = u => u>=90?"var(--red)":u>=75?"var(--orange)":u>=50?"var(--yellow)":"var(--green)";
  const utilBar = (u, w) => `<div style="display:flex;align-items:center;gap:3px"><div style="flex:1;background:var(--bg3);border-radius:3px;height:8px;overflow:hidden;min-width:${w||60}px"><div style="height:100%;width:${Math.min(u,100)}%;background:${utilCol(u)};border-radius:3px"></div></div><span style="font-size:10px;color:${utilCol(u)};font-weight:700;min-width:32px;text-align:right">${u}%</span></div>`;

  // Badges
  const badges = [];
  if (s.critical_subnets > 0) badges.push(`<span style="font-size:10px;background:rgba(244,67,54,.15);color:var(--red);padding:2px 8px;border-radius:10px;border:1px solid rgba(244,67,54,.3);font-weight:700">🔴 ${s.critical_subnets} CRITICAL</span>`);
  if (s.warning_subnets > 0) badges.push(`<span style="font-size:10px;background:rgba(255,152,0,.15);color:var(--orange);padding:2px 8px;border-radius:10px;border:1px solid rgba(255,152,0,.3);font-weight:700">🟠 ${s.warning_subnets} WARNING</span>`);
  if (!s.critical_subnets && !s.warning_subnets) badges.push(`<span style="font-size:10px;background:rgba(76,175,80,.15);color:var(--green);padding:2px 8px;border-radius:10px;border:1px solid rgba(76,175,80,.3);font-weight:700">✅ ALL SUBNETS HEALTHY</span>`);
  if (errors.length > 0) badges.push(`<span style="font-size:10px;background:rgba(244,67,54,.1);color:var(--muted);padding:2px 8px;border-radius:10px;border:1px solid var(--border)">⚠ ${errors.length} errors</span>`);

  // Site summary rows
  const siteRows = sites.map((st, i) => {
    const sc = statusCol(st.status);
    const si = statusIcon(st.status);
    return `<tr style="border-bottom:1px solid var(--border);cursor:pointer" onclick="document.getElementById('ipexh-site-${i}').style.display=document.getElementById('ipexh-site-${i}').style.display==='none'?'block':'none'" title="Click to expand devices">
      <td style="padding:4px 8px;font-weight:700;color:var(--accent);font-size:11px">${si} ${escHtml(st.site.toUpperCase())}</td>
      <td style="padding:4px 8px;text-align:center;font-size:11px">${st.device_count}</td>
      <td style="padding:4px 8px;text-align:center;font-size:11px">${st.total_subnets}</td>
      <td style="padding:4px 8px;text-align:right;font-size:11px">${st.total_ips.toLocaleString()}</td>
      <td style="padding:4px 8px;text-align:right;font-size:11px;color:var(--accent)">${st.active_hosts.toLocaleString()}</td>
      <td style="padding:4px 8px;text-align:right;font-size:11px;color:var(--green)">${st.free_ips.toLocaleString()}</td>
      <td style="padding:4px 8px;text-align:center;font-size:11px;color:${st.critical?'var(--red)':'var(--muted)'}">${st.critical||'—'}</td>
      <td style="padding:4px 8px;text-align:center;font-size:11px;color:${st.warning?'var(--orange)':'var(--muted)'}">${st.warning||'—'}</td>
      <td style="padding:4px 6px;width:90px">${utilBar(st.utilization_pct, 60)}</td>
    </tr>`;
  }).join('');

  // Device drill-down sections (hidden by default) — shows deduped subnets + per-device details
  const deviceSections = sites.map((st, i) => {
    // Deduped subnet table (primary view)
    const dedupRows = (st.deduped_subnets||[]).map(sn => {
      const snCol = sn.status==="critical"?"var(--red)":sn.status==="warning"?"var(--orange)":sn.status==="moderate"?"var(--yellow)":"var(--muted)";
      return `<tr style="border-bottom:1px solid rgba(255,255,255,.03)">
        <td style="padding:2px 8px;font-size:10px;font-family:Consolas,monospace;color:${snCol}">${escHtml(sn.subnet)}</td>
        <td style="padding:2px 6px;font-size:10px;font-family:Consolas,monospace;color:var(--muted)">${escHtml(sn.interface)}</td>
        <td style="padding:2px 6px;font-size:10px;color:var(--muted);max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(sn.description||'')}">${escHtml(sn.description||'—')}</td>
        <td style="padding:2px 6px;text-align:right;font-size:10px">${sn.total_ips}</td>
        <td style="padding:2px 6px;text-align:right;font-size:10px;color:var(--accent)">${sn.active_hosts}</td>
        <td style="padding:2px 6px;text-align:right;font-size:10px;color:var(--green)">${sn.free_ips}</td>
        <td style="padding:2px 4px;width:70px">${utilBar(sn.utilization_pct, 50)}</td>
        <td style="padding:2px 6px;text-align:center;font-size:9px;font-weight:700;color:${snCol}">${sn.status.toUpperCase()}</td>
        <td style="padding:2px 6px;font-size:9px;color:var(--muted);max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(sn.seen_on||'')}">${escHtml(sn.seen_on||'')}</td>
      </tr>`;
    }).join('');

    // Per-device summary (secondary, collapsed)
    const devSummary = (st.devices||[]).map(dv =>
      `<span style="font-family:Consolas,monospace;font-size:10px;color:var(--accent)">${escHtml(dv.hostname)}</span> <span style="font-size:9px;color:var(--muted)">${dv.dtype} · ${dv.total_subnets} subnets · ${dv.arp_count} ARP</span>`
    ).join('<br>');

    return `<div id="ipexh-site-${i}" style="display:none;background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:10px;margin:4px 0">
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:.4px;color:var(--muted);margin-bottom:4px">Deduplicated Subnets</div>
      <table style="width:100%;border-collapse:collapse"><thead>
        <tr style="color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.4px">
          <th style="padding:2px 8px;text-align:left">Subnet</th><th style="padding:2px 6px;text-align:left">Interface</th>
          <th style="padding:2px 6px;text-align:left">Description</th><th style="padding:2px 6px;text-align:right">Total</th>
          <th style="padding:2px 6px;text-align:right">Active</th><th style="padding:2px 6px;text-align:right">Free</th>
          <th style="padding:2px 4px;text-align:left">Util</th><th style="padding:2px 6px;text-align:center">Status</th>
          <th style="padding:2px 6px;text-align:left">Seen On</th>
        </tr></thead><tbody>${dedupRows}</tbody></table>
      <details style="margin-top:8px"><summary style="cursor:pointer;font-size:10px;color:var(--muted)">📋 Per-device details (${(st.devices||[]).length} devices)</summary>
        <div style="margin-top:4px;padding:4px 8px;font-size:10px">${devSummary}</div>
      </details>
    </div>`;
  }).join('');

  // Error rows
  const errHtml = errors.length ? `<div style="margin-top:8px;font-size:10px;color:var(--muted)"><details><summary style="cursor:pointer;color:var(--yellow)">⚠ ${errors.length} device errors (click to expand)</summary><div style="margin-top:4px;max-height:150px;overflow-y:auto">${errors.map(e=>`<div style="padding:1px 0"><span style="color:var(--red);font-family:Consolas,monospace">${escHtml(e.hostname)}</span>: ${escHtml(e.error)}</div>`).join('')}</div></details></div>` : '';

  el.innerHTML = `
  <div style="background:var(--bg2);border:1px solid #a78bfa;border-radius:8px;padding:14px;margin-bottom:8px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap">
      <span style="font-size:14px;font-weight:700;font-family:Consolas,monospace;color:#a78bfa">🏠 IP Exhaustion — ${target === 'ALL' ? 'All Sites' : target.toUpperCase()}</span>
      <span style="font-size:10px;background:rgba(167,139,250,.15);color:#a78bfa;padding:2px 7px;border-radius:10px;border:1px solid rgba(167,139,250,.3)">${s.total_devices||0} devices · ${s.total_sites||0} sites · ${s.devices_scanned||0} scanned</span>
      ${badges.join(' ')}
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
      <div class="stat-card" style="flex:1;min-width:80px"><div class="sv" style="color:var(--text)">${s.total_subnets||0}</div><div class="sl">Subnets</div></div>
      <div class="stat-card" style="flex:1;min-width:80px"><div class="sv" style="color:var(--text)">${(s.total_ips||0).toLocaleString()}</div><div class="sl">Total IPs</div></div>
      <div class="stat-card" style="flex:1;min-width:80px"><div class="sv" style="color:var(--accent)">${(s.active_hosts||0).toLocaleString()}</div><div class="sl">ARP Hosts</div></div>
      <div class="stat-card" style="flex:1;min-width:80px"><div class="sv" style="color:var(--green)">${(s.free_ips||0).toLocaleString()}</div><div class="sl">Free IPs</div></div>
      <div class="stat-card" style="flex:1;min-width:80px"><div class="sv" style="color:${utilCol(s.overall_utilization||0)}">${s.overall_utilization||0}%</div><div class="sl">Overall Util</div></div>
      <div class="stat-card" style="flex:1;min-width:80px"><div class="sv" style="color:${s.critical_subnets?'var(--red)':'var(--muted)'}">${s.critical_subnets||0}</div><div class="sl">Critical</div></div>
      <div class="stat-card" style="flex:1;min-width:80px"><div class="sv" style="color:${s.warning_subnets?'var(--orange)':'var(--muted)'}">${s.warning_subnets||0}</div><div class="sl">Warning</div></div>
    </div>
    <div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-bottom:6px">Site Summary <span style="text-transform:none;letter-spacing:0">(click row to expand devices)</span></div>
    <div style="max-height:300px;overflow-y:auto;margin-bottom:8px">
    <table style="width:100%;border-collapse:collapse"><thead>
      <tr style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;background:var(--bg2)">
        <th style="padding:4px 8px;text-align:left">Site</th><th style="padding:4px 8px;text-align:center">Devices</th>
        <th style="padding:4px 8px;text-align:center">Subnets</th><th style="padding:4px 8px;text-align:right">Total IPs</th>
        <th style="padding:4px 8px;text-align:right">Active</th><th style="padding:4px 8px;text-align:right">Free</th>
        <th style="padding:4px 8px;text-align:center">Crit</th><th style="padding:4px 8px;text-align:center">Warn</th>
        <th style="padding:4px 6px;text-align:left">Utilization</th>
      </tr></thead><tbody>${siteRows}</tbody></table></div>
    ${deviceSections}
    ${errHtml}
    <div style="margin-top:8px;font-size:9px;color:var(--muted)">Data sources: ARP table (L3 active hosts) · Interface IPs · Interface descriptions · SSH analysis · ${d.analysis_date||''}</div>
  </div>`;
}

function exportIPExhaustion(format) {
  if (!lastIPExhData) return;
  const d = lastIPExhData;
  const s = d.summary || {};
  const sites = d.sites || [];
  const now = d.analysis_date || new Date().toISOString();
  const target = d.target_site || "ALL";

  if (format === "csv") {
    let csv = "Site,Subnet,Interface,Description,Total_IPs,Active_Hosts,Free_IPs,Utilization_Pct,Status,Seen_On\n";
    sites.forEach(st => {
      (st.deduped_subnets||[]).forEach(sn => {
        csv += `${st.site.toUpperCase()},${sn.subnet},${sn.interface},"${(sn.description||'').replace(/"/g,'""')}",${sn.total_ips},${sn.active_hosts},${sn.free_ips},${sn.utilization_pct},${sn.status},"${sn.seen_on||''}"\n`;
      });
    });
    downloadFile(csv, `IP_Exhaustion_${target}_${ts()}.csv`, "text/csv");
    return;
  }

  let md = `# IP Exhaustion Report — ${target === 'ALL' ? 'All Sites' : target.toUpperCase()}\n\n`;
  md += `| Field | Value |\n|---|---|\n`;
  md += `| **Report Date** | ${now} |\n| **Sites** | ${s.total_sites} |\n| **Devices** | ${s.total_devices} |\n`;
  md += `| **Subnets** | ${s.total_subnets} |\n| **Total IPs** | ${(s.total_ips||0).toLocaleString()} |\n`;
  md += `| **Active Hosts** | ${(s.active_hosts||0).toLocaleString()} |\n| **Free IPs** | ${(s.free_ips||0).toLocaleString()} |\n`;
  md += `| **Overall Utilization** | **${s.overall_utilization}%** |\n| **Critical Subnets** | ${s.critical_subnets} |\n| **Warning Subnets** | ${s.warning_subnets} |\n\n`;

  // Critical/warning subnets first (from deduped)
  const problemSubnets = [];
  sites.forEach(st => {
    (st.deduped_subnets||[]).forEach(sn => {
      if (sn.status === "critical" || sn.status === "warning")
        problemSubnets.push({site: st.site.toUpperCase(), ...sn});
    });
  });
  if (problemSubnets.length) {
    md += `## ⚠️ Critical & Warning Subnets (${problemSubnets.length})\n\n`;
    md += `| Site | Subnet | Interface | Description | Active | Total | Util | Status | Seen On |\n|---|---|---|---|---|---|---|---|---|\n`;
    problemSubnets.forEach(p => md += `| ${p.site} | ${p.subnet} | \`${p.interface}\` | ${p.description||'—'} | ${p.active_hosts} | ${p.total_ips} | **${p.utilization_pct}%** | **${p.status.toUpperCase()}** | ${p.seen_on||''} |\n`);
    md += `\n`;
  }

  md += `## Site Summary\n\n| Site | Devices | Subnets | Total IPs | Active | Free | Util | Status |\n|---|---|---|---|---|---|---|---|\n`;
  sites.forEach(st => md += `| **${st.site.toUpperCase()}** | ${st.device_count} | ${st.total_subnets} | ${st.total_ips.toLocaleString()} | ${st.active_hosts.toLocaleString()} | ${st.free_ips.toLocaleString()} | ${st.utilization_pct}% | ${st.status} |\n`);
  md += `\n`;

  sites.forEach(st => {
    md += `## ${st.site.toUpperCase()} — ${st.device_count} devices, ${st.utilization_pct}% utilization\n\n`;
    const deduped = st.deduped_subnets || [];
    if (deduped.length) {
      md += `| Subnet | Interface | Description | Total | Active | Free | Util | Status | Seen On |\n|---|---|---|---|---|---|---|---|---|\n`;
      deduped.forEach(sn => md += `| ${sn.subnet} | \`${sn.interface}\` | ${sn.description||'—'} | ${sn.total_ips} | ${sn.active_hosts} | ${sn.free_ips} | ${sn.utilization_pct}% | ${sn.status} | ${sn.seen_on||''} |\n`);
      md += `\n`;
    }
  });
  md += `---\n*Generated by DCN Network Tool*\n`;
  downloadFile(md, `IP_Exhaustion_${target}_${ts()}.md`, "text/markdown");
}

// ── Reports Tab Utilities ─────────────────────────────────────────────────────
function clearReports() {
  document.getElementById("rpt-isp").style.display = "none";
  document.getElementById("rpt-bgp").style.display = "none";
  document.getElementById("rpt-ip").style.display = "none";
  document.getElementById("rpt-netportal").style.display = "none";
  document.getElementById("ipa-summary").style.display = "none";
  document.getElementById("ipa-output").style.display = "none";
  document.getElementById("rpt-out").innerHTML = '<div style="color:var(--muted);text-align:center;padding:60px;font-size:13px"><div style="font-size:32px;margin-bottom:12px">📋</div><b style="color:var(--text)">Network-Wide Reports</b><br><span style="font-size:11px">Click a report button above to scan the network.</span></div>';
  lastISPData = null; lastAllBGPData = null; lastIPExhData = null; lastNetPortalData = null; lastSubnetData = null;
}

function exportReport(format) {
  // Export whichever report is currently visible
  const ispVisible = document.getElementById("rpt-isp").style.display !== "none";
  const bgpVisible = document.getElementById("rpt-bgp").style.display !== "none";
  const ipVisible = document.getElementById("rpt-ip").style.display !== "none";
  const npVisible = document.getElementById("rpt-netportal").style.display !== "none";

  if (ispVisible && lastISPData) { exportISPLinks(format); return; }
  if (bgpVisible && lastAllBGPData) { exportAllBGP(format); return; }
  if (ipVisible && lastIPExhData) { exportIPExhaustion(format); return; }
  if (npVisible && lastNetPortalData) { exportNetPortal(format); return; }
  alert("No report data — run a report first");
}

function exportAllBGP(format) {
  if (!lastAllBGPData) return;
  const d = lastAllBGPData;
  const s = d.summary || {};
  const sessions = d.sessions || [];
  const now = d.analysis_date || new Date().toISOString();

  if (format === "csv") {
    let csv = "Site,Device,Peer_IP,Remote_AS,AS_Name,Local_AS,Type,State,Prefixes,Risk,Region\n";
    sessions.forEach(ss => csv += `${ss.site},${ss.hostname},${ss.peer_ip},${ss.remote_as},"${ss.as_name||''}",${ss.local_as},${ss.session_type},${ss.state},${ss.prefixes_accepted},${ss.risk},${ss.region}\n`);
    downloadFile(csv, `BGP_Summary_All_Sites_${ts()}.csv`, "text/csv");
    return;
  }
  let md = `# BGP Summary Report — All Sites\n\n`;
  md += `| Field | Value |\n|---|---|\n`;
  md += `| **Report Date** | ${now} |\n| **Devices with BGP** | ${s.devices_with_bgp} |\n| **Sites** | ${s.sites_with_bgp} |\n`;
  md += `| **Total Sessions** | ${s.total_sessions} |\n| **Established** | ${s.established} |\n| **Not Established** | ${s.not_established} |\n`;
  md += `| **eBGP** | ${s.ebgp_sessions} |\n| **iBGP** | ${s.ibgp_sessions} |\n\n`;
  const notEst = sessions.filter(ss => ss.state !== "established");
  if (notEst.length) {
    md += `## ⚠️ Non-Established Sessions (${notEst.length})\n\n`;
    md += `| Site | Device | Peer IP | Remote AS | AS Name | Type | State |\n|---|---|---|---|---|---|---|\n`;
    notEst.forEach(ss => md += `| ${ss.site} | \`${ss.hostname}\` | ${ss.peer_ip} | ${ss.remote_as} | ${ss.as_name||''} | ${ss.session_type} | **${ss.state.toUpperCase()}** |\n`);
    md += `\n`;
  }
  md += `## All Sessions (${sessions.length})\n\n`;
  md += `| Site | Device | Peer IP | Remote AS | AS Name | Type | State | Prefixes |\n|---|---|---|---|---|---|---|---|\n`;
  sessions.forEach(ss => md += `| ${ss.site} | \`${ss.hostname}\` | ${ss.peer_ip} | ${ss.remote_as} | ${ss.as_name||''} | ${ss.session_type} | ${ss.state} | ${ss.prefixes_accepted||'—'} |\n`);
  md += `\n---\n*Generated by DCN Network Tool*\n`;
  downloadFile(md, `BGP_Summary_All_Sites_${ts()}.md`, "text/markdown");
}

async function analyzeCurrentOutput() {
  if (!selectedDev) return;
  const output = document.getElementById("out-pre").textContent;
  const cmd = document.getElementById("cmd-lbl").textContent;
  if (!output || output === "Output will appear here…") return;
  const tmpData = { [cmd]: output };
  try {
    const r = await fetch(`${API}/analyze`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ hostname: selectedDev.hostname, dtype: selectedDev.type, data: tmpData }) });
    const d = await r.json();
    renderAnalysis(d);
    switchTabById("analysis");
  } catch(e) {
    console.error(e);
  }
}

// ── Recommendations ───────────────────────────────────────────────────────────
async function runRecommendations() {
  if (!selectedDev) return;
  const panel = document.getElementById("ana-panel");
  panel.innerHTML = '<div style="text-align:center;padding:40px"><span class="spin"></span><br><span style="color:var(--muted);font-size:12px;margin-top:8px;display:inline-block">Collecting configuration and generating recommendations…<br>This may take 30-60 seconds.</span></div>';
  switchTabById("analysis");
  try {
    const r = await fetch(`${API}/recommendations`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ ip: selectedDev.ip, dtype: selectedDev.type, hostname: selectedDev.hostname }) });
    const d = await r.json();
    if (!d.success) { panel.innerHTML = `<div style="color:var(--red);padding:14px">Error: ${d.error}</div>`; return; }
    renderRecommendations(d);
    addHistory("recommendations", "Recommendations", d.success, selectedDev.hostname);
  } catch(e) {
    panel.innerHTML = `<div style="color:var(--red);padding:14px">Fetch error: ${e}</div>`;
  }
}

function renderRecommendations(d) {
  const catIcons = { security:"🔒", performance:"⚡", resilience:"🛡️", optimization:"🔧", compliance:"📋" };
  const catLabels = { security:"Security", performance:"Performance", resilience:"Resilience", optimization:"Optimization", compliance:"Compliance" };
  const sevColors = { high:"var(--red)", medium:"var(--yellow)", low:"var(--muted)" };
  const sevLabels = { high:"HIGH", medium:"MED", low:"LOW" };

  let html = `
    <div class="asec" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <span style="font-size:15px;font-weight:700;font-family:Consolas,monospace">${escHtml(d.hostname)}</span>
      <span style="background:${d.high_count>0?'rgba(248,81,73,.15)':'rgba(63,185,80,.15)'};color:${d.high_count>0?'var(--red)':'var(--green)'};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">
        ${d.total} recommendation${d.total!==1?'s':''}</span>
      <span style="color:var(--red);font-size:11px;font-weight:600">${d.high_count} high</span>
      <span style="color:var(--yellow);font-size:11px;font-weight:600">${d.medium_count} medium</span>
      <span style="color:var(--muted);font-size:11px;margin-left:auto">${(d.timestamp||"").slice(0,19).replace('T',' ')}</span>
    </div>`;

  const recs = d.recommendations || {};
  for (const [cat, items] of Object.entries(recs)) {
    if (!items || !items.length) continue;
    html += `
    <div class="asec">
      <h4 style="display:flex;align-items:center;gap:6px">${catIcons[cat]||"📌"} ${catLabels[cat]||cat} (${items.length})</h4>
      ${items.map(r => `
        <div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin:4px 0;border-left:3px solid ${sevColors[r.severity]||'var(--muted)'}">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
            <span style="color:${sevColors[r.severity]};font-size:10px;font-weight:700;padding:1px 5px;border:1px solid ${sevColors[r.severity]};border-radius:3px">${sevLabels[r.severity]||r.severity}</span>
            <span style="font-weight:600;font-size:13px">${escHtml(r.title)}</span>
          </div>
          <div style="color:var(--muted);font-size:12px;margin-bottom:6px">${escHtml(r.detail)}</div>
          <div style="background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:6px 8px;font-family:Consolas,monospace;font-size:11px;color:var(--green);white-space:pre-wrap;cursor:pointer" title="Click to copy" onclick="navigator.clipboard.writeText(this.textContent.trim())">${escHtml(r.command)}</div>
        </div>`).join('')}
    </div>`;
  }

  if (d.total === 0) {
    html += '<div class="asec"><div style="color:var(--green);font-size:13px;padding:20px;text-align:center">✅ No recommendations — configuration follows best practices!</div></div>';
  }

  document.getElementById("ana-panel").innerHTML = html;
}

// ── AI Deep Analysis ─────────────────────────────────────────────────────────
let lastDeepData = null;

async function runDeepAnalysis() {
  if (!selectedDev) return;
  const panel = document.getElementById("ana-panel");
  const btn = document.getElementById("btn-deep");
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Collecting & Analyzing…';
  panel.innerHTML = `<div style="text-align:center;padding:40px">
    <span class="spin" style="width:28px;height:28px;border-width:3px"></span>
    <div style="color:var(--muted);font-size:12px;margin-top:12px">🧠 AI Agent collecting <b>~20 data points</b> via SSH…</div>
    <div style="color:var(--muted);font-size:11px;margin-top:4px">Config · BGP · Interfaces · MTU · SFP · Logs · NTP · Alarms · LACP · VPN</div>
    <div style="color:var(--muted);font-size:11px;margin-top:4px">This may take 60-90 seconds.</div>
  </div>`;
  switchTabById("analysis");
  try {
    const r = await fetch(`${API}/deep-analysis`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ ip: selectedDev.ip, dtype: selectedDev.type, hostname: selectedDev.hostname }) });
    const d = await r.json();
    if (d.success) {
      lastDeepData = d;
      renderDeepAnalysis(d);
      addHistory("deep-analysis", "AI Deep Analysis", true, selectedDev.hostname);
    } else {
      panel.innerHTML = `<div style="color:var(--red);padding:14px">Error: ${d.error}</div>`;
    }
  } catch(e) {
    panel.innerHTML = `<div style="color:var(--red);padding:14px">Fetch error: ${e}</div>`;
  }
  btn.disabled = false; btn.innerHTML = "🧠 AI Deep Analysis";
}

function renderDeepAnalysis(d) {
  const score = d.score || 0;
  const grade = d.grade || "?";
  const gradeLabel = d.grade_label || "";
  const sc = d.severity_counts || {};

  // Score color
  const scoreCol = score >= 90 ? "#4caf50" : score >= 75 ? "#8bc34a" : score >= 60 ? "#ffc107" : score >= 40 ? "#ff9800" : "#f44336";
  const gradeBg = score >= 90 ? "rgba(76,175,80,.15)" : score >= 75 ? "rgba(139,195,58,.15)" : score >= 60 ? "rgba(255,193,7,.15)" : score >= 40 ? "rgba(255,152,0,.15)" : "rgba(244,67,54,.15)";

  // Score ring SVG
  const pct = score / 100;
  const circumference = 2 * Math.PI * 45;
  const offset = circumference * (1 - pct);

  let html = `
  <div class="asec" style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:20px">
    <div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap">
      <!-- Score Ring -->
      <div style="position:relative;width:110px;height:110px;flex-shrink:0">
        <svg width="110" height="110" viewBox="0 0 110 110" style="transform:rotate(-90deg)">
          <circle cx="55" cy="55" r="45" fill="none" stroke="var(--bg3)" stroke-width="8"/>
          <circle cx="55" cy="55" r="45" fill="none" stroke="${scoreCol}" stroke-width="8"
                  stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
                  stroke-linecap="round" style="transition:stroke-dashoffset 1s ease"/>
        </svg>
        <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center">
          <span style="font-size:28px;font-weight:800;color:${scoreCol}">${score}</span>
          <span style="font-size:10px;color:var(--muted)">/ 100</span>
        </div>
      </div>

      <!-- Device Info -->
      <div style="flex:1;min-width:200px">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
          <span style="font-size:18px;font-weight:700;font-family:Consolas,monospace">${escHtml(d.hostname)}</span>
          <span style="font-size:14px;font-weight:800;padding:3px 12px;border-radius:6px;background:${gradeBg};color:${scoreCol}">Grade ${grade}</span>
          <span style="font-size:12px;color:${scoreCol};font-weight:600">${gradeLabel}</span>
        </div>
        <div style="font-size:12px;color:var(--muted);margin-bottom:4px">${d.model || ''} · ${(d.version || '').slice(0,30)} · ${(d.dtype||'').toUpperCase()}</div>
        <div style="font-size:11px;color:var(--muted)">${(d.timestamp||'').slice(0,19).replace('T',' ')}</div>
      </div>

      <!-- Severity Summary -->
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        ${sc.critical ? `<div style="text-align:center"><div style="font-size:20px;font-weight:700;color:#f44336">${sc.critical}</div><div style="font-size:9px;color:var(--muted)">CRITICAL</div></div>` : ''}
        ${sc.high ? `<div style="text-align:center"><div style="font-size:20px;font-weight:700;color:var(--red)">${sc.high}</div><div style="font-size:9px;color:var(--muted)">HIGH</div></div>` : ''}
        ${sc.medium ? `<div style="text-align:center"><div style="font-size:20px;font-weight:700;color:var(--yellow)">${sc.medium}</div><div style="font-size:9px;color:var(--muted)">MEDIUM</div></div>` : ''}
        ${sc.low ? `<div style="text-align:center"><div style="font-size:20px;font-weight:700;color:var(--muted)">${sc.low}</div><div style="font-size:9px;color:var(--muted)">LOW</div></div>` : ''}
        <div style="text-align:center"><div style="font-size:20px;font-weight:700;color:var(--green)">${sc.ok||0}</div><div style="font-size:9px;color:var(--muted)">OK</div></div>
      </div>
    </div>
  </div>`;

  // LLM narrative (if available)
  if (d.llm_narrative) {
    const nLines = d.llm_narrative.split("\n").filter(l => l.trim());
    html += `<div style="margin:10px 0;padding:10px 14px;background:rgba(88,166,255,0.08);border-left:3px solid var(--accent);border-radius:4px;">
      <div style="font-size:10px;color:var(--accent);font-weight:600;letter-spacing:0.08em;margin-bottom:6px;">🤖 LLM ANALYSIS (Docker Model Runner)${d.llm_powered ? '' : ' — rule-based fallback'}</div>
      ${nLines.map(l => `<div style="font-size:12px;color:var(--muted);line-height:1.6;margin-bottom:2px;">${escHtml(l)}</div>`).join("")}
    </div>`;
  }

  // Severity config
  const sevConf = {
    critical: { color: "#f44336", bg: "rgba(244,67,54,.12)", label: "CRIT", icon: "🔴" },
    high:     { color: "var(--red)", bg: "rgba(248,81,73,.12)", label: "HIGH", icon: "🟠" },
    medium:   { color: "var(--yellow)", bg: "rgba(255,193,7,.12)", label: "MED", icon: "🟡" },
    low:      { color: "var(--muted)", bg: "rgba(139,148,158,.1)", label: "LOW", icon: "⚪" },
    info:     { color: "var(--accent)", bg: "rgba(88,166,255,.08)", label: "INFO", icon: "🔵" },
    ok:       { color: "var(--green)", bg: "rgba(63,185,80,.1)", label: "OK", icon: "🟢" },
  };

  // Render categories
  const cats = d.categories || {};
  for (const [catKey, cat] of Object.entries(cats)) {
    if (!cat.items || !cat.items.length) continue;

    // Count severities in this category
    const catCritHigh = cat.items.filter(i => i.severity === "critical" || i.severity === "high").length;
    const catBorder = catCritHigh > 0 ? "var(--red)" : "var(--border)";

    html += `
    <div class="asec" style="border-left:3px solid ${catBorder}">
      <h4 style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span style="font-size:16px">${cat.icon || '📌'}</span>
        <span>${cat.title || catKey}</span>
        <span style="font-size:11px;color:var(--muted);font-weight:400">${cat.items.length} finding${cat.items.length!==1?'s':''}</span>
      </h4>
      ${cat.items.map(item => {
        const s = sevConf[item.severity] || sevConf.info;
        return `
        <div style="background:${s.bg};border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin:4px 0">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">
            <span style="font-size:11px">${s.icon}</span>
            <span style="color:${s.color};font-size:10px;font-weight:700;padding:1px 5px;border:1px solid ${s.color};border-radius:3px">${s.label}</span>
            <span style="font-weight:600;font-size:13px">${escHtml(item.title)}</span>
          </div>
          <div style="color:var(--muted);font-size:12px;line-height:1.4">${escHtml(item.detail)}</div>
          ${item.remediation ? `<div style="background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:5px 8px;margin-top:6px;font-family:Consolas,monospace;font-size:11px;color:var(--green);white-space:pre-wrap;cursor:pointer" title="Click to copy" onclick="navigator.clipboard.writeText(this.textContent.trim())">${escHtml(item.remediation)}</div>` : ''}
        </div>`;
      }).join('')}
    </div>`;
  }

  // Export button at bottom
  html += `
  <div style="text-align:center;padding:10px">
    <button class="btn" onclick="exportDeepAnalysis()" style="border-color:#a855f7;color:#a855f7">📋 Export Deep Analysis Report (.md)</button>
  </div>`;

  document.getElementById("ana-panel").innerHTML = html;
}

function exportDeepAnalysis() {
  if (!lastDeepData || !selectedDev) { alert("No deep analysis data"); return; }
  const d = lastDeepData;
  const host = selectedDev.hostname;
  const now = d.timestamp || new Date().toISOString();

  let md = `# 🧠 AI Deep Analysis Report\n\n`;
  md += `| Field | Value |\n|---|---|\n`;
  md += `| **Device** | \`${host}\` |\n`;
  md += `| **IP** | ${selectedDev.ip} |\n`;
  md += `| **Type** | ${(d.dtype||'').toUpperCase()} |\n`;
  md += `| **Model** | ${d.model || '—'} |\n`;
  md += `| **Version** | ${d.version || '—'} |\n`;
  md += `| **Health Score** | **${d.score}/100 (Grade ${d.grade} — ${d.grade_label})** |\n`;
  md += `| **Report Date** | ${now.slice(0,19).replace('T',' ')} |\n\n`;

  const sc = d.severity_counts || {};
  md += `## Severity Summary\n\n`;
  md += `| Critical | High | Medium | Low | OK |\n|---|---|---|---|---|\n`;
  md += `| ${sc.critical||0} | ${sc.high||0} | ${sc.medium||0} | ${sc.low||0} | ${sc.ok||0} |\n\n`;

  const sevEmoji = { critical:"🔴", high:"🟠", medium:"🟡", low:"⚪", info:"🔵", ok:"🟢" };

  const cats = d.categories || {};
  for (const [catKey, cat] of Object.entries(cats)) {
    if (!cat.items || !cat.items.length) continue;
    md += `## ${cat.icon||''} ${cat.title || catKey}\n\n`;
    cat.items.forEach(item => {
      const emoji = sevEmoji[item.severity] || "•";
      md += `### ${emoji} [${(item.severity||'').toUpperCase()}] ${item.title}\n\n`;
      md += `${item.detail}\n\n`;
      if (item.remediation) {
        md += `**Remediation:**\n\`\`\`\n${item.remediation}\n\`\`\`\n\n`;
      }
    });
  }

  md += `---\n*Generated by DCN Network Tool — AI Deep Analysis Agent*\n`;
  downloadFile(md, `${host}_Deep_Analysis_${ts()}.md`, "text/markdown");
}

// ── AI Log Intelligence ──────────────────────────────────────────────────────
let lastLogData = null;
let logFilterSev = "all";

async function runLogAnalysis() {
  if (!selectedDev) return;
  const panel = document.getElementById("ana-panel");
  const btn = document.getElementById("btn-logs");
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Collecting Logs…';
  panel.innerHTML = `<div style="text-align:center;padding:40px">
    <span class="spin" style="width:28px;height:28px;border-width:3px"></span>
    <div style="color:var(--muted);font-size:12px;margin-top:12px">📜 Collecting last <b>~250 syslog messages</b> via SSH…</div>
    <div style="color:var(--muted);font-size:11px;margin-top:4px">Classifying each message by severity, category, and required action.</div>
  </div>`;
  switchTabById("analysis");
  try {
    const r = await fetch(`${API}/log-analysis`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ ip: selectedDev.ip, dtype: selectedDev.type, hostname: selectedDev.hostname }) });
    const d = await r.json();
    if (d.success) {
      lastLogData = d;
      logFilterSev = "all";
      renderLogAnalysis(d);
      addHistory("log-analysis", "Log Intelligence", true, selectedDev.hostname);
    } else {
      panel.innerHTML = `<div style="color:var(--red);padding:14px">Error: ${d.error}</div>`;
    }
  } catch(e) {
    panel.innerHTML = `<div style="color:var(--red);padding:14px">Fetch error: ${e}</div>`;
  }
  btn.disabled = false; btn.innerHTML = "📜 Log Intelligence";
}

function renderLogAnalysis(d, filter) {
  const sc = d.severity_counts || {};
  const filt = filter || logFilterSev || "all";
  const sevConf = {
    critical: { color: "#f44336", bg: "rgba(244,67,54,.12)", label: "CRIT", icon: "🔴" },
    high:     { color: "var(--red)", bg: "rgba(248,81,73,.12)", label: "HIGH", icon: "🟠" },
    medium:   { color: "var(--yellow)", bg: "rgba(255,193,7,.12)", label: "MED", icon: "🟡" },
    low:      { color: "var(--muted)", bg: "rgba(139,148,158,.1)", label: "LOW", icon: "⚪" },
    info:     { color: "#6b7280", bg: "rgba(107,114,128,.08)", label: "INFO", icon: "💬" },
  };

  // Header with summary
  let html = `
  <div class="asec" style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px 20px">
    <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:12px">
      <span style="font-size:20px">📜</span>
      <span style="font-size:16px;font-weight:700;font-family:Consolas,monospace">${escHtml(d.hostname)}</span>
      <span style="font-size:12px;color:var(--muted)">Log Intelligence — ${d.total_messages} messages analyzed</span>
      <span style="font-size:11px;color:var(--muted);margin-left:auto">${(d.timestamp||'').slice(0,19).replace('T',' ')}</span>
    </div>

    <!-- Severity filter chips -->
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:4px">
      <button class="btn" onclick="logFilterSev='all';renderLogAnalysis(lastLogData,'all')"
        style="font-size:11px;padding:3px 10px;${filt==='all'?'background:var(--accent);color:#fff;border-color:var(--accent)':''}">
        All (${d.total_messages})</button>
      ${Object.entries(sevConf).map(([sev, c]) => {
        const cnt = sc[sev] || 0;
        if (!cnt) return '';
        const active = filt === sev;
        return `<button class="btn" onclick="logFilterSev='${sev}';renderLogAnalysis(lastLogData,'${sev}')"
          style="font-size:11px;padding:3px 10px;${active?`background:${c.color};color:#fff;border-color:${c.color}`:`color:${c.color};border-color:${c.color}`}">
          ${c.icon} ${c.label} (${cnt})</button>`;
      }).join('')}
    </div>
  </div>`;

  // LLM narrative (if available)
  if (d.llm_narrative) {
    const nLines = d.llm_narrative.split("\n").filter(l => l.trim());
    html += `<div style="margin:10px 0;padding:10px 14px;background:rgba(88,166,255,0.08);border-left:3px solid var(--accent);border-radius:4px;">
      <div style="font-size:10px;color:var(--accent);font-weight:600;letter-spacing:0.08em;margin-bottom:6px;">🤖 LLM ANALYSIS (Docker Model Runner)</div>
      ${nLines.map(l => `<div style="font-size:12px;color:var(--muted);line-height:1.6;margin-bottom:2px;">${escHtml(l)}</div>`).join("")}
    </div>`;
  }

  // Action items (deduplicated, critical-first)
  const actions = d.action_items || [];
  if (actions.length > 0) {
    html += `
    <div class="asec">
      <h4 style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span>⚡</span> <span>Action Items</span>
        <span style="font-size:11px;color:var(--muted);font-weight:400">${actions.length} unique issues requiring attention</span>
      </h4>
      ${actions.map(a => {
        const s = sevConf[a.severity] || sevConf.info;
        return `
        <div style="background:${s.bg};border:1px solid var(--border);border-radius:6px;padding:8px 12px;margin:3px 0;display:flex;align-items:center;gap:10px">
          <span style="font-size:12px">${s.icon}</span>
          <span style="color:${s.color};font-size:10px;font-weight:700;padding:1px 5px;border:1px solid ${s.color};border-radius:3px;flex-shrink:0">${s.label}</span>
          <span style="font-weight:600;font-size:12px;flex:1">${escHtml(a.description)}</span>
          <span style="font-size:11px;color:var(--muted);flex-shrink:0">×${a.count}</span>
          <span style="font-size:11px;color:var(--green);flex-shrink:0">${escHtml(a.action)}</span>
        </div>`;
      }).join('')}
    </div>`;
  }

  // Category breakdown bar
  const catCounts = d.category_counts || {};
  const catIcons = {routing:"🌐",interface:"🔌",hardware:"🔩",security:"🔒",system:"💻",lag:"🔗",vpn:"🛡️",auth:"👤",config:"⚙️",monitoring:"📡",compliance:"📋",ntp:"🕐",stp:"🌳",performance:"⚡",redundancy:"🔄",discovery:"🔍",other:"📝"};
  const catEntries = Object.entries(catCounts).sort((a,b) => b[1] - a[1]);
  if (catEntries.length > 0) {
    html += `
    <div class="asec">
      <h4 style="margin-bottom:8px">📊 Category Breakdown</h4>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        ${catEntries.map(([cat, cnt]) => `
          <div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:12px;display:flex;align-items:center;gap:4px">
            <span>${catIcons[cat]||'📌'}</span>
            <span style="font-weight:600">${cat}</span>
            <span style="color:var(--muted)">${cnt}</span>
          </div>`).join('')}
      </div>
    </div>`;
  }

  // Message list (filtered)
  const msgs = (d.messages || []).filter(m => filt === "all" || m.severity === filt);
  html += `
  <div class="asec">
    <h4 style="margin-bottom:8px">📋 Messages ${filt !== 'all' ? `(${filt.toUpperCase()} only)` : ''} — ${msgs.length} shown</h4>
    <div style="max-height:500px;overflow-y:auto;border:1px solid var(--border);border-radius:6px">
      <table style="width:100%;border-collapse:collapse;font-size:11px">
        <thead style="position:sticky;top:0;background:var(--bg2);z-index:1">
          <tr>
            <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border);width:55px">Severity</th>
            <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border);width:80px">Category</th>
            <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border)">Message</th>
            <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border);width:160px">Action</th>
          </tr>
        </thead>
        <tbody>
          ${msgs.map(m => {
            const s = sevConf[m.severity] || sevConf.info;
            return `<tr style="border-bottom:1px solid var(--border);background:${s.bg}">
              <td style="padding:4px 8px;white-space:nowrap"><span style="color:${s.color};font-weight:700;font-size:10px">${s.icon} ${s.label}</span></td>
              <td style="padding:4px 8px;color:var(--muted)">${escHtml(m.category)}</td>
              <td style="padding:4px 8px;font-family:Consolas,monospace;font-size:10px;word-break:break-all;cursor:pointer" title="Click to copy" onclick="navigator.clipboard.writeText(this.textContent.trim())">${escHtml(m.line.length > 200 ? m.line.slice(0,200) + '…' : m.line)}</td>
              <td style="padding:4px 8px;color:var(--green);font-size:10px">${escHtml(m.action)}</td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>
  </div>`;

  // Export button
  html += `
  <div style="text-align:center;padding:10px">
    <button class="btn" onclick="exportLogAnalysis()" style="border-color:#f59e0b;color:#f59e0b">📋 Export Log Intelligence Report (.md)</button>
  </div>`;

  document.getElementById("ana-panel").innerHTML = html;
}

function exportLogAnalysis() {
  if (!lastLogData || !selectedDev) { alert("No log analysis data"); return; }
  const d = lastLogData;
  const host = selectedDev.hostname;
  const now = d.timestamp || new Date().toISOString();

  let md = `# 📜 AI Log Intelligence Report\n\n`;
  md += `| Field | Value |\n|---|---|\n`;
  md += `| **Device** | \`${host}\` |\n`;
  md += `| **Type** | ${(d.dtype||'').toUpperCase()} |\n`;
  md += `| **Total Messages** | ${d.total_messages} |\n`;
  md += `| **Classified (non-info)** | ${d.classified} |\n`;
  md += `| **Report Date** | ${now.slice(0,19).replace('T',' ')} |\n\n`;

  const sc = d.severity_counts || {};
  md += `## Severity Summary\n\n`;
  md += `| Critical | High | Medium | Low | Info |\n|---|---|---|---|---|\n`;
  md += `| ${sc.critical||0} | ${sc.high||0} | ${sc.medium||0} | ${sc.low||0} | ${sc.info||0} |\n\n`;

  const actions = d.action_items || [];
  if (actions.length) {
    md += `## ⚡ Action Items\n\n`;
    md += `| Severity | Category | Issue | Count | Action |\n|---|---|---|---|---|\n`;
    actions.forEach(a => {
      md += `| ${a.severity.toUpperCase()} | ${a.category} | ${a.description} | ${a.count} | ${a.action} |\n`;
    });
    md += '\n';
  }

  const sevEmoji = {critical:"🔴",high:"🟠",medium:"🟡",low:"⚪",info:"💬"};
  const topMsgs = (d.messages||[]).filter(m => m.severity !== "info");
  if (topMsgs.length) {
    md += `## 📋 Classified Messages (${topMsgs.length})\n\n`;
    md += `| Sev | Category | Message | Action |\n|---|---|---|---|\n`;
    topMsgs.forEach(m => {
      const line = m.line.length > 120 ? m.line.slice(0,120) + '…' : m.line;
      md += `| ${sevEmoji[m.severity]||''} ${m.severity.toUpperCase()} | ${m.category} | \`${line.replace(/\|/g,'\\|')}\` | ${m.action} |\n`;
    });
    md += '\n';
  }

  md += `---\n*Generated by DCN Network Tool — AI Log Intelligence Agent*\n`;
  downloadFile(md, `${host}_Log_Intelligence_${ts()}.md`, "text/markdown");
}

// ── 🔮 Config Drift & Compliance ─────────────────────────────────────────────
let lastDriftData = null;
async function runConfigDrift() {
  if (!selectedDev) return;
  const panel = document.getElementById("ana-panel");
  const btn = document.getElementById("btn-drift");
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Auditing…';
  panel.innerHTML = `<div style="text-align:center;padding:40px">
    <span class="spin" style="width:28px;height:28px;border-width:3px"></span>
    <div style="color:var(--muted);font-size:12px;margin-top:12px">🔮 Running <b>18 compliance checks</b> + config drift detection…</div>
  </div>`;
  switchTabById("analysis");
  try {
    const r = await fetch(`${API}/config-drift`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ ip: selectedDev.ip, dtype: selectedDev.type, hostname: selectedDev.hostname }) });
    const d = await r.json();
    if (d.success) { lastDriftData = d; renderConfigDrift(d); addHistory("config-drift", "Config Drift & Compliance", true, selectedDev.hostname); }
    else { panel.innerHTML = `<div style="color:var(--red);padding:14px">Error: ${d.error}</div>`; }
  } catch(e) { panel.innerHTML = `<div style="color:var(--red);padding:14px">Fetch error: ${e}</div>`; }
  btn.disabled = false; btn.innerHTML = "🔮 Config Drift";
}

function renderConfigDrift(d) {
  const gc = d.grade === "A+" || d.grade === "A" ? "#22c55e" : d.grade === "B" ? "#eab308" : d.grade === "C" ? "#f97316" : "#ef4444";
  const statusIcon = { pass: "✅", fail: "❌", warn: "⚠️" };
  const sevColor = { critical: "#f44336", high: "var(--red)", medium: "var(--yellow)", low: "var(--muted)" };

  let html = `
  <div class="asec" style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px 20px">
    <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:14px">
      <span style="font-size:20px">🔮</span>
      <span style="font-size:16px;font-weight:700;font-family:Consolas,monospace">${escHtml(d.hostname)}</span>
      <span style="font-size:12px;color:var(--muted)">Config Drift & Compliance Audit</span>
      <span style="font-size:11px;color:var(--muted);margin-left:auto">${(d.timestamp||'').slice(0,19).replace('T',' ')}</span>
    </div>
    <div style="display:flex;gap:20px;align-items:center;flex-wrap:wrap">
      <div style="text-align:center">
        <svg width="90" height="90" viewBox="0 0 90 90">
          <circle cx="45" cy="45" r="38" fill="none" stroke="var(--border)" stroke-width="6"/>
          <circle cx="45" cy="45" r="38" fill="none" stroke="${gc}" stroke-width="6"
            stroke-dasharray="${d.compliance_score * 2.39} 239" stroke-dashoffset="0"
            transform="rotate(-90 45 45)" stroke-linecap="round"/>
          <text x="45" y="42" text-anchor="middle" fill="${gc}" font-size="22" font-weight="800">${d.compliance_score}</text>
          <text x="45" y="57" text-anchor="middle" fill="var(--muted)" font-size="10">Grade ${d.grade}</text>
        </svg>
      </div>
      <div style="display:flex;gap:12px;flex-wrap:wrap">
        <div style="background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.3);border-radius:8px;padding:8px 14px;text-align:center">
          <div style="font-size:20px;font-weight:800;color:#22c55e">${d.passed}</div><div style="font-size:10px;color:var(--muted)">Passed</div>
        </div>
        <div style="background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);border-radius:8px;padding:8px 14px;text-align:center">
          <div style="font-size:20px;font-weight:800;color:#ef4444">${d.failed}</div><div style="font-size:10px;color:var(--muted)">Failed</div>
        </div>
        <div style="background:rgba(234,179,8,.12);border:1px solid rgba(234,179,8,.3);border-radius:8px;padding:8px 14px;text-align:center">
          <div style="font-size:20px;font-weight:800;color:#eab308">${d.warnings}</div><div style="font-size:10px;color:var(--muted)">Warnings</div>
        </div>
      </div>
      ${d.drift_detected ? `<div style="background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.4);border-radius:8px;padding:8px 14px">
        <span style="font-size:14px">⚠️</span> <span style="color:#ef4444;font-weight:700">${d.drift_count} Config Drift(s) Detected</span>
        <div style="font-size:10px;color:var(--muted)">vs saved: ${d.saved_config_path || 'N/A'}</div>
      </div>` : d.saved_config_found ? `<div style="background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.3);border-radius:8px;padding:8px 14px">
        <span style="font-size:14px">✅</span> <span style="color:#22c55e;font-weight:700">No Config Drift</span>
        <div style="font-size:10px;color:var(--muted)">vs saved: ${d.saved_config_path}</div>
      </div>` : `<div style="background:rgba(139,148,158,.1);border:1px solid var(--border);border-radius:8px;padding:8px 14px">
        <span style="color:var(--muted);font-size:12px">No saved config found for drift comparison</span>
      </div>`}
    </div>
  </div>`;

  // Drift items
  if (d.drift_items && d.drift_items.length > 0 && d.drift_items[0].type !== "info") {
    const typeStyle = { added: { icon: "➕", color: "#22c55e", bg: "rgba(34,197,94,.08)" }, removed: { icon: "➖", color: "#ef4444", bg: "rgba(239,68,68,.08)" }, changed: { icon: "🔄", color: "#f59e0b", bg: "rgba(245,158,11,.08)" }, info: { icon: "ℹ️", color: "var(--muted)", bg: "rgba(139,148,158,.05)" } };
    html += `<div class="asec"><h4 style="margin-bottom:8px">🔄 Config Drift Details</h4>`;
    d.drift_items.forEach(item => {
      const s = typeStyle[item.type] || typeStyle.info;
      html += `<div style="background:${s.bg};border:1px solid var(--border);border-radius:6px;padding:6px 12px;margin:3px 0;display:flex;align-items:center;gap:8px;font-size:12px">
        <span>${s.icon}</span><span style="color:${s.color};font-weight:600;font-size:10px;border:1px solid ${s.color};border-radius:3px;padding:1px 5px">${item.type.toUpperCase()}</span>
        <span style="font-family:Consolas,monospace;font-size:11px">${escHtml(item.line)}</span>
      </div>`;
    });
    html += `</div>`;
  }

  // Compliance checks table
  html += `<div class="asec"><h4 style="margin-bottom:8px">📋 Compliance Checks (${d.total_checks})</h4>
    <div style="max-height:400px;overflow-y:auto;border:1px solid var(--border);border-radius:6px">
      <table style="width:100%;border-collapse:collapse;font-size:11px">
        <thead style="position:sticky;top:0;background:var(--bg2)"><tr>
          <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border);width:30px">✓</th>
          <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border);width:60px">Severity</th>
          <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border)">Check</th>
          <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border)">Detail</th>
          <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border)">Remediation</th>
        </tr></thead><tbody>`;
  (d.checks || []).forEach(c => {
    const bg = c.status === "fail" ? "rgba(239,68,68,.06)" : c.status === "warn" ? "rgba(234,179,8,.06)" : "";
    html += `<tr style="border-bottom:1px solid var(--border);background:${bg}">
      <td style="padding:4px 8px">${statusIcon[c.status]||'❓'}</td>
      <td style="padding:4px 8px;color:${sevColor[c.severity]||'var(--muted)'};font-weight:600;font-size:10px">${c.severity.toUpperCase()}</td>
      <td style="padding:4px 8px;font-weight:600">${escHtml(c.title)}</td>
      <td style="padding:4px 8px;color:var(--muted)">${escHtml(c.detail)}</td>
      <td style="padding:4px 8px;color:var(--green);font-family:Consolas,monospace;font-size:10px">${escHtml(c.remediation)}</td>
    </tr>`;
  });
  html += `</tbody></table></div></div>`;
  html += `<div style="text-align:center;padding:10px"><button class="btn" onclick="exportConfigDrift()" style="border-color:#06b6d4;color:#06b6d4">📋 Export Compliance Report (.md)</button></div>`;
  document.getElementById("ana-panel").innerHTML = html;
}

function exportConfigDrift() {
  if (!lastDriftData || !selectedDev) return;
  const d = lastDriftData, host = selectedDev.hostname;
  let md = `# 🔮 Config Drift & Compliance Report\n\n| Field | Value |\n|---|---|\n`;
  md += `| **Device** | \`${host}\` |\n| **Score** | ${d.compliance_score}/100 (${d.grade}) |\n`;
  md += `| **Passed** | ${d.passed} | \n| **Failed** | ${d.failed} |\n| **Warnings** | ${d.warnings} |\n`;
  md += `| **Drift** | ${d.drift_detected ? d.drift_count + ' change(s)' : 'None'} |\n| **Date** | ${(d.timestamp||'').slice(0,19)} |\n\n`;
  if (d.drift_items && d.drift_items.length) {
    md += `## 🔄 Config Drift\n\n| Type | Detail |\n|---|---|\n`;
    d.drift_items.forEach(i => { md += `| ${i.type.toUpperCase()} | ${i.line} |\n`; });
    md += '\n';
  }
  md += `## 📋 Compliance Checks\n\n| Status | Severity | Check | Detail | Remediation |\n|---|---|---|---|---|\n`;
  (d.checks||[]).forEach(c => { md += `| ${c.status==='pass'?'✅':c.status==='fail'?'❌':'⚠️'} | ${c.severity.toUpperCase()} | ${c.title} | ${c.detail} | \`${c.remediation||'—'}\` |\n`; });
  md += `\n---\n*Generated by DCN Network Tool — Config Drift & Compliance Agent*\n`;
  downloadFile(md, `${host}_Compliance_${ts()}.md`, "text/markdown");
}

// ── 🌐 Topology Discovery ────────────────────────────────────────────────────
let lastTopoData = null;
async function runTopology() {
  if (!selectedDev) return;
  const panel = document.getElementById("ana-panel");
  const btn = document.getElementById("btn-topo");
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Discovering…';
  panel.innerHTML = `<div style="text-align:center;padding:40px">
    <span class="spin" style="width:28px;height:28px;border-width:3px"></span>
    <div style="color:var(--muted);font-size:12px;margin-top:12px">🌐 Discovering neighbors via <b>LLDP, descriptions, BGP, OSPF, ISIS, LACP</b>…</div>
  </div>`;
  switchTabById("analysis");
  try {
    const r = await fetch(`${API}/topology`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ ip: selectedDev.ip, dtype: selectedDev.type, hostname: selectedDev.hostname }) });
    const d = await r.json();
    if (d.success) { lastTopoData = d; renderTopology(d); addHistory("topology", "Topology Discovery", true, selectedDev.hostname); }
    else { panel.innerHTML = `<div style="color:var(--red);padding:14px">Error: ${d.error}</div>`; }
  } catch(e) { panel.innerHTML = `<div style="color:var(--red);padding:14px">Fetch error: ${e}</div>`; }
  btn.disabled = false; btn.innerHTML = "🌐 Topology";
}

function renderTopology(d) {
  const srcIcons = { lldp: "📡", description: "📝", bgp: "🌍", ospf: "🔗", isis: "🔗", lacp: "⛓️", mlag: "🔄" };
  const srcColors = { lldp: "#06b6d4", description: "#8b5cf6", bgp: "#f59e0b", ospf: "#22c55e", isis: "#10b981", lacp: "#a855f7", mlag: "#ec4899" };

  let html = `
  <div class="asec" style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px 20px">
    <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:14px">
      <span style="font-size:20px">🌐</span>
      <span style="font-size:16px;font-weight:700;font-family:Consolas,monospace">${escHtml(d.hostname)}</span>
      <span style="font-size:12px;color:var(--muted)">Topology Discovery — ${d.total_neighbors} connections found</span>
      <span style="font-size:11px;color:var(--muted);margin-left:auto">${(d.timestamp||'').slice(0,19).replace('T',' ')}</span>
    </div>
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:10px">
      <div style="background:rgba(16,185,129,.12);border:1px solid rgba(16,185,129,.3);border-radius:8px;padding:8px 14px;text-align:center">
        <div style="font-size:22px;font-weight:800;color:#10b981">${d.total_neighbors}</div><div style="font-size:10px;color:var(--muted)">Connections</div>
      </div>
      <div style="background:rgba(6,182,212,.12);border:1px solid rgba(6,182,212,.3);border-radius:8px;padding:8px 14px;text-align:center">
        <div style="font-size:22px;font-weight:800;color:#06b6d4">${d.unique_devices}</div><div style="font-size:10px;color:var(--muted)">Unique Devices</div>
      </div>
      ${Object.entries(d.source_counts||{}).map(([src, cnt]) =>
        `<div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:12px;display:flex;align-items:center;gap:4px">
          <span>${srcIcons[src]||'📌'}</span><span style="font-weight:600;color:${srcColors[src]||'var(--fg)'}">${src.toUpperCase()}</span>
          <span style="color:var(--muted)">${cnt}</span>
        </div>`).join('')}
    </div>
  </div>`;

  // Visual topology map (star layout around central device)
  if (d.remote_devices && d.remote_devices.length > 0) {
    const devs = d.remote_devices.slice(0, 30);
    const n = devs.length;
    // Adaptive sizing: bigger nodes + more space when fewer neighbors
    const svgW = 700, svgH = n <= 6 ? 350 : n <= 12 ? 420 : 500;
    const cx = svgW / 2, cy = svgH / 2;
    const rad = n <= 4 ? 120 : n <= 8 ? 140 : n <= 16 ? 165 : 190;
    const nodeR = n <= 6 ? 24 : n <= 12 ? 18 : 14;
    const fontSize = n <= 6 ? 9 : n <= 12 ? 8 : 7;
    const centerR = n <= 6 ? 32 : 26;

    let svg = `<svg width="${svgW}" height="${svgH}" viewBox="0 0 ${svgW} ${svgH}" style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;width:100%">`;
    // Center node
    svg += `<circle cx="${cx}" cy="${cy}" r="${centerR+6}" fill="#06b6d4" opacity="0.1"/>`;
    svg += `<circle cx="${cx}" cy="${cy}" r="${centerR}" fill="#06b6d4" opacity="0.2"/>`;
    svg += `<text x="${cx}" y="${cy-3}" text-anchor="middle" fill="#06b6d4" font-size="${n<=6?11:9}" font-weight="800">${escHtml(d.hostname.split('.')[0])}</text>`;
    svg += `<text x="${cx}" y="${cy+10}" text-anchor="middle" fill="#06b6d4" font-size="7" opacity="0.7">${n} neighbors</text>`;

    devs.forEach((dev, i) => {
      const angle = (2 * Math.PI * i) / n - Math.PI / 2;
      const dx = cx + Math.cos(angle) * rad, dy = cy + Math.sin(angle) * rad;
      // Find all connections for this device and pick best source
      const conns = (d.neighbors||[]).filter(nb => nb.remote_device.toLowerCase().split('.')[0] === dev);
      const conn = conns[0];
      const src = conn ? conn.source : "description";
      const col = srcColors[src] || "#6b7280";
      const linkCount = conns.length;

      // Connection line (thicker if multiple links)
      svg += `<line x1="${cx}" y1="${cy}" x2="${dx}" y2="${dy}" stroke="${col}" stroke-width="${Math.min(linkCount * 1.2 + 0.5, 4)}" opacity="0.45"/>`;

      // Link count label on the line (if >1)
      if (linkCount > 1) {
        const mx = (cx + dx) / 2, my = (cy + dy) / 2;
        svg += `<rect x="${mx-8}" y="${my-6}" width="16" height="12" rx="3" fill="var(--bg2)" stroke="${col}" stroke-width="0.5" opacity="0.9"/>`;
        svg += `<text x="${mx}" y="${my+3}" text-anchor="middle" fill="${col}" font-size="7" font-weight="700">${linkCount}</text>`;
      }

      // Remote node
      svg += `<circle cx="${dx}" cy="${dy}" r="${nodeR+4}" fill="${col}" opacity="0.08"/>`;
      svg += `<circle cx="${dx}" cy="${dy}" r="${nodeR}" fill="${col}" opacity="0.2" stroke="${col}" stroke-width="1" stroke-opacity="0.3"/>`;
      const label = dev.length > 16 ? dev.slice(0,14)+'…' : dev;
      svg += `<text x="${dx}" y="${dy+2}" text-anchor="middle" fill="${col}" font-size="${fontSize}" font-weight="600">${escHtml(label)}</text>`;

      // Source badge below node name (for small topologies)
      if (n <= 8) {
        svg += `<text x="${dx}" y="${dy+12}" text-anchor="middle" fill="${col}" font-size="6" opacity="0.6">${(srcIcons[src]||'')} ${src}</text>`;
      }
    });
    svg += `</svg>`;
    html += `<div class="asec"><h4 style="margin-bottom:8px">🗺️ Topology Map</h4>${svg}</div>`;
  }

  // Neighbor table
  html += `<div class="asec"><h4 style="margin-bottom:8px">📋 All Connections (${d.total_neighbors})</h4>
    <div style="max-height:400px;overflow-y:auto;border:1px solid var(--border);border-radius:6px">
      <table style="width:100%;border-collapse:collapse;font-size:11px">
        <thead style="position:sticky;top:0;background:var(--bg2)"><tr>
          <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border);width:70px">Source</th>
          <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border)">Local Port</th>
          <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border)">Remote Device</th>
          <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border)">Remote Port</th>
          <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border)">Detail</th>
        </tr></thead><tbody>`;
  (d.neighbors||[]).forEach(n => {
    const col = srcColors[n.source] || "var(--muted)";
    html += `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:4px 8px"><span style="color:${col};font-weight:700;font-size:10px;border:1px solid ${col};border-radius:3px;padding:1px 5px">${srcIcons[n.source]||''} ${n.source.toUpperCase()}</span></td>
      <td style="padding:4px 8px;font-family:Consolas,monospace">${escHtml(n.local_port)}</td>
      <td style="padding:4px 8px;font-weight:600">${escHtml(n.remote_device)}</td>
      <td style="padding:4px 8px;font-family:Consolas,monospace;color:var(--muted)">${escHtml(n.remote_port)}</td>
      <td style="padding:4px 8px;color:var(--muted);font-size:10px">${escHtml(n.detail)}</td>
    </tr>`;
  });
  html += `</tbody></table></div></div>`;
  html += `<div style="text-align:center;padding:10px"><button class="btn" onclick="exportTopology()" style="border-color:#10b981;color:#10b981">📋 Export Topology Report (.md)</button></div>`;
  document.getElementById("ana-panel").innerHTML = html;
}

function exportTopology() {
  if (!lastTopoData || !selectedDev) return;
  const d = lastTopoData, host = selectedDev.hostname;
  let md = `# 🌐 Topology Discovery Report\n\n| Field | Value |\n|---|---|\n`;
  md += `| **Device** | \`${host}\` |\n| **Connections** | ${d.total_neighbors} |\n| **Unique Devices** | ${d.unique_devices} |\n`;
  md += `| **Date** | ${(d.timestamp||'').slice(0,19)} |\n\n`;
  md += `## Discovery Sources\n\n`;
  Object.entries(d.source_counts||{}).forEach(([src, cnt]) => { md += `- **${src.toUpperCase()}**: ${cnt}\n`; });
  md += `\n## Connected Devices\n\n${(d.remote_devices||[]).map(d => `- \`${d}\``).join('\n')}\n\n`;
  md += `## All Connections\n\n| Source | Local Port | Remote Device | Remote Port | Detail |\n|---|---|---|---|---|\n`;
  (d.neighbors||[]).forEach(n => { md += `| ${n.source.toUpperCase()} | ${n.local_port} | ${n.remote_device} | ${n.remote_port} | ${n.detail} |\n`; });
  md += `\n---\n*Generated by DCN Network Tool — Topology Discovery Agent*\n`;
  downloadFile(md, `${host}_Topology_${ts()}.md`, "text/markdown");
}

// ── 📊 Capacity Forecasting (renderer — triggered from Port Capacity) ───────
let lastCapData = null;

function renderCapacity(d) {
  const ps = d.port_stats || {};
  const capColor = d.used_pct > 90 ? "#ef4444" : d.used_pct > 75 ? "#f97316" : d.used_pct > 50 ? "#eab308" : "#22c55e";
  const sevConf = { critical:{color:"#f44336",bg:"rgba(244,67,54,.1)",icon:"🔴"}, high:{color:"var(--red)",bg:"rgba(248,81,73,.1)",icon:"🟠"}, medium:{color:"var(--yellow)",bg:"rgba(255,193,7,.1)",icon:"🟡"}, low:{color:"var(--muted)",bg:"rgba(139,148,158,.08)",icon:"⚪"}, ok:{color:"#22c55e",bg:"rgba(34,197,94,.08)",icon:"✅"} };

  let html = `
  <div class="asec" style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px 20px">
    <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:14px">
      <span style="font-size:20px">📊</span>
      <span style="font-size:16px;font-weight:700;font-family:Consolas,monospace">${escHtml(d.hostname)}</span>
      <span style="font-size:12px;color:var(--muted)">Capacity Forecasting</span>
      <span style="font-size:11px;color:var(--muted);margin-left:auto">${(d.timestamp||'').slice(0,19).replace('T',' ')}</span>
    </div>
    <div style="display:flex;gap:20px;align-items:center;flex-wrap:wrap">
      <div style="text-align:center">
        <svg width="90" height="90" viewBox="0 0 90 90">
          <circle cx="45" cy="45" r="38" fill="none" stroke="var(--border)" stroke-width="6"/>
          <circle cx="45" cy="45" r="38" fill="none" stroke="${capColor}" stroke-width="6"
            stroke-dasharray="${d.used_pct * 2.39} 239" stroke-dashoffset="0"
            transform="rotate(-90 45 45)" stroke-linecap="round"/>
          <text x="45" y="42" text-anchor="middle" fill="${capColor}" font-size="18" font-weight="800">${d.used_pct}%</text>
          <text x="45" y="57" text-anchor="middle" fill="var(--muted)" font-size="9">Port Use</text>
        </svg>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <div style="background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.3);border-radius:8px;padding:8px 14px;text-align:center">
          <div style="font-size:18px;font-weight:800;color:#22c55e">${ps.up||0}</div><div style="font-size:10px;color:var(--muted)">Up</div>
        </div>
        <div style="background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);border-radius:8px;padding:8px 14px;text-align:center">
          <div style="font-size:18px;font-weight:800;color:#ef4444">${ps.down||0}</div><div style="font-size:10px;color:var(--muted)">Down</div>
        </div>
        <div style="background:rgba(139,148,158,.1);border:1px solid var(--border);border-radius:8px;padding:8px 14px;text-align:center">
          <div style="font-size:18px;font-weight:800;color:var(--muted)">${ps.admin_down||0}</div><div style="font-size:10px;color:var(--muted)">Admin Off</div>
        </div>
        <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:8px 14px;text-align:center">
          <div style="font-size:18px;font-weight:800">${ps.total||0}</div><div style="font-size:10px;color:var(--muted)">Total</div>
        </div>
      </div>
      ${Object.keys(d.speed_breakdown||{}).length > 0 ? `<div style="display:flex;gap:6px;flex-wrap:wrap">${Object.entries(d.speed_breakdown).map(([spd,cnt]) =>
        `<span style="background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:3px 8px;font-size:11px;font-family:Consolas,monospace">${spd}: ${cnt}</span>`).join('')}</div>` : ''}
    </div>
  </div>`;

  // Findings
  if (d.findings && d.findings.length) {
    html += `<div class="asec"><h4 style="margin-bottom:8px">📋 Findings</h4>`;
    d.findings.forEach(f => {
      const s = sevConf[f.severity] || sevConf.ok;
      html += `<div style="background:${s.bg};border:1px solid var(--border);border-radius:6px;padding:8px 12px;margin:3px 0;display:flex;align-items:center;gap:10px">
        <span style="font-size:12px">${s.icon}</span>
        <span style="font-weight:600;font-size:12px;flex:1">${escHtml(f.title)}</span>
        <span style="font-size:11px;color:var(--muted)">${escHtml(f.detail)}</span>
      </div>`;
    });
    html += `</div>`;
  }

  // Utilization bar chart (top 20 ports)
  const util = d.utilization_top20 || [];
  if (util.length > 0) {
    html += `<div class="asec"><h4 style="margin-bottom:8px">📈 Top Port Utilization</h4>
      <div style="max-height:350px;overflow-y:auto">`;
    util.forEach(p => {
      const pct = p.max_pct;
      const bc = pct > 90 ? "#ef4444" : pct > 80 ? "#f97316" : pct > 70 ? "#eab308" : pct > 50 ? "#06b6d4" : "#22c55e";
      html += `<div style="display:flex;align-items:center;gap:8px;margin:2px 0;font-size:11px">
        <span style="width:110px;font-family:Consolas,monospace;flex-shrink:0">${escHtml(p.port)}</span>
        <div style="flex:1;height:16px;background:var(--bg3);border-radius:3px;overflow:hidden;position:relative">
          <div style="width:${Math.min(pct,100)}%;height:100%;background:${bc};border-radius:3px;opacity:0.7"></div>
          <span style="position:absolute;left:4px;top:1px;font-size:9px;font-weight:700;color:#fff;text-shadow:0 0 2px #000">${pct}%</span>
        </div>
        <span style="width:70px;text-align:right;color:var(--muted);font-size:10px">IN:${p.in_pct}% OUT:${p.out_pct}%</span>
      </div>`;
    });
    html += `</div></div>`;
  }

  // Forecasts
  if (d.forecasts && d.forecasts.length > 0) {
    html += `<div class="asec"><h4 style="margin-bottom:8px">🔮 Capacity Forecasts (est. 5%/quarter growth)</h4>
      <div style="border:1px solid var(--border);border-radius:6px;overflow:hidden">
        <table style="width:100%;border-collapse:collapse;font-size:11px">
          <thead style="background:var(--bg2)"><tr>
            <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border)">Port</th>
            <th style="padding:6px 8px;text-align:center;border-bottom:1px solid var(--border)">Current</th>
            <th style="padding:6px 8px;text-align:center;border-bottom:1px solid var(--border)">Est. Q to 80%</th>
            <th style="padding:6px 8px;text-align:center;border-bottom:1px solid var(--border)">Est. Q to 100%</th>
            <th style="padding:6px 8px;text-align:center;border-bottom:1px solid var(--border)">Action</th>
          </tr></thead><tbody>`;
    d.forecasts.forEach(f => {
      const ac = f.recommendation === "Upgrade soon" ? "#ef4444" : f.recommendation === "Monitor" ? "#eab308" : "#22c55e";
      html += `<tr style="border-bottom:1px solid var(--border)">
        <td style="padding:4px 8px;font-family:Consolas,monospace">${escHtml(f.port)}</td>
        <td style="padding:4px 8px;text-align:center;font-weight:700">${f.current_pct}%</td>
        <td style="padding:4px 8px;text-align:center">${f.est_quarters_to_80}Q</td>
        <td style="padding:4px 8px;text-align:center">${f.est_quarters_to_100}Q</td>
        <td style="padding:4px 8px;text-align:center;color:${ac};font-weight:700;font-size:10px">${f.recommendation}</td>
      </tr>`;
    });
    html += `</tbody></table></div></div>`;
  }

  html += `<div style="text-align:center;padding:10px"><button class="btn" onclick="exportCapacity()" style="border-color:#8b5cf6;color:#8b5cf6">📋 Export Capacity Report (.md)</button></div>`;
  document.getElementById("ana-panel").innerHTML = html;
}

function exportCapacity() {
  if (!lastCapData || !selectedDev) return;
  const d = lastCapData, host = selectedDev.hostname, ps = d.port_stats||{};
  let md = `# 📊 Capacity Forecasting Report\n\n| Field | Value |\n|---|---|\n`;
  md += `| **Device** | \`${host}\` |\n| **Port Utilization** | ${d.used_pct}% |\n`;
  md += `| **Up/Down/Admin** | ${ps.up}/${ps.down}/${ps.admin_down} of ${ps.total} |\n| **Date** | ${(d.timestamp||'').slice(0,19)} |\n\n`;
  if (d.findings) {
    md += `## Findings\n\n`;
    d.findings.forEach(f => { md += `- **[${f.severity.toUpperCase()}]** ${f.title} — ${f.detail}\n`; });
    md += '\n';
  }
  if ((d.utilization_top20||[]).length) {
    md += `## Top Port Utilization\n\n| Port | IN% | OUT% | Max% |\n|---|---|---|---|\n`;
    d.utilization_top20.forEach(p => { md += `| ${p.port} | ${p.in_pct} | ${p.out_pct} | ${p.max_pct} |\n`; });
    md += '\n';
  }
  if ((d.forecasts||[]).length) {
    md += `## Forecasts\n\n| Port | Current | Q to 80% | Q to 100% | Action |\n|---|---|---|---|---|\n`;
    d.forecasts.forEach(f => { md += `| ${f.port} | ${f.current_pct}% | ${f.est_quarters_to_80}Q | ${f.est_quarters_to_100}Q | ${f.recommendation} |\n`; });
    md += '\n';
  }
  md += `---\n*Generated by DCN Network Tool — Capacity Forecasting Agent*\n`;
  downloadFile(md, `${host}_Capacity_${ts()}.md`, "text/markdown");
}

// ── 🔐 Security Posture Audit ────────────────────────────────────────────────
let lastSecData = null;
async function runSecurityAudit() {
  if (!selectedDev) return;
  const panel = document.getElementById("ana-panel");
  const btn = document.getElementById("btn-sec");
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Scanning…';
  panel.innerHTML = `<div style="text-align:center;padding:40px">
    <span class="spin" style="width:28px;height:28px;border-width:3px"></span>
    <div style="color:var(--muted);font-size:12px;margin-top:12px">🔐 Deep security scan: <b>firmware CVE, crypto, ACL, users, SNMP, BGP, VPN</b>…</div>
  </div>`;
  switchTabById("analysis");
  try {
    const r = await fetch(`${API}/security-audit`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ ip: selectedDev.ip, dtype: selectedDev.type, hostname: selectedDev.hostname }) });
    const d = await r.json();
    if (d.success) { lastSecData = d; renderSecurityAudit(d); addHistory("security-audit", "Security Posture Audit", true, selectedDev.hostname); }
    else { panel.innerHTML = `<div style="color:var(--red);padding:14px">Error: ${d.error}</div>`; }
  } catch(e) { panel.innerHTML = `<div style="color:var(--red);padding:14px">Fetch error: ${e}</div>`; }
  btn.disabled = false; btn.innerHTML = "🔐 Security";
}

function renderSecurityAudit(d) {
  const gc = d.grade === "A+" || d.grade === "A" ? "#22c55e" : d.grade === "B" ? "#eab308" : d.grade === "C" ? "#f97316" : "#ef4444";
  const riskColor = { CRITICAL: "#f44336", HIGH: "#ef4444", MEDIUM: "#f59e0b", LOW: "#22c55e" };
  const rc = riskColor[d.risk_level] || "#6b7280";
  const sevConf = { critical:{color:"#f44336",bg:"rgba(244,67,54,.1)",icon:"🔴",label:"CRIT"}, high:{color:"var(--red)",bg:"rgba(248,81,73,.1)",icon:"🟠",label:"HIGH"}, medium:{color:"var(--yellow)",bg:"rgba(255,193,7,.1)",icon:"🟡",label:"MED"}, low:{color:"var(--muted)",bg:"rgba(139,148,158,.08)",icon:"⚪",label:"LOW"}, ok:{color:"#22c55e",bg:"rgba(34,197,94,.08)",icon:"✅",label:"OK"} };
  const catIcons = { firmware:"💾", crypto:"🔑", access:"👤", snmp:"📡", firewall:"🛡️", management:"⚙️", logging:"📝", ntp:"🕐", routing:"🌐", vpn:"🔒" };

  let html = `
  <div class="asec" style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px 20px">
    <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:14px">
      <span style="font-size:20px">🔐</span>
      <span style="font-size:16px;font-weight:700;font-family:Consolas,monospace">${escHtml(d.hostname)}</span>
      <span style="font-size:12px;color:var(--muted)">Security Posture Audit</span>
      <span style="font-size:11px;color:var(--muted);margin-left:auto">${(d.timestamp||'').slice(0,19).replace('T',' ')}</span>
    </div>
    <div style="display:flex;gap:20px;align-items:center;flex-wrap:wrap">
      <div style="text-align:center">
        <svg width="90" height="90" viewBox="0 0 90 90">
          <circle cx="45" cy="45" r="38" fill="none" stroke="var(--border)" stroke-width="6"/>
          <circle cx="45" cy="45" r="38" fill="none" stroke="${gc}" stroke-width="6"
            stroke-dasharray="${d.security_score * 2.39} 239" stroke-dashoffset="0"
            transform="rotate(-90 45 45)" stroke-linecap="round"/>
          <text x="45" y="42" text-anchor="middle" fill="${gc}" font-size="22" font-weight="800">${d.security_score}</text>
          <text x="45" y="57" text-anchor="middle" fill="var(--muted)" font-size="10">Grade ${d.grade}</text>
        </svg>
      </div>
      <div style="background:${rc}22;border:2px solid ${rc};border-radius:10px;padding:10px 20px;text-align:center">
        <div style="font-size:11px;color:var(--muted)">Risk Level</div>
        <div style="font-size:20px;font-weight:900;color:${rc}">${d.risk_level}</div>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <div style="background:rgba(244,67,54,.12);border-radius:8px;padding:6px 12px;text-align:center"><div style="font-size:16px;font-weight:800;color:#f44336">${d.critical}</div><div style="font-size:9px;color:var(--muted)">Critical</div></div>
        <div style="background:rgba(248,81,73,.12);border-radius:8px;padding:6px 12px;text-align:center"><div style="font-size:16px;font-weight:800;color:var(--red)">${d.high}</div><div style="font-size:9px;color:var(--muted)">High</div></div>
        <div style="background:rgba(255,193,7,.12);border-radius:8px;padding:6px 12px;text-align:center"><div style="font-size:16px;font-weight:800;color:var(--yellow)">${d.medium}</div><div style="font-size:9px;color:var(--muted)">Medium</div></div>
        <div style="background:rgba(34,197,94,.12);border-radius:8px;padding:6px 12px;text-align:center"><div style="font-size:16px;font-weight:800;color:#22c55e">${d.passed}</div><div style="font-size:9px;color:var(--muted)">Passed</div></div>
      </div>
      ${d.firmware_version ? `<div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:12px">💾 <span style="font-family:Consolas,monospace">${escHtml(d.firmware_version)}</span></div>` : ''}
    </div>
  </div>`;

  // Category summary bar
  const cats = d.category_summary || {};
  if (Object.keys(cats).length > 0) {
    html += `<div class="asec"><h4 style="margin-bottom:8px">📊 Category Summary</h4>
      <div style="display:flex;gap:8px;flex-wrap:wrap">`;
    Object.entries(cats).forEach(([cat, v]) => {
      const total = v.pass + v.fail;
      const pct = total ? Math.round(v.pass / total * 100) : 0;
      const col = pct === 100 ? "#22c55e" : pct >= 50 ? "#eab308" : "#ef4444";
      html += `<div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:12px;display:flex;align-items:center;gap:6px">
        <span>${catIcons[cat]||'📌'}</span><span style="font-weight:600">${cat}</span>
        <span style="color:${col};font-weight:700">${v.pass}/${total}</span>
      </div>`;
    });
    html += `</div></div>`;
  }

  // LLM narrative (if available)
  if (d.llm_narrative) {
    const nLines = d.llm_narrative.split("\n").filter(l => l.trim());
    html += `<div style="margin:10px 0;padding:10px 14px;background:rgba(88,166,255,0.08);border-left:3px solid var(--accent);border-radius:4px;">
      <div style="font-size:10px;color:var(--accent);font-weight:600;letter-spacing:0.08em;margin-bottom:6px;">🤖 LLM SECURITY ANALYSIS (Docker Model Runner)</div>
      ${nLines.map(l => `<div style="font-size:12px;color:var(--muted);line-height:1.6;margin-bottom:2px;">${escHtml(l)}</div>`).join("")}
    </div>`;
  }

  // Findings (failures first, then warnings, then OK)
  const sorted = [...(d.findings||[])].sort((a,b) => {
    const ord = {critical:0,high:1,medium:2,low:3,ok:4};
    return (ord[a.severity]||5) - (ord[b.severity]||5);
  });
  html += `<div class="asec"><h4 style="margin-bottom:8px">🔍 Security Findings (${d.total_checks})</h4>`;
  sorted.forEach(f => {
    const s = sevConf[f.severity] || sevConf.ok;
    html += `<div style="background:${s.bg};border:1px solid var(--border);border-radius:6px;padding:8px 12px;margin:3px 0;display:flex;align-items:flex-start;gap:10px">
      <span style="font-size:12px;flex-shrink:0">${s.icon}</span>
      <span style="color:${s.color};font-size:10px;font-weight:700;padding:1px 5px;border:1px solid ${s.color};border-radius:3px;flex-shrink:0">${s.label}</span>
      <div style="flex:1;min-width:0">
        <div style="font-weight:600;font-size:12px">${escHtml(f.title)}</div>
        <div style="font-size:11px;color:var(--muted)">${escHtml(f.detail)}</div>
        ${f.remediation ? `<div style="font-size:10px;color:var(--green);font-family:Consolas,monospace;margin-top:2px">${escHtml(f.remediation)}</div>` : ''}
      </div>
      <span style="background:var(--bg3);border-radius:4px;padding:2px 6px;font-size:10px;color:var(--muted);flex-shrink:0">${catIcons[f.category]||''} ${f.category}</span>
    </div>`;
  });
  html += `</div>`;

  html += `<div style="text-align:center;padding:10px"><button class="btn" onclick="exportSecurityAudit()" style="border-color:#ef4444;color:#ef4444">📋 Export Security Report (.md)</button></div>`;
  document.getElementById("ana-panel").innerHTML = html;
}

function exportSecurityAudit() {
  if (!lastSecData || !selectedDev) return;
  const d = lastSecData, host = selectedDev.hostname;
  let md = `# 🔐 Security Posture Audit Report\n\n| Field | Value |\n|---|---|\n`;
  md += `| **Device** | \`${host}\` |\n| **Security Score** | ${d.security_score}/100 (${d.grade}) |\n`;
  md += `| **Risk Level** | ${d.risk_level} |\n| **Firmware** | ${d.firmware_version||'N/A'} |\n`;
  md += `| **Critical** | ${d.critical} | \n| **High** | ${d.high} |\n| **Medium** | ${d.medium} |\n| **Passed** | ${d.passed} |\n`;
  md += `| **Date** | ${(d.timestamp||'').slice(0,19)} |\n\n`;
  const sevEmoji = {critical:"🔴",high:"🟠",medium:"🟡",low:"⚪",ok:"✅"};
  md += `## Security Findings\n\n| Sev | Category | Finding | Detail | Remediation |\n|---|---|---|---|---|\n`;
  (d.findings||[]).forEach(f => {
    md += `| ${sevEmoji[f.severity]||''} ${f.severity.toUpperCase()} | ${f.category} | ${f.title} | ${f.detail} | \`${f.remediation||'—'}\` |\n`;
  });
  md += `\n---\n*Generated by DCN Network Tool — Security Posture Audit Agent*\n`;
  downloadFile(md, `${host}_Security_Audit_${ts()}.md`, "text/markdown");
}

// ── 🔬 Hardware & Optics (PyEZ NETCONF) ──────────────────────────────────────
let lastPyezData = null;

async function runPyezStats() {
  if (!selectedDev) return;
  if (selectedDev.type !== "junos") {
    document.getElementById("ana-panel").innerHTML = '<div style="color:var(--yellow);padding:14px">⚠️ Hardware & Optics (PyEZ) is only available for Junos devices. This device is ' + escHtml(selectedDev.type) + '.</div>';
    switchTabById("analysis");
    return;
  }
  const panel = document.getElementById("ana-panel");
  const btn = document.getElementById("btn-pyez");
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Collecting…';
  panel.innerHTML = `<div style="text-align:center;padding:40px">
    <span class="spin" style="width:28px;height:28px;border-width:3px"></span>
    <div style="color:var(--muted);font-size:12px;margin-top:12px">🔬 Collecting structured statistics via <b>NETCONF</b>…</div>
    <div style="color:var(--muted);font-size:11px;margin-top:4px">FPC health · Port stats (bps/pps) · Optic diagnostics · Error counters · Storage</div>
    <div style="color:var(--muted);font-size:11px;margin-top:4px">This may take 20-40 seconds.</div>
  </div>`;
  switchTabById("analysis");
  try {
    const r = await fetch(`${API}/device/pyez-stats/${encodeURIComponent(selectedDev.hostname)}`);
    const d = await r.json();
    if (d.success) {
      lastPyezData = d;
      renderPyezStats(d);
      addHistory("pyez-stats", "Hardware & Optics", true, selectedDev.hostname);
    } else {
      panel.innerHTML = `<div style="color:var(--red);padding:14px">Error: ${escHtml(d.error)}${d.hint ? '<br><span style="color:var(--muted);font-size:11px">' + escHtml(d.hint) + '</span>' : ''}</div>`;
    }
  } catch(e) {
    panel.innerHTML = `<div style="color:var(--red);padding:14px">Fetch error: ${e}</div>`;
  }
  btn.disabled = false; btn.innerHTML = "🔬 Hardware";
}

function renderPyezStats(d) {
  const fmtBps = (bps) => {
    if (!bps || bps === 0) return "0";
    if (bps >= 1e9) return (bps/1e9).toFixed(2) + " Gbps";
    if (bps >= 1e6) return (bps/1e6).toFixed(1) + " Mbps";
    if (bps >= 1e3) return (bps/1e3).toFixed(0) + " Kbps";
    return bps + " bps";
  };
  const fmtPps = (pps) => {
    if (!pps || pps === 0) return "0";
    if (pps >= 1e6) return (pps/1e6).toFixed(2) + "M";
    if (pps >= 1e3) return (pps/1e3).toFixed(1) + "K";
    return pps.toString();
  };
  const fmtBytes = (b) => {
    if (!b || b === 0) return "0";
    if (b >= 1e15) return (b/1e15).toFixed(2) + " PB";
    if (b >= 1e12) return (b/1e12).toFixed(2) + " TB";
    if (b >= 1e9) return (b/1e9).toFixed(1) + " GB";
    if (b >= 1e6) return (b/1e6).toFixed(1) + " MB";
    return (b/1e3).toFixed(0) + " KB";
  };

  // Header
  let html = `
  <div class="asec" style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px 20px">
    <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:14px">
      <span style="font-size:20px">🔬</span>
      <span style="font-size:16px;font-weight:700;font-family:Consolas,monospace">${escHtml(d.hostname || '')}</span>
      <span style="font-size:12px;color:var(--muted)">Hardware & Optics via NETCONF (PyEZ)</span>
      ${d.from_cache ? '<span style="font-size:10px;color:var(--yellow);border:1px solid var(--yellow);border-radius:3px;padding:1px 5px">CACHED</span>' : ''}
      <span style="font-size:11px;color:var(--muted);margin-left:auto">${d.collection_time_s}s collection</span>
    </div>
    <div style="display:flex;gap:12px;flex-wrap:wrap">
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:8px 14px;font-size:12px">
        <span style="color:var(--muted)">Model</span> <span style="font-weight:700;font-family:Consolas,monospace">${escHtml(d.model || 'N/A')}</span>
      </div>
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:8px 14px;font-size:12px">
        <span style="color:var(--muted)">Version</span> <span style="font-weight:700;font-family:Consolas,monospace">${escHtml(d.version || 'N/A')}</span>
      </div>
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:8px 14px;font-size:12px">
        <span style="color:var(--muted)">Serial</span> <span style="font-weight:700;font-family:Consolas,monospace">${escHtml(d.serial || 'N/A')}</span>
      </div>
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:8px 14px;font-size:12px">
        <span style="color:var(--muted)">Uptime</span> <span style="font-weight:700">${escHtml(d.uptime || 'N/A')}</span>
      </div>
    </div>
  </div>`;

  // ── FPC Health ──
  const fpcs = (d.fpc_health && d.fpc_health.data) || [];
  if (fpcs.length > 0) {
    html += `<div class="asec"><h4 style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
      <span>🔩</span> <span>FPC / Linecard Health</span>
      <span style="font-size:11px;color:var(--muted);font-weight:400">${fpcs.length} slot(s)</span>
    </h4>
    <div style="display:flex;gap:10px;flex-wrap:wrap">`;
    fpcs.forEach(fpc => {
      const statusCol = fpc.status === "critical" ? "#ef4444" : fpc.status === "warning" ? "#eab308" : "#22c55e";
      const cpuCol = fpc.cpu_percent > 90 ? "#ef4444" : fpc.cpu_percent > 75 ? "#eab308" : "#22c55e";
      const memCol = fpc.memory_percent > 90 ? "#ef4444" : fpc.memory_percent > 75 ? "#eab308" : "#22c55e";
      html += `
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:10px 14px;min-width:140px;border-left:3px solid ${statusCol}">
        <div style="font-weight:700;font-size:13px;margin-bottom:6px">FPC ${escHtml(fpc.slot)}</div>
        <div style="font-size:11px;color:${statusCol};font-weight:600;margin-bottom:4px">${escHtml(fpc.state)}</div>
        <div style="display:flex;gap:12px">
          <div><div style="font-size:9px;color:var(--muted)">CPU</div>
            <div style="font-size:14px;font-weight:800;color:${cpuCol}">${fpc.cpu_percent}%</div>
          </div>
          <div><div style="font-size:9px;color:var(--muted)">Memory</div>
            <div style="font-size:14px;font-weight:800;color:${memCol}">${fpc.memory_percent}%</div>
          </div>
        </div>
      </div>`;
    });
    html += `</div></div>`;
  }

  // ── Optic Diagnostics ──
  const optics = (d.optics && d.optics.data) || [];
  if (optics.length > 0) {
    const warnCount = optics.filter(o => o.status === "warning").length;
    const critCount = optics.filter(o => o.status === "critical").length;
    html += `<div class="asec"><h4 style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
      <span>💡</span> <span>Optic Diagnostics</span>
      <span style="font-size:11px;color:var(--muted);font-weight:400">${optics.length} transceivers</span>
      ${critCount > 0 ? `<span style="font-size:10px;color:#ef4444;font-weight:700;border:1px solid #ef4444;border-radius:3px;padding:1px 5px">${critCount} CRITICAL</span>` : ''}
      ${warnCount > 0 ? `<span style="font-size:10px;color:#eab308;font-weight:700;border:1px solid #eab308;border-radius:3px;padding:1px 5px">${warnCount} WARNING</span>` : ''}
      ${critCount === 0 && warnCount === 0 ? '<span style="font-size:10px;color:#22c55e;font-weight:700">ALL OK</span>' : ''}
    </h4>
    <div style="border:1px solid var(--border);border-radius:6px;overflow:hidden">
      <table style="width:100%;border-collapse:collapse;font-size:11px">
        <thead style="background:var(--bg2)"><tr>
          <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border)">Port</th>
          <th style="padding:6px 8px;text-align:right;border-bottom:1px solid var(--border)">RX Power</th>
          <th style="padding:6px 8px;text-align:right;border-bottom:1px solid var(--border)">TX Power</th>
          <th style="padding:6px 8px;text-align:right;border-bottom:1px solid var(--border)">Temp</th>
          <th style="padding:6px 8px;text-align:right;border-bottom:1px solid var(--border)">Voltage</th>
          <th style="padding:6px 8px;text-align:center;border-bottom:1px solid var(--border)">Status</th>
        </tr></thead><tbody>`;
    optics.forEach(o => {
      const sc = o.status === "critical" ? "#ef4444" : o.status === "warning" ? "#eab308" : "#22c55e";
      const bg = o.status === "critical" ? "rgba(239,68,68,.06)" : o.status === "warning" ? "rgba(234,179,8,.06)" : "";
      html += `<tr style="border-bottom:1px solid var(--border);background:${bg}">
        <td style="padding:4px 8px;font-family:Consolas,monospace;font-weight:600">${escHtml(o.name)}</td>
        <td style="padding:4px 8px;text-align:right;font-family:Consolas,monospace">${o.rx_power_dbm != null ? o.rx_power_dbm.toFixed(2) + ' dBm' : '—'}</td>
        <td style="padding:4px 8px;text-align:right;font-family:Consolas,monospace">${o.tx_power_dbm != null ? o.tx_power_dbm.toFixed(2) + ' dBm' : '—'}</td>
        <td style="padding:4px 8px;text-align:right">${o.temperature_c != null ? o.temperature_c + '°C' : '—'}</td>
        <td style="padding:4px 8px;text-align:right">${o.voltage_v != null ? o.voltage_v.toFixed(3) + 'V' : '—'}</td>
        <td style="padding:4px 8px;text-align:center;color:${sc};font-weight:700;font-size:10px">${o.status === 'ok' ? '✅ OK' : o.status === 'warning' ? '⚠️ WARN' : '🔴 CRIT'}</td>
      </tr>`;
    });
    html += `</tbody></table></div></div>`;
  }

  // ── Port Statistics ──
  const ports = (d.port_stats && d.port_stats.data) || [];
  if (ports.length > 0) {
    // Sort by rx_bps descending
    const sorted = [...ports].sort((a,b) => (b.rx_bps + b.tx_bps) - (a.rx_bps + a.tx_bps));
    html += `<div class="asec"><h4 style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
      <span>📊</span> <span>Real-Time Port Statistics</span>
      <span style="font-size:11px;color:var(--muted);font-weight:400">${ports.length} ports</span>
    </h4>
    <div style="max-height:400px;overflow-y:auto;border:1px solid var(--border);border-radius:6px">
      <table style="width:100%;border-collapse:collapse;font-size:11px">
        <thead style="position:sticky;top:0;background:var(--bg2)"><tr>
          <th style="padding:6px 8px;text-align:left;border-bottom:1px solid var(--border)">Port</th>
          <th style="padding:6px 8px;text-align:right;border-bottom:1px solid var(--border)">RX Rate</th>
          <th style="padding:6px 8px;text-align:right;border-bottom:1px solid var(--border)">TX Rate</th>
          <th style="padding:6px 8px;text-align:right;border-bottom:1px solid var(--border)">RX pps</th>
          <th style="padding:6px 8px;text-align:right;border-bottom:1px solid var(--border)">TX pps</th>
          <th style="padding:6px 8px;text-align:right;border-bottom:1px solid var(--border)">RX Total</th>
          <th style="padding:6px 8px;text-align:right;border-bottom:1px solid var(--border)">TX Total</th>
          <th style="padding:6px 8px;text-align:right;border-bottom:1px solid var(--border)">Errors</th>
        </tr></thead><tbody>`;
    sorted.forEach(p => {
      const errCol = (p.rx_errors + p.rx_drops) > 0 ? "#ef4444" : "var(--muted)";
      html += `<tr style="border-bottom:1px solid var(--border)">
        <td style="padding:4px 8px;font-family:Consolas,monospace;font-weight:600">${escHtml(p.name)}</td>
        <td style="padding:4px 8px;text-align:right;font-family:Consolas,monospace;color:#06b6d4">${fmtBps(p.rx_bps)}</td>
        <td style="padding:4px 8px;text-align:right;font-family:Consolas,monospace;color:#a855f7">${fmtBps(p.tx_bps)}</td>
        <td style="padding:4px 8px;text-align:right;color:var(--muted)">${fmtPps(p.rx_pps)}</td>
        <td style="padding:4px 8px;text-align:right;color:var(--muted)">${fmtPps(p.tx_pps)}</td>
        <td style="padding:4px 8px;text-align:right;color:var(--muted);font-size:10px">${fmtBytes(p.rx_bytes)}</td>
        <td style="padding:4px 8px;text-align:right;color:var(--muted);font-size:10px">${fmtBytes(p.tx_bytes)}</td>
        <td style="padding:4px 8px;text-align:right;color:${errCol};font-weight:${(p.rx_errors+p.rx_drops)>0?'700':'400'}">${p.rx_errors + p.rx_drops > 0 ? (p.rx_errors + p.rx_drops) : '—'}</td>
      </tr>`;
    });
    html += `</tbody></table></div></div>`;
  }

  // ── Detailed Error Counters ──
  const errors = (d.port_errors && d.port_errors.data) || [];
  const portsWithErrors = errors.filter(e => e.has_errors);
  if (portsWithErrors.length > 0) {
    html += `<div class="asec"><h4 style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
      <span>⚠️</span> <span>Ports with Errors</span>
      <span style="font-size:11px;color:#ef4444;font-weight:700">${portsWithErrors.length} of ${errors.length} ports</span>
    </h4>
    <div style="max-height:350px;overflow-y:auto;border:1px solid var(--border);border-radius:6px">
      <table style="width:100%;border-collapse:collapse;font-size:10px">
        <thead style="position:sticky;top:0;background:var(--bg2)"><tr>
          <th style="padding:5px 6px;text-align:left;border-bottom:1px solid var(--border)">Port</th>
          <th style="padding:5px 6px;text-align:right;border-bottom:1px solid var(--border)">RX Errors</th>
          <th style="padding:5px 6px;text-align:right;border-bottom:1px solid var(--border)">RX Drops</th>
          <th style="padding:5px 6px;text-align:right;border-bottom:1px solid var(--border)">CRC/Frame</th>
          <th style="padding:5px 6px;text-align:right;border-bottom:1px solid var(--border)">Runts</th>
          <th style="padding:5px 6px;text-align:right;border-bottom:1px solid var(--border)">FIFO</th>
          <th style="padding:5px 6px;text-align:right;border-bottom:1px solid var(--border)">TX Errors</th>
          <th style="padding:5px 6px;text-align:right;border-bottom:1px solid var(--border)">TX Drops</th>
          <th style="padding:5px 6px;text-align:right;border-bottom:1px solid var(--border)">Collisions</th>
          <th style="padding:5px 6px;text-align:right;border-bottom:1px solid var(--border)">Total</th>
        </tr></thead><tbody>`;
    portsWithErrors.sort((a,b) => b.total_errors - a.total_errors).forEach(e => {
      const v = (val) => val > 0 ? `<span style="color:#ef4444;font-weight:700">${val.toLocaleString()}</span>` : '<span style="color:var(--muted)">—</span>';
      html += `<tr style="border-bottom:1px solid var(--border);background:rgba(239,68,68,.04)">
        <td style="padding:3px 6px;font-family:Consolas,monospace;font-weight:600">${escHtml(e.name)}</td>
        <td style="padding:3px 6px;text-align:right">${v(e.rx_errors)}</td>
        <td style="padding:3px 6px;text-align:right">${v(e.rx_drops)}</td>
        <td style="padding:3px 6px;text-align:right">${v(e.rx_frame_errors)}</td>
        <td style="padding:3px 6px;text-align:right">${v(e.rx_runts)}</td>
        <td style="padding:3px 6px;text-align:right">${v(e.rx_fifo_errors)}</td>
        <td style="padding:3px 6px;text-align:right">${v(e.tx_errors)}</td>
        <td style="padding:3px 6px;text-align:right">${v(e.tx_drops)}</td>
        <td style="padding:3px 6px;text-align:right">${v(e.tx_collisions)}</td>
        <td style="padding:3px 6px;text-align:right;font-weight:800;color:#ef4444">${e.total_errors.toLocaleString()}</td>
      </tr>`;
    });
    html += `</tbody></table></div></div>`;
  } else if (errors.length > 0) {
    html += `<div class="asec"><div style="color:#22c55e;font-size:13px;padding:10px;display:flex;align-items:center;gap:8px">✅ <span>No ports with errors (${errors.length} ports checked)</span></div></div>`;
  }

  // ── Storage / Filesystem ──
  const storage = (d.storage && d.storage.data) || [];
  if (storage.length > 0) {
    // Filter out Junos read-only package mounts (devfs, procfs, /packages/mnt/) — always 100%, not actionable
    const actionable = storage.filter(s => s.mounted_on && !/^(devfs|procfs)$/.test(s.filesystem || '') && !/\/packages\/mnt\//.test(s.mounted_on) && s.mounted_on !== "/dev" && s.mounted_on !== "/proc");
    // Deduplicate by mounted_on (dual RE can report twice)
    const seen = new Set(); const deduped = actionable.filter(s => { if (seen.has(s.mounted_on)) return false; seen.add(s.mounted_on); return true; });
    const critical = deduped.filter(s => s.used_percent >= 90);
    const warn = deduped.filter(s => s.used_percent >= 75 && s.used_percent < 90);
    const interesting = deduped.filter(s => s.used_percent >= 50 || /^\/(var|tmp|config)/.test(s.mounted_on) || s.mounted_on === "/");
    if (interesting.length > 0) {
      html += `<div class="asec"><h4 style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span>💾</span> <span>Filesystem Storage</span>
        <span style="font-size:11px;color:var(--muted);font-weight:400">${storage.length} total, ${interesting.length} shown</span>
        ${critical.length > 0 ? `<span style="font-size:10px;color:#ef4444;font-weight:700;border:1px solid #ef4444;border-radius:3px;padding:1px 5px">${critical.length} CRITICAL (≥90%)</span>` : ''}
        ${warn.length > 0 ? `<span style="font-size:10px;color:#eab308;font-weight:700;border:1px solid #eab308;border-radius:3px;padding:1px 5px">${warn.length} WARNING (≥75%)</span>` : ''}
      </h4>
      <div style="display:flex;gap:8px;flex-wrap:wrap">`;
      interesting.sort((a,b) => b.used_percent - a.used_percent).forEach(s => {
        const col = s.used_percent >= 90 ? "#ef4444" : s.used_percent >= 75 ? "#eab308" : s.used_percent >= 50 ? "#f59e0b" : "#22c55e";
        html += `
        <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:8px 12px;min-width:160px;border-left:3px solid ${col}">
          <div style="font-family:Consolas,monospace;font-size:11px;font-weight:600;margin-bottom:4px">${escHtml(s.mounted_on)}</div>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="flex:1;height:6px;background:var(--border);border-radius:3px;overflow:hidden">
              <div style="height:100%;width:${Math.min(s.used_percent, 100)}%;background:${col};border-radius:3px"></div>
            </div>
            <span style="font-size:12px;font-weight:800;color:${col}">${s.used_percent}%</span>
          </div>
          <div style="font-size:9px;color:var(--muted);margin-top:2px">${escHtml(s.filesystem || '')}</div>
        </div>`;
      });
      html += `</div></div>`;
    }
  }

  // Export button
  html += `<div style="text-align:center;padding:10px">
    <button class="btn" onclick="exportPyezStats()" style="border-color:#14b8a6;color:#14b8a6">📋 Export Hardware Report (.md)</button>
  </div>`;

  document.getElementById("ana-panel").innerHTML = html;
}

function exportPyezStats() {
  if (!lastPyezData || !selectedDev) return;
  const d = lastPyezData, host = selectedDev.hostname;
  let md = `# 🔬 Hardware & Optics Report (PyEZ NETCONF)\n\n`;
  md += `| Field | Value |\n|---|---|\n`;
  md += `| **Device** | \`${host}\` |\n| **Model** | ${d.model||'N/A'} |\n| **Version** | ${d.version||'N/A'} |\n`;
  md += `| **Serial** | ${d.serial||'N/A'} |\n| **Uptime** | ${d.uptime||'N/A'} |\n| **Collection** | ${d.collection_time_s}s |\n\n`;

  const fpcs = (d.fpc_health && d.fpc_health.data) || [];
  if (fpcs.length) {
    md += `## 🔩 FPC Health\n\n| Slot | State | CPU % | Memory % | Status |\n|---|---|---|---|---|\n`;
    fpcs.forEach(f => { md += `| ${f.slot} | ${f.state} | ${f.cpu_percent}% | ${f.memory_percent}% | ${f.status} |\n`; });
    md += '\n';
  }

  const optics = (d.optics && d.optics.data) || [];
  if (optics.length) {
    md += `## 💡 Optic Diagnostics\n\n| Port | RX dBm | TX dBm | Temp | Voltage | Status |\n|---|---|---|---|---|---|\n`;
    optics.forEach(o => { md += `| ${o.name} | ${o.rx_power_dbm != null ? o.rx_power_dbm.toFixed(2) : '—'} | ${o.tx_power_dbm != null ? o.tx_power_dbm.toFixed(2) : '—'} | ${o.temperature_c != null ? o.temperature_c + '°C' : '—'} | ${o.voltage_v != null ? o.voltage_v.toFixed(3) + 'V' : '—'} | ${o.status} |\n`; });
    md += '\n';
  }

  const errors = (d.port_errors && d.port_errors.data) || [];
  const withErr = errors.filter(e => e.has_errors);
  if (withErr.length) {
    md += `## ⚠️ Ports with Errors\n\n| Port | RX Err | Drops | CRC | Runts | FIFO | TX Err | TX Drops | Total |\n|---|---|---|---|---|---|---|---|---|\n`;
    withErr.forEach(e => { md += `| ${e.name} | ${e.rx_errors} | ${e.rx_drops} | ${e.rx_frame_errors} | ${e.rx_runts} | ${e.rx_fifo_errors} | ${e.tx_errors} | ${e.tx_drops} | **${e.total_errors}** |\n`; });
    md += '\n';
  }

  md += `---\n*Generated by DCN Network Tool — PyEZ NETCONF Collector*\n`;
  downloadFile(md, `${host}_Hardware_Report_${ts()}.md`, "text/markdown");
}


async function analyzeData(data) {
  try {
    const r = await fetch(`${API}/analyze`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ hostname: selectedDev.hostname, dtype: selectedDev.type, data }) });
    const d = await r.json();
    renderAnalysis(d);
    switchTabById("analysis");
  } catch(e) { console.error(e); }
}

function renderAnalysis(d) {
  lastAnalysisData = d;
  const sev = d.severity || "OK";
  const html = `
    <div class="asec" style="display:flex;align-items:center;gap:10px">
      <span style="font-size:15px;font-weight:700;font-family:Consolas,monospace">${d.hostname}</span>
      <span class="sb-${sev}">${sev}</span>
      <span style="color:var(--muted);font-size:12px">${d.summary}</span>
      <span style="color:var(--muted);font-size:11px;margin-left:auto">${(d.timestamp||"").slice(0,19).replace('T',' ')}</span>
    </div>
    ${d.warnings && d.warnings.length ? `
    <div class="asec">
      <h4>⚠️ Warnings (${d.warnings.length})</h4>
      ${d.warnings.map(w => `<div class="aitem"><span style="color:var(--yellow);flex-shrink:0">▶</span><span>${escHtml(w)}</span></div>`).join('')}
    </div>` : ''}
    ${d.findings && d.findings.length ? `
    <div class="asec">
      <h4>🔍 Findings (${d.findings.length})</h4>
      ${d.findings.map(f => `<div class="aitem"><span style="color:var(--accent);flex-shrink:0">•</span><span>${escHtml(f)}</span></div>`).join('')}
    </div>` : ''}
    ${d.best_practices && d.best_practices.length ? `
    <div class="asec">
      <h4>✅ Best Practices</h4>
      ${d.best_practices.map(b => `<div class="aitem"><span style="color:var(--green);flex-shrink:0">✓</span><span>${escHtml(b)}</span></div>`).join('')}
    </div>` : ''}
    ${(!d.warnings || !d.warnings.length) && (!d.findings || !d.findings.length) ? `
    <div class="asec"><div style="color:var(--green);font-size:13px">✅ No issues detected in the collected data</div></div>` : ''}
  `;
  document.getElementById("ana-panel").innerHTML = html;
}

// ── History ───────────────────────────────────────────────────────────────────
function addHistory(key, cmd, success, hostname) {
  cmdHistory.unshift({ key, cmd, success, hostname, time: new Date().toLocaleTimeString() });
  if (cmdHistory.length > 50) cmdHistory.pop();
  renderHistory();
}

function renderHistory() {
  const el = document.getElementById("hist-list");
  if (!cmdHistory.length) { el.innerHTML = '<div style="color:var(--muted);text-align:center;padding:30px;font-size:12px">No history</div>'; return; }
  el.innerHTML = cmdHistory.map((h, i) => `
    <div class="hist-item" onclick="replayHistory(${i})">
      <span class="${h.success?'hi-ok':'hi-err'}">${h.success?'✓':'✗'}</span>
      <span class="hi-t">${h.time}</span>
      <span class="hi-d">${h.hostname}</span>
      <span class="hi-c" title="${escHtml(h.cmd)}">${escHtml(h.cmd)}</span>
    </div>`).join('');
}

function replayHistory(i) {
  const h = cmdHistory[i];
  if (!selectedDev) return;
  // Route to the correct function based on entry type
  if (h.key === "snapshot") { switchTabById("collect"); runSnapshot(); return; }
  if (h.key === "capacity" || h.key === "ports" || h.key === "capacity-forecast") { switchTabById("capacity"); runPortCapacity(); return; }
  if (h.key === "incident") { switchTabById("collect"); runIncident(); return; }
  // cmd_key entries — re-run via runCmd
  if (h.key && !h.key.startsWith("raw_") && h.key !== h.cmd) {
    switchTabById("commands"); runCmd(h.key); return;
  }
  // Raw command entries — put back in box and run
  document.getElementById("raw-cmd").value = h.cmd;
  switchTabById("commands");
  runRaw();
}

function clearHistory() {
  cmdHistory = [];
  renderHistory();
}

// ── Report Export ─────────────────────────────────────────────────────────────
function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

function ts() { return new Date().toISOString().slice(0,19).replace(/[T:]/g, '-'); }

function exportPortCapacity(format) {
  // If ISP links panel is visible and has data, export that instead
  const ispEl = document.getElementById("isp-out");
  if (ispEl && ispEl.style.display !== "none" && lastISPData) { exportISPLinks(format); return; }
  if (!lastPortData || !selectedDev) { alert("No port capacity data — run Port Capacity first"); return; }
  const d = lastPortData;
  const host = selectedDev.hostname;
  const now = new Date().toISOString().slice(0,19).replace('T',' ');
  const bySpeed = d.by_speed || d.by_type || {};

  if (format === "csv") {
    let csv = "Interface Speed,Total,Up,Down,Disabled,Usage%\n";
    const speedLabels = {"et":"100G","xe":"10G","ge":"1G"};
    for (const [k, v] of Object.entries(bySpeed)) {
      const speed = speedLabels[k] || k;
      const pct = v.total > 0 ? Math.round((v.up / v.total) * 100) : 0;
      csv += `${speed},${v.total},${v.up},${v.down||0},${v.disabled||0},${pct}%\n`;
    }
    csv += `\nTOTAL,${d.total||0},${d.up||0},${d.free||0},${d.disabled||0},${d.total>0?Math.round(((d.total-d.free)/d.total)*100):0}%\n`;
    csv += `\nDevice,${host}\nModel,${d.model||''}\nPlatform,${d.platform||''}\nOptics Installed,${d.optics_installed||0}\nBreakout Ports,${d.breakout_count||0}\nTimestamp,${d.timestamp||now}\n`;
    downloadFile(csv, `${host}_Port_Capacity_${ts()}.csv`, "text/csv");
    return;
  }

  // Markdown report
  const breakout = d.breakout_count || 0;
  const logical = d.logical_ports || 0;
  const total = d.total || 0;
  const up = d.up || 0;
  const free = d.free || 0;
  const dis = d.disabled || 0;
  const optics = d.optics_installed || 0;
  const pctUsed = total > 0 ? Math.round(((total - free) / total) * 100) : 0;

  let md = `# Port Capacity Report\n\n`;
  md += `| Field | Value |\n|---|---|\n`;
  md += `| **Device** | \`${host}\` |\n`;
  md += `| **IP** | ${selectedDev.ip} |\n`;
  md += `| **Type** | ${selectedDev.type.toUpperCase()} |\n`;
  md += `| **Model** | ${d.model || '—'} |\n`;
  md += `| **Platform** | ${d.platform || '—'} |\n`;
  md += `| **Report Date** | ${d.timestamp || now} |\n\n`;

  md += `## Summary\n\n`;
  md += `| Metric | Value |\n|---|---|\n`;
  md += `| Physical Slots | ${total} |\n`;
  md += `| In Use (UP) | ${up} |\n`;
  md += `| Empty / Free | ${free} |\n`;
  md += `| Admin Disabled | ${dis} |\n`;
  md += `| Optics Installed | ${optics} |\n`;
  md += `| Utilization | **${pctUsed}%** |\n`;
  if (breakout > 0) md += `| Channelized Ports | ${breakout} → ${logical} logical |\n`;
  md += `\n`;

  md += `## Breakdown by Speed\n\n`;
  md += `| Speed | Total | Up | Down | Disabled | Usage |\n|---|---|---|---|---|---|\n`;
  const speedLabels = {"et":"100G","xe":"10G","ge":"1G"};
  for (const [k, v] of Object.entries(bySpeed)) {
    const speed = speedLabels[k] || k;
    const pct = v.total > 0 ? Math.round((v.up / v.total) * 100) : 0;
    md += `| ${speed} | ${v.total} | ${v.up} | ${v.down||0} | ${v.disabled||0} | ${pct}% |\n`;
  }

  md += `\n---\n*Generated by DCN Network Tool*\n`;
  downloadFile(md, `${host}_Port_Capacity_${ts()}.md`, "text/markdown");
}

function exportISPLinks(format) {
  if (!lastISPData) { alert("No ISP links data — run All ISP Links first"); return; }
  const d = lastISPData;
  const s = d.summary || {};
  const links = d.links || [];
  const sites = d.sites || [];
  const now = d.analysis_date || new Date().toISOString().slice(0,19).replace('T',' ');
  const growth = d.monthly_growth_pct || 5;

  if (format === "csv") {
    let csv = "Site,Device,Port,Description,Provider,Speed_Gbps,Status,In_Mbps,Out_Mbps,Peak_Mbps,Current_Util%,Projected_6Mo%,Risk,In_Errors,Out_Errors,Region\n";
    links.forEach(l => {
      csv += `${l.site},${l.hostname},${l.ifName},"${(l.description||"").replace(/"/g,'""')}","${(l.provider||"").replace(/"/g,'""')}",${l.speed_gbps},${l.status},${l.in_mbps},${l.out_mbps},${l.peak_mbps},${l.current_util_pct},${l.projected_6mo_util_pct},${l.risk},${l.in_errors},${l.out_errors},${l.region}\n`;
    });
    downloadFile(csv, `ISP_Links_Health_${ts()}.csv`, "text/csv");
    return;
  }

  let md = `# ISP Links Health Report\n\n`;
  md += `| Field | Value |\n|---|---|\n`;
  md += `| **Report Date** | ${now} |\n`;
  md += `| **Regions Scanned** | EMEA, AMER, APAC |\n`;
  md += `| **Devices Scanned** | ${s.devices_scanned || 0} |\n`;
  md += `| **Monthly Growth Rate** | ${growth}% |\n\n`;

  md += `## Summary\n\n`;
  md += `| Metric | Value |\n|---|---|\n`;
  md += `| Total ISP Links | **${s.total_isp_links || 0}** |\n`;
  md += `| Links Up | ${s.links_up || 0} |\n`;
  md += `| Links Down | ${s.links_down || 0} |\n`;
  md += `| Critical (6-mo) | ${s.critical_6mo || 0} |\n`;
  md += `| Warning (6-mo) | ${s.warning_6mo || 0} |\n`;
  md += `| Watch | ${s.watch || 0} |\n`;
  md += `| Total Capacity | ${s.total_capacity_gbps || 0} Gbps |\n`;
  md += `| Total Used | ${s.total_used_gbps || 0} Gbps |\n`;
  md += `| Avg Utilization | **${s.avg_utilization_pct || 0}%** |\n\n`;

  md += `## Site Summary\n\n`;
  md += `| Site | Links | Down | Critical | Warning | Avg Util |\n|---|---|---|---|---|---|\n`;
  sites.forEach(st => {
    md += `| **${st.site}** | ${st.links} | ${st.down || '—'} | ${st.critical || '—'} | ${st.warning || '—'} | ${st.avg_util}% |\n`;
  });
  md += `\n`;

  // Group by risk for readability
  const downLinks = links.filter(l => l.risk === 'down');
  const critLinks = links.filter(l => l.risk === 'critical');
  const warnLinks = links.filter(l => l.risk === 'warning');
  const okLinks = links.filter(l => l.risk === 'ok' || l.risk === 'watch');

  if (downLinks.length) {
    md += `## ⬛ Down Links (${downLinks.length})\n\n`;
    md += `| Site | Device | Port | Description | Speed |\n|---|---|---|---|---|\n`;
    downLinks.forEach(l => md += `| ${l.site} | \`${l.hostname}\` | \`${l.ifName}\` | ${l.description} | ${l.speed_gbps}G |\n`);
    md += `\n`;
  }
  if (critLinks.length) {
    md += `## 🔴 Critical Links (${critLinks.length})\n\n`;
    md += `| Site | Device | Port | Description | Speed | Current | 6-Mo |\n|---|---|---|---|---|---|---|\n`;
    critLinks.forEach(l => md += `| ${l.site} | \`${l.hostname}\` | \`${l.ifName}\` | ${l.description} | ${l.speed_gbps}G | **${l.current_util_pct}%** | **${l.projected_6mo_util_pct}%** |\n`);
    md += `\n`;
  }
  if (warnLinks.length) {
    md += `## 🟠 Warning Links (${warnLinks.length})\n\n`;
    md += `| Site | Device | Port | Description | Speed | Current | 6-Mo |\n|---|---|---|---|---|---|---|\n`;
    warnLinks.forEach(l => md += `| ${l.site} | \`${l.hostname}\` | \`${l.ifName}\` | ${l.description} | ${l.speed_gbps}G | ${l.current_util_pct}% | ${l.projected_6mo_util_pct}% |\n`);
    md += `\n`;
  }

  md += `## All ISP Links (${links.length})\n\n`;
  md += `| Site | Device | Port | Description | Speed | In | Out | Util% | 6-Mo% | Risk |\n|---|---|---|---|---|---|---|---|---|---|\n`;
  links.forEach(l => {
    md += `| ${l.site} | \`${l.hostname}\` | \`${l.ifName}\` | ${l.description} | ${l.speed_gbps}G | ${l.in_mbps}M | ${l.out_mbps}M | ${l.current_util_pct}% | ${l.projected_6mo_util_pct}% | ${l.risk.toUpperCase()} |\n`;
  });

  md += `\n---\n*Generated by DCN Network Tool*\n`;
  downloadFile(md, `ISP_Links_Health_${ts()}.md`, "text/markdown");
}

function exportIncident(format) {
  if (!selectedDev || !Object.keys(lastMultiData).length) { alert("No incident data — run Incident Investigation first"); return; }
  const host = selectedDev.hostname;
  const now = new Date().toISOString().slice(0,19).replace('T',' ');

  let md = `# Incident Investigation Report\n\n`;
  md += `| Field | Value |\n|---|---|\n`;
  md += `| **Device** | \`${host}\` |\n`;
  md += `| **IP** | ${selectedDev.ip} |\n`;
  md += `| **Type** | ${selectedDev.type.toUpperCase()} |\n`;
  md += `| **Report Date** | ${now} |\n\n`;

  // Parse MTU data for table
  const mtuRaw = lastMultiData.mtu;
  if (mtuRaw) {
    const mtuEntries = parseMtuEntries(mtuRaw, selectedDev.type);
    if (mtuEntries.length) {
      md += `## MTU Report\n\n`;
      md += `| Interface | MTU | Status |\n|---|---|---|\n`;
      mtuEntries.forEach(e => {
        const status = e.mtu >= 9000 ? "✅ JUMBO" : e.mtu <= 1500 ? "🔴 DEFAULT" : "⚠️ NON-STD";
        md += `| \`${e.iface}\` | ${e.mtu} | ${status} |\n`;
      });
      md += `\n`;
    }
  }

  // All other collected data as sections
  for (const [k, v] of Object.entries(lastMultiData)) {
    if (k === "mtu") continue; // Already rendered as table
    md += `## ${k}\n\n`;
    md += "```\n" + (v || "(empty)") + "\n```\n\n";
  }

  md += `---\n*Generated by DCN Network Tool*\n`;

  if (format === "csv" && mtuRaw) {
    // Export MTU as CSV
    const mtuEntries = parseMtuEntries(mtuRaw, selectedDev.type);
    let csv = "Interface,MTU,Status\n";
    mtuEntries.forEach(e => {
      const status = e.mtu >= 9000 ? "JUMBO" : e.mtu <= 1500 ? "DEFAULT" : "NON-STANDARD";
      csv += `${e.iface},${e.mtu},${status}\n`;
    });
    downloadFile(csv, `${host}_MTU_Report_${ts()}.csv`, "text/csv");
    return;
  }

  downloadFile(md, `${host}_Incident_Report_${ts()}.md`, "text/markdown");
}

function exportAnalysis() {
  if (!lastAnalysisData || !selectedDev) { alert("No analysis data — run Analysis first"); return; }
  const d = lastAnalysisData;
  const host = selectedDev.hostname;
  const now = new Date().toISOString().slice(0,19).replace('T',' ');

  let md = `# Network Analysis Report\n\n`;
  md += `| Field | Value |\n|---|---|\n`;
  md += `| **Device** | \`${host}\` |\n`;
  md += `| **IP** | ${selectedDev.ip} |\n`;
  md += `| **Type** | ${selectedDev.type.toUpperCase()} |\n`;
  md += `| **Severity** | **${d.severity || 'OK'}** |\n`;
  md += `| **Report Date** | ${d.timestamp || now} |\n\n`;
  md += `> ${d.summary || ''}\n\n`;

  if (d.warnings && d.warnings.length) {
    md += `## ⚠️ Warnings (${d.warnings.length})\n\n`;
    d.warnings.forEach(w => { md += `- ${w}\n`; });
    md += `\n`;
  }

  if (d.findings && d.findings.length) {
    md += `## 🔍 Findings (${d.findings.length})\n\n`;
    d.findings.forEach(f => { md += `- ${f}\n`; });
    md += `\n`;
  }

  if (d.best_practices && d.best_practices.length) {
    md += `## ✅ Best Practices\n\n`;
    d.best_practices.forEach(b => { md += `- ${b}\n`; });
    md += `\n`;
  }

  md += `---\n*Generated by DCN Network Tool*\n`;
  downloadFile(md, `${host}_Analysis_Report_${ts()}.md`, "text/markdown");
}

function exportFullReport() {
  if (!selectedDev) { alert("No device selected"); return; }
  const host = selectedDev.hostname;
  const now = new Date().toISOString().slice(0,19).replace('T',' ');

  let md = `# Full Device Report: ${host}\n\n`;
  md += `| Field | Value |\n|---|---|\n`;
  md += `| **Device** | \`${host}\` |\n`;
  md += `| **IP** | ${selectedDev.ip} |\n`;
  md += `| **Type** | ${selectedDev.type.toUpperCase()} |\n`;
  md += `| **Site** | ${selectedDev.site} |\n`;
  md += `| **Role** | ${selectedDev.role} |\n`;
  md += `| **Report Date** | ${now} |\n\n`;

  // Port Capacity
  if (lastPortData) {
    const d = lastPortData;
    const bySpeed = d.by_speed || d.by_type || {};
    const total = d.total||0, up = d.up||0, free = d.free||0, dis = d.disabled||0;
    const pctUsed = total > 0 ? Math.round(((total - free) / total) * 100) : 0;
    const speedLabels = {"et":"100G","xe":"10G","ge":"1G"};

    md += `## Port Capacity\n\n`;
    md += `| Metric | Value |\n|---|---|\n`;
    md += `| Model | ${d.model||'—'} |\n`;
    md += `| Physical Slots | ${total} |\n`;
    md += `| In Use (UP) | ${up} |\n`;
    md += `| Free | ${free} |\n`;
    md += `| Disabled | ${dis} |\n`;
    md += `| Optics | ${d.optics_installed||0} |\n`;
    md += `| Utilization | **${pctUsed}%** |\n\n`;

    md += `| Speed | Total | Up | Down | Disabled | Usage |\n|---|---|---|---|---|---|\n`;
    for (const [k, v] of Object.entries(bySpeed)) {
      const speed = speedLabels[k] || k;
      const pct = v.total > 0 ? Math.round((v.up / v.total) * 100) : 0;
      md += `| ${speed} | ${v.total} | ${v.up} | ${v.down||0} | ${v.disabled||0} | ${pct}% |\n`;
    }
    md += `\n`;
  }

  // MTU
  const mtuRaw = lastMultiData.mtu;
  if (mtuRaw) {
    const mtuEntries = parseMtuEntries(mtuRaw, selectedDev.type);
    if (mtuEntries.length) {
      md += `## MTU Report\n\n`;
      md += `| Interface | MTU | Status |\n|---|---|---|\n`;
      mtuEntries.forEach(e => {
        const status = e.mtu >= 9000 ? "✅ JUMBO" : e.mtu <= 1500 ? "🔴 DEFAULT" : "⚠️ NON-STD";
        md += `| \`${e.iface}\` | ${e.mtu} | ${status} |\n`;
      });
      md += `\n`;
    }
  }

  // Analysis
  if (lastAnalysisData) {
    const a = lastAnalysisData;
    md += `## Analysis — ${a.severity || 'OK'}\n\n`;
    md += `> ${a.summary || ''}\n\n`;
    if (a.warnings && a.warnings.length) {
      md += `### ⚠️ Warnings\n\n`;
      a.warnings.forEach(w => { md += `- ${w}\n`; });
      md += `\n`;
    }
    if (a.findings && a.findings.length) {
      md += `### 🔍 Findings\n\n`;
      a.findings.forEach(f => { md += `- ${f}\n`; });
      md += `\n`;
    }
    if (a.best_practices && a.best_practices.length) {
      md += `### ✅ Best Practices\n\n`;
      a.best_practices.forEach(b => { md += `- ${b}\n`; });
      md += `\n`;
    }
  }

  // Raw collected data
  if (Object.keys(lastMultiData).length) {
    md += `## Raw Collected Data\n\n`;
    for (const [k, v] of Object.entries(lastMultiData)) {
      if (k === "mtu") continue;
      const val = v || "(empty)";
      if (val.length > 2000) {
        md += `### ${k}\n\n` + "```\n" + val.slice(0, 2000) + "\n... (truncated)\n```\n\n";
      } else {
        md += `### ${k}\n\n` + "```\n" + val + "\n```\n\n";
      }
    }
  }

  md += `---\n*Generated by DCN Network Tool — ${now}*\n`;
  downloadFile(md, `${host}_Full_Report_${ts()}.md`, "text/markdown");
}

function parseMtuEntries(raw, dtype) {
  const entries = [];
  let currentIface = null;
  for (const line of raw.split('\n')) {
    const s = line.trim();
    if (!s) continue;
    if (dtype === "junos") {
      const mPhys = s.match(/^Physical interface:\s+(\S+)/);
      if (mPhys) { currentIface = mPhys[1].replace(/,$/, ''); continue; }
      if (currentIface) {
        const mMtu = s.match(/MTU:\s*(\d+)/);
        if (mMtu) { entries.push({ iface: currentIface, mtu: parseInt(mMtu[1]) }); currentIface = null; }
      }
    } else {
      const mEos = s.match(/^(Ethernet\S+|Et\S+|Vlan\S+|Port-Channel\S+).*MTU\s+(\d+)/i);
      if (mEos) { entries.push({ iface: mEos[1], mtu: parseInt(mEos[2]) }); }
    }
  }
  return entries;
}

// ── NetPortal Capacity Report ─────────────────────────────────────────────────
let lastNetPortalData = null;

// Pre-load site list into the NetPortal site selector dropdown
(async function _preloadNetPortalSites() {
  try {
    const sel = document.getElementById("netportal-site");
    if (!sel || sel.options.length > 1) return;
    const r = await fetch(`${API}/netportal/summary`);
    const d = await r.json();
    const sites = d.sites || [];
    if (Array.isArray(sites) && sites.length) {
      sites.forEach(s => {
        const o = document.createElement("option");
        o.value = s.site.toLowerCase();
        o.textContent = s.site.toUpperCase();
        sel.appendChild(o);
      });
    }
  } catch (e) { /* NetPortal not reachable — site selector stays empty, user can still use All Sites Summary */ }
})();

async function runNetPortal() {
  _hideAllReportPanels();
  const panel = document.getElementById("rpt-netportal");
  panel.style.display = "block";
  const btn = document.getElementById("btn-netportal");
  const sel = document.getElementById("netportal-site");
  const siteCode = sel.value;

  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Loading from NetPortal…';

  try {
    if (siteCode) {
      // Single site drill-down
      const r = await fetch(`${API}/netportal/site/${siteCode}`);
      const d = await r.json();
      if (d.error) { panel.innerHTML = `<div style="color:#ef4444;padding:20px">Error: ${d.error}</div>`; return; }
      lastNetPortalData = { mode: "site", site_code: siteCode, data: d };
      renderNetPortalSite(d, siteCode, panel);
    } else {
      // All-sites summary
      const r = await fetch(`${API}/netportal/summary`);
      const d = await r.json();
      if (d.error) { panel.innerHTML = `<div style="color:#ef4444;padding:20px">Error: ${d.error}</div>`; return; }
      lastNetPortalData = { mode: "summary", data: d };
      renderNetPortalSummary(d, panel);
      // Populate site selector
      if (sel.options.length <= 1) {
        d.sites.forEach(s => { const o = document.createElement("option"); o.value = s.site; o.textContent = s.site.toUpperCase(); sel.appendChild(o); });
      }
    }
  } catch (e) {
    panel.innerHTML = `<div style="color:#ef4444;padding:20px">Failed to reach NetPortal: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = '📡 NetPortal Capacity';
  }
}

function _fmtBps(bps) {
  if (!bps || bps < 1) return "0";
  if (bps >= 1e9) return (bps / 1e9).toFixed(2) + " Gbps";
  if (bps >= 1e6) return (bps / 1e6).toFixed(1) + " Mbps";
  if (bps >= 1e3) return (bps / 1e3).toFixed(0) + " Kbps";
  return bps.toFixed(0) + " bps";
}

function _utilBadge(pct) {
  if (pct >= 90) return `<span style="color:#ef4444;font-weight:700">${pct.toFixed(1)}%</span>`;
  if (pct >= 75) return `<span style="color:#f59e0b;font-weight:700">${pct.toFixed(1)}%</span>`;
  return `<span style="color:#10b981">${pct.toFixed(1)}%</span>`;
}

function renderNetPortalSummary(d, panel) {
  const sites = d.sites || [];
  const totPorts = sites.reduce((a, s) => a + s.ports_total, 0);
  const totUsed = sites.reduce((a, s) => a + s.ports_used, 0);
  const totFree = sites.reduce((a, s) => a + s.ports_free, 0);
  const totIPs = sites.reduce((a, s) => a + s.ip_usable, 0);
  const totIPUsed = sites.reduce((a, s) => a + s.ip_consumed, 0);
  const totRackU = sites.reduce((a, s) => a + s.rack_u_total, 0);
  const totRackUsed = sites.reduce((a, s) => a + s.rack_u_used, 0);
  const totWarn = sites.reduce((a, s) => a + s.warnings, 0);

  let h = `<div style="margin:8px 0"><span style="font-size:14px;font-weight:700;color:#06b6d4">📡 NetPortal Capacity — All Sites</span>
    <span style="color:var(--muted);font-size:11px;margin-left:8px">Report: ${d.generated_at ? d.generated_at.slice(0, 16).replace('T', ' ') : '?'} · ${d.site_count} sites</span></div>`;

  // Summary cards
  h += `<div style="display:flex;gap:12px;flex-wrap:wrap;margin:8px 0">`;
  h += `<div style="background:var(--bg2);padding:8px 14px;border-radius:6px;border:1px solid var(--border)"><div style="color:var(--muted);font-size:10px">SITES</div><div style="font-size:18px;font-weight:700">${d.site_count}</div></div>`;
  h += `<div style="background:var(--bg2);padding:8px 14px;border-radius:6px;border:1px solid var(--border)"><div style="color:var(--muted);font-size:10px">PORTS</div><div style="font-size:18px;font-weight:700">${totPorts.toLocaleString()}</div><div style="font-size:10px;color:#10b981">${totFree.toLocaleString()} free</div></div>`;
  h += `<div style="background:var(--bg2);padding:8px 14px;border-radius:6px;border:1px solid var(--border)"><div style="color:var(--muted);font-size:10px">PORT UTIL</div><div style="font-size:18px;font-weight:700">${totPorts ? (totUsed/totPorts*100).toFixed(1) : 0}%</div></div>`;
  h += `<div style="background:var(--bg2);padding:8px 14px;border-radius:6px;border:1px solid var(--border)"><div style="color:var(--muted);font-size:10px">RACK U</div><div style="font-size:18px;font-weight:700">${totRackU.toLocaleString()}</div><div style="font-size:10px;color:#f59e0b">${totRackUsed.toLocaleString()} used</div></div>`;
  h += `<div style="background:var(--bg2);padding:8px 14px;border-radius:6px;border:1px solid var(--border)"><div style="color:var(--muted);font-size:10px">IP POOLS</div><div style="font-size:18px;font-weight:700">${totIPs.toLocaleString()}</div><div style="font-size:10px;color:#3b82f6">${totIPUsed.toLocaleString()} consumed</div></div>`;
  if (totWarn > 0) h += `<div style="background:#2e1a1a;padding:8px 14px;border-radius:6px;border:1px solid #ef4444"><div style="color:#ef4444;font-size:10px">WARNINGS</div><div style="font-size:18px;font-weight:700;color:#ef4444">${totWarn}</div></div>`;
  h += `</div>`;

  // Sites table
  h += `<table style="width:100%;border-collapse:collapse;font-size:11px;margin-top:8px">
    <tr style="background:var(--bg2);color:var(--muted);text-align:left">
      <th style="padding:6px 8px">Site</th><th>Switches</th><th>Ports</th><th>Port Free</th><th>Port Util</th>
      <th>Racks</th><th>Rack Util</th><th>IP Prefixes</th><th>IPs Usable</th><th>IP Consumed</th><th>IP Util</th>
      <th>ARP Active</th><th>Undocumented</th><th>ISP Links</th><th>Warnings</th>
    </tr>`;

  sites.forEach(s => {
    const rowStyle = s.warnings > 0 ? 'background:rgba(239,68,68,0.08)' : '';
    h += `<tr style="border-bottom:1px solid var(--border);cursor:pointer;${rowStyle}" onclick="document.getElementById('netportal-site').value='${s.site}';runNetPortal()">
      <td style="padding:5px 8px;font-weight:700;color:#06b6d4">${s.site.toUpperCase()}</td>
      <td>${s.switches}</td>
      <td>${s.ports_total}</td>
      <td style="color:#10b981">${s.ports_free}</td>
      <td>${_utilBadge(s.ports_util_pct)}</td>
      <td>${s.racks_total}</td>
      <td>${_utilBadge(s.rack_util_pct)}</td>
      <td>${s.ip_prefixes}</td>
      <td>${s.ip_usable}</td>
      <td>${s.ip_consumed}</td>
      <td>${_utilBadge(s.ip_consumed_pct)}</td>
      <td>${s.ip_arp_active}</td>
      <td style="${s.ip_undocumented > 0 ? 'color:#f59e0b' : ''}">${s.ip_undocumented}</td>
      <td>${s.isp_links}</td>
      <td style="${s.warnings > 0 ? 'color:#ef4444;font-weight:700' : ''}">${s.warnings}</td>
    </tr>`;
  });
  h += `</table>`;
  h += `<div style="color:var(--muted);font-size:10px;margin-top:6px">Click a site row to drill down into full details</div>`;
  panel.innerHTML = h;
}

function renderNetPortalSite(d, siteCode, panel) {
  const site = d.site || {};
  const summary = site.summary || {};
  const ports = summary.ports || {};
  const ep = ports.effective_ports || {};
  const racks = summary.racks || {};
  const ipSum = summary.ip_prefixes || {};
  const switches = site.switches || [];
  const ispLinks = site.isp_links || [];
  const prefixes = site.ip_prefixes || [];
  const warnings = site.warnings || [];
  const dq = site.data_quality || {};

  let h = `<div style="margin:8px 0"><span style="font-size:14px;font-weight:700;color:#06b6d4">📡 ${siteCode.toUpperCase()} — NetPortal Capacity</span>
    <span style="color:var(--muted);font-size:11px;margin-left:8px">${d.generated_at ? d.generated_at.slice(0, 16).replace('T', ' ') : ''}</span>
    <button class="btn" style="margin-left:12px;font-size:10px" onclick="document.getElementById('netportal-site').value='';runNetPortal()">← Back to All Sites</button></div>`;

  // Summary cards row
  h += `<div style="display:flex;gap:10px;flex-wrap:wrap;margin:8px 0">`;
  h += `<div style="background:var(--bg2);padding:8px 14px;border-radius:6px;border:1px solid var(--border)"><div style="color:var(--muted);font-size:10px">SWITCHES</div><div style="font-size:16px;font-weight:700">${ports.switches || switches.length}</div></div>`;
  h += `<div style="background:var(--bg2);padding:8px 14px;border-radius:6px;border:1px solid var(--border)"><div style="color:var(--muted);font-size:10px">PORTS</div><div style="font-size:16px;font-weight:700">${ep.used || 0} / ${ep.total || 0}</div><div style="font-size:10px;color:#10b981">${ep.free || 0} free · ${_utilBadge(ep.utilization_pct || 0)}</div></div>`;
  h += `<div style="background:var(--bg2);padding:8px 14px;border-radius:6px;border:1px solid var(--border)"><div style="color:var(--muted);font-size:10px">RACKS</div><div style="font-size:16px;font-weight:700">${racks.total_racks || 0}</div><div style="font-size:10px">${racks.used_u || 0}U / ${racks.total_u || 0}U · ${_utilBadge(racks.utilization_pct || 0)}</div></div>`;
  h += `<div style="background:var(--bg2);padding:8px 14px;border-radius:6px;border:1px solid var(--border)"><div style="color:var(--muted);font-size:10px">IP POOLS</div><div style="font-size:16px;font-weight:700">${ipSum.consumed_ips || 0} / ${ipSum.total_usable_ips || 0}</div><div style="font-size:10px">${_utilBadge(ipSum.consumed_pct || 0)} · ${ipSum.total_prefixes || 0} prefix(es)</div></div>`;
  h += `<div style="background:var(--bg2);padding:8px 14px;border-radius:6px;border:1px solid var(--border)"><div style="color:var(--muted);font-size:10px">ARP ACTIVE</div><div style="font-size:16px;font-weight:700">${ipSum.arp_active || 0}</div><div style="font-size:10px;color:#f59e0b">${ipSum.undocumented_ip_count || 0} undocumented</div></div>`;
  h += `<div style="background:var(--bg2);padding:8px 14px;border-radius:6px;border:1px solid var(--border)"><div style="color:var(--muted);font-size:10px">ISP LINKS</div><div style="font-size:16px;font-weight:700">${ispLinks.length}</div></div>`;
  if (warnings.length > 0) h += `<div style="background:#2e1a1a;padding:8px 14px;border-radius:6px;border:1px solid #ef4444"><div style="color:#ef4444;font-size:10px">WARNINGS</div><div style="font-size:16px;font-weight:700;color:#ef4444">${warnings.length}</div></div>`;
  h += `</div>`;

  // Ports by speed
  const bySpeed = ep.by_speed || {};
  if (Object.keys(bySpeed).length > 0) {
    h += `<div style="margin:12px 0 4px;font-weight:700;font-size:12px;color:var(--text)">Port Capacity by Speed</div>`;
    h += `<table style="width:auto;border-collapse:collapse;font-size:11px"><tr style="background:var(--bg2);color:var(--muted)"><th style="padding:4px 12px">Speed</th><th>Total</th><th>Used</th><th>Free</th><th>Util</th></tr>`;
    Object.entries(bySpeed).sort().forEach(([spd, v]) => {
      const pct = v.total ? (v.used / v.total * 100) : 0;
      h += `<tr style="border-bottom:1px solid var(--border)"><td style="padding:4px 12px;font-weight:700">${spd}</td><td>${v.total}</td><td>${v.used}</td><td style="color:#10b981">${v.free}</td><td>${_utilBadge(pct)}</td></tr>`;
    });
    h += `</table>`;
  }

  // ISP Links
  if (ispLinks.length > 0) {
    h += `<div style="margin:12px 0 4px;font-weight:700;font-size:12px;color:var(--text)">ISP / Transit Links <span style="font-size:9px;color:var(--muted);font-weight:400">(90-day 97th percentile · source: Grafana)</span></div>`;
    h += `<table style="width:100%;border-collapse:collapse;font-size:11px"><tr style="background:var(--bg2);color:var(--muted)">
      <th style="padding:4px 8px;text-align:left">Device</th><th>Interface</th><th>Description</th><th>Speed</th>
      <th>IN 97th</th><th>OUT 97th</th><th>IN Avg 30d</th><th>OUT Avg 30d</th><th>IN Max 30d</th></tr>`;
    ispLinks.forEach(l => {
      const spd = l.speed_bps ? _fmtBps(l.speed_bps) : '?';
      h += `<tr style="border-bottom:1px solid var(--border)">
        <td style="padding:4px 8px">${(l.hostname || '').replace('.corp.internal', '')}</td>
        <td>${l.interface || ''}</td>
        <td>${l.description || l.isp_name || ''}</td>
        <td>${spd}</td>
        <td style="font-weight:700">${_fmtBps(l.in_bps_97th)}</td>
        <td>${_fmtBps(l.out_bps_97th)}</td>
        <td>${_fmtBps(l.in_bps_avg_30d)}</td>
        <td>${_fmtBps(l.out_bps_avg_30d)}</td>
        <td style="color:#f59e0b">${_fmtBps(l.in_bps_max_30d)}</td>
      </tr>`;
    });
    h += `</table>`;
  }

  // IP Prefixes
  if (prefixes.length > 0) {
    h += `<div style="margin:12px 0 4px;font-weight:700;font-size:12px;color:var(--text)">IP Prefixes</div>`;
    h += `<table style="width:100%;border-collapse:collapse;font-size:11px"><tr style="background:var(--bg2);color:var(--muted)">
      <th style="padding:4px 8px;text-align:left">Prefix</th><th>Status</th><th>Usable</th><th>ARP Active</th>
      <th>Netbox Assigned</th><th>Consumed</th><th>Util</th><th>Undocumented</th></tr>`;
    prefixes.forEach(p => {
      const u = p.utilization || {};
      h += `<tr style="border-bottom:1px solid var(--border)">
        <td style="padding:4px 8px;font-weight:700">${p.prefix}</td>
        <td><span style="color:${p.status === 'active' ? '#10b981' : '#f59e0b'}">${p.status}</span></td>
        <td>${p.total_usable || 0}</td>
        <td>${u.arp_active || 0}</td>
        <td>${u.netbox_assigned || 0}</td>
        <td>${u.consumed_ips || 0}</td>
        <td>${_utilBadge(u.consumed_pct || 0)}</td>
        <td style="${(p.undocumented_ips?.count || 0) > 0 ? 'color:#f59e0b' : ''}">${p.undocumented_ips?.count || 0}</td>
      </tr>`;
      // Show undocumented IPs if any
      if (p.undocumented_ips?.ips?.length > 0) {
        h += `<tr><td colspan="8" style="padding:2px 8px 8px 24px;background:rgba(245,158,11,0.05)">`;
        h += `<div style="font-size:10px;color:var(--muted);margin-bottom:2px">Undocumented IPs (not in Netbox):</div>`;
        h += `<table style="font-size:10px;border-collapse:collapse"><tr style="color:var(--muted)"><th style="padding:2px 8px">IP</th><th>MAC</th><th>Interface</th><th>Type</th></tr>`;
        p.undocumented_ips.ips.forEach(ip => {
          h += `<tr><td style="padding:1px 8px">${ip.ip}</td><td>${ip.mac}</td><td>${ip.oif || ''}</td><td><span style="color:${ip.mac_type === 'openstack_vm' ? '#a78bfa' : '#3b82f6'}">${ip.mac_type}</span></td></tr>`;
        });
        h += `</table></td></tr>`;
      }
    });
    h += `</table>`;
  }

  // Switches
  if (switches.length > 0) {
    h += `<div style="margin:12px 0 4px;font-weight:700;font-size:12px;color:var(--text)">Switches</div>`;
    h += `<table style="width:100%;border-collapse:collapse;font-size:11px"><tr style="background:var(--bg2);color:var(--muted)">
      <th style="padding:4px 8px;text-align:left">Hostname</th><th>Model</th><th>Vendor</th><th>VC</th>
      <th>Ports Total</th><th>Ports Used</th><th>Ports Free</th><th>Port Util</th><th>Netbox</th><th>Live</th></tr>`;
    switches.forEach(sw => {
      const pc = sw.port_capacity?.effective_ports || {};
      const dqSw = sw.data_quality || {};
      h += `<tr style="border-bottom:1px solid var(--border)">
        <td style="padding:4px 8px;font-weight:700">${sw.hostname}</td>
        <td>${sw.model || ''}</td>
        <td>${sw.vendor || ''}</td>
        <td>${sw.is_virtual_chassis ? '✓ ' + (sw.vc_members || []).join(', ') : '—'}</td>
        <td>${pc.total || 0}</td>
        <td>${pc.used || 0}</td>
        <td style="color:#10b981">${pc.free || 0}</td>
        <td>${_utilBadge(pc.utilization_pct || 0)}</td>
        <td>${dqSw.in_netbox ? '✅' : '❌'}</td>
        <td>${dqSw.in_live_data ? '✅' : '❌'}</td>
      </tr>`;
    });
    h += `</table>`;
  }

  // Racks
  if (site.racks?.length > 0) {
    h += `<div style="margin:12px 0 4px;font-weight:700;font-size:12px;color:var(--text)">Racks</div>`;
    h += `<table style="width:auto;border-collapse:collapse;font-size:11px"><tr style="background:var(--bg2);color:var(--muted)"><th style="padding:4px 12px">Name</th><th>Total U</th><th>Used U</th><th>Free U</th><th>Devices</th><th>Util</th></tr>`;
    site.racks.forEach(r => {
      h += `<tr style="border-bottom:1px solid var(--border)"><td style="padding:4px 12px;font-weight:700">${r.name}</td><td>${r.total_u}</td><td>${r.used_u}</td><td style="color:#10b981">${(r.total_u - r.used_u).toFixed(0)}</td><td>${r.device_count}</td><td>${_utilBadge(r.utilization_pct)}</td></tr>`;
    });
    h += `</table>`;
  }

  // Warnings
  if (warnings.length > 0) {
    h += `<div style="margin:12px 0 4px;font-weight:700;font-size:12px;color:#ef4444">⚠️ Warnings</div>`;
    warnings.forEach(w => {
      h += `<div style="background:rgba(239,68,68,0.1);padding:6px 10px;margin:2px 0;border-radius:4px;font-size:11px;border-left:3px solid #ef4444">${typeof w === 'string' ? w : JSON.stringify(w)}</div>`;
    });
  }

  // Data Quality
  h += `<div style="margin:12px 0 4px;font-weight:700;font-size:12px;color:var(--text)">Data Quality</div>`;
  h += `<div style="font-size:11px;color:var(--muted)">In Netbox: ${dq.in_netbox || 0} · In Live: ${dq.in_live || 0} · In Both: ${dq.in_both || 0}`;
  if (dq.only_netbox?.length) h += ` · <span style="color:#f59e0b">Only Netbox: ${dq.only_netbox.join(', ')}</span>`;
  if (dq.only_live?.length) h += ` · <span style="color:#f59e0b">Only Live: ${dq.only_live.join(', ')}</span>`;
  h += `</div>`;

  panel.innerHTML = h;
}

function exportNetPortal(format) {
  if (!lastNetPortalData) return;
  const d = lastNetPortalData;

  if (d.mode === "summary") {
    const sites = d.data.sites || [];
    if (format === "csv") {
      let csv = "Site,Switches,Ports Total,Ports Used,Ports Free,Port Util %,Racks,Rack U Total,Rack U Used,Rack Util %,IP Prefixes,IPs Usable,IPs Consumed,IP Util %,ARP Active,Undocumented,ISP Links,Warnings\n";
      sites.forEach(s => {
        csv += `${s.site},${s.switches},${s.ports_total},${s.ports_used},${s.ports_free},${s.ports_util_pct},${s.racks_total},${s.rack_u_total},${s.rack_u_used},${s.rack_util_pct},${s.ip_prefixes},${s.ip_usable},${s.ip_consumed},${s.ip_consumed_pct},${s.ip_arp_active},${s.ip_undocumented},${s.isp_links},${s.warnings}\n`;
      });
      downloadFile(csv, `NetPortal_Summary_${ts()}.csv`, "text/csv");
    } else {
      let md = `# NetPortal Capacity Summary\n\nGenerated: ${d.data.generated_at || ''}\nSites: ${d.data.site_count}\n\n`;
      md += `| Site | Switches | Ports (Used/Total) | Port Util | Rack U (Used/Total) | Rack Util | IPs (Consumed/Usable) | IP Util | Undocumented | ISP Links | Warnings |\n`;
      md += `|------|----------|-------------------|-----------|--------------------|-----------|-----------------------|---------|-------------|-----------|----------|\n`;
      sites.forEach(s => {
        md += `| ${s.site} | ${s.switches} | ${s.ports_used}/${s.ports_total} | ${s.ports_util_pct}% | ${s.rack_u_used}/${s.rack_u_total} | ${s.rack_util_pct}% | ${s.ip_consumed}/${s.ip_usable} | ${s.ip_consumed_pct}% | ${s.ip_undocumented} | ${s.isp_links} | ${s.warnings} |\n`;
      });
      downloadFile(md, `NetPortal_Summary_${ts()}.md`, "text/markdown");
    }
  } else {
    // Site drill-down export
    const site = d.data.site || {};
    const code = d.site_code.toUpperCase();
    const summary = site.summary || {};
    const ep = summary.ports?.effective_ports || {};
    const racks = summary.racks || {};
    const ipSum = summary.ip_prefixes || {};

    if (format === "csv") {
      let csv = `Site,${code}\n\nSection,Key,Value\n`;
      csv += `Ports,Total,${ep.total || 0}\nPorts,Used,${ep.used || 0}\nPorts,Free,${ep.free || 0}\nPorts,Util%,${ep.utilization_pct || 0}\n`;
      csv += `Racks,Total,${racks.total_racks || 0}\nRacks,Used U,${racks.used_u || 0}\nRacks,Total U,${racks.total_u || 0}\nRacks,Util%,${racks.utilization_pct || 0}\n`;
      csv += `IPs,Prefixes,${ipSum.total_prefixes || 0}\nIPs,Usable,${ipSum.total_usable_ips || 0}\nIPs,Consumed,${ipSum.consumed_ips || 0}\nIPs,Util%,${ipSum.consumed_pct || 0}\n`;
      csv += `\nISP Links\nHostname,Interface,Description,Speed,IN 97th,OUT 97th\n`;
      (site.isp_links || []).forEach(l => {
        csv += `${l.hostname},${l.interface},${l.description || ''},${l.speed_bps || ''},${l.in_bps_97th || 0},${l.out_bps_97th || 0}\n`;
      });
      csv += `\nIP Prefixes\nPrefix,Status,Usable,ARP Active,Consumed,Util%,Undocumented\n`;
      (site.ip_prefixes || []).forEach(p => {
        const u = p.utilization || {};
        csv += `${p.prefix},${p.status},${p.total_usable || 0},${u.arp_active || 0},${u.consumed_ips || 0},${u.consumed_pct || 0},${p.undocumented_ips?.count || 0}\n`;
      });
      downloadFile(csv, `NetPortal_${code}_${ts()}.csv`, "text/csv");
    } else {
      let md = `# NetPortal Capacity — ${code}\n\n`;
      md += `## Summary\n- **Ports:** ${ep.used || 0} / ${ep.total || 0} (${ep.utilization_pct || 0}%)\n`;
      md += `- **Racks:** ${racks.used_u || 0}U / ${racks.total_u || 0}U across ${racks.total_racks || 0} racks (${racks.utilization_pct || 0}%)\n`;
      md += `- **IP Pools:** ${ipSum.consumed_ips || 0} / ${ipSum.total_usable_ips || 0} (${ipSum.consumed_pct || 0}%)\n\n`;
      if (site.isp_links?.length) {
        md += `## ISP Links\n| Device | Interface | Description | Speed | IN 97th | OUT 97th |\n|--------|-----------|-------------|-------|---------|----------|\n`;
        site.isp_links.forEach(l => { md += `| ${(l.hostname||'').replace('.corp.internal','')} | ${l.interface} | ${l.description||''} | ${_fmtBps(l.speed_bps)} | ${_fmtBps(l.in_bps_97th)} | ${_fmtBps(l.out_bps_97th)} |\n`; });
        md += `\n`;
      }
      if (site.ip_prefixes?.length) {
        md += `## IP Prefixes\n| Prefix | Usable | ARP | Consumed | Util | Undocumented |\n|--------|--------|-----|----------|------|-------------|\n`;
        site.ip_prefixes.forEach(p => { const u=p.utilization||{}; md += `| ${p.prefix} | ${p.total_usable||0} | ${u.arp_active||0} | ${u.consumed_ips||0} | ${u.consumed_pct||0}% | ${p.undocumented_ips?.count||0} |\n`; });
      }
      downloadFile(md, `NetPortal_${code}_${ts()}.md`, "text/markdown");
    }
  }
}

// ── Junos MCP (Read-Only) ─────────────────────────────────────────────────────

let _jmcpDevices = null; // cached device list

async function _jmcpLoadDevices() {
  if (_jmcpDevices) return _jmcpDevices;
  try {
    const r = await fetch(`${API}/jmcp/devices`);
    const d = await r.json();
    _jmcpDevices = d.devices || {};
    return _jmcpDevices;
  } catch { return {}; }
}

async function _jmcpPopulateSelector() {
  const sel = document.getElementById("jmcp-device");
  if (!sel) return;
  const devs = await _jmcpLoadDevices();
  const names = Object.keys(devs).sort();
  // Group by site
  const sites = {};
  names.forEach(n => {
    const m = n.match(/^([a-z]+\d+)/);
    const site = m ? m[1].toUpperCase() : "OTHER";
    if (!sites[site]) sites[site] = [];
    sites[site].push(n);
  });
  sel.innerHTML = '<option value="">Select device...</option>';
  Object.keys(sites).sort().forEach(site => {
    const grp = document.createElement("optgroup");
    grp.label = site;
    sites[site].forEach(n => {
      const opt = document.createElement("option");
      opt.value = n;
      const dt = devs[n].dtype === "eos" ? "EOS" : "JNS";
      opt.textContent = `[${dt}] ${n} (${devs[n].ip})`;
      grp.appendChild(opt);
    });
    sel.appendChild(grp);
  });
  const junos = names.filter(n => devs[n].dtype !== "eos").length;
  const eos = names.length - junos;
  const cnt = document.getElementById("jmcp-count");
  if (cnt) cnt.textContent = `${names.length} devices (${junos} Junos + ${eos} EOS)`;
  const badge = document.getElementById("jmcp-badge");
  if (badge) badge.style.display = "inline";
}

async function _jmcpCheckStatus() {
  try {
    const r = await fetch(`${API}/jmcp/status`);
    const d = await r.json();
    if (d.junos_devices) {
      const cnt = document.getElementById("jmcp-count");
      if (cnt) cnt.textContent = `${d.junos_devices} Junos devices`;
    }
  } catch {}
}

function _jmcpSetOutput(html) {
  const el = document.getElementById("out-pre");
  if (el) el.innerHTML = html;
}

function _jmcpSetLabel(text) {
  const el = document.getElementById("cmd-lbl");
  if (el) el.textContent = text;
}

async function runJMCP() {
  const device = document.getElementById("jmcp-device")?.value;
  const command = document.getElementById("jmcp-cmd")?.value?.trim();
  if (!device) { _jmcpSetOutput('<span style="color:var(--red)">Select a device first</span>'); return; }
  if (!command) { _jmcpSetOutput('<span style="color:var(--red)">Enter a command</span>'); return; }
  _jmcpSetLabel(`${device} > ${command} — running...`);
  _jmcpSetOutput('<span style="color:var(--muted)">Connecting to device...</span>');
  try {
    const r = await fetch(`${API}/jmcp/execute`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ device, command, timeout: 60 })
    });
    const d = await r.json();
    if (d.error) {
      _jmcpSetLabel(`${device} > ${command} — ERROR`);
      _jmcpSetOutput(`<span style="color:var(--red)">${escHtml(d.error)}</span>`);
    } else {
      const dur = d.duration ? ` (${d.duration}s)` : '';
      _jmcpSetLabel(`${device} (${d.ip}) > ${command}${dur}`);
      let html = `<span style="color:var(--green)">// ${device} (${escHtml(d.ip)}) — ${escHtml(command)} — READ-ONLY</span>\n`;
      html += escHtml(d.output || '(no output)');
      if (d.stderr) html += `\n<span style="color:var(--yellow)">// stderr: ${escHtml(d.stderr)}</span>`;
      _jmcpSetOutput(html);
    }
  } catch (e) {
    _jmcpSetLabel(`${device} > ${command} — FAILED`);
    _jmcpSetOutput(`<span style="color:var(--red)">Request failed: ${escHtml(e.message)}</span>`);
  }
}

async function runJMCPFacts() {
  const device = selectedDev ? selectedDev.hostname : document.getElementById("jmcp-device")?.value;
  if (!device) { _jmcpSetOutput('<span style="color:var(--red)">Select a device from the sidebar first</span>'); return; }
  _jmcpSetLabel(`${device} — gathering facts...`);
  _jmcpSetOutput('<span style="color:var(--muted)">Connecting to device...</span>');
  try {
    const r = await fetch(`${API}/jmcp/facts`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ device })
    });
    const d = await r.json();
    if (d.error) {
      _jmcpSetLabel(`${device} — facts ERROR`);
      _jmcpSetOutput(`<span style="color:var(--red)">${escHtml(d.error)}</span>`);
    } else {
      _jmcpSetLabel(`${device} (${d.ip}) — Device Facts`);
      let html = `<span style="color:var(--green)">// ${device} (${escHtml(d.ip)}) — Device Facts — READ-ONLY</span>\n\n`;
      if (d.facts) {
        for (const [key, val] of Object.entries(d.facts)) {
          html += `<span style="color:var(--accent);font-weight:bold">═══ ${escHtml(key.toUpperCase())} ═══</span>\n`;
          html += escHtml(val || '(no data)') + '\n\n';
        }
      }
      _jmcpSetOutput(html);
    }
  } catch (e) {
    _jmcpSetLabel(`${device} — facts FAILED`);
    _jmcpSetOutput(`<span style="color:var(--red)">Request failed: ${escHtml(e.message)}</span>`);
  }
}

async function runJMCPBatch() {
  const command = document.getElementById("raw-cmd")?.value?.trim() || document.getElementById("jmcp-cmd")?.value?.trim();
  if (!command) { _jmcpSetOutput('<span style="color:var(--red)">Enter a command in the CLI input first (it will run on all devices matching a site pattern)</span>'); return; }
  const site = prompt("Enter site code to batch (e.g. UK-LON, DE-FRA), or comma-separated hostnames:");
  if (!site) return;
  // Determine devices
  const devs = await _jmcpLoadDevices();
  let targets = [];
  if (site.includes(",") || site.includes("-sw-") || site.includes("-fw-") || site.includes("-rt-")) {
    targets = site.split(",").map(s => s.trim().toLowerCase());
  } else {
    const prefix = site.toLowerCase();
    targets = Object.keys(devs).filter(n => n.startsWith(prefix));
  }
  if (!targets.length) {
    _jmcpSetOutput(`<span style="color:var(--red)">No devices found matching "${escHtml(site)}"</span>`);
    return;
  }
  _jmcpSetLabel(`Batch: ${command} on ${targets.length} devices — running...`);
  _jmcpSetOutput(`<span style="color:var(--muted)">Executing on ${targets.length} devices in parallel...</span>`);
  try {
    const r = await fetch(`${API}/jmcp/batch`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ devices: targets, command, timeout: 60 })
    });
    const d = await r.json();
    if (d.error) {
      _jmcpSetLabel(`Batch — ERROR`);
      _jmcpSetOutput(`<span style="color:var(--red)">${escHtml(d.error)}</span>`);
    } else {
      _jmcpSetLabel(`Batch: ${command} — ${d.successful}/${d.total} ok, ${d.failed} failed`);
      let html = `<span style="color:var(--green)">// BATCH: ${escHtml(command)} on ${d.total} devices — ${d.successful} ok, ${d.failed} failed — READ-ONLY</span>\n\n`;
      (d.results || []).forEach(r => {
        const color = r.status === "success" ? "var(--green)" : "var(--red)";
        const icon = r.status === "success" ? "✓" : "✗";
        html += `<span style="color:${color};font-weight:bold">═══ ${icon} ${escHtml(r.device)} (${escHtml(r.ip||'?')}) ${r.duration ? `[${r.duration}s]` : ''} ═══</span>\n`;
        html += escHtml(r.output || '(no output)') + '\n\n';
      });
      _jmcpSetOutput(html);
    }
  } catch (e) {
    _jmcpSetLabel(`Batch — FAILED`);
    _jmcpSetOutput(`<span style="color:var(--red)">Request failed: ${escHtml(e.message)}</span>`);
  }
}

async function jmcpShowDevices() {
  _jmcpSetLabel("Loading Junos device inventory...");
  try {
    const r = await fetch(`${API}/jmcp/devices`);
    const d = await r.json();
    const devs = d.devices || {};
    const names = Object.keys(devs).sort();
    // Group by site
    const sites = {};
    names.forEach(n => {
      const m = n.match(/^([a-z]+\d+)/);
      const site = m ? m[1].toUpperCase() : "OTHER";
      if (!sites[site]) sites[site] = [];
      sites[site].push(n);
    });
    const jCnt = names.filter(n => devs[n].dtype !== 'eos').length;
    const eCnt = names.length - jCnt;
    let html = `<span style="color:var(--green)">// Device Inventory — ${names.length} devices (${jCnt} Junos + ${eCnt} EOS) across ${Object.keys(sites).length} sites — READ-ONLY</span>\n\n`;
    Object.keys(sites).sort().forEach(site => {
      const sj = sites[site].filter(n => devs[n].dtype !== 'eos').length;
      const se = sites[site].length - sj;
      const mix = se > 0 ? ` · ${sj}J/${se}E` : '';
      html += `<span style="color:var(--accent);font-weight:bold">═══ ${site} (${sites[site].length} devices${mix}) ═══</span>\n`;
      sites[site].forEach(n => {
        const info = devs[n];
        const dt = info.dtype === 'eos' ? '<span style="color:#f59e0b">[EOS]</span>' : '<span style="color:#22d3ee">[JNS]</span>';
        html += `  ${dt} ${n.padEnd(22)} ${(info.ip||'').padEnd(16)} ${(info.role||'').padEnd(10)} port:${info.port}\n`;
      });
      html += '\n';
    });
    _jmcpSetLabel(`Device Inventory — ${names.length} devices (${jCnt} Junos + ${eCnt} EOS), ${Object.keys(sites).length} sites`);
    _jmcpSetOutput(html);
  } catch (e) {
    _jmcpSetOutput(`<span style="color:var(--red)">Failed to load devices: ${escHtml(e.message)}</span>`);
  }
}

// EOS equivalents for quick buttons
const _EOS_QUICK = {
  "show bgp summary": "show bgp summary",
  "show interfaces terse": "show interfaces status",
  "show route summary": "show ip route summary",
  "show arp": "show arp",
  "show chassis alarms": "show system environment all",
  "show system alarms": "show system environment cooling",
  "show version": "show version",
  "show lldp neighbors": "show lldp neighbors",
  "show configuration | display set | no-more": "show running-config",
  "show log messages | last 50": "show logging last 50",
  "show ospf neighbor": "show ip ospf neighbor",
  "show isis adjacency": "show isis neighbors",
  "show lacp interfaces": "show lacp neighbor",
  "show spanning-tree bridge": "show spanning-tree",
  "show interfaces diagnostics optics": "show interfaces transceiver",
  "show vlans": "show vlan",
  "show firewall": "show ip access-lists",
  "show chassis hardware": "show inventory",
  "show system uptime": "show uptime",
  "show interfaces | match MTU": "show interfaces",
  "show bgp neighbor": "show bgp neighbors",
  "show ethernet-switching table": "show mac address-table",
};

function jmcpQuick(cmd) {
  const el = document.getElementById("jmcp-cmd");
  if (!el) return;
  // Check if selected device is EOS — swap command if needed
  const devSel = document.getElementById("jmcp-device");
  const devName = devSel?.value;
  if (devName && _jmcpDevices?.[devName]?.dtype === "eos") {
    el.value = _EOS_QUICK[cmd] || cmd;
  } else {
    el.value = cmd;
  }
  runJMCP();
}

let _jmcpHistory = []; // conversation history for AI context

async function jmcpAsk() {
  const device = selectedDev ? selectedDev.hostname : document.getElementById("jmcp-device")?.value;
  const question = document.getElementById("jmcp-ask")?.value?.trim();
  if (!device) { _jmcpSetOutput('<span style="color:var(--red)">Select a device from the sidebar first</span>'); return; }
  if (!question) { _jmcpSetOutput('<span style="color:var(--red)">Type a question</span>'); return; }
  _jmcpSetLabel(`🤖 AI: ${device} — thinking...`);
  _jmcpSetOutput('<span style="color:#60a5fa">🤖 Analyzing your question, picking commands, connecting to device...</span>\n<span style="color:var(--muted)">This may take 15-30 seconds (LLM planning → SSH → LLM analysis)</span>');
  const btn = document.getElementById("btn-jmcp-ask");
  if (btn) { btn.disabled = true; btn.textContent = "⏳ Thinking..."; }
  try {
    const r = await fetch(`${API}/jmcp/ask`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ device, question, history: _jmcpHistory })
    });
    const d = await r.json();
    if (d.error) {
      _jmcpSetLabel(`🤖 AI: ${device} — ERROR`);
      _jmcpSetOutput(`<span style="color:var(--red)">${escHtml(d.error)}</span>`);
    } else {
      _jmcpSetLabel(`🤖 AI: ${device} (${d.ip}) — ${d.commands_run?.length || 0} commands run`);
      let html = '';
      // Question
      html += `<span style="color:#60a5fa;font-weight:bold">🤖 Q: ${escHtml(d.question)}</span>\n`;
      const dtLabel = d.dtype === 'eos' ? 'Arista EOS' : 'Junos';
      html += `<span style="color:var(--muted)">Device: ${escHtml(d.device)} (${escHtml(d.ip)}) · ${dtLabel} · Mode: READ-ONLY · LLM: ${d.llm_powered ? '✓' : '✗'}</span>\n\n`;
      // AI Analysis
      if (d.analysis) {
        html += `<span style="color:#60a5fa;font-weight:bold">═══ AI ANALYSIS ═══</span>\n`;
        html += `<div style="background:#60a5fa11;border-left:3px solid #3b82f6;padding:8px 12px;margin:4px 0 12px 0;border-radius:0 4px 4px 0;white-space:pre-wrap;line-height:1.5">${escHtml(d.analysis)}</div>\n`;
      }
      // Commands run
      html += `<span style="color:var(--accent);font-weight:bold">═══ COMMANDS EXECUTED ═══</span>\n`;
      (d.commands_run || []).forEach(cmd => {
        html += `<span style="color:var(--green)">$ ${escHtml(cmd)}</span>\n`;
        const out = d.command_outputs?.[cmd] || '(no output)';
        html += `<span style="color:var(--muted);font-size:11px">${escHtml(out)}</span>\n\n`;
      });
      _jmcpSetOutput(html);
      // Save to conversation history
      _jmcpHistory.push({ role: "user", content: question });
      _jmcpHistory.push({ role: "assistant", content: d.analysis || "" });
      if (_jmcpHistory.length > 10) _jmcpHistory = _jmcpHistory.slice(-10);
    }
  } catch (e) {
    _jmcpSetLabel(`🤖 AI: ${device} — FAILED`);
    _jmcpSetOutput(`<span style="color:var(--red)">Request failed: ${escHtml(e.message)}</span>`);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "🤖 Ask AI"; }
  }
}

async function jmcpAskSite() {
  const question = document.getElementById("jmcp-ask")?.value?.trim();
  if (!question) { _jmcpSetOutput('<span style="color:var(--red)">Type a question first in the AI input</span>'); return; }
  const site = prompt("Enter site code (e.g. UK-LON, DE-FRA, BLL1) to query ALL devices at that site:");
  if (!site) return;
  _jmcpSetLabel(`🏢 AI Site: ${site.toUpperCase()} — querying all devices...`);
  _jmcpSetOutput(`<span style="color:#22c55e">🏢 Querying ALL devices (Junos + EOS) at <b>${escHtml(site.toUpperCase())}</b>...</span>\n<span style="color:var(--muted)">LLM picking commands per platform → running on all devices in parallel → analyzing combined output\nThis may take 30-60 seconds depending on device count</span>`);
  const btn = document.getElementById("btn-jmcp-ask-site");
  if (btn) { btn.disabled = true; btn.textContent = "⏳ Running..."; }
  try {
    const r = await fetch(`${API}/jmcp/ask-site`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ question, site: site.trim() })
    });
    const d = await r.json();
    if (d.error) {
      _jmcpSetLabel(`🏢 AI Site: ${site.toUpperCase()} — ERROR`);
      _jmcpSetOutput(`<span style="color:var(--red)">${escHtml(d.error)}</span>`);
    } else {
      const plats = [d.junos_count ? `${d.junos_count} Junos` : '', d.eos_count ? `${d.eos_count} EOS` : ''].filter(Boolean).join(' + ') || `${d.device_count} devices`;
      _jmcpSetLabel(`🏢 AI: ${d.site || site.toUpperCase()} — ${plats}, ${d.successful} ok, ${d.failed} failed`);
      let html = '';
      html += `<span style="color:#22c55e;font-weight:bold">🏢 SITE QUERY: ${escHtml(d.site || site.toUpperCase())} — ${plats}</span>\n`;
      html += `<span style="color:var(--muted)">Q: ${escHtml(d.question)} · ${d.successful} ok, ${d.failed} failed · Mode: READ-ONLY · LLM: ${d.llm_powered ? '✓' : '✗'}</span>\n\n`;
      // AI Analysis
      if (d.analysis) {
        html += `<span style="color:#22c55e;font-weight:bold">═══ SITE-WIDE AI ANALYSIS ═══</span>\n`;
        html += `<div style="background:#22c55e11;border-left:3px solid #22c55e;padding:8px 12px;margin:4px 0 12px 0;border-radius:0 4px 4px 0;white-space:pre-wrap;line-height:1.5">${escHtml(d.analysis)}</div>\n`;
      }
      // Per-device results
      html += `<span style="color:var(--accent);font-weight:bold">═══ PER-DEVICE OUTPUT (${d.device_count} devices) ═══</span>\n\n`;
      (d.results || []).forEach(r => {
        const color = r.status === "success" ? "var(--green)" : "var(--red)";
        const icon = r.status === "success" ? "✓" : "✗";
        const ptag = r.dtype === 'eos' ? '<span style="color:#f59e0b">[EOS]</span>' : '<span style="color:#22d3ee">[Junos]</span>';
        html += `<span style="color:${color};font-weight:bold">── ${icon} ${ptag} ${escHtml(r.device)} (${escHtml(r.ip)}) ──</span>\n`;
        Object.entries(r.outputs || {}).forEach(([cmd, out]) => {
          if (cmd === "_connection") {
            html += `<span style="color:var(--red)">Connection error: ${escHtml(out)}</span>\n`;
          } else {
            html += `<span style="color:var(--muted);font-size:10px">$ ${escHtml(cmd)}</span>\n`;
            const lines = (out || '').split('\n');
            const preview = lines.length > 10 ? lines.slice(0, 10).join('\n') + `\n... (+${lines.length - 10} more lines)` : out;
            html += `<span style="font-size:11px">${escHtml(preview)}</span>\n`;
          }
        });
        html += '\n';
      });
      _jmcpSetOutput(html);
    }
  } catch (e) {
    _jmcpSetLabel(`🏢 AI Site — FAILED`);
    _jmcpSetOutput(`<span style="color:var(--red)">Request failed: ${escHtml(e.message)}</span>`);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "🏢 Ask Site"; }
  }
}

function clearJMCP() {
  _jmcpSetOutput('<span style="color:var(--muted)">Output cleared</span>');
  _jmcpSetLabel("Junos MCP — Read-Only Device Access");
}

function copyJMCPOutput() {
  const el = document.getElementById("jmcp-out");
  if (el) { navigator.clipboard.writeText(el.innerText); }
}

// ── Keyboard Shortcuts ────────────────────────────────────────────────────────
function _initKeyboardShortcuts() {
  document.addEventListener('keydown', e => {
    // Ctrl+K / Cmd+K — focus search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      document.getElementById('search-in').focus();
      document.getElementById('search-in').select();
    }
    // Ctrl+L / Cmd+L — clear output
    if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
      e.preventDefault();
      clearOutput();
    }
    // Escape — deselect device / blur input
    if (e.key === 'Escape') {
      if (document.activeElement && document.activeElement.tagName === 'INPUT') {
        document.activeElement.blur();
      }
    }
  });
}

// Initialize JMCP on page load
async function _jmcpInit() {
  await _jmcpPopulateSelector();
  _jmcpCheckStatus();
}

// ── Open tabs from landing page (no device needed) ───────────────────────────
function openTopoTab() {
  document.getElementById("empty-st").style.display = "none";
  document.getElementById("tabs").style.display = "flex";
  document.getElementById("dev-hdr").innerHTML = `
    <span class="dtitle" style="color:var(--accent)">🗺️ Site Topology Maps</span>
    <span style="font-size:11px;color:var(--muted)">Interactive network diagrams for all DCN sites</span>
  `;
  const tab = document.querySelector('[data-tab="topo"]');
  switchTab(tab);
  initTopoTab();
}

function openReportsTab() {
  document.getElementById("empty-st").style.display = "none";
  document.getElementById("tabs").style.display = "flex";
  document.getElementById("dev-hdr").innerHTML = `
    <span class="dtitle" style="color:var(--accent)">📋 Network Reports</span>
    <span style="font-size:11px;color:var(--muted)">Network-wide reports across all sites</span>
  `;
  const tab = document.querySelector('[data-tab="reports"]');
  switchTab(tab);
}

// ── 🗺️ Live Site Topology (D3 Force) ─────────────────────────────────────────
let topoSitesLoaded = false;
let topoCurrentSite = "";
let topoSiteDevices = [];
let _topoRefs = null; // {svg, g, zoom, sim, node, link, nodes, links}

const _TOPO_ROLE_COLORS = {
  firewall: { fill: "#f85149", stroke: "#ff6b6b", bg: "rgba(248,81,73,0.15)" },
  router:   { fill: "#f0883e", stroke: "#ffaa5e", bg: "rgba(240,136,62,0.15)" },
  switch:   { fill: "#3fb950", stroke: "#6fdd8b", bg: "rgba(63,185,80,0.15)" },
  gateway:  { fill: "#06b6d4", stroke: "#22d3ee", bg: "rgba(6,182,212,0.15)" },
  server:   { fill: "#a78bfa", stroke: "#c4b5fd", bg: "rgba(167,139,250,0.12)" },
  isp:      { fill: "#d29922", stroke: "#f0c040", bg: "rgba(210,153,34,0.15)" },
  console:  { fill: "#9e9e9e", stroke: "#bdbdbd", bg: "rgba(158,158,158,0.12)" },
  storage:  { fill: "#ec4899", stroke: "#f472b6", bg: "rgba(236,72,153,0.12)" },
  ipmi:     { fill: "#78716c", stroke: "#a8a29e", bg: "rgba(120,113,108,0.12)" },
  pxe:      { fill: "#64748b", stroke: "#94a3b8", bg: "rgba(100,116,139,0.12)" },
  dr:       { fill: "#e879f9", stroke: "#f0abfc", bg: "rgba(232,121,249,0.12)" },
  unknown:  { fill: "#6b7280", stroke: "#9ca3af", bg: "rgba(107,114,128,0.12)" },
};
const _TOPO_SPEED_STYLES = {
  "100g": { color: "#22d3ee", width: 4, dash: null },
  "10g":  { color: "#4caf50", width: 2.5, dash: null },
  "1g":   { color: "#2196f3", width: 1.5, dash: "6,3" },
  "lag":  { color: "#a78bfa", width: 2.5, dash: "4,2" },
  "unknown": { color: "#546e7a", width: 1.5, dash: null },
};
const _TOPO_SHAPE = {
  firewall: "M-14,-10 L14,-10 L10,10 L-10,10 Z",  // trapezoid
  router:   null,  // circle
  switch:   null,  // rounded rect
  isp:      "M0,-16 L18,0 L12,16 L-12,16 L-18,0 Z",  // pentagon (cloud-like)
  gateway:  null,
  server:   null,
  console:  null,
  storage:  null,
  ipmi:     null,
  pxe:      null,
  dr:       null,
  unknown:  null,
};

async function initTopoTab() {
  if (topoSitesLoaded) return;
  try {
    const r = await fetch(`${API}/topology/live-sites`);
    const d = await r.json();
    if (d.success && d.sites) {
      const sel = document.getElementById("topo-site");
      d.sites.forEach(s => {
        const o = document.createElement("option");
        o.value = s.site; o.textContent = `${s.site} (${s.devices})`;
        sel.appendChild(o);
      });
      topoSitesLoaded = true;
      if (selectedDev && selectedDev.site) {
        const su = selectedDev.site.toUpperCase();
        const match = d.sites.find(s => s.site === su);
        if (match) {
          sel.value = su;
          loadTopoSite(su);
        }
      }
    }
  } catch(e) { console.error("Failed to load topology sites:", e); }
}

async function loadTopoSite(site) {
  if (!site) {
    document.getElementById("topo-svg").style.display = "none";
    document.getElementById("topo-empty").style.display = "flex";
    document.getElementById("topo-info").textContent = "Select a site to build a live topology.";
    return;
  }
  document.getElementById("topo-empty").style.display = "none";
  document.getElementById("topo-svg").style.display = "block";
  document.getElementById("topo-info").innerHTML =
    `<span class="spin"></span> Collecting LLDP, interfaces &amp; descriptions from <b>${site}</b> devices via SSH… (10-30s)`;
  try {
    const r = await fetch(`${API}/topology/live/${site}`);
    const d = await r.json();
    if (!d.success) {
      document.getElementById("topo-info").innerHTML = `<span style="color:var(--red)">Error: ${escHtml(d.error || "Unknown error")}</span>`;
      return;
    }
    topoCurrentSite = site;
    topoSiteDevices = d.nodes ? d.nodes.filter(n => n.type === "managed") : [];
    _renderLiveTopo(d);
    const s = d.stats || {};
    let linkParts = [];
    if (s.lldp_links) linkParts.push(`${s.lldp_links} LLDP`);
    if (s.description_links) linkParts.push(`${s.description_links} desc`);
    if (s.arp_links) linkParts.push(`${s.arp_links} ARP`);
    if (s.bgp_links) linkParts.push(`${s.bgp_links} BGP`);
    if (s.cluster_links) linkParts.push(`${s.cluster_links} HA`);
    if (s.zone_links) linkParts.push(`${s.zone_links} zone`);
    let infoHtml = `<b style="color:var(--accent)">${site}</b> — ` +
      `${s.managed_devices||0} managed · ${s.discovered_devices||0} discovered · ${s.server_groups||0} groups · ` +
      `${s.total_links||0} links (${linkParts.join(', ')})`;
    if (s.vlan_count) infoHtml += ` · <span style="color:#58a6ff">${s.vlan_count} VLANs</span>`;
    if (s.vlan_links) infoHtml += ` <span style="color:#8b949e;font-size:10px">(${s.vlan_links} links)</span>`;
    if (d.errors && d.errors.length) {
      infoHtml += ` · <span style="color:var(--yellow)">${d.errors.length} SSH errors</span>`;
    }
    document.getElementById("topo-info").innerHTML = infoHtml;
  } catch(e) {
    document.getElementById("topo-info").innerHTML = `<span style="color:var(--red)">Fetch error: ${e}</span>`;
  }
}

function _renderLiveTopo(data) {
  const container = document.getElementById("topo-svg");
  container.innerHTML = "";
  const tipEl = document.getElementById("topo-tooltip");
  const W = container.clientWidth || 1400;
  const H = Math.max(700, container.clientHeight || (window.innerHeight - 200));
  const site = (topoCurrentSite || "SITE").toUpperCase();

  const nodes = (data.nodes || []).map(n => ({...n}));
  const links = (data.links || []).map(l => ({...l}));
  const nodeMap = {};
  nodes.forEach(n => { nodeMap[n.id] = n; });

  // ── Tier Assignment ─────────────────────────────────────────────────────
  const TIER_ORDER = ["isp", "firewall", "router", "core", "access", "server", "ipmi", "oob"];
  const TIER_CONFIG = {
    isp:      { label: "ISP / WAN",           bg: "rgba(214,158,46,0.08)",  border: "rgba(214,158,46,0.25)",  textColor: "#d29e2e" },
    firewall: { label: "Firewall Cluster",    bg: "rgba(248,81,73,0.10)",   border: "rgba(248,81,73,0.30)",   textColor: "#f85149" },
    router:   { label: "Routers",             bg: "rgba(240,136,62,0.08)",  border: "rgba(240,136,62,0.25)",  textColor: "#f0883e" },
    core:     { label: "Core / Distribution", bg: "rgba(63,185,80,0.08)",   border: "rgba(63,185,80,0.25)",   textColor: "#3fb950" },
    access:   { label: "Access / Leaf",       bg: "rgba(63,185,80,0.05)",   border: "rgba(63,185,80,0.15)",   textColor: "#3fb950" },
    server:   { label: "Servers / Compute",   bg: "rgba(139,148,158,0.06)", border: "rgba(139,148,158,0.15)", textColor: "#8b949e" },
    ipmi:     { label: "IPMI / PXE / Mgmt",   bg: "rgba(6,182,212,0.06)",   border: "rgba(6,182,212,0.18)",   textColor: "#06b6d4" },
    oob:      { label: "Out-of-Band",         bg: "rgba(139,148,158,0.04)", border: "rgba(139,148,158,0.10)", textColor: "#6b7280" },
  };

  function _assignTier(n) {
    const r = n.role, t = n.type, id = n.id.toLowerCase();
    if (r === "isp" || t === "cloud" || id.includes("ebgp") || id.includes("-wan")) return "isp";
    if (r === "firewall") return "firewall";
    if (r === "router") return "router";
    if (r === "switch" && t === "managed") {
      // Heuristic: sw-01/sw-02 are usually core; higher numbers are access/leaf
      const m = id.match(/sw-?(\d+)/);
      if (m) { const num = parseInt(m[1]); if (num <= 2 || num >= 99) return "core"; }
      return "access";
    }
    if (r === "switch") return "access";
    if (r === "gateway") return "core";
    if (r === "ipmi" || r === "pxe") return "ipmi";
    if (r === "console" || id.includes("oob") || id.includes("console")) return "oob";
    if (r === "server" || r === "storage" || r === "dr") return "server";
    // Inferred nodes: check what they connect to
    return "server";
  }

  nodes.forEach(n => { n._tier = _assignTier(n); });

  // ── Layout: compute X,Y per tier (adaptive for large sites) ────────────
  const TIER_PAD = 40;
  const totalNodes = nodes.length;
  const totalLinks = links.length;
  const isLargeSite = totalNodes > 40 || totalLinks > 100;
  const NODE_W = isLargeSite ? Math.max(70, 130 - totalNodes) : 110;
  const TIER_H = isLargeSite ? 140 : 120;
  const TOP_MARGIN = 70;
  const SIDE_MARGIN = 80;

  // Group nodes by tier
  const tierNodes = {};
  TIER_ORDER.forEach(t => { tierNodes[t] = []; });
  nodes.forEach(n => { if (tierNodes[n._tier]) tierNodes[n._tier].push(n); });

  // Remove empty tiers
  const activeTiers = TIER_ORDER.filter(t => tierNodes[t].length > 0);

  // Sort nodes within each tier: managed first, then by id
  activeTiers.forEach(t => {
    tierNodes[t].sort((a, b) => {
      if (a.type === "managed" && b.type !== "managed") return -1;
      if (b.type === "managed" && a.type !== "managed") return 1;
      // Keep HA pairs adjacent (strip trailing a/b)
      const aBase = a.id.replace(/[ab]$/, "");
      const bBase = b.id.replace(/[ab]$/, "");
      if (aBase !== bBase) return aBase.localeCompare(bBase);
      return a.id.localeCompare(b.id);
    });
  });

  // Compute width needed
  const maxNodesInTier = Math.max(...activeTiers.map(t => tierNodes[t].length), 1);
  const contentW = Math.max(maxNodesInTier * NODE_W + SIDE_MARGIN * 2, 800);
  const contentH = activeTiers.length * TIER_H + TOP_MARGIN + TIER_PAD * 2;
  const VW = Math.max(W, contentW + 300); // extra for legend
  const VH = Math.max(H, contentH + 60);

  // Assign positions
  activeTiers.forEach((tier, ti) => {
    const nodesInTier = tierNodes[tier];
    const tierY = TOP_MARGIN + TIER_PAD + ti * TIER_H + TIER_H / 2;
    const totalW = nodesInTier.length * NODE_W;
    const startX = (contentW - totalW) / 2 + NODE_W / 2;
    nodesInTier.forEach((n, ni) => {
      n.x = startX + ni * NODE_W;
      n.y = tierY;
    });
  });

  // ── SVG Setup ──────────────────────────────────────────────────────────
  const svg = d3.select(container).append("svg")
    .attr("width", "100%").attr("height", "100%")
    .attr("viewBox", [0, 0, VW, VH])
    .style("font-family", "'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif");

  const g = svg.append("g");
  const zoom = d3.zoom().scaleExtent([0.1, 5]).on("zoom", (e) => g.attr("transform", e.transform));
  svg.call(zoom);

  // ── Defs: gradients, filters, markers ──────────────────────────────────
  const defs = svg.append("defs");

  // Subtle drop shadow for device nodes
  const shadow = defs.append("filter").attr("id", "node-shadow").attr("x", "-30%").attr("y", "-30%").attr("width", "160%").attr("height", "160%");
  shadow.append("feDropShadow").attr("dx", "0").attr("dy", "2").attr("stdDeviation", "4").attr("flood-color", "rgba(0,0,0,0.4)");

  // Glow filter for managed devices
  const glow = defs.append("filter").attr("id", "topo-glow").attr("x", "-50%").attr("y", "-50%").attr("width", "200%").attr("height", "200%");
  glow.append("feGaussianBlur").attr("in", "SourceAlpha").attr("stdDeviation", "6").attr("result", "blur");
  const glowMerge = glow.append("feMerge");
  glowMerge.append("feMergeNode").attr("in", "blur");
  glowMerge.append("feMergeNode").attr("in", "SourceGraphic");

  // ── Site Title ─────────────────────────────────────────────────────────
  g.append("text").attr("x", contentW / 2).attr("y", 32)
    .attr("text-anchor", "middle").attr("font-size", "22px").attr("font-weight", "800")
    .attr("fill", "#e6edf3").attr("letter-spacing", "2px")
    .text(`${site} — Network Topology`);
  g.append("text").attr("x", contentW / 2).attr("y", 52)
    .attr("text-anchor", "middle").attr("font-size", "11px").attr("fill", "#8b949e")
    .text(`${nodes.length} devices · ${links.length} links · Live SSH Discovery`);

  // ── Tier Zone Backgrounds ──────────────────────────────────────────────
  const zoneG = g.append("g").attr("class", "tier-zones");
  activeTiers.forEach((tier, ti) => {
    const cfg = TIER_CONFIG[tier];
    const tierY = TOP_MARGIN + ti * TIER_H;
    const zoneH = TIER_H;
    zoneG.append("rect")
      .attr("x", 20).attr("y", tierY)
      .attr("width", contentW - 40).attr("height", zoneH)
      .attr("rx", 12).attr("ry", 12)
      .attr("fill", cfg.bg).attr("stroke", cfg.border).attr("stroke-width", 1);
    // Tier label on the left
    zoneG.append("text")
      .attr("x", 34).attr("y", tierY + 16)
      .attr("font-size", "9px").attr("font-weight", "600").attr("fill", cfg.textColor)
      .attr("text-transform", "uppercase").attr("letter-spacing", "1px")
      .text(cfg.label);
  });

  // ── Link Rendering (curved paths) ─────────────────────────────────────
  const _METHOD_STYLES = {
    cluster: { color: "#f0883e", dash: "8,4", width: 3.5 },
    bgp:     { color: "#a371f7", dash: "6,3,2,3", width: 2 },
    arp:     { color: "#56d4dd", dash: "3,5", width: 1.5 },
    zone:    { color: "#d29922", dash: "4,4", width: 1.5 },
  };

  function _linkColor(d) {
    if (d.status === "down") return "#f85149";
    const ms = _METHOD_STYLES[d.method];
    if (ms) return ms.color;
    return (_TOPO_SPEED_STYLES[d.speed] || _TOPO_SPEED_STYLES.unknown).color;
  }
  function _linkWidth(d) {
    if (d.status === "down") return 2.5;
    const ms = _METHOD_STYLES[d.method];
    let w = ms ? ms.width : (_TOPO_SPEED_STYLES[d.speed] || _TOPO_SPEED_STYLES.unknown).width;
    // HLD: thicker line for bundled parallel links
    const lc = d.link_count || 1;
    if (lc > 1) w = Math.min(w + Math.log2(lc) * 1.5, 8);
    return w;
  }
  function _linkDash(d) {
    if (d.status === "down") return "6,4";
    const ms = _METHOD_STYLES[d.method];
    if (ms) return ms.dash;
    return (_TOPO_SPEED_STYLES[d.speed] || _TOPO_SPEED_STYLES.unknown).dash;
  }

  // Resolve link source/target to node objects
  links.forEach(l => {
    if (typeof l.source === "string") l.source = nodeMap[l.source] || l.source;
    if (typeof l.target === "string") l.target = nodeMap[l.target] || l.target;
  });

  const linkG = g.append("g").attr("class", "topo-links");

  // Build paths with gentle curves to avoid overlap
  const linkSel = linkG.selectAll("path").data(links.filter(l => l.source.x !== undefined && l.target.x !== undefined)).join("path")
    .attr("d", d => {
      const sx = d.source.x, sy = d.source.y, tx = d.target.x, ty = d.target.y;
      const dx = tx - sx, dy = ty - sy;
      // Same tier → arc; different tier → gentle S-curve
      if (Math.abs(dy) < 20) {
        // Same tier: semicircle arc
        const r = Math.abs(dx) / 2.5;
        return `M${sx},${sy} A${r},${r} 0 0,1 ${tx},${ty}`;
      }
      // Different tiers: smooth bezier
      const midY = (sy + ty) / 2;
      const offsetX = (dx === 0) ? 0 : Math.sign(dx) * Math.min(Math.abs(dx) * 0.15, 30);
      return `M${sx},${sy} C${sx + offsetX},${midY} ${tx - offsetX},${midY} ${tx},${ty}`;
    })
    .attr("fill", "none")
    .attr("stroke", d => _linkColor(d))
    .attr("stroke-width", d => _linkWidth(d))
    .attr("stroke-dasharray", d => _linkDash(d))
    .attr("stroke-opacity", 0.6)
    .style("cursor", "pointer")
    .on("mouseover", (e, d) => {
      d3.select(e.currentTarget).attr("stroke-opacity", 1).attr("stroke-width", _linkWidth(d) + 2);
      let tip = `${(d.source.label||d.source.id||"").toString().toUpperCase()} ↔ ${(d.target.label||d.target.id||"").toString().toUpperCase()}`;
      if ((d.link_count || 1) > 1) tip += `\n⚡ ${d.link_count} parallel links (bundled)`;
      tip += `\nPort: ${d.source_port || "?"} → ${d.target_port || "?"}`;
      tip += `\nSpeed: ${d.speed || "?"}  Status: ${d.status || "?"}`;
      if (d.lag) tip += `\nLAG: ${d.lag}`;
      if (d.description) tip += `\nDesc: ${d.description}`;
      tip += `\nDiscovery: ${d.method}`;
      if (d.vlans && d.vlans.length > 0) {
        const vNames = d.vlans.slice(0, 8).map(t => {
          const sv = (data.vlans || []).find(v => v.tag === t);
          return sv ? `${t} (${sv.name})` : `${t}`;
        });
        tip += `\nVLANs (${d.vlans.length}): ${vNames.join(", ")}`;
        if (d.vlans.length > 8) tip += ` +${d.vlans.length - 8} more`;
      }
      tipEl.textContent = tip;
      tipEl.style.display = "block";
    })
    .on("mouseout", (e, d) => {
      d3.select(e.currentTarget).attr("stroke-opacity", 0.6).attr("stroke-width", _linkWidth(d));
      tipEl.style.display = "none";
    });

  // Port labels on links (suppress on large sites for HLD cleanliness)
  if (!isLargeSite) {
    links.filter(l => l.source.x !== undefined && l.target.x !== undefined && l.source_port && l.source_port !== "?" && l.source_port !== "BGP")
      .forEach(l => {
        const sx = l.source.x, sy = l.source.y, tx = l.target.x, ty = l.target.y;
        const t = 0.15;
        const px = sx + (tx - sx) * t;
        const py = sy + (ty - sy) * t;
        linkG.append("text").attr("x", px).attr("y", py - 4)
          .attr("text-anchor", "middle").attr("font-size", "7px").attr("fill", "#8b949e")
          .attr("font-family", "Consolas, monospace")
          .text(l.source_port.replace(/^(ge-0\/0\/|xe-0\/0\/|et-0\/0\/|Ethernet)/, "p"));
      });
  }

  // Link count badges for bundled parallel links (HLD-style)
  links.filter(l => l.source.x !== undefined && l.target.x !== undefined && (l.link_count || 1) > 1)
    .forEach(l => {
      const sx = l.source.x, sy = l.source.y, tx = l.target.x, ty = l.target.y;
      const mx = (sx + tx) / 2, my = (sy + ty) / 2;
      linkG.append("rect").attr("x", mx - 11).attr("y", my - 8).attr("width", 22).attr("height", 15).attr("rx", 4)
        .attr("fill", "rgba(13,17,23,0.9)").attr("stroke", _linkColor(l)).attr("stroke-width", 0.8);
      linkG.append("text").attr("x", mx).attr("y", my + 3).attr("text-anchor", "middle")
        .attr("font-size", "7.5px").attr("font-weight", "700").attr("fill", _linkColor(l))
        .attr("font-family", "Consolas, monospace")
        .text(`×${l.link_count}`);
    });

  // ── Node Rendering ─────────────────────────────────────────────────────
  const nodeG = g.append("g").attr("class", "topo-nodes");

  // SVG icon paths for device types
  const DEVICE_ICONS = {
    firewall: {
      // Shield shape with flame
      shape: (el, w, h) => {
        el.append("rect").attr("x", -w/2).attr("y", -h/2).attr("width", w).attr("height", h).attr("rx", 6);
        // Flame icon
        el.append("path").attr("d", "M0,-8 C-2,-4 -6,0 -6,4 C-6,8 -2,11 0,11 C2,11 6,8 6,4 C6,0 2,-4 0,-8Z M0,-3 C1,-1 3,1 3,3 C3,5 1,6 0,6 C-1,6 -3,5 -3,3 C-3,1 -1,-1 0,-3Z")
          .attr("fill", "none").attr("stroke-width", 1.2);
      },
      w: 60, h: 50
    },
    router: {
      shape: (el, w, h) => {
        el.append("circle").attr("r", w/2);
        // Crosshair arrows
        el.append("path").attr("d", "M-10,0 L10,0 M0,-10 L0,10 M-10,0 L-6,-3 M-10,0 L-6,3 M10,0 L6,-3 M10,0 L6,3 M0,-10 L-3,-6 M0,-10 L3,-6 M0,10 L-3,6 M0,10 L3,6")
          .attr("fill", "none").attr("stroke-width", 1.5);
      },
      w: 50, h: 50
    },
    switch: {
      shape: (el, w, h) => {
        el.append("rect").attr("x", -w/2).attr("y", -h/2).attr("width", w).attr("height", h).attr("rx", 4);
        // Port indicators (4 lines)
        for (let i = -3; i <= 3; i += 2) {
          el.append("line").attr("x1", i * 4 - 2).attr("y1", -h/2 + 6).attr("x2", i * 4 - 2).attr("y2", -h/2 + 2)
            .attr("stroke-width", 2.5).attr("stroke-linecap", "round");
          el.append("line").attr("x1", i * 4 - 2).attr("y1", h/2 - 6).attr("x2", i * 4 - 2).attr("y2", h/2 - 2)
            .attr("stroke-width", 2.5).attr("stroke-linecap", "round");
        }
      },
      w: 70, h: 36
    },
    server: {
      shape: (el, w, h) => {
        // Stacked rectangles (rack unit look)
        el.append("rect").attr("x", -w/2).attr("y", -h/2).attr("width", w).attr("height", h/2 - 1).attr("rx", 3);
        el.append("rect").attr("x", -w/2).attr("y", 1).attr("width", w).attr("height", h/2 - 1).attr("rx", 3);
        // Drive slots
        for (let i = 0; i < 4; i++) {
          el.append("rect").attr("x", -w/2 + 5 + i * 8).attr("y", -h/2 + 4).attr("width", 5).attr("height", h/2 - 7).attr("rx", 1)
            .attr("fill", "none").attr("stroke-width", 0.7);
        }
      },
      w: 50, h: 36
    },
    cloud: {
      shape: (el, w, h) => {
        el.append("path")
          .attr("d", "M-20,8 C-24,8 -28,4 -28,-2 C-28,-8 -24,-14 -16,-14 C-14,-18 -8,-22 0,-22 C8,-22 14,-18 16,-14 C24,-14 28,-8 28,-2 C28,4 24,8 20,8 Z")
          .attr("transform", `scale(${w/60},${h/44})`);
      },
      w: 60, h: 44
    },
    group: {
      shape: (el, w, h) => {
        // Stacked rects to show multiple units
        el.append("rect").attr("x", -w/2 + 3).attr("y", -h/2 + 3).attr("width", w - 6).attr("height", h - 6).attr("rx", 4)
          .attr("stroke-dasharray", "3,2");
        el.append("rect").attr("x", -w/2).attr("y", -h/2).attr("width", w - 6).attr("height", h - 6).attr("rx", 4);
      },
      w: 54, h: 40
    },
  };

  function _getIconType(d) {
    if (d.type === "cloud" || d.role === "isp") return "cloud";
    if (d.type === "group") return "group";
    if (d.role === "firewall") return "firewall";
    if (d.role === "router") return "router";
    if (d.role === "switch" || d.role === "gateway") return "switch";
    return "server";
  }

  const nodeSel = nodeG.selectAll("g.topo-node").data(nodes).join("g")
    .attr("class", "topo-node")
    .attr("transform", d => `translate(${d.x},${d.y})`)
    .style("cursor", "pointer");

  // Draw each node
  nodeSel.each(function(d) {
    const el = d3.select(this);
    const rc = _TOPO_ROLE_COLORS[d.role] || _TOPO_ROLE_COLORS.unknown;
    const iconType = _getIconType(d);
    const icon = DEVICE_ICONS[iconType] || DEVICE_ICONS.server;
    const isManaged = d.type === "managed";
    const scale = isManaged ? 1.0 : 0.75;
    const w = icon.w * scale, h = icon.h * scale;

    const shapeG = el.append("g").attr("class", "device-shape");
    if (isManaged) shapeG.attr("filter", "url(#node-shadow)");

    // Draw shape
    icon.shape(shapeG, w, h);

    // Style all rects/circles/paths in the shape
    shapeG.selectAll("rect, circle, path").attr("fill", rc.bg).attr("stroke", rc.stroke).attr("stroke-width", isManaged ? 2 : 1.2);
    shapeG.selectAll("line").attr("stroke", rc.stroke);

    // Inner icon elements (flame, arrows, etc.) — just stroke, no fill
    shapeG.selectAll("path:not(:first-child)").attr("fill", "none").attr("stroke", rc.fill);

    // Managed glow ring
    if (isManaged) {
      el.append("rect").attr("x", -w/2 - 6).attr("y", -h/2 - 6).attr("width", w + 12).attr("height", h + 12).attr("rx", 10)
        .attr("fill", "none").attr("stroke", rc.stroke).attr("stroke-width", 1).attr("stroke-opacity", 0.2)
        .attr("filter", "url(#topo-glow)");
    }

    // Model / info badge inside
    if (d.model && isManaged) {
      el.append("text").attr("y", h/2 - 6).attr("text-anchor", "middle")
        .attr("font-size", "6px").attr("fill", rc.fill).attr("font-family", "Consolas, monospace")
        .text(d.model.length > 14 ? d.model.substring(0, 12) + ".." : d.model);
    }

    // Error indicator
    if (d.error) {
      el.append("circle").attr("cx", w/2 - 2).attr("cy", -h/2 + 2).attr("r", 6)
        .attr("fill", "#f85149").attr("stroke", "#0d1117").attr("stroke-width", 1.5);
      el.append("text").attr("x", w/2 - 2).attr("y", -h/2 + 5).attr("text-anchor", "middle")
        .attr("font-size", "8px").attr("fill", "#fff").attr("font-weight", "bold").text("!");
    }
  });

  // Node labels (below device)
  nodeSel.append("text")
    .text(d => {
      let lbl = (d.label || d.id).toUpperCase();
      if (lbl.length > 24) lbl = lbl.substring(0, 22) + "..";
      return lbl;
    })
    .attr("text-anchor", "middle")
    .attr("dy", d => {
      const icon = DEVICE_ICONS[_getIconType(d)] || DEVICE_ICONS.server;
      const scale = d.type === "managed" ? 1.0 : 0.75;
      return icon.h * scale / 2 + 14;
    })
    .attr("font-size", d => d.type === "managed" ? "9px" : "7.5px")
    .attr("font-weight", d => d.type === "managed" ? "700" : "500")
    .attr("fill", d => d.type === "managed" ? (_TOPO_ROLE_COLORS[d.role] || _TOPO_ROLE_COLORS.unknown).stroke : "#8b949e")
    .attr("paint-order", "stroke").attr("stroke", "#0d1117").attr("stroke-width", "3px");

  // Sub-label: interface counts or member counts
  nodeSel.filter(d => d.type === "managed" && d.interfaces_total > 0).append("text")
    .attr("text-anchor", "middle")
    .attr("dy", d => {
      const icon = DEVICE_ICONS[_getIconType(d)] || DEVICE_ICONS.server;
      return icon.h / 2 + 25;
    })
    .attr("font-size", "7px").attr("fill", "#6b7280").attr("font-family", "Consolas, monospace")
    .text(d => {
      let txt = `${d.interfaces_up}↑ ${d.interfaces_down}↓`;
      if (d.bgp_peers) txt += ` · BGP:${d.bgp_up||0}/${d.bgp_peers}`;
      if (d.total_macs) txt += ` · ${d.total_macs}mac`;
      return txt;
    });

  // Group badge
  nodeSel.filter(d => d.type === "group").append("text")
    .attr("text-anchor", "middle").attr("dy", 5)
    .attr("font-size", "13px").attr("font-weight", "800")
    .attr("fill", d => (_TOPO_ROLE_COLORS[d.role] || _TOPO_ROLE_COLORS.unknown).fill)
    .text(d => (d.group_members || []).length || d.interfaces_total || "");

  // ── Hover Interactions ─────────────────────────────────────────────────
  nodeSel.on("mouseover", (e, d) => {
    const connected = new Set();
    links.forEach(l => {
      const sid = (l.source.id || l.source);
      const tid = (l.target.id || l.target);
      if (sid === d.id) connected.add(tid);
      if (tid === d.id) connected.add(sid);
    });
    connected.add(d.id);
    nodeSel.attr("opacity", n => connected.has(n.id) ? 1 : 0.12);
    linkSel.attr("stroke-opacity", l => {
      const sid = (l.source.id || l.source);
      const tid = (l.target.id || l.target);
      return (sid === d.id || tid === d.id) ? 1 : 0.04;
    });

    let tip = (d.label || d.id).toUpperCase();
    if (d.type === "managed") {
      tip += `\nRole: ${d.role}  Type: ${d.dtype}`;
      if (d.model) tip += `\nModel: ${d.model}`;
      if (d.ip) tip += `\nIP: ${d.ip}`;
      tip += `\nInterfaces: ${d.interfaces_up}↑ ${d.interfaces_down}↓ / ${d.interfaces_total}`;
      if (d.vlan_count) tip += `\nVLANs: ${d.vlan_count}`;
      if (d.total_macs) tip += `\nMAC Table: ${d.total_macs} entries`;
      if (d.bgp_peers) tip += `\nBGP: ${d.bgp_up||0}↑ ${d.bgp_down||0}↓ / ${d.bgp_peers} peers`;
      if (d.zone_descriptions && d.zone_descriptions.length) {
        tip += "\nZones:";
        d.zone_descriptions.forEach(z => { tip += `\n  ${z.interface}: ${z.description} (${z.status})`; });
      }
    } else if (d.type === "group") {
      tip += `\n${(d.group_members||[]).length} ${d.role} nodes`;
      if (d.group_members) tip += "\n" + d.group_members.slice(0, 10).join(", ") + (d.group_members.length > 10 ? " ..." : "");
    } else if (d.type === "cloud") {
      tip += `\n${d.interfaces_up||0}↑ ${d.interfaces_down||0}↓ / ${d.interfaces_total||0} peers`;
    } else {
      tip += `\nRole: ${d.role}  (${d.type})`;
    }
    if (d.error) tip += `\n⚠ ${d.error}`;
    tipEl.textContent = tip;
    tipEl.style.display = "block";
  })
  .on("mouseout", () => {
    nodeSel.attr("opacity", 1);
    linkSel.attr("stroke-opacity", 0.6);
    tipEl.style.display = "none";
  })
  .on("click", (e, d) => {
    if (d.type === "managed" && d.ip) {
      const match = allDevices.find(dev =>
        dev.hostname.split(".")[0].toLowerCase() === d.id.toLowerCase() || dev.ip === d.ip
      );
      if (match) { selectDev(match); setTimeout(() => switchTabById("topo"), 50); }
    }
  })
  .on("dblclick", (e, d) => {
    const scale = 2.5;
    const tx = VW / 2 - d.x * scale;
    const ty = VH / 2 - d.y * scale;
    svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
  });

  // Move tooltip with mouse
  svg.on("mousemove", (e) => {
    if (tipEl.style.display === "block") {
      tipEl.style.left = (e.pageX + 14) + "px";
      tipEl.style.top = (e.pageY - 12) + "px";
    }
  });

  // Drag support (adjusts position, no simulation)
  nodeSel.call(d3.drag()
    .on("drag", (e, d) => {
      d.x = e.x; d.y = e.y;
      d3.select(e.sourceEvent.target.closest(".topo-node")).attr("transform", `translate(${d.x},${d.y})`);
      // Update connected links
      linkSel.attr("d", ld => {
        const sx = ld.source.x, sy = ld.source.y, tx = ld.target.x, ty = ld.target.y;
        if (Math.abs(ty - sy) < 20) {
          const r = Math.abs(tx - sx) / 2.5;
          return `M${sx},${sy} A${r},${r} 0 0,1 ${tx},${ty}`;
        }
        const midY = (sy + ty) / 2;
        const dx2 = tx - sx;
        const offsetX = (dx2 === 0) ? 0 : Math.sign(dx2) * Math.min(Math.abs(dx2) * 0.15, 30);
        return `M${sx},${sy} C${sx + offsetX},${midY} ${tx - offsetX},${midY} ${tx},${ty}`;
      });
    })
  );

  // ── VLAN Color Palette ──────────────────────────────────────────────────
  const VLAN_COLORS = [
    "#ff6b6b", "#ffd93d", "#6bcb77", "#4d96ff", "#ff922b",
    "#c084fc", "#22d3ee", "#f472b6", "#a3e635", "#fb923c",
    "#818cf8", "#34d399", "#f87171", "#fbbf24", "#60a5fa",
    "#e879f9", "#2dd4bf", "#f97316", "#a78bfa", "#4ade80",
  ];
  const siteVlans = data.vlans || [];
  const vlanColorMap = {};  // tag -> color
  siteVlans.forEach((v, i) => { vlanColorMap[v.tag] = VLAN_COLORS[i % VLAN_COLORS.length]; });

  // ── VLAN Traffic Flow Overlay Lines ────────────────────────────────────
  const vlanFlowG = g.append("g").attr("class", "vlan-flows");
  // HLD: VLAN flows hidden by default to reduce visual noise on large sites
  // "none" = hidden, null = show all, number = single VLAN highlighted
  let _activeVlanFilter = "none";

  function _renderVlanFlows() {
    vlanFlowG.selectAll("*").remove();
    if (_activeVlanFilter === "none") return;  // Hidden by default
    // For each link that carries VLANs, draw thin colored flow lines offset from the main path
    links.filter(l => l.source.x !== undefined && l.target.x !== undefined && l.vlans && l.vlans.length > 0)
      .forEach(l => {
        const sx = l.source.x, sy = l.source.y, tx = l.target.x, ty = l.target.y;
        const vlans = _activeVlanFilter != null ? l.vlans.filter(v => v === _activeVlanFilter) : l.vlans;
        if (!vlans.length) return;

        // Calculate perpendicular offset direction
        const dx = tx - sx, dy = ty - sy;
        const len = Math.sqrt(dx * dx + dy * dy) || 1;
        const nx = -dy / len, ny = dx / len;  // normal vector

        const maxFlows = Math.min(vlans.length, 6);  // limit to 6 visible flows per link
        const spacing = 3.5;
        const startOffset = -(maxFlows - 1) * spacing / 2;

        vlans.slice(0, maxFlows).forEach((vlanTag, vi) => {
          const color = vlanColorMap[vlanTag] || "#6b7280";
          const offset = startOffset + vi * spacing;
          const osx = sx + nx * offset, osy = sy + ny * offset;
          const otx = tx + nx * offset, oty = ty + ny * offset;

          // Smooth bezier (same logic as main links)
          let pathD;
          if (Math.abs(dy) < 20) {
            const r = Math.abs(dx) / 2.5;
            pathD = `M${osx},${osy} A${r},${r} 0 0,1 ${otx},${oty}`;
          } else {
            const midY = (osy + oty) / 2;
            const ox2 = (dx === 0) ? 0 : Math.sign(dx) * Math.min(Math.abs(dx) * 0.15, 30);
            pathD = `M${osx},${osy} C${osx + ox2},${midY} ${otx - ox2},${midY} ${otx},${oty}`;
          }

          // Animated flow line
          vlanFlowG.append("path")
            .attr("d", pathD)
            .attr("fill", "none")
            .attr("stroke", color)
            .attr("stroke-width", 2)
            .attr("stroke-opacity", _activeVlanFilter != null ? 0.85 : 0.5)
            .attr("stroke-dasharray", "6,4")
            .attr("class", `vlan-flow vlan-${vlanTag}`)
            .style("animation", `vlanFlow ${1.5 + vi * 0.2}s linear infinite`);

          // Arrow marker at 70% of the path
          const t = 0.7;
          const arrowX = osx + (otx - osx) * t;
          const arrowY = osy + (oty - osy) * t;
          const angle = Math.atan2(oty - osy, otx - osx) * 180 / Math.PI;
          vlanFlowG.append("polygon")
            .attr("points", "-4,-3 4,0 -4,3")
            .attr("transform", `translate(${arrowX},${arrowY}) rotate(${angle})`)
            .attr("fill", color)
            .attr("fill-opacity", _activeVlanFilter != null ? 0.9 : 0.55)
            .attr("class", `vlan-flow vlan-${vlanTag}`);
        });

        // VLAN count badge at midpoint (if >1 VLAN and no active filter)
        if (_activeVlanFilter == null && l.vlans.length > 1) {
          const mx = (sx + tx) / 2 + nx * ((maxFlows + 1) * spacing / 2);
          const my = (sy + ty) / 2 + ny * ((maxFlows + 1) * spacing / 2);
          vlanFlowG.append("rect")
            .attr("x", mx - 10).attr("y", my - 7).attr("width", 20).attr("height", 14).attr("rx", 4)
            .attr("fill", "rgba(13,17,23,0.85)").attr("stroke", "#58a6ff").attr("stroke-width", 0.5);
          vlanFlowG.append("text")
            .attr("x", mx).attr("y", my + 3).attr("text-anchor", "middle")
            .attr("font-size", "7px").attr("font-weight", "700").attr("fill", "#58a6ff")
            .text(`${l.vlans.length}V`);
        }
      });
  }

  // Inject CSS animation for VLAN flow
  if (!document.getElementById("vlan-flow-css")) {
    const style = document.createElement("style");
    style.id = "vlan-flow-css";
    style.textContent = `
      @keyframes vlanFlow {
        from { stroke-dashoffset: 20; }
        to { stroke-dashoffset: 0; }
      }
    `;
    document.head.appendChild(style);
  }

  _renderVlanFlows();

  // ── Legend Panel ────────────────────────────────────────────────────────
  const hasVlans = siteVlans.length > 0;
  const legendH = hasVlans ? 370 + 28 + Math.min(siteVlans.length, 15) * 18 + 30 : 370;

  const lgX = contentW + 20, lgY = TOP_MARGIN + 10;
  const lg = g.append("g").attr("transform", `translate(${lgX},${lgY})`);
  lg.append("rect").attr("x", 0).attr("y", 0).attr("width", 220).attr("height", legendH).attr("rx", 10)
    .attr("fill", "rgba(13,17,23,0.85)").attr("stroke", "rgba(88,166,255,0.2)").attr("stroke-width", 1);
  lg.append("text").attr("x", 110).attr("y", 22).attr("text-anchor", "middle")
    .attr("font-size", "10px").attr("font-weight", "700").attr("fill", "#e6edf3").text("LEGEND");

  // Device types
  const devLeg = [
    { label: "Firewall", color: "#f85149" },
    { label: "Router", color: "#f0883e" },
    { label: "Switch (Core)", color: "#3fb950" },
    { label: "Switch (Access)", color: "#3fb950" },
    { label: "Server / Compute", color: "#8b949e" },
    { label: "ISP / WAN / eBGP", color: "#d29922" },
    { label: "IPMI / PXE", color: "#06b6d4" },
  ];
  devLeg.forEach((item, i) => {
    const y = 40 + i * 20;
    lg.append("rect").attr("x", 14).attr("y", y - 5).attr("width", 12).attr("height", 12).attr("rx", 3)
      .attr("fill", item.color).attr("fill-opacity", 0.25).attr("stroke", item.color).attr("stroke-width", 1.2);
    lg.append("text").attr("x", 34).attr("y", y + 5).attr("font-size", "8.5px").attr("fill", "#c9d1d9").text(item.label);
  });

  // Link speeds
  lg.append("text").attr("x", 14).attr("y", 198).attr("font-size", "9px").attr("font-weight", "600").attr("fill", "#8b949e").text("LINK SPEED");
  const speedLeg = [
    { label: "100G Fiber", color: "#22d3ee", w: 4, dash: null },
    { label: "10G Fiber", color: "#4caf50", w: 2.5, dash: null },
    { label: "1G Copper", color: "#2196f3", w: 1.5, dash: "6,3" },
    { label: "LAG/Trunk", color: "#a78bfa", w: 2, dash: "3,2" },
  ];
  speedLeg.forEach((item, i) => {
    const y = 214 + i * 18;
    lg.append("line").attr("x1", 14).attr("y1", y).attr("x2", 44).attr("y2", y)
      .attr("stroke", item.color).attr("stroke-width", item.w).attr("stroke-dasharray", item.dash);
    lg.append("text").attr("x", 52).attr("y", y + 3).attr("font-size", "8px").attr("fill", "#c9d1d9").text(item.label);
  });

  // Discovery methods
  lg.append("text").attr("x", 14).attr("y", 290).attr("font-size", "9px").attr("font-weight", "600").attr("fill", "#8b949e").text("DISCOVERY");
  const discLeg = [
    { label: "HA Cluster", color: "#f0883e", dash: "8,4" },
    { label: "BGP Peer", color: "#a371f7", dash: "6,3,2,3" },
    { label: "ARP Table", color: "#56d4dd", dash: "3,5" },
  ];
  discLeg.forEach((item, i) => {
    const y = 306 + i * 18;
    lg.append("line").attr("x1", 14).attr("y1", y).attr("x2", 44).attr("y2", y)
      .attr("stroke", item.color).attr("stroke-width", 2).attr("stroke-dasharray", item.dash);
    lg.append("text").attr("x", 52).attr("y", y + 3).attr("font-size", "8px").attr("fill", "#c9d1d9").text(item.label);
  });

  // ── VLAN Legend ──────────────────────────────────────────────────────────
  if (hasVlans) {
    const vlanStartY = 365;
    // Separator line
    lg.append("line").attr("x1", 14).attr("y1", vlanStartY - 10).attr("x2", 206).attr("y2", vlanStartY - 10)
      .attr("stroke", "rgba(88,166,255,0.15)").attr("stroke-width", 1);

    // Section header with count
    lg.append("text").attr("x", 14).attr("y", vlanStartY + 8)
      .attr("font-size", "9px").attr("font-weight", "700").attr("fill", "#58a6ff")
      .text(`VLAN TRAFFIC FLOW (${siteVlans.length})`);

    // "Show All" button — shows all VLAN flows
    const resetG = lg.append("g").attr("class", "vlan-reset").style("cursor", "pointer")
      .attr("transform", `translate(135,${vlanStartY})`)
      .on("click", () => {
        _activeVlanFilter = null;
        _renderVlanFlows();
        lg.selectAll(".vlan-leg-item").attr("opacity", 1);
        linkSel.attr("stroke-opacity", 0.6);
        nodeSel.attr("opacity", 1);
      });
    resetG.append("rect").attr("x", 0).attr("y", -7).attr("width", 30).attr("height", 14).attr("rx", 3)
      .attr("fill", "rgba(88,166,255,0.1)").attr("stroke", "#58a6ff").attr("stroke-width", 0.5);
    resetG.append("text").attr("x", 15).attr("y", 3).attr("text-anchor", "middle")
      .attr("font-size", "7px").attr("fill", "#58a6ff").attr("font-weight", "600").text("ALL");

    // "Hide" button — hides all VLAN flows (default state)
    const hideG = lg.append("g").style("cursor", "pointer")
      .attr("transform", `translate(170,${vlanStartY})`)
      .on("click", () => {
        _activeVlanFilter = "none";
        _renderVlanFlows();
        lg.selectAll(".vlan-leg-item").attr("opacity", 0.5);
        linkSel.attr("stroke-opacity", 0.6);
        nodeSel.attr("opacity", 1);
      });
    hideG.append("rect").attr("x", 0).attr("y", -7).attr("width", 34).attr("height", 14).attr("rx", 3)
      .attr("fill", "rgba(248,81,73,0.1)").attr("stroke", "#f85149").attr("stroke-width", 0.5);
    hideG.append("text").attr("x", 17).attr("y", 3).attr("text-anchor", "middle")
      .attr("font-size", "7px").attr("fill", "#f85149").attr("font-weight", "600").text("HIDE");

    // Individual VLANs (up to 15)
    const displayVlans = siteVlans.slice(0, 15);
    displayVlans.forEach((v, i) => {
      const y = vlanStartY + 24 + i * 18;
      const color = vlanColorMap[v.tag] || "#6b7280";

      const itemG = lg.append("g").attr("class", "vlan-leg-item").style("cursor", "pointer")
        .attr("opacity", 0.5)  // dimmed by default since flows are hidden
        .on("click", () => {
          // Toggle: click to show this VLAN, click again to hide all
          if (_activeVlanFilter === v.tag) {
            _activeVlanFilter = "none";
            _renderVlanFlows();
            lg.selectAll(".vlan-leg-item").attr("opacity", 0.5);
            linkSel.attr("stroke-opacity", 0.6);
            nodeSel.attr("opacity", 1);
          } else {
            _activeVlanFilter = v.tag;
            _renderVlanFlows();
            lg.selectAll(".vlan-leg-item").attr("opacity", 0.3);
            itemG.attr("opacity", 1);
            linkSel.attr("stroke-opacity", l => (l.vlans && l.vlans.includes(v.tag)) ? 0.9 : 0.08);
            const vlanDevices = new Set(v.device_list || []);
            nodeSel.attr("opacity", n => vlanDevices.has(n.id) ? 1 : 0.15);
          }
        })
        .on("mouseover", function() {
          if (_activeVlanFilter === "none") return;  // Don't preview when flows are hidden
          vlanFlowG.selectAll(`.vlan-flow:not(.vlan-${v.tag})`).attr("stroke-opacity", 0.1).attr("fill-opacity", 0.1);
          vlanFlowG.selectAll(`.vlan-${v.tag}`).attr("stroke-opacity", 1).attr("fill-opacity", 1);
        })
        .on("mouseout", function() {
          if (_activeVlanFilter == null) {
            vlanFlowG.selectAll(".vlan-flow").attr("stroke-opacity", 0.5).attr("fill-opacity", 0.55);
          }
        });

      // Color dot with animated ring
      itemG.append("circle").attr("cx", 20).attr("cy", y).attr("r", 5)
        .attr("fill", color).attr("fill-opacity", 0.35).attr("stroke", color).attr("stroke-width", 1.5);
      // Flow arrow indicator
      itemG.append("path")
        .attr("d", `M28,${y} L38,${y}`)
        .attr("stroke", color).attr("stroke-width", 1.8).attr("stroke-dasharray", "3,2")
        .attr("marker-end", "none");
      itemG.append("polygon")
        .attr("points", `-3,-2.5 3,0 -3,2.5`)
        .attr("transform", `translate(41,${y})`)
        .attr("fill", color).attr("fill-opacity", 0.8);

      // VLAN tag + name
      const name = v.name.length > 14 ? v.name.substring(0, 12) + ".." : v.name;
      itemG.append("text").attr("x", 48).attr("y", y + 3)
        .attr("font-size", "7.5px").attr("fill", "#e6edf3").attr("font-weight", "600")
        .text(`${v.tag}`);
      itemG.append("text").attr("x", 74).attr("y", y + 3)
        .attr("font-size", "7px").attr("fill", "#8b949e")
        .text(name);

      // Device count badge
      itemG.append("text").attr("x", 198).attr("y", y + 3).attr("text-anchor", "end")
        .attr("font-size", "7px").attr("fill", color).attr("font-weight", "600")
        .text(`${v.devices}d ${v.interfaces}p`);
    });

    // "More..." indicator
    if (siteVlans.length > 15) {
      const y = vlanStartY + 24 + 15 * 18;
      lg.append("text").attr("x", 110).attr("y", y).attr("text-anchor", "middle")
        .attr("font-size", "7px").attr("fill", "#6b7280").attr("font-style", "italic")
        .text(`+${siteVlans.length - 15} more VLANs`);
    }
  }

  // ── Store refs & auto-fit ──────────────────────────────────────────────
  _topoRefs = { svg, g, zoom, sim: null, node: nodeSel, link: linkSel, nodes, links, W: VW, H: VH };

  // Auto-fit on render
  setTimeout(() => {
    const bounds = g.node().getBBox();
    if (bounds.width > 0 && bounds.height > 0) {
      const scale = Math.min(W / (bounds.width + 40), H / (bounds.height + 40), 1.5) * 0.92;
      const tx = W / 2 - (bounds.x + bounds.width / 2) * scale;
      const ty = H / 2 - (bounds.y + bounds.height / 2) * scale;
      svg.transition().duration(600).call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
    }
  }, 100);
}

function topoFit() {
  if (!_topoRefs) return;
  const { svg, g, zoom, W, H } = _topoRefs;
  const bounds = g.node().getBBox();
  if (bounds.width > 0) {
    const scale = Math.min(W / (bounds.width + 100), H / (bounds.height + 100), 2) * 0.85;
    const tx = W / 2 - (bounds.x + bounds.width / 2) * scale;
    const ty = H / 2 - (bounds.y + bounds.height / 2) * scale;
    svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
  }
}
function topoZoomIn() {
  if (!_topoRefs) return;
  const { svg, zoom } = _topoRefs;
  svg.transition().duration(300).call(zoom.scaleBy, 1.5);
}
function topoZoomOut() {
  if (!_topoRefs) return;
  const { svg, zoom } = _topoRefs;
  svg.transition().duration(300).call(zoom.scaleBy, 0.67);
}
function topoReset() {
  if (topoCurrentSite) loadTopoSite(topoCurrentSite);
}

// ══════════════════════════════════════════════════════════════════════════════
// NAPALM Tab
// ══════════════════════════════════════════════════════════════════════════════

let _napInit = false;
let _napJobId = null;
let _napPoll = null;
let _napLastResult = null;
let _napLastTool = null;

async function initNapalmTab() {
  if (_napInit) return;
  _napInit = true;
  try {
    const r = await fetch(`${API}/napalm/status`);
    const d = await r.json();
    const sel = document.getElementById("nap-site");
    sel.innerHTML = '<option value="">Select site…</option>';
    for (const [s, info] of Object.entries(d.sites || {})) {
      sel.innerHTML += `<option value="${s}">${s.toUpperCase()} (${info.devices} devices)</option>`;
    }
    document.getElementById("nap-status").textContent =
      `NAPALM ${d.available ? '✅' : '❌'} · ${d.total_devices} devices`;
  } catch (e) {
    document.getElementById("nap-status").textContent = "NAPALM: unavailable";
  }
}

function napSiteChanged() {
  const site = document.getElementById("nap-site").value;
  if (site) _napLoadSnapshots(site);
}

async function _napLoadSnapshots(site) {
  try {
    const r = await fetch(`${API}/napalm/snapshots/${site.toUpperCase()}`);
    const snaps = await r.json();
    const selA = document.getElementById("nap-snap-a");
    const selB = document.getElementById("nap-snap-b");
    const opts = snaps.map(s => `<option value="${s.file}">${s.file}</option>`).join("");
    selA.innerHTML = opts || '<option value="">No snapshots</option>';
    selB.innerHTML = opts || '<option value="">No snapshots</option>';
    if (snaps.length >= 2) selB.selectedIndex = 1;
  } catch (e) {}
}

async function napRun(tool) {
  const site = document.getElementById("nap-site").value;
  if (!site && tool !== "version-audit") {
    document.getElementById("nap-output").innerHTML =
      '<div style="color:var(--yellow);text-align:center;padding:40px">⚠️ Select a site first</div>';
    return;
  }
  _napShowProgress("Starting...", 0);
  try {
    const r = await fetch(`${API}/napalm/${tool}`, {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({site}),
    });
    const d = await r.json();
    if (d.error) { _napHideProgress(); _napShowError(d.error); return; }
    _napJobId = d.job_id;
    _napLastTool = tool;
    _napPollJob(d.job_id, tool);
  } catch (e) { _napHideProgress(); _napShowError(e.message); }
}

async function napSnapshot(label) {
  const site = document.getElementById("nap-site").value;
  if (!site) { _napShowError("Select a site first"); return; }
  _napShowProgress(`Taking ${label.toUpperCase()} snapshot...`, 0);
  try {
    const r = await fetch(`${API}/napalm/snapshot`, {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({site, label}),
    });
    const d = await r.json();
    _napJobId = d.job_id;
    _napLastTool = "snapshot";
    _napPollJob(d.job_id, "snapshot");
  } catch (e) { _napHideProgress(); _napShowError(e.message); }
}

async function napDiff() {
  const fA = document.getElementById("nap-snap-a").value;
  const fB = document.getElementById("nap-snap-b").value;
  if (!fA || !fB) { _napShowError("Select two snapshots to compare"); return; }
  document.getElementById("nap-output").innerHTML =
    '<div style="text-align:center;padding:40px"><span class="spin"></span> Comparing...</div>';
  try {
    const r = await fetch(`${API}/napalm/snapshot-diff`, {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({file_a: fA, file_b: fB}),
    });
    const d = await r.json();
    _napLastResult = d; _napLastTool = "diff";
    _napRenderDiff(d);
  } catch (e) { _napShowError(e.message); }
}

function _napPollJob(jobId, tool) {
  if (_napPoll) clearInterval(_napPoll);
  _napPoll = setInterval(async () => {
    try {
      const r = await fetch(`${API}/napalm/jobs/${jobId}`);
      const j = await r.json();
      _napShowProgress(j.message, j.progress);
      if (j.status === "done") {
        clearInterval(_napPoll);
        _napHideProgress();
        _napLastResult = j.result;
        _napRenderResult(tool, j.result);
        if (tool === "snapshot") {
          const site = document.getElementById("nap-site").value;
          if (site) _napLoadSnapshots(site);
        }
      } else if (j.status === "error") {
        clearInterval(_napPoll);
        _napHideProgress();
        _napShowError(j.message);
      }
    } catch (e) {}
  }, 1200);
}

function _napShowProgress(msg, pct) {
  document.getElementById("nap-progress").style.display = "block";
  document.getElementById("nap-prog-msg").textContent = msg;
  document.getElementById("nap-prog-fill").style.width = pct + "%";
}
function _napHideProgress() { document.getElementById("nap-progress").style.display = "none"; }
function _napShowError(msg) {
  document.getElementById("nap-output").innerHTML =
    `<div style="color:var(--red);padding:20px;text-align:center">❌ ${msg}</div>`;
}
function clearNapalm() {
  document.getElementById("nap-output").innerHTML =
    '<div style="color:var(--muted);text-align:center;padding:60px;font-size:13px"><div style="font-size:32px;margin-bottom:12px">🔧</div>Cleared. Select a tool to run.</div>';
  _napLastResult = null;
}

function _napRenderResult(tool, data) {
  const out = document.getElementById("nap-output");
  const fn = {
    "version-audit": _napRenderVersion,
    "bgp-status": _napRenderBgp,
    "env-health": _napRenderEnv,
    "interface-errors": _napRenderErrors,
    "lldp-topology": _napRenderLldp,
    "site-collect": _napRenderCollect,
    "snapshot": _napRenderSnap,
    "global-report": _napRenderGlobal,
  }[tool];
  if (fn) out.innerHTML = fn(data);
  else out.innerHTML = `<pre style="color:var(--text);font-size:11px;white-space:pre-wrap">${JSON.stringify(data, null, 2)}</pre>`;
}

function _napSC(val, label, color) {
  return `<div class="stat-card"><div class="sv" style="color:${color}">${val}</div><div class="sl">${label}</div></div>`;
}
function _napBadge(text, type) {
  const colors = {ok:"var(--green)",error:"var(--red)",warn:"var(--yellow)",info:"var(--accent)"};
  const c = colors[type] || "var(--muted)";
  return `<span style="padding:1px 6px;border-radius:9px;font-size:10px;font-weight:700;background:${c}22;color:${c};border:1px solid ${c}33">${text}</span>`;
}
function _napUptime(s) {
  if (!s || s < 0) return "-";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
  return d > 0 ? `${d}d ${h}h` : `${h}h ${Math.floor((s%3600)/60)}m`;
}
function _napFmt(n) { return (n||0).toLocaleString(); }

// ── Version Audit Renderer ──
function _napRenderVersion(d) {
  let h = `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
    ${_napSC(d.total,"Devices","var(--accent)")}${_napSC(d.total-d.errors,"Reachable","var(--green)")}
    ${_napSC(d.errors,"Unreachable","var(--red)")}${_napSC(d.mismatches.length,"Mismatches",d.mismatches.length?"var(--yellow)":"var(--green)")}</div>`;
  if (d.mismatches.length) {
    h += `<div class="asec" style="border-color:var(--yellow);margin-bottom:8px"><h4 style="color:var(--yellow)">⚠️ Version Mismatches</h4>`;
    for (const m of d.mismatches) h += `<div class="aitem"><span style="color:var(--yellow)">⚠️</span><span><b>${m.model}</b> (${m.driver}): ${m.versions.map(v=>`<code style="color:var(--yellow)">${v}</code>`).join(", ")}<br><small style="color:var(--muted)">${m.devices.join(", ")}</small></span></div>`;
    h += `</div>`;
  }
  h += `<div class="asec"><h4>📋 Device Inventory</h4><div style="overflow-x:auto"><table style="width:100%;font-size:11px;border-collapse:collapse">
    <tr style="border-bottom:1px solid var(--border)">${["Site","Device","IP","Vendor","Model","OS Version","Serial","Uptime","Status"].map(c=>`<th style="text-align:left;padding:4px 6px;color:var(--muted);font-size:10px">${c}</th>`).join("")}</tr>`;
  for (const r of d.devices) {
    const st = r.error ? _napBadge("Error","error") : _napBadge("OK","ok");
    h += `<tr style="border-bottom:1px solid var(--border)"><td style="padding:3px 6px">${r.site}</td><td style="padding:3px 6px;font-family:Consolas,monospace;font-size:11px">${r.hostname}</td><td style="padding:3px 6px;font-family:Consolas,monospace;font-size:11px">${r.ip}</td><td style="padding:3px 6px">${r.vendor}</td><td style="padding:3px 6px">${r.model}</td><td style="padding:3px 6px;font-family:Consolas,monospace">${r.os_version}</td><td style="padding:3px 6px;font-family:Consolas,monospace">${r.serial}</td><td style="padding:3px 6px">${_napUptime(r.uptime)}</td><td style="padding:3px 6px">${st}</td></tr>`;
  }
  h += `</table></div></div>`;
  return h;
}

// ── BGP Status Renderer ──
function _napRenderBgp(d) {
  let h = `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
    ${_napSC(d.devices.length,"Devices","var(--accent)")}${_napSC(d.total_peers,"Total Peers","var(--green)")}
    ${_napSC(d.total_peers-d.total_down,"Up","var(--green)")}${_napSC(d.total_down,"Down",d.total_down?"var(--red)":"var(--green)")}</div>`;
  const down = [];
  for (const dev of d.devices) for (const p of (dev.peers||[])) if (!p.is_up) down.push({h:dev.hostname,...p});
  if (down.length) {
    h += `<div class="asec" style="border-color:var(--red);margin-bottom:8px"><h4 style="color:var(--red)">🔴 Down Peers</h4>`;
    for (const p of down) h += `<div class="aitem"><span style="color:var(--red)">❌</span><span><b>${p.h}</b> → <code>${p.peer_ip}</code> ${p.description?`(${p.description})`:""} · VRF: ${p.vrf}</span></div>`;
    h += `</div>`;
  }
  for (const dev of d.devices) {
    if (dev.error) { h += `<div class="asec" style="margin-bottom:6px"><h4>${dev.hostname} ${_napBadge("Error","error")}</h4></div>`; continue; }
    if (!dev.peers.length) continue;
    h += `<div class="asec" style="margin-bottom:6px"><h4>${dev.hostname} — ${dev.total} peers (${dev.up}↑ ${dev.down}↓)</h4><div style="overflow-x:auto"><table style="width:100%;font-size:11px;border-collapse:collapse">
      <tr style="border-bottom:1px solid var(--border)">${["Peer IP","VRF","State","Description","Uptime","Rcvd","Sent"].map(c=>`<th style="text-align:left;padding:3px 6px;color:var(--muted);font-size:10px">${c}</th>`).join("")}</tr>`;
    for (const p of dev.peers) {
      const st = p.is_up ? _napBadge("UP","ok") : _napBadge("DOWN","error");
      h += `<tr style="border-bottom:1px solid var(--border)"><td style="padding:3px 6px;font-family:Consolas,monospace">${p.peer_ip}</td><td style="padding:3px 6px">${p.vrf}</td><td style="padding:3px 6px">${st}</td><td style="padding:3px 6px">${p.description||"-"}</td><td style="padding:3px 6px">${_napUptime(p.uptime)}</td><td style="padding:3px 6px">${p.received}</td><td style="padding:3px 6px">${p.sent}</td></tr>`;
    }
    h += `</table></div></div>`;
  }
  return h;
}

// ── Environment Health Renderer ──
function _napRenderEnv(d) {
  const ac = d.alerts.length, cc = d.alerts.filter(a=>a.critical).length;
  let h = `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
    ${_napSC(d.devices.length,"Devices","var(--accent)")}${_napSC(ac,"Alerts",ac?"var(--red)":"var(--green)")}
    ${_napSC(cc,"Critical",cc?"var(--red)":"var(--green)")}</div>`;
  if (d.alerts.length) {
    h += `<div class="asec" style="border-color:var(--red);margin-bottom:8px"><h4 style="color:var(--red)">🚨 Health Alerts</h4>`;
    for (const a of d.alerts) h += `<div class="aitem"><span style="color:${a.critical?"var(--red)":"var(--yellow)"}"><span>${a.critical?"🔴":"⚠️"}</span></span><span><b>${a.hostname}</b> ${a.type.toUpperCase()}: ${a.sensor} = <b>${a.value}</b></span></div>`;
    h += `</div>`;
  }
  h += `<div class="asec"><h4>📊 Device Health</h4><div style="overflow-x:auto"><table style="width:100%;font-size:11px;border-collapse:collapse">
    <tr style="border-bottom:1px solid var(--border)">${["Device","Model","CPU%","Mem%","Fans","Power","Temp","Uptime"].map(c=>`<th style="text-align:left;padding:3px 6px;color:var(--muted);font-size:10px">${c}</th>`).join("")}</tr>`;
  for (const r of d.devices) {
    if (r.error) { h += `<tr style="border-bottom:1px solid var(--border)"><td style="padding:3px 6px;font-family:Consolas,monospace">${r.hostname}</td><td colspan="7">${_napBadge(r.error,"error")}</td></tr>`; continue; }
    const cpuB = r.cpu_pct>80?"error":r.cpu_pct>60?"warn":"ok";
    const memB = r.memory_pct>85?"error":r.memory_pct>70?"warn":"ok";
    h += `<tr style="border-bottom:1px solid var(--border)"><td style="padding:3px 6px;font-family:Consolas,monospace">${r.hostname}</td><td style="padding:3px 6px">${r.model}</td><td style="padding:3px 6px">${_napBadge(r.cpu_pct+"%",cpuB)}</td><td style="padding:3px 6px">${_napBadge(r.memory_pct+"%",memB)}</td><td style="padding:3px 6px">${r.fans_ok?_napBadge("OK","ok"):_napBadge("FAIL","error")}</td><td style="padding:3px 6px">${r.power_ok?_napBadge("OK","ok"):_napBadge("FAIL","error")}</td><td style="padding:3px 6px">${r.temp_alerts.length?_napBadge(r.temp_alerts.length+" alerts","error"):_napBadge("OK","ok")}</td><td style="padding:3px 6px">${_napUptime(r.uptime)}</td></tr>`;
  }
  h += `</table></div></div>`;
  return h;
}

// ── Interface Errors Renderer ──
function _napRenderErrors(d) {
  let h = `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
    ${_napSC(d.total_interfaces_with_errors,"Interfaces w/ Errors",d.total_interfaces_with_errors?"var(--yellow)":"var(--green)")}</div>`;
  if (!d.errors.length) return h + `<div style="color:var(--green);text-align:center;padding:40px;font-size:14px">✅ No interface errors found</div>`;
  h += `<div class="asec"><h4>⚡ Interface Errors (by total)</h4><div style="overflow-x:auto"><table style="width:100%;font-size:11px;border-collapse:collapse">
    <tr style="border-bottom:1px solid var(--border)">${["Device","Interface","Desc","State","Speed","RX Err","TX Err","RX Disc","TX Disc","Total"].map(c=>`<th style="text-align:left;padding:3px 6px;color:var(--muted);font-size:10px">${c}</th>`).join("")}</tr>`;
  for (const e of d.errors) {
    const st = e.is_up?_napBadge("UP","ok"):_napBadge("DOWN","error");
    const sev = e.total>10000?"error":e.total>1000?"warn":"info";
    h += `<tr style="border-bottom:1px solid var(--border)"><td style="padding:3px 6px;font-family:Consolas,monospace">${e.hostname}</td><td style="padding:3px 6px;font-family:Consolas,monospace">${e.interface}</td><td style="padding:3px 6px">${e.description||"-"}</td><td style="padding:3px 6px">${st}</td><td style="padding:3px 6px">${e.speed||"-"}</td><td style="padding:3px 6px">${_napFmt(e.rx_errors)}</td><td style="padding:3px 6px">${_napFmt(e.tx_errors)}</td><td style="padding:3px 6px">${_napFmt(e.rx_discards)}</td><td style="padding:3px 6px">${_napFmt(e.tx_discards)}</td><td style="padding:3px 6px">${_napBadge(_napFmt(e.total),sev)}</td></tr>`;
  }
  h += `</table></div></div>`;
  return h;
}

// ── LLDP Topology Renderer ──
function _napRenderLldp(d) {
  let h = `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
    ${_napSC(d.total_nodes,"Nodes","var(--accent)")}${_napSC(d.total_links,"Links","var(--green)")}</div>`;
  h += `<div class="asec"><h4>🔗 LLDP Links</h4><div style="overflow-x:auto"><table style="width:100%;font-size:11px;border-collapse:collapse">
    <tr style="border-bottom:1px solid var(--border)">${["Source","Port","","Target","Port"].map(c=>`<th style="text-align:left;padding:3px 6px;color:var(--muted);font-size:10px">${c}</th>`).join("")}</tr>`;
  for (const l of d.links) {
    h += `<tr style="border-bottom:1px solid var(--border)"><td style="padding:3px 6px;font-family:Consolas,monospace">${l.source}</td><td style="padding:3px 6px;font-family:Consolas,monospace">${l.source_port}</td><td style="padding:3px 6px;color:var(--accent)">→</td><td style="padding:3px 6px;font-family:Consolas,monospace">${l.target}</td><td style="padding:3px 6px;font-family:Consolas,monospace">${l.target_port}</td></tr>`;
  }
  h += `</table></div></div>`;
  h += `<div class="asec"><h4>◎ Nodes (${d.nodes.length})</h4><div style="display:flex;flex-wrap:wrap;gap:6px">`;
  for (const n of d.nodes) h += `<span style="padding:3px 8px;background:var(--bg3);border:1px solid var(--border);border-radius:4px;font-family:Consolas,monospace;font-size:11px">${n}</span>`;
  h += `</div></div>`;
  return h;
}

// ── Full Collection Renderer ──
function _napRenderCollect(d) {
  let h = `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
    ${_napSC(d.devices.length,"Devices","var(--accent)")}</div>`;
  h += `<div class="aitem" style="border:1px solid var(--border);border-radius:6px;padding:8px;margin-bottom:8px"><span>📁</span><span>Saved to: <code style="color:var(--accent)">${d.output_file}</code></span></div>`;
  h += `<div class="asec"><h4>📊 Collection Summary</h4><div style="overflow-x:auto"><table style="width:100%;font-size:11px;border-collapse:collapse">
    <tr style="border-bottom:1px solid var(--border)">${["Device","Model","Version","Interfaces","IPs","LLDP","ARP","Status"].map(c=>`<th style="text-align:left;padding:3px 6px;color:var(--muted);font-size:10px">${c}</th>`).join("")}</tr>`;
  for (const r of d.devices) {
    const st = r.error ? _napBadge(r.error,"error") : _napBadge("OK","ok");
    h += `<tr style="border-bottom:1px solid var(--border)"><td style="padding:3px 6px;font-family:Consolas,monospace">${r.hostname}</td><td style="padding:3px 6px">${r.model}</td><td style="padding:3px 6px;font-family:Consolas,monospace">${r.version}</td><td style="padding:3px 6px">${r.interfaces}</td><td style="padding:3px 6px">${r.ips}</td><td style="padding:3px 6px">${r.lldp_neighbors}</td><td style="padding:3px 6px">${r.arp_entries}</td><td style="padding:3px 6px">${st}</td></tr>`;
  }
  h += `</table></div></div>`;
  return h;
}

// ── Snapshot Renderer ──
function _napRenderSnap(d) {
  return `<div class="aitem" style="border:1px solid var(--green);border-radius:6px;padding:12px;background:rgba(63,185,80,.05)"><span>📸</span><span><b>${(d.label||"").toUpperCase()}</b> snapshot saved: <code style="color:var(--green)">${d.file}</code> (${d.devices} devices)</span></div>`;
}

// ── Diff Renderer ──
function _napRenderDiff(d) {
  const out = document.getElementById("nap-output");
  let h = `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
    ${_napSC(d.total_changes,"Changes",d.total_changes?"var(--yellow)":"var(--green)")}</div>`;
  if (!d.changes.length) { out.innerHTML = h + `<div style="color:var(--green);text-align:center;padding:40px;font-size:14px">✅ No changes — network state identical</div>`; return; }
  h += `<div class="asec"><h4>🔍 Changes (${d.file_a} → ${d.file_b})</h4>`;
  for (const c of d.changes) {
    const icon = c.type.includes("removed")?"➖":c.type.includes("added")?"➕":"🔄";
    const color = c.type.includes("removed")?"var(--red)":c.type.includes("added")?"var(--green)":"var(--yellow)";
    h += `<div class="aitem"><span style="color:${color}">${icon}</span><span><b>${c.hostname}</b> ${_napBadge(c.type,"info")} ${c.interface?`<code>${c.interface}</code>`:""} ${c.details}</span></div>`;
  }
  h += `</div>`;
  out.innerHTML = h;
}

// ── NAPALM Export ──
function napExport(fmt) {
  if (!_napLastResult || !_napLastTool) return;
  let md = `# NAPALM ${_napLastTool} — ${new Date().toISOString().slice(0,19)}\n\n`;
  if (_napLastTool === "version-audit" && _napLastResult.devices) {
    md += `| Site | Device | IP | Vendor | Model | OS Version | Serial | Status |\n|---|---|---|---|---|---|---|---|\n`;
    for (const r of _napLastResult.devices) md += `| ${r.site} | ${r.hostname} | ${r.ip} | ${r.vendor} | ${r.model} | ${r.os_version} | ${r.serial} | ${r.error||"OK"} |\n`;
  } else if (_napLastTool === "bgp-status" && _napLastResult.devices) {
    for (const dev of _napLastResult.devices) {
      md += `## ${dev.hostname}\n\n| Peer IP | VRF | State | Description | Uptime | Rcvd | Sent |\n|---|---|---|---|---|---|---|\n`;
      for (const p of (dev.peers||[])) md += `| ${p.peer_ip} | ${p.vrf} | ${p.is_up?"UP":"DOWN"} | ${p.description||"-"} | ${_napUptime(p.uptime)} | ${p.received} | ${p.sent} |\n`;
      md += "\n";
    }
  } else if (_napLastTool === "global-report") {
    const d = _napLastResult;
    md = `# 🌍 Global Report — All Sites\n\n**${d.sites_total} sites** · ${(d.tools||[]).join(", ")} · ${(d.timestamp||"").slice(0,19)}\n\n`;
    if (d.version_audit) {
      const v = d.version_audit;
      md += `## ⬡ Version Audit\n\n**${v.total} devices** · ${v.errors} unreachable · ${v.mismatches.length} mismatches\n\n`;
      if (v.mismatches.length) {
        md += `### Version Mismatches\n\n`;
        for (const m of v.mismatches) md += `- **${m.model}** (${m.driver}): ${m.versions.join(", ")} — ${m.devices.join(", ")}\n`;
        md += "\n";
      }
      md += `| Site | Devices | Reachable | Errors |\n|---|---|---|---|\n`;
      for (const [site, s] of Object.entries(v.by_site).sort((a,b)=>a[0].localeCompare(b[0]))) md += `| ${site} | ${s.total} | ${s.reachable} | ${s.errors} |\n`;
      md += "\n";
    }
    if (d.bgp_status) {
      const b = d.bgp_status;
      md += `## ⇋ BGP Status\n\n**${b.total_peers} peers** across ${b.total_sites_with_bgp} sites · ${b.total_down} down\n\n`;
      if (b.down_peers.length) {
        md += `### Down Peers\n\n| Site | Device | Peer IP | Remote AS | Description |\n|---|---|---|---|---|\n`;
        for (const p of b.down_peers) md += `| ${p.site} | ${p.hostname} | ${p.peer_ip} | ${p.remote_as} | ${p.description||"-"} |\n`;
        md += "\n";
      }
      md += `| Site | Devices | Total Peers | Up | Down |\n|---|---|---|---|---|\n`;
      for (const [site, s] of Object.entries(b.by_site).sort((a,b)=>a[0].localeCompare(b[0]))) { if (s.total_peers > 0) md += `| ${site} | ${s.devices} | ${s.total_peers} | ${s.up} | ${s.down} |\n`; }
      md += "\n";
    }
    if (d.env_health) {
      const e = d.env_health;
      md += `## ♥ Env Health\n\n**${e.total_alerts} alerts** · ${e.critical_alerts} critical\n\n`;
      if (e.alerts.length) {
        md += `### Health Alerts\n\n| Site | Device | Type | Value | Critical |\n|---|---|---|---|---|\n`;
        for (const a of e.alerts) md += `| ${a.site} | ${a.hostname} | ${a.type} | ${a.value} | ${a.critical?"YES":"no"} |\n`;
        md += "\n";
      }
      md += `| Site | Devices | Alerts |\n|---|---|---|\n`;
      for (const [site, s] of Object.entries(e.by_site).sort((a,b)=>a[0].localeCompare(b[0]))) md += `| ${site} | ${s.devices} | ${s.alerts} |\n`;
      md += "\n";
    }
  } else {
    md += "```json\n" + JSON.stringify(_napLastResult, null, 2) + "\n```\n";
  }
  const blob = new Blob([md], {type:"text/markdown"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `napalm_${_napLastTool}_${new Date().toISOString().slice(0,10)}.md`;
  a.click();
}


// ── Global Report ─────────────────────────────────────────────────────────────

async function napGlobalReport() {
  const out = document.getElementById("nap-output");
  // Show tool selector inline
  out.innerHTML = `<div style="max-width:500px;margin:40px auto;text-align:center">
    <div style="font-size:28px;margin-bottom:12px">🌍</div>
    <h3 style="color:var(--text);margin:0 0 8px">Global Report — All Sites</h3>
    <p style="color:var(--muted);font-size:12px;margin-bottom:16px">Select which audits to run across all ${Object.keys(window._napSiteCount||{}).length || 53} sites (414 devices).<br>This will take several minutes.</p>
    <div style="display:flex;flex-direction:column;gap:8px;align-items:center;margin-bottom:16px">
      <label style="color:var(--text);font-size:13px;cursor:pointer"><input type="checkbox" id="gr-ver" checked style="margin-right:6px"> ⬡ Version Audit</label>
      <label style="color:var(--text);font-size:13px;cursor:pointer"><input type="checkbox" id="gr-bgp" checked style="margin-right:6px"> ⇋ BGP Status</label>
      <label style="color:var(--text);font-size:13px;cursor:pointer"><input type="checkbox" id="gr-env" checked style="margin-right:6px"> ♥ Env Health</label>
    </div>
    <button class="btn" onclick="_napStartGlobalReport()" style="border-color:#e879f9;color:#e879f9;font-weight:700;padding:6px 24px;font-size:13px">🚀 Start Global Report</button>
  </div>`;
}

async function _napStartGlobalReport() {
  const tools = [];
  if (document.getElementById("gr-ver")?.checked) tools.push("version-audit");
  if (document.getElementById("gr-bgp")?.checked) tools.push("bgp-status");
  if (document.getElementById("gr-env")?.checked) tools.push("env-health");
  if (!tools.length) { alert("Select at least one tool"); return; }
  _napShowProgress("Starting global report...", 0);
  try {
    const r = await fetch(`${API}/napalm/global-report`, {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({tools}),
    });
    const d = await r.json();
    if (d.error) { _napHideProgress(); _napShowError(d.error); return; }
    _napJobId = d.job_id;
    _napLastTool = "global-report";
    _napPollJob(d.job_id, "global-report");
  } catch (e) { _napHideProgress(); _napShowError(e.message); }
}

function _napRenderGlobal(d) {
  const ts = (d.timestamp || "").slice(0, 19).replace("T", " ");
  let h = `<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">
    <span style="font-size:28px">🌍</span>
    <div><div style="font-size:16px;font-weight:700;color:var(--text)">Global Report — All Sites</div>
    <div style="font-size:11px;color:var(--muted)">${d.sites_total} sites · ${d.tools.join(", ")} · ${ts}</div></div></div>`;

  // ── Version Audit Summary ──
  if (d.version_audit) {
    const v = d.version_audit;
    h += `<div class="asec" style="margin-bottom:8px"><h4 style="color:#58a6ff">⬡ Version Audit — ${v.total} devices (${v.errors} unreachable, ${v.mismatches.length} mismatches)</h4>`;
    if (v.mismatches.length) {
      h += `<div style="margin-bottom:8px">`;
      for (const m of v.mismatches) h += `<div class="aitem"><span style="color:var(--yellow)">⚠️</span><span><b>${m.model}</b> (${m.driver}): ${m.versions.map(vv=>`<code style="color:var(--yellow)">${vv}</code>`).join(", ")}<br><small style="color:var(--muted)">${m.devices.join(", ")}</small></span></div>`;
      h += `</div>`;
    }
    h += `<div style="overflow-x:auto"><table style="width:100%;font-size:11px;border-collapse:collapse">
      <tr style="border-bottom:1px solid var(--border)">${["Site","Devices","Reachable","Errors"].map(c=>`<th style="text-align:left;padding:4px 8px;color:var(--muted);font-size:10px">${c}</th>`).join("")}</tr>`;
    for (const [site, s] of Object.entries(v.by_site).sort((a,b)=>a[0].localeCompare(b[0]))) {
      const errBadge = s.errors > 0 ? _napBadge(s.errors, "error") : _napBadge("0", "ok");
      h += `<tr style="border-bottom:1px solid var(--border)"><td style="padding:3px 8px;font-weight:600">${site}</td><td style="padding:3px 8px">${s.total}</td><td style="padding:3px 8px">${_napBadge(s.reachable, "ok")}</td><td style="padding:3px 8px">${errBadge}</td></tr>`;
    }
    h += `</table></div></div>`;
  }

  // ── BGP Status Summary ──
  if (d.bgp_status) {
    const b = d.bgp_status;
    h += `<div class="asec" style="margin-bottom:8px"><h4 style="color:#3fb950">⇋ BGP Status — ${b.total_peers} peers across ${b.total_sites_with_bgp} sites (${b.total_down} down)</h4>`;
    if (b.down_peers.length) {
      h += `<div style="margin-bottom:8px"><div style="color:var(--red);font-size:11px;font-weight:600;margin-bottom:4px">🔴 Down Peers (${b.total_down})</div>`;
      for (const p of b.down_peers.slice(0, 50)) h += `<div class="aitem"><span style="color:var(--red)">❌</span><span><b>${p.site} / ${p.hostname}</b> → <code>${p.peer_ip}</code> AS${p.remote_as} ${p.description ? `(${p.description})` : ""}</span></div>`;
      if (b.down_peers.length > 50) h += `<div style="color:var(--muted);font-size:11px;padding:4px 0">… and ${b.down_peers.length - 50} more</div>`;
      h += `</div>`;
    }
    h += `<div style="overflow-x:auto"><table style="width:100%;font-size:11px;border-collapse:collapse">
      <tr style="border-bottom:1px solid var(--border)">${["Site","Devices","Total Peers","Up","Down"].map(c=>`<th style="text-align:left;padding:4px 8px;color:var(--muted);font-size:10px">${c}</th>`).join("")}</tr>`;
    for (const [site, s] of Object.entries(b.by_site).sort((a,b)=>a[0].localeCompare(b[0]))) {
      if (s.total_peers === 0) continue;
      const downBadge = s.down > 0 ? _napBadge(s.down, "error") : _napBadge("0", "ok");
      h += `<tr style="border-bottom:1px solid var(--border)"><td style="padding:3px 8px;font-weight:600">${site}</td><td style="padding:3px 8px">${s.devices}</td><td style="padding:3px 8px">${s.total_peers}</td><td style="padding:3px 8px">${_napBadge(s.up, "ok")}</td><td style="padding:3px 8px">${downBadge}</td></tr>`;
    }
    h += `</table></div></div>`;
  }

  // ── Env Health Summary ──
  if (d.env_health) {
    const e = d.env_health;
    h += `<div class="asec" style="margin-bottom:8px"><h4 style="color:#f85149">♥ Env Health — ${e.total_alerts} alerts (${e.critical_alerts} critical)</h4>`;
    if (e.alerts.length) {
      h += `<div style="margin-bottom:8px">`;
      for (const a of e.alerts.slice(0, 50)) {
        const icon = a.critical ? "🔴" : "⚠️";
        const color = a.critical ? "var(--red)" : "var(--yellow)";
        h += `<div class="aitem"><span style="color:${color}">${icon}</span><span><b>${a.site} / ${a.hostname}</b> ${a.type.toUpperCase()}: <b>${a.value}</b></span></div>`;
      }
      if (e.alerts.length > 50) h += `<div style="color:var(--muted);font-size:11px;padding:4px 0">… and ${e.alerts.length - 50} more</div>`;
      h += `</div>`;
    }
    h += `<div style="overflow-x:auto"><table style="width:100%;font-size:11px;border-collapse:collapse">
      <tr style="border-bottom:1px solid var(--border)">${["Site","Devices","Alerts"].map(c=>`<th style="text-align:left;padding:4px 8px;color:var(--muted);font-size:10px">${c}</th>`).join("")}</tr>`;
    for (const [site, s] of Object.entries(e.by_site).sort((a,b)=>a[0].localeCompare(b[0]))) {
      const alertBadge = s.alerts > 0 ? _napBadge(s.alerts, "error") : _napBadge("0", "ok");
      h += `<tr style="border-bottom:1px solid var(--border)"><td style="padding:3px 8px;font-weight:600">${site}</td><td style="padding:3px 8px">${s.devices}</td><td style="padding:3px 8px">${alertBadge}</td></tr>`;
    }
    h += `</table></div></div>`;
  }

  return h;
}

// ── BGP Topology ──────────────────────────────────────────────────────────────
let _bgpTopoData = null;

function napBgpTopology() {
  const site = document.getElementById("nap-site").value;
  if (!site) { alert("Select a site first"); return; }
  const out = document.getElementById("nap-output");
  out.innerHTML = `<div style="text-align:center;padding:60px;color:var(--muted)"><div style="font-size:24px;margin-bottom:12px">◉</div>Collecting BGP data for <b>${site.toUpperCase()}</b>...<br><small>This may take 30-60 seconds</small></div>`;
  fetch("/api/napalm/bgp-status", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({site})})
    .then(r=>r.json()).then(d=>{
      if (d.error) { out.innerHTML=`<div style="color:var(--red);padding:20px">${d.error}</div>`; return; }
      const jid = d.job_id;
      const poll = setInterval(()=>{
        fetch(`/api/napalm/jobs/${jid}`).then(r=>r.json()).then(j=>{
          if (j.status==="done") { clearInterval(poll); _bgpTopoData=j.result; _napRenderBgpTopology(j.result, out); }
          else if (j.status==="error") { clearInterval(poll); out.innerHTML=`<div style="color:var(--red);padding:20px">${j.message}</div>`; }
          else { out.querySelector("small") && (out.querySelector("small").textContent = j.message || "Working..."); }
        });
      }, 2000);
    });
}

function _napRenderBgpTopology(data, container) {
  const W = container.clientWidth || 1200, H = Math.max(700, window.innerHeight - 200);
  // Build nodes and links from BGP data
  const nodes = [], links = [], nodeMap = {};
  const asColors = {};
  const palette = ["#58a6ff","#3fb950","#f0883e","#f85149","#d29922","#a78bfa","#06b6d4","#ec4899","#84cc16","#14b8a6","#f97316","#8b5cf6","#ef4444","#22d3ee","#facc15"];
  let colorIdx = 0;
  function getAsColor(asn) {
    if (!asColors[asn]) asColors[asn] = palette[colorIdx++ % palette.length];
    return asColors[asn];
  }

  // Add local device nodes
  for (const dev of (data.devices || [])) {
    if (dev.error || !dev.peers || !dev.peers.length) continue;
    const localAs = dev.peers[0]?.local_as || 0;
    const nid = "dev:" + dev.hostname;
    if (!nodeMap[nid]) {
      nodeMap[nid] = { id: nid, label: dev.hostname, type: "local", as: localAs, peerCount: dev.total, upCount: dev.up, downCount: dev.down };
      nodes.push(nodeMap[nid]);
    }
  }

  // Add peer nodes and links
  const peerSeen = {}; // track unique peer IPs across devices
  for (const dev of (data.devices || [])) {
    if (dev.error || !dev.peers) continue;
    const devId = "dev:" + dev.hostname;
    for (const p of dev.peers) {
      const peerAs = p.remote_as || 0;
      const isIbgp = p.peer_type === "Internal" || (peerAs > 0 && p.local_as > 0 && peerAs === p.local_as);
      // If peer matches another local device, link directly
      const peerDevId = "dev:" + (p.description || "");
      const isLocalPeer = nodeMap[peerDevId];
      let targetId;
      if (isLocalPeer) {
        targetId = peerDevId;
      } else {
        // External or remote peer - create peer node
        const peerLabel = p.description || p.peer_ip;
        targetId = "peer:" + p.peer_ip;
        if (!nodeMap[targetId]) {
          const group = p.group || (isIbgp ? "iBGP" : "eBGP");
          nodeMap[targetId] = { id: targetId, label: peerLabel, type: isIbgp ? "ibgp-peer" : "ebgp-peer",
            as: peerAs, ip: p.peer_ip, group: group,
            import_policy: p.import_policy || "", export_policy: p.export_policy || "",
            af: p.af_configured || "", uptime: p.uptime, is_up: p.is_up,
            received: p.received || 0, sent: p.sent || 0 };
          nodes.push(nodeMap[targetId]);
        }
      }
      // Avoid duplicate links (A->B and B->A for local peers)
      const linkKey = [devId, targetId].sort().join("||");
      if (!peerSeen[linkKey]) {
        peerSeen[linkKey] = true;
        links.push({
          source: devId, target: targetId,
          is_up: p.is_up, isIbgp: isIbgp,
          peer_ip: p.peer_ip, remote_as: peerAs, local_as: p.local_as || 0,
          description: p.description || "", group: p.group || "",
          import_policy: p.import_policy || "", export_policy: p.export_policy || "",
          received: p.received || 0, sent: p.sent || 0, uptime: p.uptime || -1,
          af: p.af_configured || ""
        });
      }
    }
  }

  // Count stats
  const ibgpCount = links.filter(l=>l.isIbgp).length;
  const ebgpCount = links.filter(l=>!l.isIbgp).length;
  const downCount = links.filter(l=>!l.is_up).length;
  const uniqueAs = [...new Set(nodes.filter(n=>n.as>0).map(n=>n.as))];

  // Render HTML container
  let html = `<div style="margin-bottom:8px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
    <div style="display:flex;gap:6px;flex-wrap:wrap">
      ${_napSC(nodes.filter(n=>n.type==="local").length, "Local Routers", "var(--accent)")}
      ${_napSC(ibgpCount, "iBGP Sessions", "var(--green)")}
      ${_napSC(ebgpCount, "eBGP Sessions", "var(--orange)")}
      ${_napSC(downCount, "Down", downCount ? "var(--red)" : "var(--green)")}
      ${_napSC(uniqueAs.length, "Unique AS", "#a78bfa")}
    </div>
    <div style="margin-left:auto;display:flex;gap:6px;align-items:center">
      <label style="font-size:10px;color:var(--muted)">Filter:</label>
      <button class="btn" style="font-size:10px;padding:2px 8px;border-color:var(--green);color:var(--green)" onclick="_bgpTopoFilter('ibgp')">iBGP</button>
      <button class="btn" style="font-size:10px;padding:2px 8px;border-color:var(--orange);color:var(--orange)" onclick="_bgpTopoFilter('ebgp')">eBGP</button>
      <button class="btn" style="font-size:10px;padding:2px 8px;border-color:var(--red);color:var(--red)" onclick="_bgpTopoFilter('down')">Down</button>
      <button class="btn" style="font-size:10px;padding:2px 8px;border-color:var(--accent);color:var(--accent)" onclick="_bgpTopoFilter('all')">All</button>
    </div>
  </div>
  <div id="bgp-topo-svg" style="background:var(--bg);border:1px solid var(--border);border-radius:8px;position:relative;overflow:hidden"></div>
  <div id="bgp-topo-tooltip" style="position:fixed;display:none;background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 14px;font-size:11px;color:var(--text);pointer-events:none;z-index:9999;max-width:400px;box-shadow:0 4px 20px rgba(0,0,0,.6)"></div>
  <div style="margin-top:8px;display:flex;gap:16px;flex-wrap:wrap;font-size:10px;color:var(--muted)">
    <span><svg width="16" height="8"><rect width="16" height="8" rx="3" fill="#58a6ff"/></svg> Local Router</span>
    <span><svg width="16" height="8"><rect width="16" height="8" rx="3" fill="#3fb950"/></svg> iBGP Peer</span>
    <span><svg width="16" height="8"><rect width="16" height="8" rx="3" fill="#f0883e"/></svg> eBGP Peer</span>
    <span><svg width="16" height="2" style="vertical-align:middle"><line x1="0" y1="1" x2="16" y2="1" stroke="#3fb950" stroke-width="2"/></svg> iBGP Link</span>
    <span><svg width="16" height="2" style="vertical-align:middle"><line x1="0" y1="1" x2="16" y2="1" stroke="#f0883e" stroke-width="2" stroke-dasharray="4,2"/></svg> eBGP Link</span>
    <span><svg width="16" height="2" style="vertical-align:middle"><line x1="0" y1="1" x2="16" y2="1" stroke="#f85149" stroke-width="3"/></svg> Down</span>
    <span style="margin-left:auto">Drag nodes to reposition | Scroll to zoom | Click node for details</span>
  </div>`;
  container.innerHTML = html;

  // Build D3 force graph
  const svgContainer = document.getElementById("bgp-topo-svg");
  svgContainer.style.height = H + "px";
  const svg = d3.select(svgContainer).append("svg")
    .attr("width", "100%").attr("height", H)
    .attr("viewBox", [0, 0, W, H]);

  const g = svg.append("g");

  // Zoom behavior
  const zoom = d3.zoom().scaleExtent([0.2, 5]).on("zoom", (e) => g.attr("transform", e.transform));
  svg.call(zoom);

  // Arrow markers
  const defs = svg.append("defs");
  ["ibgp","ebgp","down"].forEach(t => {
    const color = t==="ibgp"?"#3fb950":t==="ebgp"?"#f0883e":"#f85149";
    defs.append("marker").attr("id","arrow-"+t).attr("viewBox","0 -5 10 10")
      .attr("refX",25).attr("refY",0).attr("markerWidth",6).attr("markerHeight",6).attr("orient","auto")
      .append("path").attr("d","M0,-5L10,0L0,5").attr("fill",color).attr("opacity",0.6);
  });

  // Force simulation
  const sim = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id(d=>d.id).distance(d => {
      if (d.isIbgp) return 120;
      return 200;
    }))
    .force("charge", d3.forceManyBody().strength(d => d.type === "local" ? -600 : -200))
    .force("center", d3.forceCenter(W/2, H/2))
    .force("collision", d3.forceCollide().radius(d => d.type === "local" ? 40 : 25))
    .force("x", d3.forceX(W/2).strength(0.03))
    .force("y", d3.forceY(H/2).strength(0.03));

  // Links
  const link = g.append("g").selectAll("line").data(links).join("line")
    .attr("stroke", d => !d.is_up ? "#f85149" : d.isIbgp ? "#3fb950" : "#f0883e")
    .attr("stroke-width", d => !d.is_up ? 2.5 : d.isIbgp ? 1.8 : 1.5)
    .attr("stroke-dasharray", d => d.isIbgp ? null : "6,3")
    .attr("stroke-opacity", d => !d.is_up ? 0.9 : 0.5)
    .attr("marker-end", d => !d.is_up ? "url(#arrow-down)" : d.isIbgp ? "url(#arrow-ibgp)" : "url(#arrow-ebgp)")
    .style("cursor", "pointer")
    .on("mouseover", (e, d) => _bgpTopoShowLinkTip(e, d))
    .on("mouseout", () => _bgpTopoHideTip());

  // Nodes
  const node = g.append("g").selectAll("g").data(nodes).join("g")
    .style("cursor", "pointer")
    .call(d3.drag().on("start", (e,d) => { if(!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
      .on("drag", (e,d) => { d.fx=e.x; d.fy=e.y; })
      .on("end", (e,d) => { if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }));

  // Node circles
  node.append("circle")
    .attr("r", d => d.type === "local" ? 22 : 13)
    .attr("fill", d => {
      if (d.type === "local") return "#58a6ff";
      if (d.type === "ibgp-peer") return "#3fb950";
      return "#f0883e";
    })
    .attr("fill-opacity", d => d.type === "local" ? 0.2 : 0.15)
    .attr("stroke", d => {
      if (d.type === "local") return "#58a6ff";
      if (d.type === "ibgp-peer") return "#3fb950";
      return "#f0883e";
    })
    .attr("stroke-width", d => d.type === "local" ? 2.5 : 1.5);

  // Node labels
  node.append("text")
    .text(d => {
      if (d.type === "local") return d.label.toUpperCase();
      const lbl = d.label || d.ip || "?";
      return lbl.length > 20 ? lbl.substring(0,18) + ".." : lbl;
    })
    .attr("text-anchor", "middle").attr("dy", d => d.type === "local" ? 35 : 22)
    .attr("font-size", d => d.type === "local" ? "11px" : "9px")
    .attr("font-weight", d => d.type === "local" ? "700" : "400")
    .attr("fill", d => d.type === "local" ? "#58a6ff" : "var(--muted)")
    .attr("font-family", "Consolas, monospace");

  // AS label inside local nodes
  node.filter(d => d.type === "local" && d.as).append("text")
    .text(d => "AS" + d.as).attr("text-anchor","middle").attr("dy",4)
    .attr("font-size","8px").attr("fill","#58a6ff").attr("font-weight","600");

  // AS label inside peer nodes
  node.filter(d => d.type !== "local" && d.as).append("text")
    .text(d => d.as).attr("text-anchor","middle").attr("dy",4)
    .attr("font-size","7px").attr("fill", d => d.type === "ibgp-peer" ? "#3fb950" : "#f0883e").attr("font-weight","600");

  // Status indicator for down peers
  node.filter(d => d.type !== "local" && d.is_up === false).append("circle")
    .attr("cx", d => d.type === "local" ? 16 : 10).attr("cy", d => d.type === "local" ? -16 : -10)
    .attr("r", 4).attr("fill", "#f85149").attr("stroke", "#0d1117").attr("stroke-width", 1);

  // Node hover/click
  node.on("mouseover", (e, d) => _bgpTopoShowNodeTip(e, d, links))
    .on("mouseout", () => _bgpTopoHideTip())
    .on("click", (e, d) => _bgpTopoShowNodeTip(e, d, links));

  // Simulation tick
  sim.on("tick", () => {
    link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
      .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
    node.attr("transform", d => `translate(${d.x},${d.y})`);
  });

  // Store refs for filtering
  window._bgpTopoRefs = { link, node, nodes, links, sim, svg, g, zoom };

  // Initial zoom to fit
  setTimeout(() => {
    const bounds = g.node().getBBox();
    if (bounds.width > 0 && bounds.height > 0) {
      const scale = Math.min(W / (bounds.width + 100), H / (bounds.height + 100), 1.5) * 0.85;
      const tx = W/2 - (bounds.x + bounds.width/2) * scale;
      const ty = H/2 - (bounds.y + bounds.height/2) * scale;
      svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
    }
  }, 2000);
}

function _bgpTopoShowNodeTip(e, d, allLinks) {
  const tip = document.getElementById("bgp-topo-tooltip");
  let h = `<div style="font-weight:700;font-size:13px;margin-bottom:6px;color:${d.type==="local"?"#58a6ff":d.type==="ibgp-peer"?"#3fb950":"#f0883e"}">${d.label || d.ip || "?"}</div>`;
  h += `<table style="font-size:10px;border-collapse:collapse">`;
  if (d.type === "local") {
    h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Type</td><td><b>Local Router</b></td></tr>`;
    h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">AS</td><td><b>${d.as}</b></td></tr>`;
    h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Peers</td><td>${d.upCount} up / ${d.downCount} down / ${d.peerCount} total</td></tr>`;
    const myLinks = allLinks.filter(l => (l.source.id||l.source)===d.id || (l.target.id||l.target)===d.id);
    const groups = {};
    myLinks.forEach(l => { const g = l.group || (l.isIbgp?"iBGP":"eBGP"); groups[g] = (groups[g]||0)+1; });
    if (Object.keys(groups).length) {
      h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Groups</td><td>${Object.entries(groups).map(([k,v])=>`${k} (${v})`).join(", ")}</td></tr>`;
    }
  } else {
    h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Type</td><td><b>${d.type==="ibgp-peer"?"iBGP":"eBGP"}</b></td></tr>`;
    h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Peer IP</td><td><code>${d.ip||"-"}</code></td></tr>`;
    h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">AS</td><td><b>${d.as}</b></td></tr>`;
    h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Group</td><td>${d.group||"-"}</td></tr>`;
    h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">State</td><td>${d.is_up?'<span style="color:#3fb950">UP</span>':'<span style="color:#f85149">DOWN</span>'}</td></tr>`;
    if (d.uptime > 0) h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Uptime</td><td>${_napUptime(d.uptime)}</td></tr>`;
    if (d.received) h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Prefixes Rcvd</td><td>${(d.received||0).toLocaleString()}</td></tr>`;
    if (d.sent) h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Prefixes Sent</td><td>${(d.sent||0).toLocaleString()}</td></tr>`;
    if (d.import_policy) h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Import</td><td style="color:#06b6d4">${d.import_policy}</td></tr>`;
    if (d.export_policy) h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Export</td><td style="color:#a78bfa">${d.export_policy}</td></tr>`;
    if (d.af) h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Address Family</td><td>${d.af}</td></tr>`;
  }
  h += `</table>`;
  tip.innerHTML = h;
  tip.style.display = "block";
  tip.style.left = Math.min(e.clientX + 12, window.innerWidth - 420) + "px";
  tip.style.top = Math.min(e.clientY - 10, window.innerHeight - 300) + "px";
}

function _bgpTopoShowLinkTip(e, d) {
  const tip = document.getElementById("bgp-topo-tooltip");
  const srcLabel = (d.source.label || d.source.id || "?");
  const tgtLabel = (d.target.label || d.target.id || "?");
  let h = `<div style="font-weight:700;font-size:12px;margin-bottom:6px">${srcLabel} ↔ ${tgtLabel}</div>`;
  h += `<table style="font-size:10px;border-collapse:collapse">`;
  h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Type</td><td><b style="color:${d.isIbgp?"#3fb950":"#f0883e"}">${d.isIbgp?"iBGP":"eBGP"}</b></td></tr>`;
  h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">State</td><td>${d.is_up?'<span style="color:#3fb950">Established</span>':'<span style="color:#f85149">DOWN</span>'}</td></tr>`;
  h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Peer IP</td><td><code>${d.peer_ip}</code></td></tr>`;
  h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Local AS</td><td>${d.local_as}</td></tr>`;
  h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Remote AS</td><td>${d.remote_as}</td></tr>`;
  if (d.group) h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Group</td><td>${d.group}</td></tr>`;
  if (d.uptime > 0) h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Uptime</td><td>${_napUptime(d.uptime)}</td></tr>`;
  h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Prefixes</td><td>Rcvd: ${(d.received||0).toLocaleString()} / Sent: ${(d.sent||0).toLocaleString()}</td></tr>`;
  if (d.import_policy) h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Import Policy</td><td style="color:#06b6d4">${d.import_policy}</td></tr>`;
  if (d.export_policy) h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Export Policy</td><td style="color:#a78bfa">${d.export_policy}</td></tr>`;
  if (d.af) h += `<tr><td style="color:var(--muted);padding:1px 8px 1px 0">Address Family</td><td>${d.af}</td></tr>`;
  h += `</table>`;
  tip.innerHTML = h;
  tip.style.display = "block";
  tip.style.left = Math.min(e.clientX + 12, window.innerWidth - 420) + "px";
  tip.style.top = Math.min(e.clientY - 10, window.innerHeight - 300) + "px";
}

function _bgpTopoHideTip() {
  const tip = document.getElementById("bgp-topo-tooltip");
  if (tip) tip.style.display = "none";
}

function _bgpTopoFilter(mode) {
  const r = window._bgpTopoRefs;
  if (!r) return;
  r.link.attr("display", d => {
    if (mode === "all") return null;
    if (mode === "ibgp") return d.isIbgp ? null : "none";
    if (mode === "ebgp") return !d.isIbgp ? null : "none";
    if (mode === "down") return !d.is_up ? null : "none";
    return null;
  }).attr("stroke-opacity", d => {
    if (mode === "all") return !d.is_up ? 0.9 : 0.5;
    return 0.8;
  });
  // Show/hide nodes based on their connected visible links
  r.node.attr("opacity", d => {
    if (d.type === "local") return 1;
    if (mode === "all") return 1;
    const hasVisible = r.links.some(l => {
      const sid = l.source.id || l.source, tid = l.target.id || l.target;
      const connected = sid === d.id || tid === d.id;
      if (!connected) return false;
      if (mode === "ibgp") return l.isIbgp;
      if (mode === "ebgp") return !l.isIbgp;
      if (mode === "down") return !l.is_up;
      return true;
    });
    return hasVisible ? 1 : 0.1;
  });
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function switchTabById(tabId) {
  const tab = document.querySelector(`[data-tab="${tabId}"]`);
  if (tab) switchTab(tab);
}
