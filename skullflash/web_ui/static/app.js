/* Skull Flash Dashboard — vanilla JS, no dependencies */
'use strict';

let currentScanId = null;
let findingsCount = 0;

// ── Gauge helpers ─────────────────────────────────────────────────────────────

function _polarToCartesian(cx, cy, r, angleDeg) {
  const rad = (angleDeg - 180) * Math.PI / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

function _arcPath(score) {
  // score 0-100 maps to arc from (20,100) sweeping 0°–180° on a 80-radius semicircle
  const cx = 100, cy = 100, r = 80;
  const angle = Math.min(score, 99.9) / 100 * 180;
  const start = _polarToCartesian(cx, cy, r, 0);
  const end = _polarToCartesian(cx, cy, r, angle);
  const large = angle > 90 ? 1 : 0;
  return `M ${start.x},${start.y} A ${r},${r} 0 ${large},1 ${end.x},${end.y}`;
}

function updateGauge(score) {
  const arc = document.getElementById('gauge-arc');
  const label = document.getElementById('gauge-label');
  const risk = document.getElementById('gauge-risk');
  if (!arc) return;

  arc.setAttribute('d', score > 0 ? _arcPath(score) : 'M 20,100 A 80,80 0 0,1 20.001,100');

  const color = score >= 70 ? '#f85149' : score >= 40 ? '#d29922' : '#3fb950';
  arc.setAttribute('stroke', color);
  label.setAttribute('fill', color);
  label.textContent = Math.round(score);

  const riskLabel = score >= 70 ? 'ALTO' : score >= 40 ? 'MÉDIO' : 'BAIXO';
  risk.textContent = riskLabel;
  risk.style.color = color;
}

// ── Feed ─────────────────────────────────────────────────────────────────────

function appendFeed(text, type) {
  const feed = document.getElementById('feed');
  if (!feed) return;
  // Remove placeholder
  const placeholder = feed.querySelector('.feed-item');
  if (placeholder && placeholder.textContent === 'Aguardando scan…') placeholder.remove();

  const item = document.createElement('div');
  item.className = `feed-item ev-${type || 'status'}`;
  item.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
  feed.appendChild(item);
  feed.scrollTop = feed.scrollHeight;
}

// ── Findings table ────────────────────────────────────────────────────────────

const _SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function addFinding(finding) {
  const tbody = document.getElementById('findings-body');
  if (!tbody) return;

  // Remove empty-row placeholder
  const empty = tbody.querySelector('.empty-row');
  if (empty) empty.remove();

  findingsCount++;
  const sev = (finding.severity || 'INFO').toUpperCase();
  const cvss = finding.cvss_score != null ? finding.cvss_score.toFixed(1) : '—';
  const assets = (finding.affected_assets || []).join(', ');

  const tr = document.createElement('tr');
  tr.dataset.sev = _SEV_ORDER.indexOf(sev);
  tr.innerHTML = `
    <td><code>${finding.id || ''}</code></td>
    <td title="${_esc(finding.description || '')}">${_esc(finding.title || '')}</td>
    <td><span class="badge sev-${sev}">${sev}</span></td>
    <td>${_esc(assets)}</td>
    <td>${cvss}</td>
  `;

  // Insert in severity order
  let inserted = false;
  for (const existing of tbody.children) {
    if (parseInt(existing.dataset.sev || 99) > parseInt(tr.dataset.sev)) {
      tbody.insertBefore(tr, existing);
      inserted = true;
      break;
    }
  }
  if (!inserted) tbody.appendChild(tr);

  const badge = document.getElementById('findings-count');
  if (badge) badge.textContent = `(${findingsCount})`;
}

function _esc(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── SSE handler ───────────────────────────────────────────────────────────────

function handleEvent(event) {
  const data = JSON.parse(event.data);
  const { type } = data;

  if (type === 'done') {
    document.getElementById('conn-dot').classList.remove('live');
    document.getElementById('btn-scan').disabled = false;
    appendFeed('Scan concluído.', 'done');
    return;
  }

  if (type === 'status') {
    appendFeed(data.message, 'status');
    return;
  }

  if (type === 'error') {
    appendFeed(`ERRO: ${data.message}`, 'error');
    return;
  }

  if (type === 'host_discovered') {
    const h = data.host;
    appendFeed(`Host descoberto: ${h.ip} ${h.hostname ? '(' + h.hostname + ')' : ''} — ${h.state}`, 'status');
    return;
  }

  if (type === 'port_open') {
    appendFeed(`Porta aberta: ${data.host}:${data.port} — ${data.service || '?'} ${data.product || ''} ${data.version || ''}`.trim(), 'port_open');
    return;
  }

  if (type === 'finding') {
    const f = data.finding;
    appendFeed(`Finding: [${f.severity}] ${f.title}`, 'finding');
    addFinding(f);
    return;
  }

  if (type === 'risk_score') {
    updateGauge(data.score);
    return;
  }

  if (type === 'summary') {
    const el = document.getElementById('summary-text');
    if (el) { el.textContent = data.text; el.style.color = 'var(--text)'; }
    return;
  }
}

// ── Scan control ──────────────────────────────────────────────────────────────

async function startScan() {
  const target = document.getElementById('target').value.trim();
  if (!target) { alert('Informe um alvo.'); return; }

  // Reset UI
  findingsCount = 0;
  document.getElementById('findings-body').innerHTML =
    '<tr class="empty-row"><td colspan="5">Aguardando findings…</td></tr>';
  document.getElementById('findings-count').textContent = '';
  document.getElementById('feed').innerHTML = '';
  document.getElementById('summary-text').textContent = 'Scan em andamento…';
  document.getElementById('summary-text').style.color = 'var(--muted)';
  updateGauge(0);

  const btn = document.getElementById('btn-scan');
  btn.disabled = true;
  document.getElementById('conn-dot').classList.add('live');

  const body = {
    target,
    ports: document.getElementById('ports').value.trim() || '1-1000',
    run_osint: document.getElementById('chk-osint').checked,
    run_ssl: document.getElementById('chk-ssl').checked,
    run_cve: document.getElementById('chk-cve').checked,
    run_web: document.getElementById('chk-web').checked,
  };

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const { scan_id } = await res.json();
    currentScanId = scan_id;

    const source = new EventSource(`/api/scan/${scan_id}/stream`);
    source.onmessage = handleEvent;
    source.onerror = () => {
      source.close();
      document.getElementById('conn-dot').classList.remove('live');
      btn.disabled = false;
    };
  } catch (err) {
    appendFeed(`Erro ao iniciar scan: ${err.message}`, 'error');
    btn.disabled = false;
    document.getElementById('conn-dot').classList.remove('live');
  }
}

function exportReport(format) {
  if (!currentScanId) { alert('Nenhum scan concluído.'); return; }
  window.open(`/api/scan/${currentScanId}/report?format=${format}`, '_blank');
}
