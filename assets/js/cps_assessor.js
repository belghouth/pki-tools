/* cps_assessor.js — CPS-to-BR Coverage Assessor frontend logic */

(function () {
  'use strict';

  // ── State ──────────────────────────────────────────────────────────────────
  let currentData = null;
  let activeFilter = 'all';

  // ── Boot ───────────────────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initForm();
    initFilterButtons();
    initExpandCollapse();
    initDownloadButtons();
    initRefreshCache();
  });

  // ── Tab switching ──────────────────────────────────────────────────────────
  function initTabs() {
    const tabs    = document.querySelectorAll('.input-tab');
    const panes   = document.querySelectorAll('.input-pane');

    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('input-tab--active'));
        panes.forEach(p => p.classList.add('input-pane--hidden'));

        tab.classList.add('input-tab--active');
        const pane = document.getElementById('pane-' + tab.dataset.tab);
        if (pane) pane.classList.remove('input-pane--hidden');
      });
    });
  }

  // ── Form submission ────────────────────────────────────────────────────────
  function initForm() {
    const form = document.getElementById('assess-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      await runAssessment(form);
    });
  }

  async function runAssessment(form) {
    const btn         = document.getElementById('btn-assess');
    const spinner     = document.getElementById('assess-spinner');
    const errorBox    = document.getElementById('assess-error');
    const statsBar    = document.getElementById('stats-bar');
    const reportCard  = document.getElementById('report-card');

    setLoading(btn, spinner, true);
    clearError(errorBox);
    statsBar.style.display  = 'none';
    reportCard.style.display = 'none';

    const formData = new FormData(form);
    formData.set('action', 'assess');

    // Include the active tab so PHP knows which input method is in use.
    const activeTab = document.querySelector('.input-tab--active');
    if (activeTab) formData.set('input_method', activeTab.dataset.tab);

    try {
      const resp = await fetch(form.action || window.location.href, {
        method: 'POST',
        body: formData,
      });

      if (!resp.ok) {
        throw new Error('Server returned ' + resp.status);
      }

      const data = await resp.json();

      if (data.error) {
        showError(errorBox, data.error);
        return;
      }

      currentData = data;
      activeFilter = 'all';

      renderStats(data);
      renderReport(data);

      statsBar.style.display   = 'grid';
      reportCard.style.display = 'block';

      reportCard.scrollIntoView({ behavior: 'smooth', block: 'start' });

    } catch (err) {
      showError(errorBox, 'Request failed: ' + err.message);
    } finally {
      setLoading(btn, spinner, false);
    }
  }

  // ── Cache refresh ──────────────────────────────────────────────────────────
  function initRefreshCache() {
    const btn       = document.getElementById('btn-refresh-cache');
    const statusEl  = document.getElementById('cache-status-msg');
    if (!btn) return;

    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.textContent = 'Refreshing…';
      if (statusEl) statusEl.textContent = '';

      const fd = new FormData();
      fd.set('action', 'refresh_cache');

      try {
        const resp = await fetch(window.location.href, { method: 'POST', body: fd });
        const data = await resp.json();
        if (statusEl) {
          statusEl.textContent = data.message || (data.ok ? 'Cache updated.' : 'Refresh failed.');
          statusEl.className   = 'cache-status-msg ' + (data.ok ? 'cache-status-ok' : 'cache-status-err');
        }
        // Update the version indicator in the UI
        const verEl = document.getElementById('br-version-indicator');
        if (verEl && data.version) verEl.textContent = 'BR v' + data.version;

      } catch {
        if (statusEl) {
          statusEl.textContent = 'Network error during refresh.';
          statusEl.className   = 'cache-status-msg cache-status-err';
        }
      } finally {
        btn.disabled    = false;
        btn.textContent = 'Refresh BR Cache';
      }
    });
  }

  // ── Stats bar ──────────────────────────────────────────────────────────────
  function renderStats(data) {
    const meta     = data.meta     || {};
    const sections = data.sections || [];

    const counts = { present: 0, thin: 0, missing: 0 };
    sections.forEach(s => { counts[s.status] = (counts[s.status] || 0) + 1; });

    const total    = sections.length;
    const coverage = total > 0
      ? Math.round(((counts.present + counts.thin) / total) * 1000) / 10
      : 0;

    const set = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    set('stat-pages',      meta.cps_pages      ?? '—');
    set('stat-words',      meta.cps_word_count  != null
          ? Number(meta.cps_word_count).toLocaleString() : '—');
    set('stat-br-version', meta.br_version      ?? '—');
    set('stat-br-total',   total);
    set('stat-covered',    counts.present);
    set('stat-thin',       counts.thin);
    set('stat-missing',    counts.missing);
    set('stat-coverage',   coverage.toFixed(1) + '%');

    // Coverage % bar
    const fillEl = document.getElementById('coverage-fill');
    if (fillEl) {
      fillEl.style.width = coverage + '%';
      fillEl.className   = 'coverage-fill ' + coverageClass(coverage);
    }
  }

  function coverageClass(pct) {
    if (pct >= 70) return 'coverage-fill--good';
    if (pct >= 40) return 'coverage-fill--warn';
    return 'coverage-fill--bad';
  }

  // ── Report / tree renderer ─────────────────────────────────────────────────
  function renderReport(data) {
    const meta     = data.meta     || {};
    const sections = data.sections || [];

    // Update header meta badges
    const set = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
    set('report-filename',   meta.cps_filename   ?? 'document');
    set('report-assessed-at', meta.assessed_at ? new Date(meta.assessed_at).toLocaleString() : '—');
    set('report-coverage',   (meta.coverage_percent ?? 0).toFixed(1) + '%');

    const tree = document.getElementById('json-tree');
    if (!tree) return;
    tree.innerHTML = '';

    sections.forEach((section, idx) => {
      tree.appendChild(makeSectionRow(section, idx));
    });

    applyFilter(activeFilter);
  }

  function makeSectionRow(section, idx) {
    const statusColor = { present: 'var(--status-present)', thin: 'var(--status-thin)', missing: 'var(--status-missing)' };
    const statusLabel = { present: 'PRESENT', thin: 'THIN', missing: 'MISSING' };

    const row = document.createElement('div');
    row.className = 'tree-row tree-row--' + section.status;
    row.dataset.status = section.status;
    row.dataset.idx    = idx;

    const confPct = Math.round((section.confidence || 0) * 100);

    row.innerHTML = `
      <div class="tree-row-header" role="button" aria-expanded="false">
        <span class="tree-toggle">▶</span>
        <span class="status-badge status-badge--${section.status}">${statusLabel[section.status] || section.status}</span>
        <span class="tree-section-id">${esc(section.br_section)}</span>
        <span class="tree-section-title">${esc(section.br_title)}</span>
        <span class="tree-conf-wrap">
          <span class="tree-conf-bar"><span class="tree-conf-fill tree-conf-fill--${section.status}" style="width:${confPct}%"></span></span>
          <span class="tree-conf-pct">${confPct}%</span>
        </span>
      </div>
      <div class="tree-row-detail" hidden>
        <table class="tree-detail-table">
          <tr><td class="td-key">br_section</td><td class="td-val">${esc(section.br_section)}</td></tr>
          <tr><td class="td-key">br_title</td><td class="td-val">${esc(section.br_title)}</td></tr>
          <tr><td class="td-key">status</td><td class="td-val"><span class="status-badge status-badge--${section.status}">${statusLabel[section.status]}</span></td></tr>
          <tr><td class="td-key">confidence</td><td class="td-val">${(section.confidence || 0).toFixed(3)} (${confPct}%)</td></tr>
          <tr><td class="td-key">cps_reference</td><td class="td-val td-ref">${esc(section.cps_reference || '—')}</td></tr>
          <tr><td class="td-key">notes</td><td class="td-val">${esc(section.notes || '—')}</td></tr>
        </table>
      </div>
    `;

    const header = row.querySelector('.tree-row-header');
    const detail = row.querySelector('.tree-row-detail');
    const toggle = row.querySelector('.tree-toggle');

    header.addEventListener('click', () => {
      const open = !detail.hidden;
      detail.hidden = open;
      toggle.textContent = open ? '▶' : '▼';
      header.setAttribute('aria-expanded', String(!open));
    });

    return row;
  }

  // ── Filter buttons ─────────────────────────────────────────────────────────
  function initFilterButtons() {
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-filter]');
      if (!btn) return;

      document.querySelectorAll('[data-filter]').forEach(b => b.classList.remove('filter-btn--active'));
      btn.classList.add('filter-btn--active');

      activeFilter = btn.dataset.filter;
      applyFilter(activeFilter);
    });
  }

  function applyFilter(filter) {
    document.querySelectorAll('.tree-row').forEach(row => {
      const show = filter === 'all' || row.dataset.status === filter;
      row.style.display = show ? '' : 'none';
    });
  }

  // ── Expand / Collapse all ──────────────────────────────────────────────────
  function initExpandCollapse() {
    document.addEventListener('click', (e) => {
      if (e.target.id === 'btn-expand-all') {
        document.querySelectorAll('.tree-row-detail').forEach(d => { d.hidden = false; });
        document.querySelectorAll('.tree-toggle').forEach(t => { t.textContent = '▼'; });
        document.querySelectorAll('.tree-row-header').forEach(h => h.setAttribute('aria-expanded', 'true'));
      }
      if (e.target.id === 'btn-collapse-all') {
        document.querySelectorAll('.tree-row-detail').forEach(d => { d.hidden = true; });
        document.querySelectorAll('.tree-toggle').forEach(t => { t.textContent = '▶'; });
        document.querySelectorAll('.tree-row-header').forEach(h => h.setAttribute('aria-expanded', 'false'));
      }
    });
  }

  // ── Download buttons ───────────────────────────────────────────────────────
  function initDownloadButtons() {
    document.addEventListener('click', (e) => {
      if (e.target.id === 'btn-dl-json') downloadJSON();
      if (e.target.id === 'btn-dl-csv')  downloadCSV();
    });
  }

  function downloadJSON() {
    if (!currentData) return;
    const dateStr = isoDateCompact();
    triggerDownload(
      JSON.stringify(currentData, null, 2),
      'application/json',
      `cps_assessment_${dateStr}.json`
    );
  }

  function downloadCSV() {
    if (!currentData || !currentData.sections) return;
    const cols = ['br_section', 'br_title', 'status', 'confidence', 'cps_reference', 'notes'];
    const rows = [cols.join(',')];
    currentData.sections.forEach(s => {
      rows.push(cols.map(c => csvCell(s[c] ?? '')).join(','));
    });
    const dateStr = isoDateCompact();
    triggerDownload(rows.join('\r\n'), 'text/csv', `cps_assessment_${dateStr}.csv`);
  }

  function triggerDownload(content, type, filename) {
    const blob = new Blob([content], { type });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement('a'), { href: url, download: filename });
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  // ── Helpers ────────────────────────────────────────────────────────────────
  function setLoading(btn, spinner, loading) {
    if (btn)     btn.disabled     = loading;
    if (btn)     btn.textContent  = loading ? 'Assessing…' : 'Run Assessment';
    if (spinner) spinner.style.display = loading ? 'inline-block' : 'none';
  }

  function showError(box, msg) {
    if (!box) return;
    box.style.display = 'flex';
    const span = box.querySelector('span:last-child');
    if (span) span.textContent = msg;
    else box.textContent = msg;
  }

  function clearError(box) {
    if (!box) return;
    box.style.display = 'none';
  }

  function esc(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function csvCell(val) {
    const s = String(val).replace(/"/g, '""');
    return /[,"\r\n]/.test(s) ? `"${s}"` : s;
  }

  function isoDateCompact() {
    return new Date().toISOString().slice(0, 10).replace(/-/g, '');
  }
})();
